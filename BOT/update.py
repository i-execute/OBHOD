from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import releases
from .shell import LocalShell, ShellError

REPO = "i-execute/OBHOD"
BRANCH = "main"
REMOTE = "origin"
UNIT = "obhod.service"
MARKER = "update.json"
TAG_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+$")
GET_URL = "https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh"
GET_HOSTS = ("raw.githubusercontent.com", "github.com", "codeload.github.com", "objects.githubusercontent.com")
GET_MAX = 262144
GET_TIMEOUT = 30.0
REINSTALL_TIMEOUT = 1800.0
STAGE_ENV = "OBHOD_STAGE_DIR"
STAGE_DIR = "/var/tmp/obhod-stage"
DEST_DIR = "/opt/obhod-src"
REINSTALL_UNIT = "obhod-reinstall"
KEPT_UNTRACKED = (".venv", ".env")
COMPILE_TARGETS = ("BOT", "Storage/remote", "tools")
MODES = ("commit", "release")
GIT_TIMEOUT = 180.0
COMPILE_TIMEOUT = 180.0
DEPS_TIMEOUT = 900.0
UNIT_TIMEOUT = 30.0
RESTART_DELAY = 3
TAIL = 400
PREVIEW_FILES = 8


class UpdateError(Exception):
    def __init__(self, message: str, code: str = "", detail: str = "", path: str = "", step: str = "", log: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.detail = detail
        self.path = path
        self.step = step
        self.log = list(log or [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "code": self.code,
            "detail": self.detail,
            "path": self.path,
            "step": self.step,
            "log": list(self.log),
        }


@dataclass
class UpdateInfo:
    root: str = ""
    git: bool = False
    branch: str = ""
    commit: str = ""
    subject: str = ""
    tag: str = ""
    dirty: int = 0
    behind: int = 0
    ahead: int = 0
    remote: str = ""
    remote_subject: str = ""
    release: str = ""
    release_error: str = ""
    unit: str = UNIT
    unit_state: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "git": bool(self.git),
            "branch": self.branch,
            "commit": self.commit,
            "subject": self.subject,
            "tag": self.tag,
            "dirty": int(self.dirty),
            "behind": int(self.behind),
            "ahead": int(self.ahead),
            "remote": self.remote,
            "remote_subject": self.remote_subject,
            "release": self.release,
            "release_error": self.release_error,
            "unit": self.unit,
            "unit_state": self.unit_state,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "UpdateInfo":
        data = dict(raw or {})
        return UpdateInfo(
            root=str(data.get("root", "") or ""),
            git=bool(data.get("git", False)),
            branch=str(data.get("branch", "") or ""),
            commit=str(data.get("commit", "") or ""),
            subject=str(data.get("subject", "") or ""),
            tag=str(data.get("tag", "") or ""),
            dirty=int(data.get("dirty", 0) or 0),
            behind=int(data.get("behind", 0) or 0),
            ahead=int(data.get("ahead", 0) or 0),
            remote=str(data.get("remote", "") or ""),
            remote_subject=str(data.get("remote_subject", "") or ""),
            release=str(data.get("release", "") or ""),
            release_error=str(data.get("release_error", "") or ""),
            unit=str(data.get("unit", UNIT) or UNIT),
            unit_state=str(data.get("unit_state", "") or ""),
        )

    @property
    def update_available(self) -> bool:
        return bool(self.behind or (self.release and self.release != self.tag))


@dataclass
class UpdateResult:
    ok: bool = False
    mode: str = ""
    source: str = ""
    target: str = ""
    subject: str = ""
    steps: list[str] = field(default_factory=list)
    message: str = ""
    restarted: bool = False
    rollback: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": bool(self.ok),
            "mode": self.mode,
            "source": self.source,
            "target": self.target,
            "subject": self.subject,
            "steps": list(self.steps),
            "message": self.message,
            "restarted": bool(self.restarted),
            "rollback": bool(self.rollback),
        }


def clean_output(text: str) -> str:
    return (text or "").strip()[:TAIL]


def plain_error(text: str) -> str:
    body = " ".join(str(text or "").split())
    if "function not implemented" in body.lower():
        return (
            "the service could not write its own files (the sandbox forbids that write), "
            "so an in-bot reinstall cannot replace /opt/obhod; run get.sh from a normal root shell"
        )
    if "read-only file system" in body.lower():
        return "a file is on a read-only mount, the unit needs the write access to the install directory"
    return body[:200]


READONLY_HINTS = ("function not implemented", "read-only file system", "cannot open", "operation not permitted", "cannot remove", "permission denied")


PATH_RE = re.compile(r"(/[A-Za-z0-9._+@%/-]{2,})")
STEP_RE = re.compile(r"^\s*(?:step:\s*|starting\s+)(.{3,80})$")


def failed_path(line: str) -> str:
    found = PATH_RE.findall(str(line or ""))
    return found[0] if found else ""


def failed_step(text: str) -> str:
    found = ""
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("error:") or stripped.startswith("the install"):
            break
        match = STEP_RE.match(stripped)
        if match:
            found = match.group(1).strip()
        elif stripped.lower().startswith(("copying", "installing", "downloading", "updating")):
            found = stripped.rstrip(". ").strip()
    return found[:80]


def installer_log(text: str, keep: int = 8) -> list[str]:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    tail = lines[-keep:]
    return [line[:160] for line in tail]


def fs_flags(path: str) -> dict[str, str]:
    target = Path(path or "/")
    for candidate in (target, *target.parents):
        try:
            status = os.statvfs(str(candidate))
        except OSError:
            continue
        if not status.f_flag & os.ST_RDONLY:
            continue
        flags = {"path": str(candidate), "fstype": "", "mount": str(candidate), "options": "ro"}
        try:
            for line in Path("/proc/mounts").read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[1] == str(candidate):
                    flags["fstype"] = parts[2]
                    flags["options"] = parts[3]
                    break
        except OSError:
            pass
        return flags
    return {}


def unit_protects(unit: str = UNIT) -> dict[str, str]:
    path = Path("/proc/self/cgroup")
    inside = False
    try:
        body = path.read_text(encoding="utf-8", errors="replace")
        inside = bool(unit) and (unit in body or unit.removesuffix(".service") in body)
    except OSError:
        inside = False
    if not inside:
        return {"inside": "no", "protect_system": "", "paths": ""}
    settings: dict[str, str] = {}
    try:
        for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace").splitlines():
            fields = line.split()
            if len(fields) > 4 and fields[4] == "/":
                settings["root"] = fields[4]
                break
    except OSError:
        pass
    return {"inside": "yes", "protect_system": "strict", "paths": str(settings.get("root", ""))}


def read_only_mounts() -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    try:
        lines = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return found
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        options = parts[3].split(",")
        if "ro" not in options:
            continue
        found.append({"path": parts[1], "fstype": parts[2], "options": parts[3]})
    return found[:8]


def installer_report(text: str) -> dict[str, str]:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    detail = ""
    for line in reversed(lines):
        low = line.lower()
        if any(hint in low for hint in READONLY_HINTS):
            detail = line
            break
    if not detail:
        for line in lines:
            if line.startswith("error:") or line.startswith("the install"):
                detail = line
                break
    if not detail and lines:
        detail = lines[-1]
    return {
        "detail": detail[:300],
        "path": failed_path(detail),
        "step": failed_step(text),
    }


def installer_failure(text: str) -> str:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    for line in lines:
        if line.startswith("error:") or line.startswith("the install"):
            return plain_error(line)
    for line in reversed(lines):
        low = line.lower()
        if any(hint in low for hint in READONLY_HINTS):
            return plain_error(line)
    return plain_error(lines[-1]) if lines else ""


def allowed_get(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme != "https":
        return False
    host = (parts.hostname or "").lower()
    return any(host == item or host.endswith("." + item) for item in GET_HOSTS)


def fetch_get_body(url: str, timeout: float = GET_TIMEOUT) -> str:
    if not allowed_get(url):
        raise UpdateError("the get.sh address %s is not allowed" % url)
    request = urllib.request.Request(url, headers={"User-Agent": "obhod-get/1", "Accept": "text/plain"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(GET_MAX + 1)
    except urllib.error.HTTPError as exc:
        raise UpdateError("the get.sh download answered http %d" % int(getattr(exc, "code", 0) or 0)) from None
    except (OSError, ValueError):
        raise UpdateError("the get.sh download did not finish, check that github is reachable") from None
    if len(body) > GET_MAX:
        raise UpdateError("the get.sh body is larger than %d bytes" % GET_MAX)
    return body.decode("utf-8", "replace")


SANDBOX_REASONS = {
    1: "operation not permitted",
    30: "the file system is read-only",
    13: "permission denied",
    38: "the kernel call is not implemented for this file system",
    5: "the input/output failed",
}


def write_probe(path: Path) -> tuple[bool, str]:
    target = Path(path)
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, "%s (%s)" % (SANDBOX_REASONS.get(exc.errno or 0, exc.strerror or str(exc)), target)
    probe = target / ".obhod-write-probe"
    try:
        handle = os.open(str(probe), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.write(handle, b"probe")
            os.fsync(handle)
        finally:
            os.close(handle)
        os.unlink(str(probe))
    except OSError as exc:
        return False, "%s (%s)" % (SANDBOX_REASONS.get(exc.errno or 0, exc.strerror or str(exc)), target)
    return True, ""


def same_commit(left: str, right: str) -> bool:
    first = str(left or "").strip()
    second = str(right or "").strip()
    if not first or not second:
        return False
    return first.startswith(second) or second.startswith(first)


class Updater:
    def __init__(
        self,
        shell: LocalShell | None = None,
        root: str | Path | None = None,
        state_dir: str | Path | None = None,
        repo: str = REPO,
        branch: str = BRANCH,
        unit: str = UNIT,
    ) -> None:
        self.shell = shell or LocalShell()
        self.repo = repo
        self.branch = branch
        self.unit = unit
        default_root = os.environ.get("OBHOD_DIR", "") or str(Path(__file__).resolve().parent.parent)
        self._root = Path(root) if root else Path(default_root)
        self._state_dir = Path(state_dir) if state_dir else None

    @property
    def root(self) -> Path:
        return self._root

    @property
    def marker_path(self) -> Path:
        base = self._state_dir or (self._root / ".state")
        return Path(base) / MARKER

    async def _run(self, argv: list[str], timeout: float) -> Any:
        try:
            return await self.shell.run_argv(argv, timeout=timeout)
        except ShellError as exc:
            raise UpdateError(exc.message) from None
        except OSError as exc:
            raise UpdateError("the command could not start: %s" % exc) from None

    async def _git(self, *args: str, timeout: float = GIT_TIMEOUT) -> Any:
        return await self._run(["git", "-C", str(self.root), *args], timeout)

    async def _git_text(self, *args: str, timeout: float = GIT_TIMEOUT) -> str:
        out = await self._git(*args, timeout=timeout)
        return str(out.text or "").strip() if int(out.code or 0) == 0 else ""

    async def _unit_state(self) -> str:
        if shutil.which("systemctl") is None:
            return "absent"
        out = await self._run(["systemctl", "is-active", self.unit], UNIT_TIMEOUT)
        text = [line for line in str(out.text or "").splitlines() if line.strip()]
        if text:
            return text[0].strip()
        return "inactive" if int(out.code or 0) else "active"

    async def read(self) -> UpdateInfo:
        info = UpdateInfo(root=str(self.root), unit=self.unit)
        if not self.root.is_dir():
            raise UpdateError("the source directory %s is missing" % self.root)
        inside = await self._git_text("rev-parse", "--is-inside-work-tree")
        if inside != "true":
            raise UpdateError("the source directory %s is not a git checkout" % self.root)
        info.git = True
        info.branch = await self._git_text("branch", "--show-current") or self.branch
        info.commit = await self._git_text("rev-parse", "--short", "HEAD")
        info.subject = await self._git_text("log", "-1", "--pretty=%s")
        info.tag = await self._git_text("describe", "--tags", "--abbrev=0")
        status = await self._git_text("status", "--porcelain")
        info.dirty = len([line for line in status.splitlines() if line.strip()])
        info.unit_state = await self._unit_state()
        return info

    async def _release(self) -> tuple[str, str]:
        tag, reason = await asyncio.to_thread(releases.latest_tag_any, self.repo)
        if TAG_RE.match(tag or ""):
            return tag, ""
        return "", reason or "no_tag"

    async def check_commit(self) -> UpdateInfo:
        info = await self.read()
        fetched = await self._git("fetch", "--prune", "--tags", REMOTE)
        if int(fetched.code or 0) != 0:
            raise UpdateError("the fetch failed: %s" % clean_output(fetched.text))
        ref = "%s/%s" % (REMOTE, info.branch or self.branch)
        info.remote = await self._git_text("rev-parse", "--short", ref)
        info.remote_subject = await self._git_text("log", "-1", "--pretty=%s", ref)
        behind = await self._git_text("rev-list", "--count", "HEAD..%s" % ref)
        ahead = await self._git_text("rev-list", "--count", "%s..HEAD" % ref)
        info.behind = int(behind or 0)
        info.ahead = int(ahead or 0)
        return info

    async def check_release(self) -> UpdateInfo:
        info = await self.read()
        info.release, info.release_error = await self._release()
        return info

    async def check_all(self) -> UpdateInfo:
        info = await self.check_commit()
        info.release, info.release_error = await self._release()
        return info

    def get_script(self) -> Path:
        return Path("/usr/local/bin/obhod-get")

    def env_file(self) -> Path:
        return Path(os.environ.get("OBHOD_ENV") or "/etc/obhod/obhod.env")

    def stage_dir(self) -> Path:
        return Path(os.environ.get(STAGE_ENV) or STAGE_DIR)

    async def fetch_get(self) -> str:
        cached = self.get_script()
        failure = ""
        try:
            body = await asyncio.to_thread(fetch_get_body, GET_URL, GET_TIMEOUT)
        except UpdateError as exc:
            body, failure = "", exc.message
        if body and "obhod-install.sh" in body:
            return body
        if cached.is_file():
            text = cached.read_text(encoding="utf-8", errors="replace")
            if "obhod-install.sh" in text:
                return text
        raise UpdateError("the get.sh script could not be fetched: %s" % (failure or "the body is empty"))

    def dest(self) -> Path:
        return Path(os.environ.get("OBHOD_DIR") or DEST_DIR)

    def reinstall_command(self, env_file: str = "") -> str:
        parts = ["curl -fsSL %s | sudo bash -s -- install --yes" % GET_URL]
        if env_file:
            parts[-1] += " --env-file=%s" % env_file
        return parts[-1]

    async def probe_write(self, path: Path) -> tuple[bool, str]:
        return await asyncio.to_thread(write_probe, path)

    async def preflight(self) -> tuple[bool, str]:
        ok, reason = await self.probe_write(self.root)
        if ok:
            return True, ""
        return False, reason

    async def system_flags(self) -> dict[str, Any]:
        flags = await asyncio.to_thread(fs_flags, str(self.root))
        dest_flags = await asyncio.to_thread(fs_flags, str(self.dest()))
        return {
            "root_flags": flags,
            "dest_flags": dest_flags,
            "readonly_mounts": await asyncio.to_thread(read_only_mounts),
            "protected": await asyncio.to_thread(unit_protects, self.unit),
        }

    async def probe_reinstall(self) -> tuple[bool, str]:
        writable, reason = await self.preflight()
        if not writable:
            return False, reason
        body = await self.fetch_get()
        script = self.stage_dir() / "get.sh"
        try:
            self.stage_dir().mkdir(parents=True, exist_ok=True)
            os.chmod(self.stage_dir(), 0o700)
            script.write_text(body, encoding="utf-8")
            os.chmod(script, 0o700)
        except OSError as exc:
            return False, "the staged script could not be written (%s)" % (exc.strerror or exc)
        out = await self._run(["bash", "-n", str(script)], UNIT_TIMEOUT)
        if int(out.code or 0) != 0:
            return False, "the fetched get.sh does not parse: %s" % clean_output(out.text)[:120]
        return True, str(script)

    async def describe(self) -> dict[str, Any]:
        dest = self.dest()
        dest_ok, dest_reason = await self.probe_write(dest)
        root_ok, root_reason = await self.probe_write(self.root)
        helper = self.get_script()
        info: dict[str, Any] = {
            "root": str(self.root),
            "unit_state": await self._unit_state(),
            "python": (self.root / "venv" / "bin" / "python").is_file() or (self.root / ".venv" / "bin" / "python").is_file(),
            "dest": str(dest),
            "dest_write": dest_ok,
            "dest_reason": dest_reason,
            "root_write": root_ok,
            "root_reason": root_reason,
            "helper": helper.is_file(),
            "helper_write": helper.is_file() and os.access(helper, os.W_OK),
            "user": os.getuid(),
            "command": self.reinstall_command(str(self.env_file()) if self.env_file().is_file() else ""),
        }
        info.update(await self.system_flags())
        return info

    async def detached(self, argv: list[str], unit: str = REINSTALL_UNIT) -> bool:
        if shutil.which("systemd-run") is None:
            return False
        out = await self._run(
            [
                "systemd-run",
                "--quiet",
                "--collect",
                "--unit=" + unit,
                "--property=Type=oneshot",
                "--property=StandardOutput=journal",
                "--property=StandardError=journal",
                *argv,
            ],
            UNIT_TIMEOUT,
        )
        return int(out.code or 0) == 0

    async def reinstall(self, on_log: Any = None) -> str:
        writable, reason = await self.preflight()
        if not writable:
            raise UpdateError(
                "the bot cannot rewrite its own files in %s (%s), so the update is done from a root shell"
                % (self.root, reason or "the unit keeps the tree read-only"),
                "readonly",
            )
        body = await self.fetch_get()
        script = self.stage_dir() / "get.sh"
        try:
            self.stage_dir().mkdir(parents=True, exist_ok=True)
            os.chmod(self.stage_dir(), 0o700)
            script.write_text(body, encoding="utf-8")
            os.chmod(script, 0o700)
        except OSError as exc:
            raise UpdateError("the reinstall script could not be written to %s: %s" % (script, exc)) from None
        env_file = self.env_file()
        args = ["bash", str(script), "install", "--yes"]
        if env_file.is_file():
            args.append("--env-file=%s" % env_file)
        detached = await self.detached(args)
        if detached:
            return "the reinstall is running in the background, the service restarts itself when it is done"
        out = await self._run(args, REINSTALL_TIMEOUT)

        text = str(out.text or "")
        if int(out.code or 0) == 0:
            return text
        report = installer_report(text)
        raise UpdateError(
            "the reinstall failed with the exit code %d: %s" % (int(out.code or 0), report["detail"] or "no output"),
            "installer",
            detail=report["detail"],
            path=report["path"],
            step=report["step"],
            log=installer_log(text),
        )

    async def preview(self, mode: str) -> dict[str, Any]:
        info = await self.read()
        fetched = await self._git("fetch", "--prune", "--tags", REMOTE)
        if int(fetched.code or 0) != 0:
            raise UpdateError("the fetch failed: %s" % clean_output(fetched.text))
        info.release, info.release_error = await self._release()
        target, subject = await self._resolve(mode, info)
        count = await self._git_text("rev-list", "--count", "%s..%s" % (info.commit, target))
        changed = await self._git_text("diff", "--name-status", "%s..%s" % (info.commit, target))
        files = []
        for line in changed.splitlines()[:PREVIEW_FILES]:
            parts = line.split("\t")
            if len(parts) >= 2:
                files.append("%s %s" % (parts[0].strip(), parts[1].strip()))
        return {
            "base": info.commit,
            "target": target[:7],
            "subject": subject,
            "commits": int(count or 0),
            "files": files,
            "total": len([line for line in changed.splitlines() if line.strip()]),
        }

    async def _resolve(self, mode: str, info: UpdateInfo) -> tuple[str, str]:
        if mode == "commit":
            ref = "%s/%s" % (REMOTE, info.branch or self.branch)
            sha = await self._git_text("rev-parse", ref)
            if not sha:
                raise UpdateError("the branch %s is not in the checkout" % ref)
            return sha, await self._git_text("log", "-1", "--pretty=%s", ref)
        if mode == "release":
            tag = info.release
            if not TAG_RE.match(tag or ""):
                raise UpdateError("no published tag was found, the api answered %s" % (info.release_error or "nothing"))
            sha = await self._git_text("rev-parse", "refs/tags/%s^{commit}" % tag)
            if not sha:
                raise UpdateError("the tag %s is not in the checkout, run the fetch again" % tag)
            return sha, await self._git_text("log", "-1", "--pretty=%s", tag)
        raise UpdateError("the update mode %s is not known" % mode)

    async def _compile(self) -> tuple[bool, str]:
        targets = [str(self.root / name) for name in COMPILE_TARGETS if (self.root / name).is_dir()]
        if not targets:
            return False, "there is nothing to compile in %s" % self.root
        out = await self._run([sys.executable or "python3", "-m", "compileall", "-q", *targets], COMPILE_TIMEOUT)
        return int(out.code or 0) == 0, clean_output(out.text)

    def _python(self) -> str:
        venv = self.root / ".venv" / "bin" / "python"
        if venv.is_file() and os.access(str(venv), os.X_OK):
            return str(venv)
        return sys.executable or "python3"

    async def _install_deps(self) -> tuple[bool, str]:
        requirements = self.root / "requirements.txt"
        if not requirements.is_file():
            return True, ""
        out = await self._run(
            [self._python(), "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r", str(requirements)],
            DEPS_TIMEOUT,
        )
        return int(out.code or 0) == 0, clean_output(out.text)

    async def _reset(self, target: str, steps: list[str]) -> None:
        out = await self._git("reset", "--hard", target)
        if int(out.code or 0) != 0:
            raise UpdateError("the reset to %s failed: %s" % (target[:12], clean_output(out.text)))
        steps.append("reset to %s" % target[:12])
        kept = list(KEPT_UNTRACKED)
        state = self._state_dir
        if state is not None:
            try:
                kept.append(str(Path(state).resolve().relative_to(self.root.resolve())))
            except ValueError:
                pass
        keep = [item for name in kept if name for item in ("-e", name)]
        clean = await self._git("clean", "-fd", *keep)
        if int(clean.code or 0) != 0:
            steps.append("the clean skipped: %s" % clean_output(clean.text))
        else:
            steps.append("untracked files removed")

    async def _restart(self) -> bool:
        if shutil.which("systemctl") is None:
            return False
        if shutil.which("systemd-run") is not None:
            argv = [
                "systemd-run",
                "--quiet",
                "--collect",
                "--on-active=%d" % RESTART_DELAY,
                "--unit=obhod-self-update",
                "systemctl",
                "restart",
                self.unit,
            ]
        else:
            argv = ["systemctl", "restart", "--no-block", self.unit]
        try:
            out = await self._run(argv, UNIT_TIMEOUT)
        except UpdateError:
            return False
        return int(out.code or 0) == 0

    async def apply(self, mode: str) -> UpdateResult:
        if mode not in MODES:
            raise UpdateError("the update mode %s is not known" % mode)
        result = UpdateResult(mode=mode)
        before = await self.read()
        result.source = before.commit
        fetched = await self._git("fetch", "--prune", "--tags", REMOTE)
        result.steps.append("fetch from %s" % REMOTE)
        if int(fetched.code or 0) != 0:
            result.message = "the fetch failed: %s" % clean_output(fetched.text)
            return result
        info = await self.read()
        info.release, info.release_error = await self._release()
        target, subject = await self._resolve(mode, info)
        result.target = target[:7]
        result.subject = subject
        if same_commit(target, before.commit):
            result.ok = True
            result.message = "already up to date"
            return result
        await self._reset(target, result.steps)
        compiled, output = await self._compile()
        result.steps.append("syntax check passed" if compiled else "syntax check failed")
        if not compiled:
            await self._reset(before.commit, result.steps)
            result.rollback = True
            result.message = "the new tree does not compile, the rollback to %s is done: %s" % (
                before.commit[:12],
                output or "no output",
            )
            return result
        changed = await self._git_text("diff", "--name-only", "%s..%s" % (before.commit, target))
        if "requirements.txt" in changed.splitlines():
            installed, output = await self._install_deps()
            result.steps.append("dependencies synced" if installed else "the dependency sync failed")
            if not installed:
                await self._reset(before.commit, result.steps)
                result.rollback = True
                result.message = "the dependencies did not install, the rollback to %s is done: %s" % (
                    before.commit[:12],
                    output or "no output",
                )
                return result
        self.write_marker(
            {
                "mode": mode,
                "from": before.commit,
                "to": target,
                "subject": subject,
                "at": time.time(),
                "pending": True,
                "unit": self.unit,
                "root": str(self.root),
            }
        )
        result.ok = True
        result.message = "updated to %s" % subject
        result.restarted = await self._restart()
        result.steps.append("the restart of %s is requested" % self.unit if result.restarted else "restart skipped")
        return result

    def marker(self) -> dict[str, Any]:
        path = self.marker_path
        try:
            if path.is_symlink() or not path.is_file():
                return {}
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return raw if isinstance(raw, dict) else {}

    def write_marker(self, payload: dict[str, Any]) -> None:
        path = self.marker_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                path.unlink()
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError:
            return

    async def verify(self) -> dict[str, Any]:
        marker = self.marker()
        if not marker or not marker.get("pending"):
            return {}
        target = str(marker.get("to", "") or "")
        try:
            info = await self.read()
        except UpdateError:
            return {}
        compiled, output = await self._compile()
        state = await self._unit_state()
        matched = not target or same_commit(info.commit, target)
        healthy = bool(compiled) and matched
        marker.update(
            {
                "pending": False,
                "healthy": healthy,
                "state": state,
                "verified": time.time(),
                "commit": info.commit,
                "output": "" if healthy else output,
            }
        )
        self.write_marker(marker)
        return marker
