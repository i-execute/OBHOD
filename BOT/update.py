from __future__ import annotations

import asyncio
import gzip
import inspect
import json
import logging
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

log = logging.getLogger("obhod.update")

REPO = "i-execute/OBHOD"
BRANCH = "main"
REMOTE = "origin"
UNIT = "obhod.service"
MARKER = "update.json"
TAG_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+$")
GET_URL = "https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh"
GET_FALLBACK_URL = "https://github.com/i-execute/OBHOD/raw/main/get.sh"
GET_URLS = (GET_URL, GET_FALLBACK_URL)
GET_HOSTS = ("raw.githubusercontent.com", "github.com", "codeload.github.com", "objects.githubusercontent.com")
GET_MAX = 262144
GET_TIMEOUT = 30.0
GET_CACHE_TTL = 30.0
FETCH_TTL = 15.0
GIT_LOW_SPEED = ("-c", "http.lowSpeedLimit=1024", "-c", "http.lowSpeedTime=20")
REINSTALL_TIMEOUT = 1800.0
STAGE_ENV = "OBHOD_STAGE_DIR"
STAGE_DIR = "/var/tmp/obhod-stage"
DEST_DIR = "/opt/obhod-src"
REINSTALL_UNIT = "obhod-reinstall"
SELF_UNIT = "obhod-self-update"
KEPT_UNTRACKED = ("venv", ".venv", ".env", "obhod.env")
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
    def __init__(self, message: str, code: str = "", detail: str = "", path: str = "", step: str = "", log: list[str] | None = None, copy_ok: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.detail = detail
        self.path = path
        self.step = step
        self.log = list(log or [])
        self.copy_ok = bool(copy_ok)

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "code": self.code,
            "detail": self.detail,
            "path": self.path,
            "step": self.step,
            "log": list(self.log),
            "copy_ok": self.copy_ok,
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


BLOCKED_TARGETS = ("/etc/obhod", "/opt/obhod", "/usr/local/bin", "/etc/systemd/system", "/var/lib/obhod")


def blocked_target(line: str) -> str:
    for item in BLOCKED_TARGETS:
        if item in str(line or ""):
            return item
    return ""


def code_blocked(detail: str) -> str:
    low = str(detail or "").lower()
    if not any(hint in low for hint in READONLY_HINTS):
        return ""
    if blocked_target(detail) in BLOCKED_TARGETS:
        return "blocked"
    return "installer"


def plain_error(text: str) -> str:
    body = " ".join(str(text or "").split())
    low = body.lower()
    where = blocked_target(body)
    suffix = " (%s)" % where if where else ""
    if "function not implemented" in low:
        return "the sandbox refused the write%s, run get.sh from a normal root shell" % suffix
    if "read-only file system" in low or "read-only mount" in low:
        return "the sandbox refused the write%s, run get.sh from a normal root shell" % suffix
    return body[:200]


COPY_FAIL_MARKS = ("tar: ", "cp: ", "could not be copied", "cannot create", "cannot open", "cannot remove")

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
    copy_failed = ""
    seen_copy = False
    for line in lines:
        low = line.lower()
        if "copied " in low or "files updated in" in low:
            seen_copy = True
            continue
        if any(mark in low for mark in COPY_FAIL_MARKS):
            copy_failed = line
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
    report = {
        "detail": detail[:300],
        "path": failed_path(detail),
        "step": failed_step(text),
        "copy_ok": bool(seen_copy and not copy_failed),
        "copy_detail": copy_failed[:200],
    }
    return report


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


def decode_get_payload(raw: bytes, headers: object) -> bytes:
    if not raw or headers is None or not hasattr(headers, "get"):
        return raw
    encoding = str(headers.get("Content-Encoding", "") or "").strip().lower()
    if encoding == "gzip":
        try:
            return gzip.decompress(raw)[: GET_MAX + 1]
        except OSError as exc:
            raise UpdateError("the get.sh gzip stream is broken: %s" % exc) from None
    return raw


def fetch_get_body(url: str, timeout: float = GET_TIMEOUT) -> str:
    if not allowed_get(url):
        raise UpdateError("the get.sh address %s is not allowed" % url)
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "obhod-get/1",
            "Accept": "text/plain",
            "Accept-Encoding": "gzip",
        },
    )
    last_error = ""
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                geturl = getattr(response, "geturl", None)
                if callable(geturl):
                    final_url = str(geturl() or "")
                    if final_url and not allowed_get(final_url):
                        raise UpdateError("the get.sh redirect %s is not allowed" % final_url)
                raw = response.read(GET_MAX + 1)
                body = decode_get_payload(raw, getattr(response, "headers", None))
                if len(body) > GET_MAX:
                    raise UpdateError("the get.sh body is larger than %d bytes" % GET_MAX)
                return body.decode("utf-8", "replace")
        except UpdateError:
            raise
        except urllib.error.HTTPError as exc:
            code = int(getattr(exc, "code", 0) or 0)
            last_error = "the get.sh download answered http %d" % code
            if code < 500 and code != 429:
                raise UpdateError(last_error) from None
        except (OSError, ValueError):
            last_error = "the get.sh download did not finish, check that github is reachable"
        if attempt == 0:
            time.sleep(0.25)
    raise UpdateError(last_error or "the get.sh download did not finish, check that github is reachable")


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
        self._fetched_at = 0.0
        self._get_cache: tuple[float, str] = (0.0, "")

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
        branch, commit, subject, tag, status, unit_state = await asyncio.gather(
            self._git_text("branch", "--show-current"),
            self._git_text("rev-parse", "--short", "HEAD"),
            self._git_text("log", "-1", "--pretty=%s"),
            self._git_text("describe", "--tags", "--abbrev=0"),
            self._git_text("status", "--porcelain"),
            self._unit_state(),
        )
        info.branch = branch or self.branch
        info.commit = commit
        info.subject = subject
        info.tag = tag
        info.dirty = len([line for line in status.splitlines() if line.strip()])
        info.unit_state = unit_state
        return info

    async def _release(self) -> tuple[str, str]:
        tag, reason = await asyncio.to_thread(releases.latest_tag_any, self.repo)
        if TAG_RE.match(tag or ""):
            return tag, ""
        return "", reason or "no_tag"

    async def _fetch_remote(self, force: bool = False) -> Any:
        now = time.monotonic()
        if not force and self._fetched_at > 0 and (now - self._fetched_at) < FETCH_TTL:
            return None
        extra: tuple[str, ...] = ("--unshallow",) if (self.root / ".git" / "shallow").is_file() else ()
        fetched = await self._git(*GIT_LOW_SPEED, "fetch", "--prune", "--tags", *extra, REMOTE)
        if int(fetched.code or 0) == 0:
            self._fetched_at = time.monotonic()
        return fetched

    async def check_commit(self, force: bool = False) -> UpdateInfo:
        info = await self.read()
        fetched = await self._fetch_remote(force=force)
        if fetched is not None and int(fetched.code or 0) != 0:
            raise UpdateError("the fetch failed: %s" % clean_output(fetched.text))
        ref = "%s/%s" % (REMOTE, info.branch or self.branch)
        remote, remote_subject, behind, ahead = await asyncio.gather(
            self._git_text("rev-parse", "--short", ref),
            self._git_text("log", "-1", "--pretty=%s", ref),
            self._git_text("rev-list", "--count", "HEAD..%s" % ref),
            self._git_text("rev-list", "--count", "%s..HEAD" % ref),
        )
        info.remote = remote
        info.remote_subject = remote_subject
        info.behind = int(behind or 0)
        info.ahead = int(ahead or 0)
        return info

    async def check_release(self) -> UpdateInfo:
        info = await self.read()
        info.release, info.release_error = await self._release()
        return info

    async def check_all(self, force: bool = False) -> UpdateInfo:
        info, (release_tag, release_err) = await asyncio.gather(
            self.check_commit(force=force),
            self._release(),
        )
        info.release, info.release_error = release_tag, release_err
        return info

    def get_script(self) -> Path:
        return Path("/usr/local/bin/obhod-get")

    def env_file(self) -> Path:
        return Path(os.environ.get("OBHOD_ENV") or "/etc/obhod/obhod.env")

    def stage_dir(self) -> Path:
        return Path(os.environ.get(STAGE_ENV) or STAGE_DIR)

    async def fetch_get(self) -> str:
        now = time.monotonic()
        if self._get_cache[1] and self._get_cache[0] > now:
            return self._get_cache[1]
        cached = self.get_script()
        failure = ""
        for candidate in GET_URLS:
            try:
                body = await asyncio.to_thread(fetch_get_body, candidate, GET_TIMEOUT)
            except UpdateError as exc:
                body, failure = "", exc.message
                continue
            if body and "obhod-install.sh" in body:
                self._get_cache = (time.monotonic() + GET_CACHE_TTL, body)
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

    async def can_update(self) -> tuple[bool, str]:
        info = await self.describe()
        if not info.get("root_write"):
            return False, str(info.get("root_reason") or "the install directory is not writable")
        if str((info.get("protected") or {}).get("inside")) == "yes":
            return False, "the service runs inside a strict sandbox"
        flags = info.get("root_flags") or {}
        if flags.get("path"):
            return False, "the install directory is on a read-only mount %s" % flags.get("path")
        return True, ""

    def _write_staged_script(self, body: str) -> Path:
        stage = self.stage_dir()
        stage.mkdir(parents=True, exist_ok=True)
        os.chmod(stage, 0o700)
        script = stage / "get.sh"
        tmp = stage / "get.sh.tmp"
        handle = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o700)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(body)
        os.chmod(tmp, 0o700)
        os.replace(tmp, script)
        return script

    async def probe_reinstall(self) -> tuple[bool, str]:
        writable, reason = await self.preflight()
        if not writable:
            return False, reason
        body = await self.fetch_get()
        try:
            script = self._write_staged_script(body)
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

    async def detached(self, argv: list[str], unit: str = REINSTALL_UNIT, after: str = "") -> bool:
        if shutil.which("systemd-run") is None:
            return False
        if after:
            timer = [
                "systemd-run",
                "--quiet",
                "--collect",
                "--no-block",
                "--on-active=%d" % RESTART_DELAY,
                "--unit=%s-timer" % SELF_UNIT,
                "systemctl",
                "restart",
                after,
            ]
            queued = await self._run(timer, UNIT_TIMEOUT)
            if int(queued.code or 0) != 0:
                log.warning("the delayed restart could not be queued: %s", clean_output(queued.text)[:200])
            if not argv:
                return int(queued.code or 0) == 0
        request = [
            "systemd-run",
            "--quiet",
            "--collect",
            "--no-block",
            "--unit=" + unit,
            "--property=Type=oneshot",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
            *argv,
        ]
        out = await self._run(request, UNIT_TIMEOUT)
        if int(out.code or 0) != 0:
            log.warning("the detached unit %s did not start: %s", unit, clean_output(out.text)[:200])
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
        try:
            script = self._write_staged_script(body)
        except OSError as exc:
            raise UpdateError("the reinstall script could not be written to %s: %s" % (self.stage_dir() / "get.sh", exc)) from None
        env_file = self.env_file()
        args = ["bash", str(script), "install", "--yes"]
        if env_file.is_file():
            args.append("--env-file=%s" % env_file)
        detached = await self.detached(args, REINSTALL_UNIT, self.unit)
        if detached:
            return "the reinstall is running in the background as %s, the output goes to the journal under that unit name, the service restarts itself when it is done" % REINSTALL_UNIT
        out = await self._run(args, REINSTALL_TIMEOUT)

        text = str(out.text or "")
        if int(out.code or 0) == 0:
            return text
        report = installer_report(text)
        blocked = code_blocked(report["detail"])
        raise UpdateError(
            "the reinstall failed with the exit code %d: %s" % (int(out.code or 0), report["detail"] or "no output"),
            blocked or "installer",
            detail=report["detail"],
            path=report["path"],
            step=report["step"],
            log=installer_log(text),
            copy_ok=report["copy_ok"],
        )

    async def preview(self, mode: str) -> dict[str, Any]:
        info = await self.read()
        fetched = await self._fetch_remote(force=False)
        if fetched is not None and int(fetched.code or 0) != 0:
            raise UpdateError("the fetch failed: %s" % clean_output(fetched.text))
        info.release, info.release_error = await self._release()
        target, subject = await self._resolve(mode, info)
        count, changed = await asyncio.gather(
            self._git_text("rev-list", "--count", "%s..%s" % (info.commit, target)),
            self._git_text("diff", "--name-status", "%s..%s" % (info.commit, target)),
        )
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
        for folder in (".venv", "venv"):
            venv = self.root / folder / "bin" / "python"
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

    async def _sync_unit(self) -> None:
        if os.geteuid() != 0 or shutil.which("systemctl") is None:
            return
        template = self.root / "Storage" / "obhod.service"
        target = Path("/etc/systemd/system") / self.unit
        if not template.is_file() or template.is_symlink() or not target.is_file() or target.is_symlink():
            return
        try:
            current = target.read_text(encoding="utf-8")
            raw = template.read_text(encoding="utf-8")
        except OSError:
            return
        env_file = str(self.env_file())
        state_dir = str(self._state_dir or "/var/lib/obhod")
        for line in current.splitlines():
            if line.startswith("EnvironmentFile="):
                env_file = line.split("=", 1)[1].strip() or env_file
        rendered = (
            raw.replace("@PREFIX@/venv/bin/python", self._python())
            .replace("@PREFIX@", str(self.root))
            .replace("@ENV_FILE@", env_file)
            .replace("@STATE_DIR@", state_dir)
        )
        if rendered == current:
            return
        try:
            tmp = target.with_suffix(".service.tmp")
            tmp.write_text(rendered, encoding="utf-8")
            os.chmod(tmp, 0o644)
            os.replace(tmp, target)
            await self._run(["systemctl", "daemon-reload"], UNIT_TIMEOUT)
        except (OSError, UpdateError):
            return

    async def _restart(self) -> bool:
        await self._sync_unit()
        if shutil.which("systemctl") is None:
            return False
        if shutil.which("systemd-run") is not None:
            queued = await self.detached([], SELF_UNIT, self.unit)
            if queued:
                return True
        out = await self._run(["systemctl", "restart", "--no-block", self.unit], UNIT_TIMEOUT)
        return int(out.code or 0) == 0

    async def _emit_step(self, on_step: Any, stage: str, **payload: Any) -> None:
        if not callable(on_step):
            return
        maybe = on_step(stage, dict(payload))
        if inspect.isawaitable(maybe):
            await maybe

    async def apply(self, mode: str, on_step: Any = None) -> UpdateResult:
        if mode not in MODES:
            raise UpdateError("the update mode %s is not known" % mode)
        result = UpdateResult(mode=mode)
        before = await self.read()
        result.source = before.commit
        log.info("update %s starts from %s at %s", mode, before.commit[:12], self.root)
        await self._emit_step(on_step, "fetch", source=before.commit[:12])
        fetched = await self._fetch_remote(force=True)
        result.steps.append("fetch from %s" % REMOTE)
        log.info("update fetch from %s: code=%s %s", REMOTE, fetched.code, clean_output(fetched.text)[:200])
        if int(fetched.code or 0) != 0:
            result.message = "the fetch failed: %s" % clean_output(fetched.text)
            log.warning("update %s stopped, the fetch failed: %s", mode, result.message)
            return result
        await self._emit_step(on_step, "compare", source=before.commit[:12])
        info = await self.read()
        info.release, info.release_error = await self._release()
        target, subject = await self._resolve(mode, info)
        result.target = target[:7]
        result.subject = subject
        log.info("update %s target %s %s, release %s", mode, target[:12], subject[:80], info.release or info.release_error or "none")
        if same_commit(target, before.commit):
            result.ok = True
            result.message = "already up to date"
            log.info("update %s reports already up to date at %s", mode, before.commit[:12])
            return result
        await self._emit_step(on_step, "apply", source=before.commit[:12], target=result.target, subject=subject)
        await self._reset(target, result.steps)
        await self._emit_step(on_step, "verify", source=before.commit[:12], target=result.target, subject=subject)
        compiled, output = await self._compile()
        result.steps.append("syntax check passed" if compiled else "syntax check failed")
        if not compiled:
            log.warning("update %s stopped, the tree does not compile: %s", mode, clean_output(output)[:300])
            await self._reset(before.commit, result.steps)
            result.rollback = True
            result.message = "the new tree does not compile, the rollback to %s is done: %s" % (
                before.commit[:12],
                output or "no output",
            )
            return result
        changed = await self._git_text("diff", "--name-only", "%s..%s" % (before.commit, target))
        deps_needed = "requirements.txt" in changed.splitlines()
        if deps_needed:
            await self._emit_step(on_step, "deps", source=before.commit[:12], target=result.target, subject=subject, deps=True)
            installed, output = await self._install_deps()
            result.steps.append("dependencies synced" if installed else "the dependency sync failed")
            if not installed:
                log.warning("update %s stopped, the dependency sync failed: %s", mode, clean_output(output)[:300])
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
        await self._emit_step(on_step, "restarting", source=before.commit[:12], target=result.target, subject=subject, deps=deps_needed)
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
                "subject": info.subject,
                "branch": info.branch,
                "repo": self.repo,
                "output": "" if healthy else output,
            }
        )
        self.write_marker(marker)
        return marker
