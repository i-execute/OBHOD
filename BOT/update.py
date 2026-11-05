from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time
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
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


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
        tag, reason = releases.latest_tag_any(self.repo)
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

    async def reinstall(self) -> str:
        args = ["systemd-run", "--wait", "--collect", "--pipe", "--unit=obhod-reinstall", "bash", "-c", "curl -fsSL https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh | bash -s -- --yes"]
        out = await self._run(args, 900)
        text = str(out.text or "")
        if int(out.code or 0) != 0:
            raise UpdateError("the reinstall failed: %s" % text[-300:])
        return text

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
