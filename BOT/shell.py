from __future__ import annotations

import asyncio
import json
import os
import pwd
import shutil
import sys
import tempfile
from dataclasses import dataclass
from typing import Any

STAGE_MARKER = "OBHOD_STAGE="
MANIFEST_ENV = "OBHOD_SUDO"
STAGE_ENV = "OBHOD_STAGE_DIR"
STAGE_DIR = "/var/tmp/obhod-stage"
MAX_STAGE = 64 * 1024 * 1024
SYSTEMCTL_VERBS = (
    "restart",
    "start",
    "stop",
    "reload",
    "reload-or-restart",
    "reset-failed",
    "daemon-reload",
    "enable",
    "disable",
    "kill",
    "try-restart",
)
READ_VERBS = ("cat", "head", "tail", "grep", "ls", "stat", "wc", "readlink", "md5sum", "sha256sum", "diff", "cmp")
WRITE_VERBS = ("cp", "mv", "install", "mkdir", "chmod", "chown", "rm", "tee", "tar", "touch", "ln", "sed", "truncate", "dd", "patch", "unzip", "gunzip", "gzip")
HELPER = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import BOT.shell as staging\n"
    "raise SystemExit(staging.run_helper(sys.argv[2], sys.argv[3:]))\n"
)


class ShellError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class ShellOutput:
    text: str
    code: int = 0


def agent_argv(argv: list[str], source: str) -> list[str]:
    return [sys.executable or "python3", "-c", source] + [str(item) for item in argv]


def plain(value: str) -> str:
    text = str(value or "")
    return bool(text) and all(char.isalnum() or char in "-_./:=@+,%+" for char in text)


def quote_argv(argv: list[str]) -> str:
    return " ".join(item if plain(item) else "'" + item.replace("'", "'\\''") + "'" for item in (str(part) for part in argv))


def verb_of(argv: list[str]) -> str:
    items = [str(item) for item in argv]
    index = 0
    while index < len(items) and items[index] in {"sudo", "env", "nohup", "timeout"}:
        index += 1
        if items[index - 1] == "env":
            while index < len(items) and "=" in items[index] and not items[index].startswith("/"):
                index += 1
        if items[index - 1] == "timeout":
            index += 1
    return os.path.basename(items[index]) if index < len(items) else ""


def read_target(argv: list[str]) -> str:
    items = [str(item) for item in argv]
    verb = verb_of(items)
    if verb not in READ_VERBS:
        return ""
    found = ""
    for item in items[1:]:
        if item.startswith("-"):
            continue
        if os.path.isabs(item):
            found = item
    return found


def write_target(argv: list[str]) -> str:
    items = [str(item) for item in argv]
    verb = verb_of(items)
    if verb not in WRITE_VERBS and verb != "systemctl":
        return ""
    if verb == "systemctl":
        return "/etc/systemd/system" if any(item in SYSTEMCTL_VERBS for item in items) else ""
    found = ""
    for item in items[1:]:
        if item.startswith("-"):
            continue
        if os.path.isabs(item):
            found = item
    return found


def sudo_prefix() -> list[str]:
    return ["sudo", "-n", "--"]


def drop_privs() -> Any:
    uid = int(os.environ.get("SUDO_UID", "0") or 0)
    gid = int(os.environ.get("SUDO_GID", "0") or 0)
    if uid <= 0:
        return None
    try:
        entry = pwd.getpwuid(uid)
    except KeyError:
        return None
    try:
        os.setgroups(list(os.getgrouplist(entry.pw_name, entry.pw_gid)))
        os.setgid(gid or entry.pw_gid)
        os.setuid(uid)
    except OSError:
        return None
    return entry.pw_name


def stage_dir() -> str:
    return os.environ.get(STAGE_ENV, "") or STAGE_DIR


def stage_file(body: bytes) -> str:
    folder = stage_dir()
    os.makedirs(folder, mode=0o700, exist_ok=True)
    try:
        os.chmod(folder, 0o700)
    except OSError:
        pass
    uid = int(os.environ.get("SUDO_UID", "0") or 0)
    gid = int(os.environ.get("SUDO_GID", "0") or 0)
    handle, path = tempfile.mkstemp(dir=folder, prefix="payload-", suffix=".bin")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(body or b"")
            stream.flush()
            os.fsync(stream.fileno())
        if uid > 0:
            os.chown(path, uid, gid)
        os.chmod(path, 0o600)
    except OSError as exc:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise ShellError("the payload could not be staged: %s" % exc) from None
    return path


def read_body(path: str) -> bytes:
    with open(path, "rb") as stream:
        return stream.read(MAX_STAGE)


def emit_stage(path: str, mode: str = "write") -> None:
    line = STAGE_MARKER + json.dumps({"path": path, "mode": mode}, sort_keys=True)
    stdout_write(line + "\n")


def run_helper(mode: str, args: list[str]) -> int:
    wanted: Any = None
    if mode == "read" and args:
        wanted = args[0]
    if mode == "write" and args:
        wanted = args[0]
    if mode == "stat" and args:
        try:
            info = os.stat(args[0])
        except OSError:
            emit_stage("", "missing")
            return 0
        emit_stage("%d %d" % (int(info.st_uid), int(info.st_mode & 0o777)), "stat")
        return 0
    if not wanted:
        emit_stage("", "missing")
        return 0
    if mode == "read":
        try:
            body = read_body(str(wanted))
        except OSError as exc:
            stdout_write("the file could not be read: %s" % exc)
            return 1
        stream = getattr(sys.stdout, "buffer", None)
        if stream is None:
            stdout_write(body.decode("utf-8", "replace"))
        else:
            stream.write(body)
            stream.flush()
        return 0
    body = sys.stdin.buffer.read(MAX_STAGE) if getattr(sys.stdin, "buffer", None) is not None else b""
    try:
        path = stage_file(body)
    except ShellError as exc:
        stdout_write(exc.message)
        return 1
    emit_stage(path, "write")
    return 0


def stdout_write(text: str) -> None:
    stream = getattr(sys.stdout, "buffer", None)
    if stream is None:
        sys.stdout.write(str(text or ""))
        sys.stdout.flush()
        return
    stream.write(str(text or "").encode("utf-8", "surrogateescape"))
    stream.flush()


def staged_path(text: str) -> tuple[str, str]:
    for line in reversed(str(text or "").splitlines()):
        token = line.strip()
        if not token.startswith(STAGE_MARKER):
            continue
        try:
            body = json.loads(token[len(STAGE_MARKER) :])
        except ValueError:
            return "", ""
        if not isinstance(body, dict):
            return "", ""
        return str(body.get("path", "") or ""), str(body.get("mode", "") or "")
    return "", ""


class LocalShell:
    def __init__(self, command_timeout: float = 300.0, root: str | os.PathLike[str] | None = None) -> None:
        self.command_timeout = float(command_timeout)
        self.root = str(root or os.environ.get("OBHOD_DIR") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self._sudo: bool | None = None

    @property
    def escalated(self) -> bool:
        return os.geteuid() != 0

    def python(self) -> str:
        return sys.executable or "python3"

    def require_root(self) -> None:
        if not self.escalated:
            return
        if MANIFEST_ENV in os.environ and shutil.which("sudo"):
            return
        if not shutil.which("sudo"):
            raise ShellError(
                "the bot must run as root on its own machine, start it as root or from systemd; "
                "a non root start needs sudo (apt install sudo) and the unit needs the sudo group"
            )

    async def usable_sudo(self) -> bool:
        if not self.escalated:
            return True
        if self._sudo is not None:
            return self._sudo
        out = await self._spawn(["sudo", "-n", "true"], None, 20.0)
        self._sudo = int(out.code or 0) == 0
        if not self._sudo:
            raise ShellError(
                "the bot is not root and sudo is not passwordless for this user; "
                "run it from systemd (see the unit) or add the sudoers line from the installer"
            )
        return True

    async def _spawn(
        self,
        argv: list[str],
        stdin: bytes | None,
        limit: float,
        cwd: str = "",
        stdin_file: str = "",
    ) -> ShellOutput:
        handle = None
        source: Any = asyncio.subprocess.PIPE
        if stdin_file:
            try:
                handle = open(stdin_file, "rb")
            except OSError as exc:
                raise ShellError("the staged payload is gone: %s" % exc) from None
            source = handle
        try:
            child = await asyncio.create_subprocess_exec(
                *argv,
                stdin=source,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=dict(os.environ),
                cwd=cwd or None,
            )
        except OSError as exc:
            if handle is not None:
                handle.close()
            raise ShellError(f"the command could not start: {exc}") from None
        try:
            out, _ = await asyncio.wait_for(child.communicate(None if stdin_file else (stdin if stdin is not None else b"")), limit)
        except asyncio.TimeoutError:
            child.kill()
            await child.wait()
            raise ShellError(f"the command did not finish within {int(limit)} seconds") from None
        finally:
            if handle is not None:
                handle.close()
        text = (out or b"").decode("utf-8", "replace")
        return ShellOutput(text=text.strip(), code=int(child.returncode or 0))

    async def _helper(self, mode: str, args: list[str], limit: float) -> ShellOutput:
        return await self._spawn(
            sudo_prefix() + [self.python(), "-c", HELPER, self.root, mode, *args],
            None,
            limit,
        )

    async def _staged(self, argv: list[str], stdin: bytes | None, limit: float) -> ShellOutput:
        target = read_target(argv)
        mode = "read" if target else "write"
        wanted = target or write_target(argv)
        if not wanted:
            return await self._spawn(sudo_prefix() + argv, stdin, limit)
        probe = await self._helper(mode, [wanted], min(limit, 30.0))
        path, kind = staged_path(probe.text)
        if mode == "read" and path:
            body = read_body(path)
            self._drop(path)
            if int(probe.code or 0) != 0:
                return ShellOutput(text=body.decode("utf-8", "replace").strip(), code=int(probe.code or 1))
            final = await self._spawn(sudo_prefix() + argv, body, limit)
            return final
        if mode == "read":
            return await self._spawn(sudo_prefix() + argv, stdin, limit)
        if not path:
            return await self._spawn(sudo_prefix() + argv, stdin, limit)
        try:
            with open(path, "wb") as stream:
                stream.write(stdin if stdin is not None else b"")
        except OSError as exc:
            self._drop(path)
            return ShellOutput(text="the payload could not be written: %s" % exc, code=1)
        out = await self._spawn(sudo_prefix() + argv, None, limit, stdin_file=path)
        self._drop(path)
        return out

    def _drop(self, path: str) -> None:
        try:
            os.unlink(path)
        except OSError:
            return

    async def run_argv(self, argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> ShellOutput:
        self.require_root()
        limit = float(timeout or self.command_timeout)
        items = [str(item) for item in argv]
        if not self.escalated:
            return await self._spawn(items, stdin, limit)
        await self.usable_sudo()
        if MANIFEST_ENV in os.environ:
            return await self._spawn(sudo_prefix() + items, stdin, limit)
        return await self._staged(items, stdin, limit)

    async def run(self, command: str, stdin: bytes | None = None, timeout: float | None = None, cfg: object = None) -> ShellOutput:
        return await self.run_argv(["/bin/sh", "-c", command], stdin=stdin, timeout=timeout)
