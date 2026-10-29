from __future__ import annotations

import asyncio
import io
import os
import re
import shlex
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import i18n
from .models import SshSettings
from .shell import LocalShell, ShellError, ShellOutput

INSTALL_DIR = "/opt/obhod"
STATE_DIR = "/var/lib/obhod"
ENV_FILE = "/etc/obhod/obhod.env"
UNIT_PATH = "/etc/systemd/system/obhod.service"
PAYLOAD_ITEMS = ("BOT", "Storage", "requirements.txt", "run.sh", "pytest.ini")
REFUSAL = "the install is possible only from root, run sudo bash run.sh bootstrap"


class BootstrapError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def tr() -> i18n.Translator:
    return i18n.translator(i18n.DEFAULT_LANGUAGE)


def _printf(text: str) -> str:
    return "printf '%s\\n' " + shlex.quote(text)


def check_root(euid: int | None = None) -> None:
    value = os.geteuid() if euid is None else int(euid)
    if value != 0:
        raise BootstrapError(REFUSAL)


def verify_admin(user_id: int, expected: int) -> tuple[bool, int, str]:
    who = int(user_id or 0)
    want = int(expected or 0)
    if who <= 0:
        return False, want, tr()("BOOT_ID_NONE")
    if want <= 0:
        return True, who, tr()("BOOT_ID_PINNED")
    if who != want:
        return False, want, tr()("BOOT_ID_MISMATCH", who=who, want=want)
    return True, want, tr()("BOOT_ID_MATCH")


@dataclass
class BootstrapPlan:
    token: str = ""
    api_id: int = 0
    api_hash: str = ""
    admin_id: int = 0
    install_dir: str = INSTALL_DIR
    state_dir: str = STATE_DIR
    python: str = "python3"
    dev: bool = False
    check: bool = False
    steps: list[str] = field(default_factory=list)

    def settings(self) -> SshSettings:
        return SshSettings()

    def validate(self) -> None:
        safe_path(self.install_dir, "the install directory")
        safe_path(self.state_dir, "the state directory")
        for name, value in (("BOT_TOKEN", self.token), ("API_HASH", self.api_hash)):
            if any(char in value for char in "\n\r\x00") or "OBHODENV" in value or "OBHODUNIT" in value:
                raise BootstrapError("%s contains a forbidden character" % name)
        if not str(self.api_id).isdigit() or int(self.api_id) <= 0:
            raise BootstrapError("API_ID must be a positive number")
        if not str(self.admin_id).isdigit() or int(self.admin_id) < 0:
            raise BootstrapError("ADMIN_ID must be a number, zero means the first user claims it")

    def env_text(self) -> str:
        pairs = [
            ("BOT_TOKEN", self.token),
            ("API_ID", str(self.api_id)),
            ("API_HASH", self.api_hash),
            ("ADMIN_ID", str(self.admin_id)),
            ("OBHOD_STATE_DIR", self.state_dir),
            ("OBHOD_LOG_LEVEL", "INFO"),
        ]
        return "\n".join(f"{name}={value}" for name, value in pairs) + "\n"


SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,120}$")


def safe_path(value: str, label: str) -> str:
    text = str(value or "").strip()
    if not SAFE_PATH.match(text) or ".." in text.split("/"):
        raise BootstrapError("%s must be a simple absolute path" % label)
    return text


def parse_args(argv: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {"dev": False, "check": False}
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in {"--dev", "--check"}:
            out[token[2:]] = True
            index += 1
            continue
        if not token.startswith("--"):
            index += 1
            continue
        body = token[2:]
        if "=" in body:
            key, value = body.split("=", 1)
        else:
            key = body
            value = argv[index + 1] if index + 1 < len(argv) else ""
            index += 1
        out[key.replace("-", "_")] = value
        index += 1
    return out


def plan_from(args: dict[str, Any]) -> BootstrapPlan:
    return BootstrapPlan(
        token=str(args.get("token") or args.get("bot_token") or ""),
        api_id=int(args.get("api_id") or 0),
        api_hash=str(args.get("api_hash") or ""),
        admin_id=int(args.get("admin_id") or 0),
        install_dir=str(args.get("install_dir") or INSTALL_DIR),
        state_dir=str(args.get("state_dir") or STATE_DIR),
        dev=bool(args.get("dev", False)),
        check=bool(args.get("check", False)),
    )


UNIT_TEMPLATE = """[Unit]
Description=OBHOD bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={root}
EnvironmentFile={env}
Environment=HOME=/root
ExecStart={root}/.venv/bin/python -m BOT
Restart=on-failure
RestartSec=5
User=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateDevices=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
ReadWritePaths={state} /var/log /root/.goygram -/etc/fail2ban -/etc/ssh -/etc/systemd/system -/usr/local/bin -/usr/local/etc/xray -/usr/local/share/xray -/var/lib/xray-manager -/root/.ssh -/home
LogsDirectory=obhod
LogsDirectoryMode=0700

[Install]
WantedBy=multi-user.target
"""


def install_script(plan: BootstrapPlan, phase: str = "deps") -> str:
    t = tr()
    head = [
        "set -euo pipefail",
        "ROOT=" + shlex.quote(safe_path(plan.install_dir, "the install directory")),
        "STATE=" + shlex.quote(safe_path(plan.state_dir, "the state directory")),
        f"ENV_FILE={ENV_FILE}",
        f"UNIT={UNIT_PATH}",
        f'PY="${{PYTHON:-{plan.python}}}"',
        'if [ "$(id -u)" != "0" ]; then ' + _printf(t("BOOT_ROOT_FIRST")) + "; exit 1; fi",
        'if ! command -v "$PY" >/dev/null 2>&1; then ' + _printf(t("BOOT_NO_PYTHON")) + "; exit 1; fi",
        'mkdir -p "$ROOT" "$STATE" "$(dirname "$ENV_FILE")"',
        'mkdir -p -m 700 /root/.goygram /root/.ssh',
        'mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d /etc/fail2ban/action.d /etc/ssh/sshd_config.d',
        'mkdir -p /usr/local/bin /usr/local/etc/xray /usr/local/share/xray /etc/systemd/system',
        'mkdir -p /var/lib/xray-manager /var/log/xray',
        'chmod 700 "$STATE"',
    ]
    lines = list(head)
    if phase == "deps":
        lines.extend(
            [
                'rm -rf "$ROOT/.venv"',
                '"$PY" -m venv "$ROOT/.venv"',
                '"$ROOT/.venv/bin/pip" install --quiet --upgrade pip',
                '"$ROOT/.venv/bin/pip" install --quiet -r "$ROOT/requirements.txt"',
                _printf(t("BOOT_DEPS_DONE")),
            ]
        )
    if phase == "finalize":
        lines.extend(
            [
                'cat > "$ENV_FILE" <<OBHODENV',
                plan.env_text().rstrip("\n"),
                "OBHODENV",
                'chmod 600 "$ENV_FILE"',
                'cat > "$UNIT" <<OBHODUNIT',
                UNIT_TEMPLATE.format(root=plan.install_dir, env=ENV_FILE, state=plan.state_dir).rstrip("\n"),
                "OBHODUNIT",
                'chmod 644 "$UNIT"',
                "if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then",
                "  systemctl daemon-reload",
                "  systemctl enable obhod.service >/dev/null 2>&1 || true",
                "  systemctl restart obhod.service",
                "  " + _printf(t("BOOT_UNIT_STARTED")),
                "else",
                "  " + _printf(t("BOOT_UNIT_MANUAL")),
                "fi",
            ]
        )
    lines.append(_printf(t("BOOT_SHELL_DONE")))
    return "\n".join(lines) + "\n"


def payload_archive(root: Path | None = None) -> bytes:
    base = Path(root or Path(__file__).resolve().parent.parent)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name in PAYLOAD_ITEMS:
            target = base / name
            if not target.exists():
                continue
            bundle.add(target, arcname=name, filter=_skip_cache)
    return buffer.getvalue()


def _skip_cache(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    parts = Path(info.name).parts
    if any(part in {"__pycache__", ".pytest_cache", ".venv"} for part in parts):
        return None
    return info


CHECK_SCRIPT = """set -u
if [ "$(id -u)" != "0" ]; then printf 'root=no\\n'; else printf 'root=yes\\n'; fi
if command -v python3 >/dev/null 2>&1; then printf 'python=%s\\n' "$(python3 -c 'import sys;print(sys.version.split()[0])')"; else printf 'python=none\\n'; fi
if command -v systemctl >/dev/null 2>&1; then printf 'systemd=yes\\n'; else printf 'systemd=no\\n'; fi
if command -v tar >/dev/null 2>&1; then printf 'tar=yes\\n'; else printf 'tar=no\\n'; fi
printf 'disk=%s\\n' "$(df -Pk / | awk 'NR==2 {print $4}')"
python3 - <<'CHECKPY' 2>/dev/null || true
import socket
def probe(host, port):
    try:
        with socket.create_connection((host, port), timeout=5):
            return "yes"
    except OSError:
        return "no"
print("github=" + probe("github.com", 443))
print("telegram=" + probe("api.telegram.org", 443))
CHECKPY
printf 'check done\\n'
"""


async def check_plan(shell: LocalShell, plan: BootstrapPlan) -> list[tuple[str, bool, str]]:
    out = await shell.run_argv(["/bin/bash", "-s"], stdin=CHECK_SCRIPT.encode("utf-8"), timeout=180)
    values: dict[str, str] = {}
    for line in out.text.splitlines():
        token = line.strip()
        if "=" in token and not token.startswith("check"):
            key, value = token.split("=", 1)
            values[key.strip()] = value.strip()
    checks: list[tuple[str, bool, str]] = []
    checks.append((tr()("BOOT_CHK_ROOT"), values.get("root") == "yes", values.get("root", tr()("BOOT_NO_ANSWER"))))
    python = values.get("python", "none")
    checks.append((tr()("BOOT_CHK_PYTHON"), python not in {"", "none"}, python))
    systemd = values.get("systemd") == "yes"
    checks.append((tr()("BOOT_CHK_SYSTEMD"), systemd, tr()("BOOT_YES") if systemd else tr()("BOOT_NO_PROCESS")))
    tar = values.get("tar") == "yes"
    checks.append((tr()("BOOT_CHK_TAR"), tar, tr()("BOOT_YES") if tar else tr()("BOOT_NO")))
    disk = values.get("disk", "0")
    try:
        free_gb = int(disk) / 1024 / 1024
    except ValueError:
        free_gb = 0.0
    checks.append((tr()("BOOT_CHK_DISK"), free_gb >= 1.0, tr()("BOOT_DISK_GB", value=f"{free_gb:.1f}")))
    github = values.get("github") == "yes"
    checks.append((tr()("BOOT_CHK_GITHUB"), github, tr()("BOOT_REACHABLE") if github else tr()("BOOT_UNREACHABLE")))
    telegram = values.get("telegram") == "yes"
    checks.append((tr()("BOOT_CHK_TELEGRAM"), telegram, tr()("BOOT_REACHABLE") if telegram else tr()("BOOT_UNREACHABLE")))
    return checks


def format_checks(checks: list[tuple[str, bool, str]]) -> list[str]:
    lines = []
    for name, ok, detail in checks:
        mark = tr()("BOOT_MARK_OK") if ok else tr()("BOOT_MARK_NO")
        lines.append(f"{mark} {name}: {detail}")
    return lines


async def run_script(shell: LocalShell, script: str, timeout: float = 600.0) -> ShellOutput:
    return await shell.run_argv(["/bin/bash", "-s"], stdin=script.encode("utf-8"), timeout=timeout)


async def push_files(shell: LocalShell, blob: bytes, plan: BootstrapPlan) -> ShellOutput:
    prepare = await shell.run_argv(
        ["/bin/sh", "-c", f"mkdir -p {shlex.quote(plan.install_dir)} {shlex.quote(plan.state_dir)}"],
        timeout=120,
    )
    if prepare.code != 0:
        return prepare
    return await shell.run_argv(["/bin/tar", "-xzf", "-", "-C", plan.install_dir], stdin=blob, timeout=600)


async def install_files(shell: LocalShell, blob: bytes, plan: BootstrapPlan) -> list[ShellOutput]:
    out: list[ShellOutput] = []
    out.append(await push_files(shell, blob, plan))
    if out[-1].code == 0:
        out.append(await run_script(shell, install_script(plan, "deps")))
    return out


async def bootstrap(
    plan: BootstrapPlan,
    shell: LocalShell | None = None,
    payload: bytes | None = None,
    confirm: Callable[[], Any] | None = None,
    on_step: Callable[[str], Any] | None = None,
) -> list[str]:
    check_root(0 if not plan.dev else os.geteuid())
    client = shell or LocalShell()
    steps: list[str] = []

    async def note(text: str) -> None:
        steps.append(text)
        if on_step is not None:
            result = on_step(text)
            if hasattr(result, "__await__"):
                await result

    await note(tr()("BOOT_STEP_ROOT"))
    if not plan.token:
        raise BootstrapError("the bot token is not set")
    plan.validate()
    await note(tr()("BOOT_STEP_PUSH"))
    try:
        outs = await install_files(client, payload if payload is not None else payload_archive(), plan)
    except ShellError as exc:
        raise BootstrapError(f"the local install did not finish: {exc.message}") from None
    for out in outs:
        if out.code != 0:
            raise BootstrapError("the local install failed: " + out.text[-300:])
    await note(tr()("BOOT_STEP_FILES"))
    await note(tr()("BOOT_STEP_WAIT_ID"))
    if confirm is not None:
        result = confirm()
        if hasattr(result, "__await__"):
            result = await result
        user_id = int(result or 0)
    else:
        user_id = int(plan.admin_id or 0)
    ok, admin_id, message = verify_admin(user_id, plan.admin_id)
    if not ok:
        raise BootstrapError(message)
    plan.admin_id = admin_id
    await note(message)
    try:
        out = await run_script(client, install_script(plan, "finalize"))
    except ShellError as exc:
        raise BootstrapError(f"the service start did not finish: {exc.message}") from None
    if out.code != 0:
        raise BootstrapError("the service start failed: " + out.text[-300:])
    await note(tr()("BOOT_STEP_SERVICE"))
    await note(tr()("BOOT_STEP_NEXT"))
    return steps


def run(argv: list[str] | None = None) -> int:
    import sys

    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    plan = plan_from(args)
    try:
        check_root()
        if plan.check:
            return asyncio.run(check_only(plan))
        steps = asyncio.run(bootstrap(plan))
    except BootstrapError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    for line in steps:
        print(line)
    return 0


async def check_only(plan: BootstrapPlan, shell: LocalShell | None = None) -> int:
    client = shell or LocalShell()
    try:
        checks = await check_plan(client, plan)
    except ShellError as exc:
        raise BootstrapError(f"the local check did not finish: {exc.message}") from None
    for line in format_checks(checks):
        print(line)
    return 0 if all(item[1] for item in checks) else 1


def main(argv: list[str] | None = None) -> int:
    return run(argv)


def unit_text(plan: BootstrapPlan) -> str:
    return UNIT_TEMPLATE.format(root=plan.install_dir, env=ENV_FILE, state=plan.state_dir)
