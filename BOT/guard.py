from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import SshSettings
from .xrayrpc import XrayControl, XrayError, XrayResponse, b64

REMOTE_DIR = Path(__file__).resolve().parent.parent / "Storage" / "remote"
FAIL2BAN_SCRIPT = REMOTE_DIR / "fail2ban_agent.py"
SSH_SCRIPT = REMOTE_DIR / "ssh_agent.py"

DEFAULT_BANTIME = 30
DEFAULT_FINDTIME = 1920
DEFAULT_MAXRETRY = 1
DEFAULT_SSH_BANTIME = "3d"
DEFAULT_SSH_FINDTIME = 3600
DEFAULT_SSH_MAXRETRY = 3
DEFAULT_IGNOREIP = "127.0.0.1/8 ::1"
DEFAULT_LOGPATH = "/var/log/xray/access.log"


def script_code(path: Path, name: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise XrayError("%s is missing next to the bot: %s" % (name, exc), "internal") from None


DEFAULT_JAIL = "obhod-ipl"
LEGACY_JAIL = "3x-ipl"


def jail_name(raw: object) -> str:
    value = str(raw or "").strip() or DEFAULT_JAIL
    return DEFAULT_JAIL if value == LEGACY_JAIL else value


@dataclass
class BanState:
    installed: bool = False
    jail: str = DEFAULT_JAIL
    ssh_jail: str = "obhod-sshd"
    sub_jail: str = "obhod-subs"
    jails: list[str] = field(default_factory=list)
    banned: list[str] = field(default_factory=list)
    ssh_banned: list[str] = field(default_factory=list)
    sub_banned: list[str] = field(default_factory=list)
    chain: str = "OBHOD-IPL"
    chain_rules: list[str] = field(default_factory=list)
    port: int = 0

    @property
    def active(self) -> bool:
        return bool(self.installed and self.jail in self.jails)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BanState":
        data = raw or {}
        main = data.get("main") or {}
        ssh = data.get("ssh") or {}
        return cls(
            installed=bool(data.get("installed", False)),
            jail=jail_name(data.get("jail")),
            ssh_jail=str(data.get("ssh_jail", "obhod-sshd") or "obhod-sshd"),
            jails=[str(item) for item in data.get("jails") or []],
            banned=[str(item) for item in main.get("banned") or []],
            ssh_banned=[str(item) for item in ssh.get("banned") or []],
            sub_banned=[str(item) for item in (data.get("subs") or {}).get("banned") or []],
            sub_jail=str(data.get("sub_jail", "obhod-subs") or "obhod-subs"),
            chain=str(data.get("chain", "OBHOD-IPL") or "OBHOD-IPL"),
            chain_rules=[str(item) for item in data.get("chain_rules") or []],
            port=int(data.get("port", 0) or 0),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "installed": self.installed,
            "jail": self.jail,
            "ssh_jail": self.ssh_jail,
            "sub_jail": self.sub_jail,
            "jails": list(self.jails),
            "banned": list(self.banned),
            "ssh_banned": list(self.ssh_banned),
            "sub_banned": list(self.sub_banned),
            "chain": self.chain,
            "chain_rules": list(self.chain_rules),
            "port": int(self.port),
        }


@dataclass
class SshState:
    config: str = ""
    config_exists: bool = False
    dropin: str = ""
    dropin_exists: bool = False
    ports: list[int] = field(default_factory=lambda: [22])
    permit_root_login: str = ""
    password_authentication: str = ""
    pubkey_authentication: str = ""
    key_user: str = ""
    key_path: str = ""
    keys: int = 0
    key_list: list[dict[str, Any]] = field(default_factory=list)
    service: str = ""
    sshd: bool = False
    systemd: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SshState":
        data = raw or {}
        return cls(
            config=str(data.get("config", "") or ""),
            config_exists=bool(data.get("config_exists", False)),
            dropin=str(data.get("dropin", "") or ""),
            dropin_exists=bool(data.get("dropin_exists", False)),
            ports=[int(item) for item in data.get("ports") or [22]],
            permit_root_login=str(data.get("permit_root_login", "") or ""),
            password_authentication=str(data.get("password_authentication", "") or ""),
            pubkey_authentication=str(data.get("pubkey_authentication", "") or ""),
            key_user=str(data.get("key_user", "") or ""),
            key_path=str(data.get("key_path", "") or ""),
            keys=int(data.get("keys", 0) or 0),
            key_list=[
                {
                    "type": str(item.get("type", "") or "")[:32],
                    "comment": str(item.get("comment", "") or "")[:48],
                    "fingerprint": str(item.get("fingerprint", "") or "")[:64],
                    "bytes": int(item.get("bytes", 0) or 0),
                }
                for item in data.get("key_list") or []
                if isinstance(item, dict)
            ][:32],
            service=str(data.get("service", "") or ""),
            sshd=bool(data.get("sshd", False)),
            systemd=bool(data.get("systemd", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config,
            "config_exists": self.config_exists,
            "dropin": self.dropin,
            "dropin_exists": self.dropin_exists,
            "ports": list(self.ports),
            "permit_root_login": self.permit_root_login,
            "password_authentication": self.password_authentication,
            "pubkey_authentication": self.pubkey_authentication,
            "key_user": self.key_user,
            "key_path": self.key_path,
            "keys": int(self.keys),
            "key_list": list(self.key_list),
            "service": self.service,
            "sshd": self.sshd,
            "systemd": self.systemd,
        }


class GuardClient:
    def __init__(self, control: XrayControl | None = None) -> None:
        self.control = control or XrayControl()

    async def _call(self, cfg: SshSettings, script: Path, name: str, argv: list[str], timeout: float = 180.0) -> XrayResponse:
        source = script_code(script, name)
        response = await self.control.call(cfg, argv, timeout=timeout, source=source)
        response.raise_for_status()
        return response

    async def status(self, cfg: SshSettings, port: int = 0) -> BanState:
        response = await self._call(cfg, FAIL2BAN_SCRIPT, "fail2ban script", ["status", "--port=%d" % int(port)], 120)
        return BanState.from_dict(response.data)

    async def install(
        self,
        cfg: SshSettings,
        port: int = 0,
        bantime: int = DEFAULT_BANTIME,
        findtime: int = DEFAULT_FINDTIME,
        maxretry: int = DEFAULT_MAXRETRY,
        logpath: str = DEFAULT_LOGPATH,
        ssh: bool = True,
        ssh_bantime: str = DEFAULT_SSH_BANTIME,
        ssh_maxretry: int = DEFAULT_SSH_MAXRETRY,
        ignoreip: str = DEFAULT_IGNOREIP,
        security: bool = True,
    ) -> BanState:
        argv = [
            "install",
            "--port=%d" % int(port),
            "--bantime=%d" % int(bantime),
            "--findtime=%d" % int(findtime),
            "--maxretry=%d" % int(maxretry),
            "--logpath=%s" % (logpath or DEFAULT_LOGPATH),
            "--ssh_bantime=%s" % (ssh_bantime or DEFAULT_SSH_BANTIME),
            "--ssh_maxretry=%d" % int(ssh_maxretry),
            "--ignoreip=%s" % (ignoreip or DEFAULT_IGNOREIP),
        ]
        if not ssh:
            argv.append("--ssh=no")
        if not security:
            argv.append("--security=no")
        response = await self._call(cfg, FAIL2BAN_SCRIPT, "fail2ban script", argv, 300)
        return BanState.from_dict(response.data)

    async def remove(self, cfg: SshSettings, port: int = 0) -> BanState:
        response = await self._call(cfg, FAIL2BAN_SCRIPT, "fail2ban script", ["remove", "--port=%d" % int(port)], 240)
        return BanState.from_dict(response.data)

    async def ban(self, cfg: SshSettings, address: str, port: int = 0) -> BanState:
        response = await self._call(cfg, FAIL2BAN_SCRIPT, "fail2ban script", ["ban", "--ip=%s" % address, "--port=%d" % int(port)], 120)
        return BanState.from_dict(response.data)

    async def unban(self, cfg: SshSettings, address: str, port: int = 0) -> BanState:
        response = await self._call(cfg, FAIL2BAN_SCRIPT, "fail2ban script", ["unban", "--ip=%s" % address, "--port=%d" % int(port)], 120)
        return BanState.from_dict(response.data)

    async def ssh_status(self, cfg: SshSettings) -> SshState:
        response = await self._call(cfg, SSH_SCRIPT, "ssh script", ["status"], 90)
        return SshState.from_dict(response.data)

    async def ssh_apply(
        self,
        cfg: SshSettings,
        port: int = 0,
        password: str = "",
        root: str = "",
    ) -> SshState:
        argv = ["apply"]
        if port:
            argv.append("--port=%d" % int(port))
        if password in {"yes", "no"}:
            argv.append("--password=%s" % password)
        if root:
            argv.append("--root=%s" % root)
        response = await self._call(cfg, SSH_SCRIPT, "ssh script", argv, 240)
        return SshState.from_dict(response.data)

    async def ssh_add_key(self, cfg: SshSettings, public_key: str) -> SshState:
        payload = b64((public_key or "").strip().encode("utf-8"))
        response = await self._call(cfg, SSH_SCRIPT, "ssh script", ["key", "--key-b64=%s" % payload], 120)
        return SshState.from_dict(response.data)

    async def ssh_remove(self, cfg: SshSettings) -> SshState:
        response = await self._call(cfg, SSH_SCRIPT, "ssh script", ["remove"], 240)
        return SshState.from_dict(response.data)
