from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import releases
from .shell import LocalShell, ShellError, ShellOutput, agent_argv

PROTO = 3
SCRIPT_REPO = "hackdiaz-dev/free-turn-proxy"
FALLBACK_VERSION = "v4.1.1"
DEFAULT_VERSION = FALLBACK_VERSION
RELEASE_URL = "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/{version}/{asset}"
SCRIPT_URL = RELEASE_URL
PINNED_SCRIPT_SHA256 = {
    "v4.1.1": "91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100",
}
VERSION_CHOICES = ("latest", "v4.1.1")
ASSET_BY_ARCH = {
    "x86_64": "server-linux-amd64",
    "amd64": "server-linux-amd64",
    "aarch64": "server-linux-arm64",
    "arm64": "server-linux-arm64",
    "armv7l": "server-linux-armv7",
    "armv7": "server-linux-armv7",
    "armv6l": "server-linux-armv7",
    "i686": "server-linux-386",
    "i386": "server-linux-386",
    "riscv64": "server-linux-riscv64",
}
METHODS = ("systemd", "docker")
BACKENDS = ("new", "external")
MODES = ("udp", "tcp")
OBF_PROFILES = ("rtpopus3", "rtpopus2", "rtpopus", "none")
DNS_MODES = ("auto", "plain", "doh")
TARGETS = ("all", "freeturn", "wg")
DEFAULT_LISTEN_PORT = 56000
DEFAULT_WG_PORT = 51820
DEFAULT_WG_NET = "10.13.13.0/24"
INSTALL_DIR = "/opt/free-turn-proxy"
UNIT_NAME = "free-turn-proxy.service"
CONTAINER_NAME = "free-turn-proxy"
CLIENTS_FILE = INSTALL_DIR + "/auth/clients.json"
NAME_MAX = 32
OWNER_NAME = "owner"
KCP_DEFAULTS = {
    "nodelay": 1,
    "interval": 20,
    "resend": 2,
    "nc": 1,
    "sndwnd": 512,
    "rcvwnd": 512,
    "mtu": 1200,
    "acknodelay": True,
}
LINK_PREFIX = "freeturn://"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
CID_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
HOSTPORT_RE = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]{1,253}):(\d{1,5})$")

FT_ERROR_CODES = {
    "bad_arg": "wrong arguments for the install script",
    "needs_root": "the install script needs root on the server",
    "not_installed": "freeturn is not installed on the server",
    "unsupported_arch": "the server architecture is not supported by freeturn",
    "no_systemd": "systemd is missing on the server, choose the docker method",
    "docker_failed": "docker could not be installed or started",
    "download_failed": "the freeturn script or the release could not be downloaded",
    "digest_mismatch": "the freeturn script digest does not match the pinned one",
    "wg_unsupported": "the kernel has no wireguard support, use the external backend",
    "wg_install_failed": "wireguard tools could not be installed",
    "wg_conflict": "an existing wireguard setup conflicts with freeturn",
    "backend_locked": "the backend cannot be changed without a wireguard removal first",
    "port_busy": "the udp port is busy on the server",
    "subnet_conflict": "the wireguard subnet overlaps the host network",
    "subnet_full": "the wireguard subnet has no free address left",
    "host_unknown": "the public address could not be detected, set it by hand",
    "exists": "the object already exists",
    "not_found": "the object was not found",
    "owner_protected": "the owner client cannot be removed",
    "start_failed": "the core did not start",
    "internal": "internal error of the install script",
    "transport": "the transport to the install script failed",
    "proto_mismatch": "the install script protocol version does not match",
    "not_pinned": "this freeturn version has no pinned install script yet",
}

REMOTE_DIR = Path(__file__).resolve().parent.parent
AGENT_PATH = REMOTE_DIR / "Storage" / "remote" / "freeturn_agent.py"


class FtError(Exception):
    def __init__(self, message: str, code: str = "internal") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def agent_code() -> str:
    try:
        return AGENT_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise FtError(f"the freeturn script is missing next to the bot: {exc}", "internal") from None


def normalize_version(version: str = "") -> str:
    text = str(version or "").strip().lower()
    if text in {"", "default"}:
        return FALLBACK_VERSION
    if text in {"latest", "auto"}:
        return "latest"
    if text == "local":
        return "local"
    return text if text.startswith("v") else "v" + text


def resolve_version(version: str = "", lookup: object = None) -> tuple[str, str]:
    tag = normalize_version(version)
    if tag == "local":
        return FALLBACK_VERSION, "local"
    if tag != "latest":
        if tag not in PINNED_SCRIPT_SHA256:
            raise FtError("freeturn %s has no pinned install script yet" % tag, "not_pinned")
        return tag, "pinned"
    found, reason = (lookup or (lambda repo: releases.latest_tag(repo)))(SCRIPT_REPO)
    if found and found in PINNED_SCRIPT_SHA256:
        return found, "api"
    return FALLBACK_VERSION, "fallback" if not found else "not_pinned"


def script_url(version: str = DEFAULT_VERSION) -> str:
    tag = version if version.startswith("v") else "v" + version
    return SCRIPT_URL.format(version=tag, asset="install.sh")


def script_digest(version: str = DEFAULT_VERSION) -> str:
    tag = version if version.startswith("v") else "v" + version
    return PINNED_SCRIPT_SHA256.get(tag, "")


def asset_of_arch(arch: str) -> str:
    return ASSET_BY_ARCH.get(str(arch or "").strip().lower(), "")


def core_url(version: str, arch: str) -> str:
    asset = asset_of_arch(arch)
    if not asset:
        return ""
    return RELEASE_URL.format(version=version if version.startswith("v") else "v" + version, asset=asset)


def is_port(value: object) -> bool:
    text = str(value if value is not None else "").strip()
    if not text.isdigit():
        return False
    return 1 <= int(text) <= 65535


def valid_cidr(value: str) -> bool:
    text = str(value or "").strip()
    if "/" not in text:
        return False
    address, _, size = text.partition("/")
    if not size.isdigit():
        return False
    prefix = int(size)
    octets = address.split(".")
    if len(octets) != 4:
        return False
    numbers = []
    for item in octets:
        if not item.isdigit() or not 0 <= int(item) <= 255:
            return False
        numbers.append(int(item))
    if prefix < 16 or prefix > 29:
        return False
    if prefix == 24 and numbers[3] != 0:
        return False
    if prefix == 16 and (numbers[2] != 0 or numbers[3] != 0):
        return False
    return True


def valid_hex64(value: str) -> bool:
    return bool(HEX64_RE.match(str(value or "").strip().lower()))


def valid_name(value: str) -> bool:
    return bool(NAME_RE.match(str(value or "").strip()))


def valid_host(value: str) -> bool:
    text = str(value or "").strip()
    if not text or len(text) > 253:
        return False
    return bool(HOST_RE.match(text))


def valid_hostport(value: str) -> bool:
    match = HOSTPORT_RE.match(str(value or "").strip())
    if not match:
        return False
    return is_port(match.group(2))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes:
    token = str(text or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        raise FtError("the link payload is not base64url", "bad_link")
    try:
        return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except (ValueError, TypeError):
        raise FtError("the link payload cannot be decoded", "bad_link") from None


@dataclass
class FtResponse:
    result: str = "err"
    code: str = ""
    msg: str = ""
    stage: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)
    proto: int = PROTO

    @property
    def ok(self) -> bool:
        return self.result == "ok"

    def raise_for_status(self) -> None:
        if self.ok:
            return
        text = self.msg or FT_ERROR_CODES.get(self.code, self.code) or "unknown error"
        if self.stage and self.code not in {"bad_arg", "proto_mismatch"}:
            text = "%s (stage %s)" % (text, self.stage)
        raise FtError(text, self.code or "internal")


def parse_response(text: str) -> FtResponse:
    payload = ""
    for line in (text or "").splitlines():
        token = line.strip()
        if token.startswith("{") and token.endswith("}"):
            payload = token
    if not payload:
        raise FtError((text or "").strip()[:400] or "the install script returned no answer", "transport")
    try:
        raw = json.loads(payload)
    except ValueError:
        raise FtError("the answer is not parseable: %s" % payload[:200], "transport") from None
    if not isinstance(raw, dict):
        raise FtError("the answer is not an object", "transport")
    response = FtResponse(
        result=str(raw.get("result", "err")),
        code=str(raw.get("code", "") or ""),
        msg=str(raw.get("msg", "") or ""),
        stage=str(raw.get("stage", "") or ""),
        data=raw.get("data") if isinstance(raw.get("data"), dict) else {},
        logs=[str(item)[:400] for item in raw.get("logs") or []][-200:],
        proto=int(raw.get("proto", 0) or 0),
    )
    if response.proto != PROTO:
        raise FtError("the install script speaks protocol %s and the bot expects %s" % (response.proto, PROTO), "proto_mismatch")
    return response


@dataclass
class FtConfig:
    method: str = "systemd"
    backend: str = "new"
    connect: str = ""
    host: str = ""
    listen_port: int = DEFAULT_LISTEN_PORT
    wg_port: int = DEFAULT_WG_PORT
    wg_net: str = DEFAULT_WG_NET
    mode: str = "udp"
    obf_profile: str = "rtpopus3"
    version: str = "latest"

    def check(self) -> "FtConfig":
        if self.method not in METHODS:
            raise FtError("the install method must be systemd or docker", "bad_arg")
        if self.backend not in BACKENDS:
            raise FtError("the backend must be new or external", "bad_arg")
        if self.mode not in MODES:
            raise FtError("the mode must be udp or tcp", "bad_arg")
        if self.obf_profile not in OBF_PROFILES:
            raise FtError("the obfuscation profile is unknown", "bad_arg")
        if not is_port(self.listen_port):
            raise FtError("the listen port is out of range", "bad_arg")
        if self.backend == "new" and self.mode == "tcp":
            raise FtError("the tcp mode needs an external backend", "bad_arg")
        if self.backend == "new":
            if not is_port(self.wg_port):
                raise FtError("the wireguard port is out of range", "bad_arg")
            if not valid_cidr(self.wg_net):
                raise FtError("the wireguard subnet must be a /16 to /29 network address", "bad_arg")
        if self.host and not valid_host(self.host):
            raise FtError("the public address is not usable", "bad_arg")
        if self.connect and not valid_hostport(self.connect):
            raise FtError("the external endpoint must look like host:port", "bad_arg")
        tag = normalize_version(self.version)
        if tag == "latest" or tag == "local":
            return self
        if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
            raise FtError("the version must be latest or vX.Y.Z", "bad_arg")
        if tag not in PINNED_SCRIPT_SHA256:
            raise FtError(FT_ERROR_CODES["not_pinned"], "not_pinned")
        return self

    def free_port(self, used: list[int]) -> "FtConfig":
        taken = {int(item) for item in used}
        while int(self.listen_port) in taken:
            self.listen_port = int(self.listen_port) + 1
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "backend": self.backend,
            "connect": self.connect,
            "host": self.host,
            "listen_port": int(self.listen_port),
            "wg_port": int(self.wg_port),
            "wg_net": self.wg_net,
            "mode": self.mode,
            "obf_profile": self.obf_profile,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "FtConfig":
        data = raw or {}
        method = str(data.get("method", "systemd") or "systemd")
        backend = str(data.get("backend", "new") or "new")
        mode = str(data.get("mode", "udp") or "udp")
        obf = str(data.get("obf_profile", "rtpopus3") or "rtpopus3")
        return cls(
            method=method if method in METHODS else "systemd",
            backend=backend if backend in BACKENDS else "new",
            connect=str(data.get("connect", "") or ""),
            host=str(data.get("host", "") or "")[:253],
            listen_port=int(data.get("listen_port", DEFAULT_LISTEN_PORT) or DEFAULT_LISTEN_PORT),
            wg_port=int(data.get("wg_port", DEFAULT_WG_PORT) or DEFAULT_WG_PORT),
            wg_net=str(data.get("wg_net", DEFAULT_WG_NET) or DEFAULT_WG_NET),
            mode=mode if mode in MODES else "udp",
            obf_profile=obf if obf in OBF_PROFILES else "rtpopus3",
            version=str(data.get("version", "latest") or "latest")[:24],
        )

    def server_argv(self) -> list[str]:
        out = [
            "--method=%s" % self.method,
            "--backend=%s" % self.backend,
            "--listen-port=%d" % int(self.listen_port),
            "--mode=%s" % self.mode,
            "--obf-profile=%s" % self.obf_profile,
            "--version=%s" % self.version,
        ]
        if self.backend == "new":
            out.insert(3, "--wg-port=%d" % int(self.wg_port))
            out.insert(4, "--wg-net=%s" % self.wg_net)
        if self.host:
            out.append("--host=%s" % self.host)
        if self.connect:
            out.append("--connect=%s" % self.connect)
        return out


@dataclass
class FtClient:
    name: str = ""
    client_id: str = ""
    owner: bool = False
    ip: str = ""
    pub: str = ""
    handshake: int = 0

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "FtClient":
        data = raw or {}
        name = str(data.get("name", "") or "")[:NAME_MAX]
        cid = str(data.get("client_id", "") or "").strip().lower()
        return cls(
            name=name,
            client_id=cid if CID_RE.match(cid) else "",
            owner=bool(data.get("self", False)),
            ip=str(data.get("ip", "") or "")[:45],
            pub=str(data.get("pub", "") or "")[:64],
            handshake=int(data.get("hs", 0) or 0),
        )


@dataclass
class FtShare:
    backend: str = ""
    host: str = ""
    port: int = 0
    mode: str = ""
    obf_profile: str = ""
    key_present: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "FtShare":
        data = raw or {}
        key = str(data.get("obf_key", "") or "")
        return cls(
            backend=str(data.get("backend", "") or "")[:16],
            host=str(data.get("host", "") or "")[:253],
            port=int(data.get("port", 0) or 0),
            mode=str(data.get("mode", "") or "")[:8],
            obf_profile=str(data.get("obf_profile", "") or "")[:16],
            key_present=valid_hex64(key) or bool(data.get("key_present", False)),
        )

    def peer(self) -> str:
        if not self.host or not self.port:
            return ""
        return "%s:%d" % (self.host, int(self.port))


@dataclass
class FtState:
    installed: bool = False
    running: bool = False
    euid: int = -1
    arch: str = ""
    method: str = ""
    version: str = ""
    config: FtConfig = field(default_factory=FtConfig)
    key_present: bool = False
    configured: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "installed": bool(self.installed),
            "running": bool(self.running),
            "euid": int(self.euid),
            "arch": self.arch,
            "method": self.method,
            "version": self.version,
            "config": self.config.to_dict(),
            "key_present": bool(self.key_present),
        }

    @property
    def root(self) -> bool:
        return int(self.euid) == 0

    @property
    def asset(self) -> str:
        return asset_of_arch(self.arch)

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "FtState":
        data = raw or {}
        config = FtConfig.from_dict(data.get("config"))
        key = str((data.get("config") or {}).get("obf_key", "") or "")
        return cls(
            installed=bool(data.get("installed", False)),
            running=bool(data.get("running", False)),
            euid=int(data.get("euid", -1) or -1),
            arch=str(data.get("arch", "") or "")[:24],
            method=str(data.get("method", "") or "")[:16],
            version=str(data.get("version", "") or "")[:32],
            config=config,
            key_present=valid_hex64(key) or bool(data.get("key_present", False)),
            configured=bool((data.get("config") or {}) and data.get("config")),
        )


class FtControl:
    def __init__(self, shell: LocalShell | None = None, timeout: float = 300.0, version: str = DEFAULT_VERSION) -> None:
        self.shell = shell or LocalShell()
        self.timeout = float(timeout)
        self.version = version

    def script_flags(self, version: str = "") -> tuple[list[str], str]:
        tag, _source = resolve_version(version or self.version)
        out = ["--script-url=%s" % script_url(tag)]
        digest = script_digest(tag)
        if digest:
            out.append("--script-sha256=%s" % digest)
        return out, tag

    def plan_argv(self, argv: list[str], version: str = "") -> list[str]:
        requested = ""
        for item in argv:
            if item.startswith("--version="):
                requested = item.split("=", 1)[1]
                break
        chosen = version or requested or self.version
        flags, tag = self.script_flags(chosen)
        keep = normalize_version(chosen) == "local"
        items = [item for item in argv if not item.startswith("--version=")]
        if requested:
            items.append("--version=%s" % ("local" if keep else tag))
        return items + flags

    async def call(self, argv: list[str], timeout: float | None = None, version: str = "") -> FtResponse:
        try:
            out: ShellOutput = await self.shell.run_argv(agent_argv(self.plan_argv(argv, version), agent_code()), timeout=timeout or self.timeout)
        except ShellError as exc:
            raise FtError(exc.message, "transport") from None
        return parse_response(out.text)

    async def probe(self) -> FtState:
        response = await self.call(["probe"], timeout=120)
        response.raise_for_status()
        return FtState.from_dict(response.data)

    async def apply(self, config: FtConfig, update: bool = False, obf_key: str = "") -> FtState:
        config.check()
        argv = ["apply"] + config.server_argv()
        if obf_key:
            if not valid_hex64(obf_key):
                raise FtError("the obfuscation key must be 64 hexadecimal characters", "bad_arg")
            argv.append("--obf-key=%s" % obf_key.strip().lower())
        if update:
            argv.append("--update")
        response = await self.call(argv, timeout=max(self.timeout, 900.0))
        response.raise_for_status()
        return FtState.from_dict(response.data)

    async def stop(self) -> FtResponse:
        response = await self.call(["stop"], timeout=180)
        response.raise_for_status()
        return response

    async def restart(self) -> FtResponse:
        response = await self.call(["restart"], timeout=240)
        response.raise_for_status()
        return response

    async def logs(self, tail: int = 120) -> list[str]:
        size = max(1, min(int(tail), 2000))
        response = await self.call(["logs", "--tail=%d" % size], timeout=120)
        response.raise_for_status()
        return [str(item) for item in response.data.get("lines") or []][-size:]

    async def client_list(self) -> tuple[list[FtClient], FtShare]:
        response = await self.call(["client-list"], timeout=120)
        response.raise_for_status()
        clients = [FtClient.from_dict(item) for item in response.data.get("clients") or [] if isinstance(item, dict)]
        return clients, FtShare.from_dict(response.data.get("share"))

    async def client_add(self, name: str) -> tuple[FtClient, str, str]:
        if not valid_name(name):
            raise FtError("the client name must be latin letters, digits, dot, dash or underscore", "bad_arg")
        response = await self.call(["client-add", "--name=%s" % name], timeout=180)
        response.raise_for_status()
        return FtClient.from_dict(response.data.get("client")), str(response.data.get("link", "") or ""), str(response.data.get("conf_b64", "") or "")

    async def client_conf(self, name: str) -> tuple[FtClient, str, str]:
        if not valid_name(name):
            raise FtError("the client name is not usable", "bad_arg")
        response = await self.call(["client-conf", "--name=%s" % name], timeout=120)
        response.raise_for_status()
        return FtClient.from_dict(response.data.get("client")), str(response.data.get("link", "") or ""), str(response.data.get("conf_b64", "") or "")

    async def client_remove(self, name: str) -> FtResponse:
        if not valid_name(name):
            raise FtError("the client name is not usable", "bad_arg")
        if name == OWNER_NAME:
            raise FtError(FT_ERROR_CODES["owner_protected"], "owner_protected")
        response = await self.call(["client-remove", "--name=%s" % name], timeout=180)
        response.raise_for_status()
        return response

    async def uninstall(self, target: str = "all", purge: bool = True) -> FtResponse:
        if target not in TARGETS:
            raise FtError("the uninstall target must be all, freeturn or wg", "bad_arg")
        argv = ["uninstall", "--target=%s" % target]
        if purge:
            argv.append("--purge")
        response = await self.call(argv, timeout=300)
        response.raise_for_status()
        return response


def decode_link(link: str) -> dict[str, Any]:
    text = str(link or "").strip()
    if not text.lower().startswith(LINK_PREFIX):
        raise FtError("the link must start with freeturn://", "bad_link")
    payload = text[len(LINK_PREFIX):]
    raw = unb64url(payload)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise FtError("the link payload is not json", "bad_link") from None
    if not isinstance(data, dict):
        raise FtError("the link payload is not an object", "bad_link")
    if int(data.get("v", 0) or 0) != 1:
        raise FtError("the link version is not supported", "bad_link")
    if not str(data.get("provider", "") or "").strip():
        raise FtError("the link has no provider", "bad_link")
    if not valid_hostport(str(data.get("peer", "") or "")):
        raise FtError("the link has no usable peer", "bad_link")
    key = str(data.get("key", "") or "")
    if key and not valid_hex64(key):
        raise FtError("the link obfuscation key is malformed", "bad_link")
    cid = str(data.get("cid", "") or "")
    if cid and not CID_RE.match(cid.lower()):
        raise FtError("the link client id is malformed", "bad_link")
    return data


def encode_link(fields: dict[str, Any]) -> str:
    body = dict(fields)
    if int(body.get("v", 0) or 0) != 1:
        raise FtError("the link version must be 1", "bad_link")
    for name in ("provider", "peer"):
        if not str(body.get(name, "") or "").strip():
            raise FtError("the link needs a provider and a peer", "bad_link")
    payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return LINK_PREFIX + b64url(payload)


def complete_link(link: str, config: FtConfig, transport: str = "udp") -> str:
    data = decode_link(link)
    data.setdefault("transport", transport if transport in ("tcp", "udp") else "udp")
    data.setdefault("obf", config.obf_profile if config.obf_profile != "none" else "")
    if config.mode == "tcp":
        data.setdefault("mode", "tcp")
        data.setdefault("kcp", dict(KCP_DEFAULTS))
        data.setdefault("n", 12)
        data.setdefault("spc", 12)
    data.setdefault("mcap", False)
    data.setdefault("dns", "auto")
    cleaned = {name: value for name, value in data.items() if value not in ("", None)}
    return encode_link(cleaned)


def normalize_conf(text: str) -> str:
    lines = []
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.lower().startswith("mtu"):
            continue
        lines.append(line)
    return "\n".join(lines)


def summarize(config: FtConfig, state: FtState) -> list[tuple[str, str]]:
    return [
        ("method", config.method),
        ("backend", config.backend),
        ("listen", str(config.listen_port)),
        ("wg", "%d %s" % (config.wg_port, config.wg_net) if config.backend == "new" else "-"),
        ("mode", config.mode),
        ("obf", config.obf_profile),
        ("version", state.version or config.version),
    ]
