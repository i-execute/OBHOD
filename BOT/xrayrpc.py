from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import SshSettings
from .shell import LocalShell, ShellError, ShellOutput, agent_argv

PROTO = 3
DEFAULT_VERSION = "v26.10.31"
UNIT_NAME = "xray.service"
CORE_NAME = "xray"

PINNED_SHA256 = {
    "64": "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214",
    "arm64-v8a": "1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d",
    "arm32-v7a": "2387f55239ee7799fd67d5382e79f589c1da07a97d993e86b058f2290b8e456b",
    "arm32-v6": "28c27bbd262bcc751e2e07115f47ce50d79611289e19e8b499b3065497b0e1ec",
    "32": "4064a12c7712f28f0a85082be3564c088f7861f2220ddb5e4de409c91837511d",
    "s390x": "c83452b49eb7c9064ca9afd68d5e0afaa820d0eae25e763306e68665bdc800c4",
    "riscv64": "1159825b0d448fc7f56ca6f12e4872de2bf80a6639964819e0827fa0ad1283e8",
}

ASSET_BY_ARCH = {
    "x86_64": "64",
    "amd64": "64",
    "aarch64": "arm64-v8a",
    "arm64": "arm64-v8a",
    "armv7l": "arm32-v7a",
    "armv7": "arm32-v7a",
    "armv6l": "arm32-v6",
    "i686": "32",
    "i386": "32",
    "s390x": "s390x",
    "riscv64": "riscv64",
}

RELEASE_URL = "https://github.com/XTLS/Xray-core/releases/download/{version}/Xray-linux-{asset}.zip"
DGST_URL = RELEASE_URL + ".dgst"

XRAY_ERROR_CODES = {
    "bad_arg": "wrong arguments",
    "needs_root": "root rights are required on the server",
    "no_python": "python3 is missing on the server",
    "unsupported_arch": "the server architecture is not supported",
    "download_failed": "the core release download failed",
    "digest_mismatch": "the archive digest does not match",
    "unpack_failed": "the core archive could not be unpacked",
    "config_invalid": "the core rejected the configuration",
    "config_missing": "no configuration was supplied",
    "no_systemd": "systemd is missing on the server",
    "start_failed": "the core did not start",
    "not_installed": "the core is not installed",
    "port_busy": "the port is busy on the server, another service holds it, pick another port",
    "not_found": "not found",
    "internal": "internal error of the core script",
    "transport": "the transport to the server failed",
    "proto_mismatch": "the core script protocol version does not match",
}

REMOTE_DIR = Path(__file__).resolve().parent.parent
AGENT_PATH = REMOTE_DIR / "Storage" / "remote" / "xray_agent.py"
SUB_SERVER_PATH = REMOTE_DIR / "Storage" / "remote" / "sub_server.py"


def _load_remote(name: str, path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise XrayError(f"{name} is missing next to the bot: {exc}", "internal") from None


def agent_code() -> str:
    return _load_remote("core script", AGENT_PATH)


def sub_server_code() -> str:
    return _load_remote("subscription server", SUB_SERVER_PATH)


ARG_LIMIT = 65536


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def payload_arg(flag: str, payload: bytes) -> tuple[str, bytes]:
    encoded = b64(payload)
    if len(encoded) + len(flag) + 4 > ARG_LIMIT:
        return "--%s=-" % flag, encoded.encode("ascii")
    return "--%s=%s" % (flag, encoded), b""


@dataclass
class XrayResponse:
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
        text = self.msg or XRAY_ERROR_CODES.get(self.code, self.code) or "unknown error"
        if self.stage and self.code != "bad_arg":
            text = f"{text} (stage {self.stage})"
        raise XrayError(text, self.code or "internal")


class XrayError(Exception):
    def __init__(self, message: str, code: str = "internal") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


SUB_PORT = 2096


@dataclass
class SubState:
    installed: bool = False
    registry: str = ""
    unit: str = ""
    entries: int = 0
    port: int = SUB_PORT
    listening: bool = False
    service: str = "absent"
    systemd: bool = False

    @property
    def active(self) -> bool:
        return bool(self.listening)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SubState":
        raw = raw or {}
        return cls(
            installed=bool(raw.get("installed", False)),
            registry=str(raw.get("registry", "") or ""),
            unit=str(raw.get("unit", "") or ""),
            entries=int(raw.get("entries", 0) or 0),
            port=int(raw.get("port", SUB_PORT) or SUB_PORT),
            listening=bool(raw.get("listening", False)),
            service=str(raw.get("service", "absent") or "absent"),
            systemd=bool(raw.get("systemd", False)),
        )


@dataclass
class CoreState:
    installed: bool = False
    version: str = ""
    pinned: str = DEFAULT_VERSION
    core_path: str = ""
    config_path: str = ""
    config_exists: bool = False
    config_digest: str = ""
    inbounds: int = 0
    port: int = 0
    ports: list[int] = field(default_factory=list)
    listening: list[int] = field(default_factory=list)
    service: str = "absent"
    unit: bool = False
    systemd: bool = False
    arch: str = ""
    asset: str = ""
    fallback: bool = False
    fallback_version: str = ""

    @property
    def running(self) -> bool:
        return self.service == "active"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CoreState:
        raw = raw or {}
        return cls(
            installed=bool(raw.get("installed", False)),
            version=str(raw.get("version", "") or ""),
            pinned=str(raw.get("pinned", DEFAULT_VERSION) or DEFAULT_VERSION),
            core_path=str(raw.get("core_path", "") or ""),
            config_path=str(raw.get("config_path", "") or ""),
            config_exists=bool(raw.get("config_exists", False)),
            config_digest=str(raw.get("config_digest", "") or ""),
            inbounds=int(raw.get("inbounds", 0) or 0),
            port=int(raw.get("port", 0) or 0),
            ports=[int(item) for item in raw.get("ports") or []],
            listening=[int(item) for item in raw.get("listening") or []],
            service=str(raw.get("service", "absent") or "absent"),
            unit=bool(raw.get("unit", False)),
            systemd=bool(raw.get("systemd", False)),
            arch=str(raw.get("arch", "") or ""),
            asset=str(raw.get("asset", "") or ""),
            fallback=bool(raw.get("fallback", False)),
            fallback_version=str(raw.get("fallback_version", "") or ""),
        )


def parse_response(text: str) -> XrayResponse:
    payload = ""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            payload = stripped
    if not payload:
        raise XrayError((text or "").strip()[:400] or "the core script returned no answer", "transport")
    try:
        raw = json.loads(payload)
    except ValueError:
        raise XrayError(f"the answer is not parseable: {payload[:200]}", "transport") from None
    if not isinstance(raw, dict):
        raise XrayError("the answer is not an object", "transport")
    response = XrayResponse(
        result=str(raw.get("result", "err")),
        code=str(raw.get("code", "") or ""),
        msg=str(raw.get("msg", "") or ""),
        stage=str(raw.get("stage", "") or ""),
        data=raw.get("data") if isinstance(raw.get("data"), dict) else {},
        logs=[str(item) for item in raw.get("logs") or []],
        proto=int(raw.get("proto", 0) or 0),
    )
    if response.proto != PROTO:
        raise XrayError(f"the core script speaks protocol {response.proto} and the bot expects {PROTO}", "proto_mismatch")
    return response


class XrayControl:
    def __init__(self, shell: LocalShell | None = None, timeout: float = 300.0) -> None:
        self.shell = shell or LocalShell()
        self.timeout = float(timeout)

    async def call(
        self,
        cfg: SshSettings,
        argv: list[str],
        timeout: float | None = None,
        source: str = "",
        stdin: bytes | None = None,
    ) -> XrayResponse:
        try:
            out: ShellOutput = await self.shell.run_argv(
                agent_argv(argv, source or agent_code()),
                stdin=stdin,
                timeout=timeout or self.timeout,
            )
        except ShellError as exc:
            raise XrayError(exc.message, "transport") from None
        return parse_response(out.text)

    async def probe(self, cfg: SshSettings) -> CoreState:
        response = await self.call(cfg, ["probe"], timeout=90)
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def install_core(
        self,
        cfg: SshSettings,
        version: str = DEFAULT_VERSION,
        url: str = "",
        sha256: str = "",
        force: bool = False,
    ) -> XrayResponse:
        argv = ["install-core", f"--version={version}"]
        if url:
            argv.append(f"--url={url}")
        if sha256:
            argv.append(f"--sha256={sha256}")
        if force:
            argv.append("--force")
        response = await self.call(cfg, argv, timeout=max(self.timeout, 600.0))
        response.raise_for_status()
        return response

    async def apply(self, cfg: SshSettings, config: str, version: str = DEFAULT_VERSION, restart: bool = True) -> CoreState:
        payload = config.encode("utf-8") if isinstance(config, str) else bytes(config)
        flag, stdin = payload_arg("config-b64", payload)
        argv = ["apply", flag, f"--version={version}"]
        if not restart:
            argv.append("--no-restart")
        response = await self.call(cfg, argv, timeout=max(self.timeout, 600.0), stdin=stdin)
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def test_config(self, cfg: SshSettings, config: str) -> tuple[bool, str]:
        payload = config.encode("utf-8") if isinstance(config, str) else bytes(config)
        flag, stdin = payload_arg("config-b64", payload)
        response = await self.call(cfg, ["test-config", flag], timeout=120, stdin=stdin)
        response.raise_for_status()
        return bool(response.data.get("valid", False)), str(response.data.get("output", "") or "")

    async def restart(self, cfg: SshSettings) -> CoreState:
        response = await self.call(cfg, ["restart"], timeout=180)
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def stop(self, cfg: SshSettings) -> CoreState:
        response = await self.call(cfg, ["stop"], timeout=120)
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def start(self, cfg: SshSettings) -> CoreState:
        response = await self.call(cfg, ["start"], timeout=120)
        response.raise_for_status()
        return CoreState.from_dict(response.data)

    async def logs(self, cfg: SshSettings, tail: int = 120) -> list[str]:
        response = await self.call(cfg, ["logs", f"--tail={int(tail)}"], timeout=120)
        response.raise_for_status()
        return [str(item) for item in response.data.get("lines") or []]

    async def x25519(self, cfg: SshSettings) -> tuple[str, str]:
        response = await self.call(cfg, ["x25519"], timeout=60)
        response.raise_for_status()
        return str(response.data.get("private", "") or ""), str(response.data.get("public", "") or "")

    async def mldsa65(self, cfg: SshSettings) -> tuple[str, str]:
        response = await self.call(cfg, ["mldsa65"], timeout=90)
        response.raise_for_status()
        return str(response.data.get("seed", "") or ""), str(response.data.get("verify", "") or "")

    async def vlessenc(self, cfg: SshSettings) -> dict[str, str]:
        response = await self.call(cfg, ["vlessenc"], timeout=90)
        response.raise_for_status()
        return {str(key): str(value) for key, value in response.data.items()}

    async def sub_install(self, cfg: SshSettings, port: int = SUB_PORT) -> SubState:
        payload = sub_server_code().encode("utf-8")
        flag, stdin = payload_arg("server-b64", payload)
        response = await self.call(cfg, ["sub-install", flag, f"--port={int(port)}"], timeout=180, stdin=stdin)
        response.raise_for_status()
        return SubState.from_dict(response.data)

    async def sub_sync(self, cfg: SshSettings, registry: dict[str, Any], port: int = SUB_PORT) -> SubState:
        payload = json.dumps(registry, ensure_ascii=False, sort_keys=True).encode("utf-8")
        flag, stdin = payload_arg("registry-b64", payload)
        response = await self.call(cfg, ["sub-sync", flag, f"--port={int(port)}"], timeout=180, stdin=stdin)
        response.raise_for_status()
        return SubState.from_dict(response.data)

    async def sub_status(self, cfg: SshSettings, port: int = SUB_PORT) -> SubState:
        response = await self.call(cfg, ["sub-status", f"--port={int(port)}"], timeout=90)
        response.raise_for_status()
        return SubState.from_dict(response.data)

    async def sub_stop(self, cfg: SshSettings, port: int = SUB_PORT) -> SubState:
        response = await self.call(cfg, ["sub-stop", f"--port={int(port)}"], timeout=120)
        response.raise_for_status()
        return SubState.from_dict(response.data)

    async def uninstall(self, cfg: SshSettings, purge: bool = True) -> XrayResponse:
        argv = ["uninstall"]
        if purge:
            argv.append("--purge")
        response = await self.call(cfg, argv, timeout=180)
        response.raise_for_status()
        return response


def release_asset(version: str, asset: str) -> str:
    return RELEASE_URL.format(version=version, asset=asset)


def asset_of_arch(arch: str) -> str:
    return ASSET_BY_ARCH.get(arch, "")


def pinned_digest(arch: str) -> str:
    return PINNED_SHA256.get(ASSET_BY_ARCH.get(arch, ""), "")


def digest_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_dgst(body: str, key: str = "SHA2-256") -> str:
    for line in (body or "").splitlines():
        token = line.strip()
        if "=" not in token:
            continue
        name, value = token.split("=", 1)
        if name.strip().upper().replace("_", "-") == key.upper():
            return value.strip().lower()
    return ""


def parse_xray_version(text: str) -> str:
    for line in (text or "").splitlines():
        token = line.strip()
        if token.startswith("Xray"):
            parts = token.split()
            if len(parts) >= 2:
                return parts[1]
    return ""
