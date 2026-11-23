from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import SshSettings
from .shell import LocalShell, ShellError, ShellOutput, agent_argv

PINNED_VERSION = "2026.11.1"
PROTO = 1
AGENT_PATH = Path(__file__).resolve().parent.parent / "Storage" / "remote" / "cloudflared_agent.py"


class CloudflaredError(Exception):
    def __init__(self, message: str, code: str = "internal") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass
class CloudflaredState:
    installed: bool = False
    version: str = ""
    pinned: str = PINNED_VERSION
    fallback: bool = False
    fallback_version: str = ""
    service: str = "absent"
    unit: bool = False
    url: str = ""
    local_url: str = ""
    latest_source: str = ""

    @property
    def active(self) -> bool:
        return self.service == "active"

    @classmethod
    def from_dict(cls, raw: Any) -> "CloudflaredState":
        value = raw if isinstance(raw, dict) else {}
        return cls(
            installed=bool(value.get("installed", False)),
            version=str(value.get("version", "") or "")[:32],
            pinned=str(value.get("pinned", PINNED_VERSION) or PINNED_VERSION)[:32],
            fallback=bool(value.get("fallback", False)),
            fallback_version=str(value.get("fallback_version", "") or "")[:32],
            service=str(value.get("service", "absent") or "absent")[:24],
            unit=bool(value.get("unit", False)),
            url=str(value.get("url", "") or "")[:180],
            local_url=str(value.get("local_url", "") or "")[:180],
            latest_source=str(value.get("latest_source", "") or "")[:24],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "installed": self.installed,
            "version": self.version,
            "pinned": self.pinned,
            "fallback": self.fallback,
            "fallback_version": self.fallback_version,
            "service": self.service,
            "unit": self.unit,
            "url": self.url,
            "local_url": self.local_url,
            "latest_source": self.latest_source,
        }


def agent_code() -> str:
    try:
        return AGENT_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise CloudflaredError("Cloudflared agent is missing: %s" % exc, "internal") from None


def parse_response(text: str) -> dict[str, Any]:
    try:
        raw = json.loads(text.strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise CloudflaredError("Cloudflared agent returned invalid data", "transport") from exc
    if not isinstance(raw, dict) or int(raw.get("proto", 0) or 0) != PROTO:
        raise CloudflaredError("Cloudflared agent protocol mismatch", "proto_mismatch")
    if raw.get("result") != "ok":
        raise CloudflaredError(str(raw.get("msg", "Cloudflared request failed") or "Cloudflared request failed"), str(raw.get("code", "internal") or "internal"))
    return raw.get("data") if isinstance(raw.get("data"), dict) else {}


class CloudflaredControl:
    def __init__(self, shell: LocalShell | None = None, timeout: float = 300) -> None:
        self.shell = shell or LocalShell()
        self.timeout = float(timeout)

    async def call(self, cfg: SshSettings, argv: list[str], timeout: float | None = None) -> CloudflaredState:
        try:
            out: ShellOutput = await self.shell.run_argv(agent_argv(argv, agent_code()), timeout=timeout or self.timeout)
        except ShellError as exc:
            raise CloudflaredError(exc.message, "transport") from None
        return CloudflaredState.from_dict(parse_response(out.text))

    async def status(self, cfg: SshSettings) -> CloudflaredState:
        return await self.call(cfg, ["status"], 90)

    async def install(self, cfg: SshSettings, version: str = "latest", force: bool = False) -> CloudflaredState:
        args = ["install", "--version=%s" % (version or "latest")]
        if force:
            args.append("--force=1")
        return await self.call(cfg, args, 600)

    async def up(self, cfg: SshSettings, local_url: str) -> CloudflaredState:
        return await self.call(cfg, ["up", "--url=%s" % local_url], 300)

    async def down(self, cfg: SshSettings) -> CloudflaredState:
        return await self.call(cfg, ["down"], 180)

    async def logs(self, cfg: SshSettings) -> CloudflaredState:
        return await self.call(cfg, ["logs"], 120)

    async def remove(self, cfg: SshSettings) -> CloudflaredState:
        return await self.call(cfg, ["remove"], 180)
