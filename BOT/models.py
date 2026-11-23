from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


class ModelError(Exception):
    pass


def valid_port(value: object) -> int:
    text = str(value or "").strip()
    if not text.isdigit():
        raise ModelError("the port must be a number")
    port = int(text)
    if port < 1 or port > 65535:
        raise ModelError("the port must be between 1 and 65535")
    return port


@dataclass
class SshSettings:
    port: int = 22
    root_mode: str = "root"

    def is_ready(self) -> bool:
        return True

    configured = is_ready

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "SshSettings":
        data = raw or {}
        try:
            port = int(data.get("port", 22) or 22)
        except (TypeError, ValueError):
            port = 22
        if not 1 <= port <= 65535:
            port = 22
        return SshSettings(port=port, root_mode=str(data.get("root_mode", "root") or "root"))
