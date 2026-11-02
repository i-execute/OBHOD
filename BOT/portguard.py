from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SEP = ","
CRITICAL = (22, 2222)
RESERVED_LOW = 1024
MAX_TRACKED = 64


class PortError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class Owner:
    port: int = 0
    proto: str = ""
    process: str = ""
    address: str = ""
    protected: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": int(self.port),
            "proto": self.proto,
            "process": self.process[:64],
            "address": self.address[:64],
            "protected": bool(self.protected),
            "reason": self.reason[:32],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "Owner":
        data = raw if isinstance(raw, dict) else {}
        try:
            port = int(data.get("port", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        return cls(
            port=max(min(port, 65535), 0),
            proto=str(data.get("proto", "") or "")[:4],
            process=str(data.get("process", "") or "")[:64],
            address=str(data.get("address", "") or "")[:64],
            protected=bool(data.get("protected", False)),
            reason=str(data.get("reason", "") or "")[:32],
        )


def parse_ports(raw: object) -> list[int]:
    out: list[int] = []
    for chunk in str(raw or "").split(SEP):
        item = chunk.strip()
        if not item.isdigit():
            continue
        value = int(item)
        if 1 <= value <= 65535 and value not in out:
            out.append(value)
    return out[:MAX_TRACKED]


def join(ports: list[int]) -> str:
    return SEP.join(str(item) for item in sorted(set(ports))[:MAX_TRACKED])


def protected_ports(state: Any, extra: Any = None) -> list[int]:
    ports: list[int] = []
    ssh = getattr(state, "ssh", None)
    for port in list(getattr(ssh, "ports", []) or []) + [getattr(ssh, "port", 0)]:
        try:
            ports.append(int(port))
        except (TypeError, ValueError):
            continue
    if not ports:
        ports.append(22)
    xray = getattr(state, "xray", None)
    for inbound in getattr(xray, "inbounds", []) or []:
        try:
            ports.append(int(getattr(inbound, "port", 0) or 0))
        except (TypeError, ValueError):
            continue
    try:
        ports.append(int(getattr(xray, "sub_port", 0) or 0))
    except (TypeError, ValueError):
        pass
    for port in extra or []:
        try:
            ports.append(int(port))
        except (TypeError, ValueError):
            continue
    out = [item for item in ports if 1 <= item <= 65535]
    return sorted(set(out))[:MAX_TRACKED]


def is_protected(port: int, keep: list[int]) -> bool:
    return int(port) in set(int(item) for item in keep)


def check(port: int, keep: list[int], mode: str) -> None:
    value = int(port)
    if not 1 <= value <= 65535:
        raise PortError("the port is out of range")
    if mode in {"closed", "vk"} and is_protected(value, keep):
        raise PortError("port %d belongs to ssh or to another module, the guard will not touch it" % value)
    if value in CRITICAL and mode == "closed":
        raise PortError("port %d is never closed by the guard" % value)


def describe(owners: list[Owner]) -> str:
    return ", ".join("%d/%s %s" % (item.port, item.proto or "?", item.process or "-") for item in owners[:12])


def parse_ss(text: str, keep: list[int]) -> list[Owner]:
    out: list[Owner] = []
    for line in str(text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        address = ""
        port = 0
        for part in parts[1:]:
            found = re.match(r"^\[?[0-9a-fA-F.*:%]*\]?:(\d{1,5})$", part)
            if found:
                address = part
                port = int(found.group(1))
                break
        if not port:
            continue
        process = ""
        match = re.search(r'users:\(\("([^"]{1,64})"', line)
        if match:
            process = match.group(1)
        owner = Owner(port=port, proto=proto, process=process, address=address[:64])
        owner.protected = is_protected(port, keep) or port in CRITICAL
        owner.reason = "ssh" if port in CRITICAL else ("module" if owner.protected else "")
        out.append(owner)
        if len(out) >= MAX_TRACKED:
            break
    return out


def untouched(owners: list[Owner]) -> list[Owner]:
    return [item for item in owners if item.protected]


def busy_ports(owners: list[Owner]) -> list[int]:
    return sorted({int(item.port) for item in owners if int(item.port)})


def foreign_ports(owners: list[Owner], own: list[int]) -> list[int]:
    mine = {int(item) for item in own}
    return sorted({int(item.port) for item in owners if int(item.port) and int(item.port) not in mine})


def owner_label(port: int, owners: list[Owner]) -> str:
    for item in owners:
        if int(item.port) == int(port):
            return item.process or item.proto or "unknown"
    return "unknown"


def free_port(preferred: int, used: object, span: int = 512) -> int:
    taken = {int(item) for item in used if str(item).strip().lstrip("-").isdigit()}
    start = int(preferred)
    if not 1 <= start <= 65535:
        start = RESERVED_LOW + 1
    for step in range(max(1, int(span))):
        candidate = start + step
        if candidate > 65535:
            break
        if candidate in CRITICAL:
            continue
        if candidate in taken:
            continue
        return candidate
    for candidate in range(RESERVED_LOW + 1, 65535):
        if candidate in CRITICAL or candidate in taken:
            continue
        return candidate
    return 0
