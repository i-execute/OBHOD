from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from . import antiddos, ipscan

MIN_INTERVAL = 3 * 60 * 60
MAX_INTERVAL = 6 * 60 * 60
MAX_RELAYS = 256
MAX_HOSTS = 128
MAX_ERROR = 120


def interval(randbelow: Callable[[int], int] | None = None) -> int:
    width = MAX_INTERVAL - MIN_INTERVAL + 1
    try:
        offset = int((randbelow or secrets.randbelow)(width))
    except (TypeError, ValueError):
        offset = 0
    return MIN_INTERVAL + max(0, min(width - 1, offset))


def _host(value: object) -> str:
    try:
        target, kind = ipscan.clean_target(str(value or ""))
    except ValueError:
        return ""
    return target if kind == "domain" else ""


def collect(addresses: Iterable[object], hosts: Iterable[object] = (), resolver: Callable[[str], Iterable[str]] | None = None) -> list[str]:
    values: list[str] = []
    for raw in addresses:
        address = ipscan.routable_ip(raw)
        if address and address not in values:
            values.append(address)
        if len(values) >= MAX_RELAYS:
            return antiddos.exempt_entries(values)[:MAX_RELAYS]
    resolve = resolver or ipscan.resolve_all
    known_hosts: list[str] = []
    for raw in hosts:
        host = _host(raw)
        if host and host not in known_hosts:
            known_hosts.append(host)
        if len(known_hosts) >= MAX_HOSTS:
            break
    for host in known_hosts:
        try:
            resolved = resolve(host)
        except (OSError, ValueError):
            continue
        for raw in resolved:
            address = ipscan.routable_ip(raw)
            if address and address not in values:
                values.append(address)
            if len(values) >= MAX_RELAYS:
                return antiddos.exempt_entries(values)[:MAX_RELAYS]
    return antiddos.exempt_entries(values)[:MAX_RELAYS]


@dataclass
class State:
    cidrs: list[str] = field(default_factory=list)
    scanned_at: int = 0
    next_scan_at: int = 0
    error: str = ""

    def normalise(self) -> "State":
        self.cidrs = antiddos.exempt_entries(self.cidrs)[:MAX_RELAYS]
        try:
            self.scanned_at = max(0, int(self.scanned_at or 0))
        except (TypeError, ValueError):
            self.scanned_at = 0
        try:
            self.next_scan_at = max(0, int(self.next_scan_at or 0))
        except (TypeError, ValueError):
            self.next_scan_at = 0
        self.error = str(self.error or "")[:MAX_ERROR]
        return self

    def due(self, now: int | None = None) -> bool:
        point = int(time.time() if now is None else now)
        return not self.next_scan_at or point >= self.next_scan_at

    def schedule(self, now: int | None = None, randbelow: Callable[[int], int] | None = None) -> int:
        point = int(time.time() if now is None else now)
        self.next_scan_at = point + interval(randbelow)
        return self.next_scan_at

    def record(self, addresses: Iterable[object], hosts: Iterable[object] = (), now: int | None = None, randbelow: Callable[[int], int] | None = None, resolver: Callable[[str], Iterable[str]] | None = None) -> list[str]:
        self.cidrs = collect(addresses, hosts, resolver)
        self.scanned_at = int(time.time() if now is None else now)
        self.error = ""
        self.schedule(self.scanned_at, randbelow)
        return list(self.cidrs)

    def failed(self, error: object, now: int | None = None, randbelow: Callable[[int], int] | None = None) -> None:
        point = int(time.time() if now is None else now)
        self.error = str(error or "scan_failed")[:MAX_ERROR]
        self.schedule(point, randbelow)

    def to_dict(self) -> dict[str, object]:
        self.normalise()
        return {
            "cidrs": list(self.cidrs),
            "scanned_at": int(self.scanned_at),
            "next_scan_at": int(self.next_scan_at),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, raw: object) -> "State":
        data = raw if isinstance(raw, dict) else {}
        return cls(
            cidrs=list(data.get("cidrs") or []) if isinstance(data.get("cidrs"), list) else [],
            scanned_at=data.get("scanned_at", 0),
            next_scan_at=data.get("next_scan_at", 0),
            error=data.get("error", ""),
        ).normalise()
