from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

KIND_PORTSCAN = "portscan"
KIND_SSH = "ssh_brute"
KIND_HONEYPOT = "honeypot"
KIND_BAN = "fail2ban"
KIND_SUBS = "sub_abuse"
KIND_CORE = "core"
KINDS = (KIND_PORTSCAN, KIND_SSH, KIND_BAN, KIND_HONEYPOT, KIND_SUBS, KIND_CORE)
DEFAULT_ON = {
    KIND_PORTSCAN: True,
    KIND_SSH: True,
    KIND_BAN: True,
    KIND_HONEYPOT: True,
    KIND_SUBS: False,
    KIND_CORE: True,
}
SEVERITY = {
    KIND_PORTSCAN: "warn",
    KIND_SSH: "bad",
    KIND_BAN: "warn",
    KIND_HONEYPOT: "bad",
    KIND_SUBS: "warn",
    KIND_CORE: "bad",
}
COOLDOWN = {
    KIND_PORTSCAN: 1800.0,
    KIND_SSH: 900.0,
    KIND_BAN: 300.0,
    KIND_HONEYPOT: 300.0,
    KIND_SUBS: 3600.0,
    KIND_CORE: 600.0,
}
PER_IP = {
    KIND_PORTSCAN: 3600.0,
    KIND_SSH: 1800.0,
    KIND_BAN: 900.0,
    KIND_HONEYPOT: 1800.0,
    KIND_SUBS: 3600.0,
    KIND_CORE: 1800.0,
}
PORT_SCAN_PORTS = 12
PORT_SCAN_WINDOW = 300.0
SSH_FAILS = 10
SSH_WINDOW = 600.0
HONEY_TOUCH = 1
HONEY_PORTS = 2
MAX_TRACKED = 512
MAX_QUEUE = 64
ADDRESS_LIMIT = 64


def mask(address: object) -> str:
    text = str(address or "").strip()
    if not text:
        return "-"
    head = text.split(".")[0] if "." in text else text[:8]
    tail = text.rsplit(".", 1)[-1] if "." in text else ""
    return "%s.x.x.%s" % (head, tail) if tail else head


@dataclass
class Settings:
    enabled: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_ON))
    cooldown: dict[str, float] = field(default_factory=lambda: dict(COOLDOWN))
    mute_until: float = 0.0

    def on(self, kind: str) -> bool:
        if kind not in KINDS:
            return False
        return bool(self.enabled.get(kind, DEFAULT_ON.get(kind, False)))

    def toggle(self, kind: str) -> bool:
        if kind not in KINDS:
            raise ValueError("unknown notification kind: " + str(kind))
        value = not self.on(kind)
        self.enabled[kind] = value
        return value

    def silence(self, seconds: float = 0.0) -> None:
        self.mute_until = time.time() + max(0.0, float(seconds))

    def muted(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) < float(self.mute_until or 0.0)

    def any_on(self) -> bool:
        return any(self.on(kind) for kind in KINDS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": {kind: self.on(kind) for kind in KINDS},
            "cooldown": {kind: float(self.cooldown.get(kind, COOLDOWN[kind])) for kind in KINDS},
            "mute_until": float(self.mute_until or 0.0),
        }

    @staticmethod
    def from_dict(raw: Any) -> "Settings":
        data = raw if isinstance(raw, dict) else {}
        settings = Settings()
        enabled = data.get("enabled") if isinstance(data.get("enabled"), dict) else {}
        for kind in KINDS:
            if kind in enabled:
                settings.enabled[kind] = bool(enabled[kind])
        cooling = data.get("cooldown") if isinstance(data.get("cooldown"), dict) else {}
        for kind in KINDS:
            try:
                value = float(cooling.get(kind, COOLDOWN[kind]))
            except (TypeError, ValueError):
                value = COOLDOWN[kind]
            settings.cooldown[kind] = max(0.0, min(value, 86400.0))
        try:
            settings.mute_until = float(data.get("mute_until", 0.0) or 0.0)
        except (TypeError, ValueError):
            settings.mute_until = 0.0
        return settings


@dataclass
class Event:
    kind: str
    address: str = ""
    detail: str = ""
    count: int = 1
    at: float = 0.0
    ports: int = 0
    evidence: list[str] = field(default_factory=list)

    def severity(self) -> str:
        return SEVERITY.get(self.kind, "warn")

    def key(self) -> tuple[str, str]:
        return (self.kind, self.address)


@dataclass
class Observation:
    kind: str
    address: str = ""
    port: int = 0
    detail: str = ""
    at: float = 0.0


class Centre:

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings if settings is not None else Settings()
        self.seen: dict[tuple[str, str], float] = {}
        self.source: dict[str, float] = {}
        self.ports: dict[str, dict[int, float]] = {}
        self.fails: dict[str, list[float]] = {}
        self.queue: list[Event] = []

    def observe(self, obs: Observation, now: float | None = None) -> list[Event]:
        moment = now if now is not None else (obs.at or time.time())
        address = str(obs.address or "").strip()[:64]
        if not address:
            return []
        if obs.kind == KIND_PORTSCAN:
            return self.scan(address, int(obs.port or 0), moment)
        if obs.kind == KIND_SSH:
            return self.bruteforce(address, moment)
        if obs.kind == KIND_HONEYPOT:
            return self.honeypot(address, int(obs.port or 0), obs.detail, moment)
        if obs.kind in (KIND_BAN, KIND_SUBS, KIND_CORE):
            return self.direct(obs.kind, address, obs.detail, moment)
        return []

    def scan(self, address: str, port: int, now: float) -> list[Event]:
        if not port:
            return []
        table = self.ports.setdefault(address, {})
        table[port] = now
        for key in [item for item, at in table.items() if now - at > PORT_SCAN_WINDOW]:
            table.pop(key, None)
        if len(self.ports) > MAX_TRACKED:
            for key in sorted(self.ports, key=lambda item: max(self.ports[item].values()) if self.ports[item] else 0.0)[:-MAX_TRACKED]:
                self.ports.pop(key, None)
        if len(table) < PORT_SCAN_PORTS:
            return []
        ports = sorted(table)
        self.ports.pop(address, None)
        return self.deliver(
            Event(KIND_PORTSCAN, address, detail="%d ports" % len(ports), count=len(ports), at=now, ports=len(ports), evidence=[str(item) for item in ports[:ADDRESS_LIMIT]]),
            now,
        )

    def bruteforce(self, address: str, now: float) -> list[Event]:
        marks = [item for item in self.fails.get(address, []) if now - item <= SSH_WINDOW]
        marks.append(now)
        self.fails[address] = marks
        if len(self.fails) > MAX_TRACKED:
            for key in sorted(self.fails, key=lambda item: self.fails[item][-1] if self.fails[item] else 0.0)[:-MAX_TRACKED]:
                self.fails.pop(key, None)
        if len(marks) < SSH_FAILS:
            return []
        self.fails[address] = []
        return self.deliver(Event(KIND_SSH, address, detail="%d failures" % len(marks), count=len(marks), at=now), now)

    def honeypot(self, address: str, port: int, detail: str, now: float) -> list[Event]:
        table = self.ports.setdefault("honey:" + address, {})
        table[port] = now
        if len(table) < HONEY_TOUCH:
            return []
        touched = len(table)
        self.ports.pop("honey:" + address, None)
        return self.deliver(
            Event(KIND_HONEYPOT, address, detail=detail or "decoy", count=touched, at=now, ports=touched, evidence=[str(item) for item in sorted(table)[:ADDRESS_LIMIT]]),
            now,
        )

    def direct(self, kind: str, address: str, detail: str, now: float) -> list[Event]:
        return self.deliver(Event(kind, address, detail=detail, at=now), now)

    def force(self, kind: str, address: str, detail: str = "", now: float | None = None) -> list[Event]:
        return self.direct(kind, str(address or ""), detail, now if now is not None else time.time())

    def deliver(self, event: Event, now: float) -> list[Event]:
        if not self.settings.on(event.kind):
            return []
        if self.settings.muted(now):
            return []
        source = self.source.get(event.kind, 0.0)
        if source and now - source < float(self.settings.cooldown.get(event.kind, COOLDOWN[event.kind])):
            return []
        last = self.seen.get(event.key(), 0.0)
        if last and now - last < float(PER_IP.get(event.kind, 900.0)):
            return []
        self.source[event.kind] = now
        self.seen[event.key()] = now
        if len(self.seen) > MAX_TRACKED * 4:
            for key in sorted(self.seen, key=lambda item: self.seen[item])[:-MAX_TRACKED * 2]:
                self.seen.pop(key, None)
        self.push(event)
        return [event]

    def push(self, event: "Event") -> None:
        self.queue.append(event)
        self.queue = self.queue[-MAX_QUEUE:]

    def drain(self) -> list[Event]:
        rows = list(self.queue)
        self.queue = []
        return rows

    def toggle(self, kind: str) -> bool:
        return self.settings.toggle(kind)

    def summary(self) -> dict[str, Any]:
        return {
            "enabled": {kind: self.settings.on(kind) for kind in KINDS},
            "muted": self.settings.muted(),
            "queued": len(self.queue),
            "tracked": len(self.seen),
        }


def owner_of(bot: Any) -> int:
    try:
        value = int(getattr(bot, "admin_id", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return value if value > 0 else 0


def delivery_target(bot: Any) -> int:
    owner = owner_of(bot)
    if not owner:
        return 0
    state = getattr(bot, "state", None)
    if state is not None and int(getattr(state, "admin_id", 0) or 0) not in (0, owner):
        return 0
    return owner


def parse_events(payload: Any) -> list[Observation]:
    rows = payload.get("rows") if isinstance(payload, dict) else None
    out: list[Observation] = []
    for row in rows or []:
        if not isinstance(row, str):
            continue
        fields = {}
        parts = row.split()
        if not parts or parts[0] != "honeypot":
            continue
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                fields[key] = value
        address = fields.get("ip", "")
        if not address or address in {"127.0.0.1", "0.0.0.0", "::1"}:
            continue
        try:
            port = int(fields.get("port", "0"))
        except ValueError:
            port = 0
        out.append(Observation(KIND_HONEYPOT, address, port, fields.get("event", "probe")))
    return out


def parse_banning(payload: Any) -> list[Observation]:
    rows = payload.get("banned") if isinstance(payload, dict) else None
    out: list[Observation] = []
    for address in rows or []:
        text = str(address or "").strip()
        if text:
            out.append(Observation(KIND_BAN, text, detail="banned"))
    return out
