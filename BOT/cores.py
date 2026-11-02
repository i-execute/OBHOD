from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MAX_CORES = 16
STATE_INSTALLED = "installed"
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"
STATE_MISSING = "missing"
STATE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class Core:
    key: str
    route: str
    icon: str
    name_key: str
    note_key: str
    order: int = 0

    def name(self, t: Any) -> str:
        return t(self.name_key)

    def note(self, t: Any) -> str:
        return t(self.note_key)


@dataclass
class Card:
    key: str
    name: str
    icon: str
    route: str
    note: str
    state: str = STATE_UNKNOWN
    version: str = ""
    ports: list[str] = field(default_factory=list)
    clients: int = 0
    active: bool = False

    def state_text(self, t: Any) -> str:
        return t("CORE_STATE_%s" % self.state.upper())

    def ports_text(self) -> str:
        return ", ".join(self.ports)

    def detail(self, t: Any) -> str:
        parts = [self.state_text(t)]
        if self.version:
            parts.append(self.version)
        if self.ports:
            parts.append("%s %s" % (t("CORE_ROW_PORTS"), self.ports_text()))
        if self.clients:
            parts.append("%s %d" % (t("CORE_ROW_CLIENTS"), self.clients))
        return " ".join(parts)

    def label(self, t: Any) -> str:
        mark = t("UI_ACTIVE_MARK") if self.active else ""
        return ("%s%s" % (t(self.name), mark)).strip()


REGISTRY: tuple[Core, ...] = (
    Core("xray", "xr:home", "xray", "CORE_NAME_XRAY", "CORE_NOTE_XRAY", 10),
    Core("freeturn", "ft:home", "tunnel", "CORE_NAME_FREETURN", "CORE_NOTE_FREETURN", 20),
)


def keys() -> tuple[str, ...]:
    return tuple(item.key for item in REGISTRY)


def all_cores() -> tuple[Core, ...]:
    return tuple(sorted(REGISTRY, key=lambda item: item.order))


def core(name: object) -> Core | None:
    wanted = str(name or "").strip().lower()
    for item in REGISTRY:
        if item.key == wanted:
            return item
    return None


def default_key() -> str:
    return all_cores()[0].key if REGISTRY else ""


def normalize(value: object) -> str:
    found = core(value)
    if found is not None:
        return found.key
    return default_key()


def register(item: Core) -> None:
    global REGISTRY
    if core(item.key) is not None:
        REGISTRY = tuple(entry for entry in REGISTRY if entry.key != item.key)
    if len(REGISTRY) >= MAX_CORES:
        raise ValueError("too many cores")
    REGISTRY = REGISTRY + (item,)


def xray_card(raw: dict[str, Any] | None, clients: int, active: str) -> Card:
    book = raw if isinstance(raw, dict) else {}
    found = core("xray")
    card = Card(
        key="xray",
        name=found.name_key if found else "CORE_NAME_XRAY",
        icon=found.icon if found else "xray",
        route=found.route if found else "xr:home",
        note=found.note_key if found else "CORE_NOTE_XRAY",
        clients=max(int(clients or 0), 0),
        active=active == "xray",
    )
    installed = bool(book.get("installed", False))
    service = str(book.get("service", "") or "").lower()
    card.version = str(book.get("version", "") or "")[:24]
    ports = book.get("listening") or []
    card.ports = [str(item) for item in ports][:8]
    if not installed:
        card.state = STATE_MISSING
    elif service == "active":
        card.state = STATE_RUNNING
    elif service:
        card.state = STATE_STOPPED
    return card


def freeturn_card(raw: Any, clients: int, active: str) -> Card:
    found = core("freeturn")
    card = Card(
        key="freeturn",
        name=found.name_key if found else "CORE_NAME_FREETURN",
        icon=found.icon if found else "tunnel",
        route=found.route if found else "ft:home",
        note=found.note_key if found else "CORE_NOTE_FREETURN",
        clients=max(int(clients or 0), 0),
        active=active == "freeturn",
    )
    installed = bool(getattr(raw, "installed", False))
    running = bool(getattr(raw, "running", False))
    card.version = str(getattr(raw, "version", "") or "")[:24]
    config = getattr(raw, "config", None)
    port = int(getattr(config, "listen_port", 0) or getattr(config, "wg_port", 0) or 0)
    if port:
        card.ports = [str(port)]
    if not installed:
        card.state = STATE_MISSING
    elif running:
        card.state = STATE_RUNNING
    else:
        card.state = STATE_STOPPED
    return card


def snapshot(state: Any, xray_raw: dict[str, Any] | None, ft_clients: int = 0) -> list[Card]:
    active = normalize(getattr(state, "core", ""))
    clients = sum(len(getattr(item, "clients", [])) for item in getattr(getattr(state, "xray", None), "inbounds", []))
    out: list[Card] = []
    for item in sorted(all_cores(), key=lambda entry: (entry.order, entry.key)):
        if item.key == "xray":
            out.append(xray_card(xray_raw, clients, active))
        elif item.key == "freeturn":
            out.append(freeturn_card(getattr(state, "freeturn", None), ft_clients, active))
    return out


def running_count(cards: list[Card]) -> int:
    return sum(1 for item in cards if item.state == STATE_RUNNING)


def installed_count(cards: list[Card]) -> int:
    return sum(1 for item in cards if item.state in {STATE_RUNNING, STATE_STOPPED})


def find(cards: list[Card], key: object) -> Card | None:
    wanted = str(key or "").strip().lower()
    for item in cards:
        if item.key == wanted:
            return item
    return None
