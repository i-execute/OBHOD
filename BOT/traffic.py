from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .freeturn import FtClient

MAX_PEERS = 8192
UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
STALE = 180.0


def valid_key(value: object) -> bool:
    text = str(value or "").strip()
    if len(text) != 44 or not text.endswith("="):
        return False
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return all(char in alphabet for char in text)


def size_of(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number != number or number < 0 or number == float("inf"):
        return 0.0
    return number


def human(value: object) -> str:
    number = size_of(value)
    index = 0
    while number >= 1024.0 and index < len(UNITS) - 1:
        number /= 1024.0
        index += 1
    if index == 0:
        return "%d %s" % (int(number), UNITS[index])
    return "%.1f %s" % (number, UNITS[index])


def speed(value: object) -> str:
    return human(value) + "/s"


def ago(seconds: object) -> str:
    total = int(size_of(seconds))
    if total <= 0:
        return "0s"
    if total < 60:
        return "%ds" % total
    if total < 3600:
        return "%dm %ds" % (total // 60, total % 60)
    if total < 86400:
        return "%dh %dm" % (total // 3600, (total % 3600) // 60)
    return "%dd %dh" % (total // 86400, (total % 86400) // 3600)


def day_of(epoch: object) -> int:
    value = int(size_of(epoch))
    if value <= 0:
        return 0
    try:
        return int(time.strftime("%Y%m%d", time.gmtime(value)))
    except (OverflowError, OSError, ValueError):
        return 0


def stamp(epoch: object) -> str:
    value = int(size_of(epoch))
    if value <= 0:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.gmtime(value))
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class Peer:
    iface: str = ""
    pub: str = ""
    endpoint: str = ""
    allowed: str = ""
    hs: int = 0
    rx: int = 0
    tx: int = 0
    keepalive: int = 0

    @property
    def total(self) -> int:
        return int(self.rx) + int(self.tx)

    @property
    def online(self) -> bool:
        return bool(self.hs)

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "Peer":
        data = raw if isinstance(raw, dict) else {}
        return cls(
            iface=str(data.get("iface", "") or "")[:15],
            pub=str(data.get("pub", "") or "")[:44],
            endpoint=str(data.get("endpoint", "") or "")[:64],
            allowed=str(data.get("allowed", "") or "")[:64],
            hs=max(int(size_of(data.get("hs"))), 0),
            rx=max(int(size_of(data.get("rx"))), 0),
            tx=max(int(size_of(data.get("tx"))), 0),
            keepalive=max(int(size_of(data.get("keepalive"))), 0),
        )


@dataclass
class Sample:
    at: float = 0.0
    rx: int = 0
    tx: int = 0


@dataclass
class Usage:
    name: str = ""
    pub: str = ""
    rx: int = 0
    tx: int = 0
    hs: int = 0
    endpoint: str = ""
    down: float = 0.0
    up: float = 0.0
    first_at: float = 0.0
    owner: bool = False
    day_at: float = 0.0
    rx0: int = 0
    tx0: int = 0

    @property
    def total(self) -> int:
        return int(self.rx) + int(self.tx)

    @property
    def online(self) -> bool:
        return bool(self.hs) and (time.time() - float(self.hs)) < STALE

    @property
    def day_rx(self) -> int:
        return max(int(self.rx) - int(self.rx0), 0)

    @property
    def day_tx(self) -> int:
        return max(int(self.tx) - int(self.tx0), 0)

    @property
    def day_total(self) -> int:
        return self.day_rx + self.day_tx

    def last_seen(self) -> int:
        if not self.hs:
            return 0
        return max(int(time.time() - float(self.hs)), 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pub": self.pub,
            "rx": int(self.rx),
            "tx": int(self.tx),
            "hs": int(self.hs),
            "down": round(float(self.down), 1),
            "up": round(float(self.up), 1),
            "first_at": float(self.first_at),
            "day_at": float(self.day_at),
            "rx0": int(self.rx0),
            "tx0": int(self.tx0),
        }

    @classmethod
    def from_dict(cls, name: str, raw: dict[str, Any] | None) -> "Usage":
        data = raw if isinstance(raw, dict) else {}
        return cls(
            name=name,
            pub=str(data.get("pub", "") or "")[:44],
            rx=max(int(size_of(data.get("rx"))), 0),
            tx=max(int(size_of(data.get("tx"))), 0),
            hs=max(int(size_of(data.get("hs"))), 0),
            down=size_of(data.get("down")),
            up=size_of(data.get("up")),
            first_at=size_of(data.get("first_at")),
            day_at=size_of(data.get("day_at")),
            rx0=max(int(size_of(data.get("rx0"))), 0),
            tx0=max(int(size_of(data.get("tx0"))), 0),
        )


@dataclass
class Traffic:
    peers: dict[str, Peer] = field(default_factory=dict)
    samples: dict[str, Sample] = field(default_factory=dict)
    interfaces: list[str] = field(default_factory=list)
    checked_at: float = 0.0
    error: str = ""

    def load(self, rows: Any, interfaces: Any = None) -> "Traffic":
        found: dict[str, Peer] = {}
        for row in rows or []:
            peer = Peer.from_dict(row)
            if not valid_key(peer.pub):
                continue
            found[peer.pub] = peer
            if len(found) >= MAX_PEERS:
                break
        self.peers = found
        names = []
        for item in interfaces or []:
            name = str(item)[:15]
            if name and name not in names:
                names.append(name)
        self.interfaces = names[:8]
        self.checked_at = time.time()
        self.error = ""
        return self

    def sample(self, name: str, pub: str) -> tuple[float, float]:
        peer = self.peers.get(pub)
        if peer is None:
            self.samples.pop(pub, None)
            return 0.0, 0.0
        now = time.time()
        previous = self.samples.get(pub)
        self.samples[pub] = Sample(at=now, rx=peer.rx, tx=peer.tx)
        if previous is None or now - previous.at < 1.0:
            return 0.0, 0.0
        span = now - previous.at
        down = max(peer.rx - previous.rx, 0) / span
        up = max(peer.tx - previous.tx, 0) / span
        return down, up

    def usage(self, clients: list[FtClient], history: dict[str, Any] | None = None) -> list[Usage]:
        saved = history or {}
        out: list[Usage] = []
        for client in clients:
            pub = str(client.pub or "").strip()
            peer = self.peers.get(pub)
            stored = Usage.from_dict(client.name, saved.get(client.name))
            down, up = self.sample(client.name, pub) if peer is not None else (0.0, 0.0)
            rx = max(peer.rx if peer else 0, stored.rx)
            tx = max(peer.tx if peer else 0, stored.tx)
            day_at, rx0, tx0 = self.day_base(stored, rx, tx)
            out.append(
                Usage(
                    name=client.name,
                    pub=pub,
                    rx=rx,
                    tx=tx,
                    hs=peer.hs if peer else stored.hs,
                    endpoint=peer.endpoint if peer else "",
                    down=down,
                    up=up,
                    first_at=stored.first_at or (peer.hs if peer else 0),
                    owner=bool(client.owner),
                    day_at=day_at,
                    rx0=rx0,
                    tx0=tx0,
                )
            )
        known = {client.pub for client in clients if client.pub}
        for pub, peer in self.peers.items():
            if pub in known:
                continue
            name = "peer-%s" % pub[-6:]
            down, up = self.sample(name, pub)
            day_at, rx0, tx0 = self.day_base(Usage(), peer.rx, peer.tx)
            out.append(
                Usage(
                    name=name,
                    pub=pub,
                    rx=peer.rx,
                    tx=peer.tx,
                    hs=peer.hs,
                    endpoint=peer.endpoint,
                    down=down,
                    up=up,
                    first_at=peer.hs,
                    day_at=day_at,
                    rx0=rx0,
                    tx0=tx0,
                )
            )
        out.sort(key=lambda item: (-item.total, item.name))
        return out

    def day_base(self, stored: Usage, rx: int, tx: int) -> tuple[float, int, int]:
        now = time.time()
        stale = day_of(stored.day_at) != day_of(now)
        rolled = rx < int(stored.rx0) or tx < int(stored.tx0)
        if stale or rolled or not stored.day_at:
            return now, rx, tx
        return float(stored.day_at), int(stored.rx0), int(stored.tx0)

    def totals(self, rows: list[Usage]) -> dict[str, Any]:
        return {
            "rx": sum(item.rx for item in rows),
            "tx": sum(item.tx for item in rows),
            "down": sum(item.down for item in rows),
            "up": sum(item.up for item in rows),
            "online": sum(1 for item in rows if item.online),
            "peers": len(self.peers),
            "clients": len(rows),
            "day_rx": sum(item.day_rx for item in rows),
            "day_tx": sum(item.day_tx for item in rows),
            "checked_at": self.checked_at,
        }

    def find(self, rows: list[Usage], name: str) -> Usage | None:
        wanted = str(name or "").strip()
        for item in rows:
            if item.name == wanted:
                return item
        return None


def history_from(rows: list[Usage], limit: int = 4096) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in rows[:limit]:
        if not item.name:
            continue
        out[item.name] = item.to_dict()
    return out
