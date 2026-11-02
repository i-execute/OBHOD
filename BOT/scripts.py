from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any

from . import fwguard

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
SCRIPT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_SCRIPTS = 64
MAX_LINKS = 8


@dataclass(frozen=True)
class Target:
    key: str
    name: str
    repo: str
    asset: str
    note_key: str
    optional: bool = False

    def url(self, tag: str = "") -> str:
        text = str(tag or "").strip()
        if not text or text == "latest":
            return "https://github.com/%s/releases/latest/download/%s" % (self.repo, self.asset)
        reference = text if text.startswith("v") else "v" + text
        return "https://github.com/%s/releases/download/%s/%s" % (self.repo, reference, self.asset)

    def raw(self, tag: str = "") -> str:
        branch = tag or "main"
        return "https://raw.githubusercontent.com/%s/%s/%s" % (self.repo, branch, self.asset)


TARGETS: tuple[Target, ...] = (
    Target("freeturn", "install.sh", "hackdiaz-dev/free-turn-proxy", "install.sh", "SCR_NOTE_INSTALL"),
    Target("freeturn_checksums", "checksums.txt", "hackdiaz-dev/free-turn-proxy", "checksums.txt", "SCR_NOTE_CHECKSUMS", True),
)


def targets() -> tuple[Target, ...]:
    return TARGETS


def target(key: object) -> Target | None:
    wanted = str(key or "").strip().lower()
    for item in TARGETS:
        if item.key == wanted:
            return item
    return None


def valid_digest(value: object) -> str:
    text = str(value or "").strip().lower()
    return text if DIGEST_RE.match(text) else ""


def digest_of(body: bytes) -> str:
    return hashlib.sha256(body or b"").hexdigest()


def valid_size(value: object) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(number, 0)


@dataclass
class Record:
    key: str = ""
    name: str = ""
    url: str = ""
    note_key: str = ""
    cached: bool = False
    digest: str = ""
    size: int = 0
    at: float = 0.0
    remote_digest: str = ""
    remote_size: int = 0
    error: str = ""
    optional: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.cached and self.remote_digest and self.remote_digest != self.digest)

    @property
    def missing(self) -> bool:
        return not self.cached

    @property
    def pending(self) -> bool:
        if self.changed:
            return True
        return self.missing and not self.optional

    def state_key(self) -> str:
        if self.missing:
            return "SCR_MISSING"
        if self.changed:
            return "SCR_CHANGED"
        return "SCR_CACHED"

    def short(self) -> str:
        return (self.digest or self.remote_digest or "")[:12] or "-"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "digest": self.digest,
            "size": int(self.size),
            "at": float(self.at),
            "remote_digest": self.remote_digest,
        }


@dataclass
class Report:
    records: list[Record] = field(default_factory=list)
    checked_at: float = 0.0
    error: str = ""

    def pending(self) -> list[Record]:
        return [item for item in self.records if item.pending]

    def cached(self) -> list[Record]:
        return [item for item in self.records if item.cached]

    def changed(self) -> list[Record]:
        return [item for item in self.records if item.changed]

    @property
    def has_news(self) -> bool:
        return bool(self.changed())

    def to_dict(self) -> dict[str, Any]:
        return {"records": [item.to_dict() for item in self.records], "checked_at": self.checked_at}


def parse_cache(raw: Any) -> list[Record]:
    out: list[Record] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()
        if not SCRIPT_NAME_RE.match(name):
            continue
        out.append(
            Record(
                key=str(item.get("key", "") or "")[:32],
                name=name,
                digest=valid_digest(item.get("digest")),
                size=valid_size(item.get("size")),
                at=float(item.get("at", 0) or 0),
            )
        )
        if len(out) >= MAX_SCRIPTS:
            break
    return out


def merge(cached: list[Record], probes: dict[str, dict[str, Any]], tag: str = "") -> Report:
    by_name = {item.name: item for item in cached}
    report = Report(records=[], checked_at=time.time())
    for item in targets():
        record = Record(
            key=item.key,
            name=item.asset.rsplit("/", 1)[-1],
            url=item.url(tag),
            note_key=item.note_key,
            optional=item.optional,
        )
        hit = by_name.get(record.name)
        if hit is not None:
            record.cached = True
            record.digest = hit.digest
            record.size = hit.size
            record.at = hit.at
        probe = probes.get(item.key) or {}
        record.remote_digest = valid_digest(probe.get("digest"))
        record.remote_size = valid_size(probe.get("size"))
        record.error = str(probe.get("error", "") or "")[:160]
        report.records.append(record)
    return report


def aliases() -> list[str]:
    return sorted({item.asset.rsplit("/", 1)[-1] for item in TARGETS})


def vk_holder() -> str:
    return fwguard.holders()
