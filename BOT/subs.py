from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

MAX_LINKS = 4096
MAX_BODY = 8 * 1024 * 1024
MAX_LINK = 4096
ALL_EMAIL = "*"
ALL_TITLE = "OBHOD all"
LOCAL_PREFIXES = ("http://", "https://")


class SubError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class Bundle:
    id: str = ""
    key: str = ""
    title: str = "OBHOD"
    links: list[str] = field(default_factory=list)
    quotas: list[dict[str, int]] = field(default_factory=list)

    def path(self) -> str:
        return "/%s/%s" % (self.id, self.key)

    def json_path(self) -> str:
        return self.path() + "/json"

    def url(self, address: str, port: int) -> str:
        return local_url(address, port) + self.path()

    def quota(self) -> dict[str, int]:
        return sum_quota(getattr(self, "quotas", []) or [])

    def json_url(self, address: str, port: int) -> str:
        return local_url(address, port) + self.json_path()

    def safe_url(self, address: str, port: int) -> str:
        try:
            return self.url(address, port)
        except SubError:
            return ""

    def public_url(self, base: str) -> str:
        return "%s%s" % (str(base or "").rstrip("/"), self.path())

    def public_json_url(self, base: str) -> str:
        return "%s%s" % (str(base or "").rstrip("/"), self.json_path())

    def safe_json_url(self, address: str, port: int) -> str:
        try:
            return self.json_url(address, port)
        except SubError:
            return ""

    def payload(self) -> str:
        return payload_of(self.links)

    def size(self) -> int:
        return len(self.payload())


def url_of(bundle: Bundle, address: str, port: int, base: str = "") -> str:
    if base:
        return bundle.public_url(base)
    return bundle.safe_url(address, port)


def json_url_of(bundle: Bundle, address: str, port: int, base: str = "") -> str:
    if base:
        return bundle.public_json_url(base)
    return bundle.safe_json_url(address, port)


def local_url(address: object, port: object) -> str:
    host = str(address or "").strip().strip("/")
    if not host:
        raise SubError("the server address is empty")
    if host.startswith(LOCAL_PREFIXES):
        base = host.rstrip("/")
        return base if ":" in base.split("//", 1)[-1] else "%s:%d" % (base, int(port))
    try:
        number = int(port)
    except (TypeError, ValueError):
        raise SubError("the subscription port is not a number") from None
    if not 1 <= number <= 65535:
        raise SubError("the subscription port is out of range")
    if any(char in host for char in " \t\r\n;|&`$<>\"'\\"):
        raise SubError("the server address carries forbidden characters")
    if len(host) > 253:
        raise SubError("the server address is too long")
    return "http://%s:%d" % (host, number)


def clean_links(links: Any) -> list[str]:
    if isinstance(links, str):
        links = [links]
    elif isinstance(links, (bytes, bytearray)):
        links = [bytes(links).decode("utf-8", "replace")]
    elif not isinstance(links, (list, tuple, set, frozenset)):
        try:
            links = list(links or [])
        except TypeError:
            return []
    out: list[str] = []
    for item in links or []:
        text = str(item or "").strip()
        if not text or len(text) > MAX_LINK:
            continue
        if any(char in text for char in "\r\n\t"):
            continue
        if text in out:
            continue
        out.append(text)
        if len(out) >= MAX_LINKS:
            break
    return out


def raw_budget() -> int:
    return (MAX_BODY // 4) * 3


def keep_links(links: Any) -> list[str]:
    found = clean_links(links)
    budget = raw_budget()
    kept: list[str] = []
    size = 0
    for item in found:
        chunk = len(item.encode("utf-8")) + 1
        if kept and size + chunk > budget:
            break
        kept.append(item)
        size += chunk
    return kept


def payload_of(links: Any) -> str:
    kept = keep_links(links)
    if not kept:
        return ""
    body = "\n".join(kept) + "\n"
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return encoded if len(encoded) <= MAX_BODY else ""


def dropped(links: Any) -> int:
    return len(clean_links(links)) - len(keep_links(links))


def json_body(bundle: Bundle, address: str = "", port: int = 0) -> str:
    body = {
        "title": bundle.title[:64],
        "count": len(bundle.links),
        "links": list(bundle.links),
        "refresh": 12,
    }
    if address:
        body["url"] = bundle.safe_url(address, port)
    return json.dumps(body, ensure_ascii=True, sort_keys=True)


def xray_links(links: Any) -> list[str]:
    return [item for item in clean_links(links) if item.startswith("vless://")]


def aggregate(xray_state: Any, extra_links: Any = None, address: str = "", port: int = 0) -> Bundle:
    bundle = Bundle()
    if xray_state is not None:
        bundle.id, bundle.key = xray_state.ensure_sub_all()
        bundle.title = ALL_TITLE
        all_fn = getattr(xray_state, "all_links", None)
        if callable(all_fn):
            bundle.links.extend(all_fn(address))
        else:
            for item in xray_state.subscriptions(address):
                bundle.links.extend(item.links)
    bundle.links.extend(xray_links(extra_links))
    bundle.links = xray_links(bundle.links)
    return bundle


def usage_of(stats: Any, email: str) -> dict[str, int]:
    up = 0
    down = 0
    if isinstance(stats, dict) and email:
        try:
            up = max(int(stats.get("user>>>%s>>>traffic>>>uplink" % email) or 0), 0)
        except (TypeError, ValueError):
            up = 0
        try:
            down = max(int(stats.get("user>>>%s>>>traffic>>>downlink" % email) or 0), 0)
        except (TypeError, ValueError):
            down = 0
    return {"up": up, "down": down}


def quota_of(client: Any, usage: Any = None) -> dict[str, int]:
    gb = 0
    try:
        gb = max(int(getattr(client, "total_gb", 0) or 0), 0)
    except (TypeError, ValueError):
        gb = 0
    try:
        expire = max(int(getattr(client, "expiry_ms", 0) or 0) // 1000, 0)
    except (TypeError, ValueError):
        expire = 0
    used = usage if isinstance(usage, dict) else {}
    try:
        up = max(int(used.get("up") or 0), 0)
    except (TypeError, ValueError):
        up = 0
    try:
        down = max(int(used.get("down") or 0), 0)
    except (TypeError, ValueError):
        down = 0
    return {"up": up, "down": down, "total": gb * 1024 * 1024 * 1024, "expire": expire}


def sum_quota(items: Any) -> dict[str, int]:
    total = 0
    up = 0
    down = 0
    expire = 0
    for item in items or []:
        if not isinstance(item, dict):
            continue
        total += max(int(item.get("total") or 0), 0)
        up += max(int(item.get("up") or 0), 0)
        down += max(int(item.get("down") or 0), 0)
        value = max(int(item.get("expire") or 0), 0)
        if value and (not expire or value < expire):
            expire = value
    return {"up": up, "down": down, "total": total, "expire": expire}


def entry_of(bundle: Bundle, refresh: int = 12, title: str = "") -> dict[str, Any]:
    quota = bundle.quota()
    return {
        "key": bundle.key,
        "email": ALL_EMAIL,
        "inbound": 0,
        "title": (title or bundle.title)[:64],
        "refresh": int(refresh),
        "filename": "obhod-all",
        "enabled": True,
        "path": bundle.path(),
        "links": list(bundle.links),
        "up": quota["up"],
        "down": quota["down"],
        "total": quota["total"],
        "expire": quota["expire"],
    }


def preview(payload: str, limit: int = 120) -> str:
    return str(payload or "")[:limit]


def decode(payload: str) -> list[str]:
    try:
        raw = base64.b64decode(str(payload or "").encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return [line for line in text.splitlines() if line.strip()]
