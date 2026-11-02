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

    def path(self) -> str:
        return "/%s/%s" % (self.id, self.key)

    def json_path(self) -> str:
        return self.path() + "/json"

    def url(self, address: str, port: int) -> str:
        return local_url(address, port) + self.path()

    def json_url(self, address: str, port: int) -> str:
        return local_url(address, port) + self.json_path()

    def payload(self) -> str:
        return payload_of(self.links)

    def size(self) -> int:
        return len(self.payload())


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
        try:
            body["url"] = bundle.url(address, port)
        except SubError:
            body["url"] = ""
    return json.dumps(body, ensure_ascii=True, sort_keys=True)


def aggregate(xray_state: Any, extra_links: Any = None, address: str = "", port: int = 0) -> Bundle:
    bundle = Bundle()
    if xray_state is not None:
        bundle.id, bundle.key = xray_state.ensure_sub_all()
        bundle.title = ALL_TITLE
        for item in xray_state.subscriptions(address):
            bundle.links.extend(item.links)
    bundle.links.extend(clean_links(extra_links))
    bundle.links = clean_links(bundle.links)
    return bundle


def entry_of(bundle: Bundle, refresh: int = 12, title: str = "") -> dict[str, Any]:
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
