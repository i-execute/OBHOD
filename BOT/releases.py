from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

API = "https://api.github.com/repos/%s/releases/latest"
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
AGENT = "obhod-releases/1"
TIMEOUT = 8.0
OK_TTL = 600.0
FAIL_TTL = 300.0
CACHE: dict[str, tuple[float, str, str]] = {}


def tag_of(body: bytes) -> str:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, AttributeError):
        return ""
    if not isinstance(data, dict):
        return ""
    tag = str(data.get("tag_name", "") or "").strip()
    return tag if TAG_RE.match(tag) else ""


def rate_limited(exc: BaseException) -> bool:
    code = int(getattr(exc, "code", 0) or 0)
    headers = getattr(exc, "headers", None)
    if code == 429:
        return True
    if headers is None:
        return False
    retry = str(headers.get("Retry-After", "") or "").strip()
    if retry.isdigit():
        return True
    remaining = str(headers.get("X-RateLimit-Remaining", "") or "").strip()
    return code == 403 and remaining == "0"


def fetch(repo: str, timeout: float = TIMEOUT) -> tuple[str, str]:
    request = urllib.request.Request(API % repo, headers={"User-Agent": AGENT, "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(65536)
    except urllib.error.HTTPError as exc:
        return "", "rate_limited" if rate_limited(exc) else "http_%d" % int(getattr(exc, "code", 0) or 0)
    except (OSError, ValueError):
        return "", "unreachable"
    try:
        tag = tag_of(body)
    except Exception:
        return "", "unreachable"
    return (tag, "") if tag else ("", "no_tag")


def latest_tag(repo: str, timeout: float = TIMEOUT, use_cache: bool = True) -> tuple[str, str]:
    if use_cache:
        hit = CACHE.get(repo)
        if hit and hit[0] > time.monotonic():
            return hit[1], hit[2]
    tag, reason = fetch(repo, timeout)
    CACHE[repo] = (time.monotonic() + (OK_TTL if tag else FAIL_TTL), tag, reason)
    return tag, reason


def resolve(repo: str, fallback: str, pinned: object, timeout: float = TIMEOUT) -> tuple[str, str]:
    tag, reason = latest_tag(repo, timeout)
    allowed = pinned if hasattr(pinned, "__contains__") else ()
    if tag and tag in allowed:
        return tag, "api"
    if not tag:
        return fallback, "fallback"
    return fallback, "not_pinned"


def clear() -> None:
    CACHE.clear()
