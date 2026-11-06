from __future__ import annotations

import gzip
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com/repos/%s/releases/latest"
ALLOWED_HOSTS = ("api.github.com", "github.com")
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
ANY_TAG_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+$")
AGENT = "obhod-releases/1"
TIMEOUT = 8.0
MAX_BODY = 65536
OK_TTL = 600.0
FAIL_TTL = 300.0
CACHE: dict[str, tuple[float, str, str]] = {}
RAW_CACHE: dict[str, tuple[float, str, bytes, str]] = {}
LOCK = threading.Lock()


def allowed_url(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme != "https":
        return False
    host = (parts.hostname or "").lower()
    return host in ALLOWED_HOSTS


def decode_payload(body: bytes, headers: object) -> bytes:
    if not body or headers is None or not hasattr(headers, "get"):
        return body
    encoding = str(headers.get("Content-Encoding", "") or "").strip().lower()
    if encoding == "gzip":
        try:
            return gzip.decompress(body)[:MAX_BODY]
        except OSError:
            return b""
    return body


def parse_tag(body: bytes, pattern: re.Pattern[str]) -> str:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, AttributeError):
        return ""
    if not isinstance(data, dict):
        return ""
    tag = str(data.get("tag_name", "") or "").strip()
    return tag if pattern.match(tag) else ""


def tag_of(body: bytes) -> str:
    return parse_tag(body, TAG_RE)


def any_tag_of(body: bytes) -> str:
    return parse_tag(body, ANY_TAG_RE)


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


def fetch_raw(repo: str, timeout: float = TIMEOUT, etag: str = "", cached_body: bytes = b"") -> tuple[bytes, str, str]:
    url = API % repo
    if not allowed_url(url):
        return b"", "unreachable", ""
    req_headers = {
        "User-Agent": AGENT,
        "Accept": "application/vnd.github+json",
        "Accept-Encoding": "gzip",
    }
    if etag and cached_body:
        req_headers["If-None-Match"] = etag
    request = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            geturl = getattr(response, "geturl", None)
            if callable(geturl):
                final_url = str(geturl() or "")
                if final_url and not allowed_url(final_url):
                    return b"", "unreachable", ""
            resp_headers = getattr(response, "headers", None)
            new_etag = ""
            if resp_headers is not None and hasattr(resp_headers, "get"):
                new_etag = str(resp_headers.get("ETag", "") or "").strip()[:128]
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                return b"", "no_tag", ""
            body = decode_payload(raw, resp_headers)
            return body, "", new_etag or etag
    except urllib.error.HTTPError as exc:
        code = int(getattr(exc, "code", 0) or 0)
        if code == 304 and cached_body:
            return cached_body, "", etag
        reason = "rate_limited" if rate_limited(exc) else "http_%d" % code
        return b"", reason, etag
    except (OSError, ValueError):
        return b"", "unreachable", etag


def fetch_any(repo: str, timeout: float = TIMEOUT) -> tuple[str, str]:
    body, reason, _etag = fetch_raw(repo, timeout)
    if reason:
        return "", reason
    tag = any_tag_of(body)
    return (tag, "") if tag else ("", "no_tag")


def fetch(repo: str, timeout: float = TIMEOUT) -> tuple[str, str]:
    body, reason, _etag = fetch_raw(repo, timeout)
    if reason:
        return "", reason
    try:
        tag = tag_of(body)
    except Exception:
        return "", "unreachable"
    return (tag, "") if tag else ("", "no_tag")


def cached_lookup(key: str, repo: str, parser, direct_fn, timeout: float, use_cache: bool) -> tuple[str, str]:
    now = time.monotonic()
    prior_etag = ""
    prior_body = b""
    if use_cache:
        with LOCK:
            hit = CACHE.get(key)
            if hit and hit[0] > now:
                return hit[1], hit[2]
            raw_hit = RAW_CACHE.get(repo)
            if raw_hit and raw_hit[0] > now and not raw_hit[3]:
                parsed = parser(raw_hit[2])
                result = (parsed, "") if parsed else ("", "no_tag")
                CACHE[key] = (raw_hit[0], result[0], result[1])
                return result
            if raw_hit:
                prior_etag = raw_hit[1]
                prior_body = raw_hit[2]
    if prior_etag and prior_body and direct_fn is None:
        body, reason, new_etag = fetch_raw(repo, timeout, prior_etag, prior_body)
        if reason:
            tag = ""
        else:
            tag = parser(body)
            reason = "" if tag else "no_tag"
        expires = time.monotonic() + (OK_TTL if tag else FAIL_TTL)
        with LOCK:
            if body and not reason:
                RAW_CACHE[repo] = (expires, new_etag, body, "")
            CACHE[key] = (expires, tag, reason)
        return tag, reason
    if direct_fn is not None:
        tag, reason = direct_fn(repo, timeout)
        expires = time.monotonic() + (OK_TTL if tag else FAIL_TTL)
        with LOCK:
            CACHE[key] = (expires, tag, reason)
        return tag, reason
    body, reason, new_etag = fetch_raw(repo, timeout, prior_etag, prior_body)
    if reason:
        tag = ""
    else:
        tag = parser(body)
        reason = "" if tag else "no_tag"
    expires = time.monotonic() + (OK_TTL if tag else FAIL_TTL)
    with LOCK:
        if body and not reason:
            RAW_CACHE[repo] = (expires, new_etag, body, "")
        CACHE[key] = (expires, tag, reason)
    return tag, reason


def latest_tag(repo: str, timeout: float = TIMEOUT, use_cache: bool = True) -> tuple[str, str]:
    custom = None if getattr(fetch, "__code__", None) is _DEFAULT_FETCH_CODE else fetch
    return cached_lookup(repo, repo, tag_of, custom, timeout, use_cache)


def latest_tag_any(repo: str, timeout: float = TIMEOUT, use_cache: bool = True) -> tuple[str, str]:
    custom = None if getattr(fetch_any, "__code__", None) is _DEFAULT_FETCH_ANY_CODE else fetch_any
    return cached_lookup("any:" + repo, repo, any_tag_of, custom, timeout, use_cache)


_DEFAULT_FETCH_CODE = fetch.__code__
_DEFAULT_FETCH_ANY_CODE = fetch_any.__code__


def resolve(repo: str, fallback: str, pinned: object, timeout: float = TIMEOUT) -> tuple[str, str]:
    tag, reason = latest_tag(repo, timeout)
    allowed = pinned if hasattr(pinned, "__contains__") else ()
    if tag and tag in allowed:
        return tag, "api"
    if not tag:
        return fallback, "fallback"
    return fallback, "not_pinned"


def clear() -> None:
    with LOCK:
        CACHE.clear()
        RAW_CACHE.clear()
