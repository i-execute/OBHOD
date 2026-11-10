from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import gzip
import ipaddress
import json
import time
import urllib.error
import urllib.request

API = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d"
AGENT = "obhod-fwguard/1"
TIMEOUT = 12.0
MAX_BODY = 262144
OK_TTL = 86400.0
FAIL_TTL = 300.0
MIN_PREFIX = 8
MAX_PREFIXES = 512
ASNS = (
    (47541, "VKONTAKTE-SPB-AS LLC VK"),
    (47542, "VKONTAKTE-MSK-CDN-AS LLC VK"),
    (47764, "VK-AS LLC VK"),
    (28709, "VKONTAKTE-REGIONAL-CDN LLC VK"),
    (60863, "VK-AS LLC VK"),
    (62243, "VKONTAKTE-SPBZN-AS LLC VK"),
)
CACHE: dict[str, tuple[float, list[str], str]] = {}


class GuardError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def decode_body(raw: bytes, headers: object) -> bytes:
    if not raw or headers is None or not hasattr(headers, "get"):
        return raw
    encoding = str(headers.get("Content-Encoding", "") or "").strip().lower()
    if encoding == "gzip":
        try:
            return gzip.decompress(raw)[:MAX_BODY]
        except OSError:
            return b""
    return raw


def prefixes_of(body: bytes) -> list[str]:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, AttributeError):
        return []
    if not isinstance(data, dict):
        return []
    inner = data.get("data")
    if not isinstance(inner, dict):
        return []
    out: list[str] = []
    for item in inner.get("prefixes") or []:
        prefix = str((item or {}).get("prefix", "") or "").strip()
        if not prefix or ":" in prefix:
            continue
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if network.version == 4 and network.prefixlen >= MIN_PREFIX:
            out.append(str(network))
    return out


def collapse(items: list[str]) -> list[str]:
    networks = []
    for item in items:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return [str(item) for item in ipaddress.collapse_addresses(networks)]


def fetch_asn(asn: int, timeout: float = TIMEOUT) -> tuple[list[str], str]:
    request = urllib.request.Request(
        API % asn,
        headers={
            "User-Agent": AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(262144)
            body = decode_body(raw, getattr(response, "headers", None))
    except urllib.error.HTTPError as exc:
        return [], "http_%d" % int(getattr(exc, "code", 0) or 0)
    except (OSError, ValueError):
        return [], "unreachable"
    found = prefixes_of(body)
    return (found, "") if found else ([], "no_prefixes")


def vk_cidrs(timeout: float = TIMEOUT, use_cache: bool = True) -> tuple[list[str], str]:
    now = time.monotonic()
    if use_cache:
        hit = CACHE.get("vk")
        if hit and hit[0] > now:
            return hit[1], hit[2]
    collected: list[str] = []
    reason = ""
    if len(ASNS) > 1:
        with ThreadPoolExecutor(max_workers=len(ASNS)) as pool:
            futures = [pool.submit(fetch_asn, asn, timeout) for asn, _holder in ASNS]
            results = [future.result() for future in futures]
    else:
        results = [fetch_asn(asn, timeout) for asn, _holder in ASNS]
    for found, why in results:
        collected.extend(found)
        if why and not reason:
            reason = why
    merged = collapse(collected)[:MAX_PREFIXES]
    if not merged:
        CACHE["vk"] = (now + FAIL_TTL, [], reason or "no_prefixes")
        return [], reason or "no_prefixes"
    CACHE["vk"] = (now + OK_TTL, merged, "")
    return merged, ""


def join_cidrs(items: list[str]) -> str:
    return ",".join(items)


def clear() -> None:
    CACHE.clear()


def holders() -> str:
    return ", ".join("AS%d %s" % (asn, holder) for asn, holder in ASNS)
