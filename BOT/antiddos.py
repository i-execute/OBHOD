from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable

from .rkn_seed import RKN_SEED_ZHEX, RKN_SOURCES

LEVELS = ("ok", "warn", "bad")
RKN_GUARD_AUTHOR = "Flecksis"
RKN_GUARD_REPO = "https://github.com/Flecksis/rkn-guard"

TABLE = "obhod_ddos"
SET_SYN = "syn_flood"
SET_CONN = "conn_flood"
SET_UDP = "udp_flood"
SET_ICMP = "icmp_flood"
SET_SCAN = "port_scan"
SET_RKN_V4 = "rkn_v4"
SET_RKN_V6 = "rkn_v6"
SET_ALLOW_V4 = "rkn_allow_v4"
SET_ALLOW_V6 = "rkn_allow_v6"
SET_BAN_V4 = "manual_ban_v4"
SET_BAN_V6 = "manual_ban_v6"
DEFAULT_PORTS = (22, 443)
MAX_PORTS = 16
MAX_SET_SIZE = 1 << 20
MAX_WINDOW = 3600
MIN_BURST = 1
MIN_RATE = 1
MIN_V4_PREFIX = 12
MIN_V6_PREFIX = 28
MIN_MANUAL_V4_PREFIX = 8
MIN_MANUAL_V6_PREFIX = 24
MAX_RKN_BYTES = 4 * 1024 * 1024
MAX_ZHEX_CHARS = 524288
MAX_CUSTOM_ENTRIES = 512
MAX_CUSTOM_SOURCES = 16
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

PROTECTED_V4 = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("149.154.160.0/20"),
    ipaddress.ip_network("91.108.4.0/22"),
    ipaddress.ip_network("91.108.8.0/22"),
    ipaddress.ip_network("91.108.56.0/22"),
    ipaddress.ip_network("1.1.1.1/32"),
    ipaddress.ip_network("1.0.0.1/32"),
    ipaddress.ip_network("8.8.8.8/32"),
    ipaddress.ip_network("8.8.4.4/32"),
    ipaddress.ip_network("9.9.9.9/32"),
)
PROTECTED_V6 = (
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
    ipaddress.ip_network("2001:67c:4e8::/48"),
    ipaddress.ip_network("2001:b28:f23d::/48"),
    ipaddress.ip_network("2001:b28:f23f::/48"),
)

SYN_RATE = 180
SYN_BURST = 240
CONN_RATE = 300
CONN_BURST = 360
UDP_RATE = 400
UDP_BURST = 200
ICMP_RATE = 20
ICMP_BURST = 10
SCAN_RATE = 60
BAN_TIMEOUT = 3600
SET_SIZE = 65536

PPS_WARN = 60000
PPS_BAD = 200000
CONNTRACK_WARN = 0.70
CONNTRACK_BAD = 0.90
SET_WARN = 8
SET_BAD = 60
DROP_WARN = 200
DROP_BAD = 5000

PANEL_NAMES = ("3x-ui", "x-ui", "xray-ui", "marzban", "hiddify", "v2board", "xpanel", "sspanel")
PANEL_PORTS = (2053, 2083, 2087, 2096, 8443, 54321)
PROXY_PORTS = (1080, 1081, 3128, 7890, 7891, 8118, 8388, 8880, 9000)
DATASTORE_PORTS = (3306, 5432, 6379, 9042, 11211, 27017, 27018)
RISKY_PORTS = {
    21: "ftp",
    23: "telnet",
    25: "smtp",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    445: "smb",
    2049: "nfs",
    2375: "docker socket",
    2376: "docker tls",
    2379: "etcd",
    5900: "vnc",
    6443: "kubernetes api",
    9100: "node exporter",
    10085: "xray api",
    19999: "netdata",
}
PROBE_RANK = {"bad": 3, "warn": 2, "info": 1}

FIELD = re.compile(r"^[a-z_]{2,24}$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class DDoSerror(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def clamp(value: object, low: int, high: int, fallback: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return int(fallback)
    return int(max(low, min(number, high)))


def ports_of(raw: object) -> list[int]:
    if isinstance(raw, (list, tuple, set)):
        text = ",".join(str(item) for item in raw)
    else:
        text = str(raw or "")
    out: list[int] = []
    for match in re.finditer(r"(?<![\w-])(\d{1,5})(?!\w)", text):
        value = int(match.group(1))
        if 1 <= value <= 65535 and value not in out:
            out.append(value)
    return out[:MAX_PORTS]


def ports_text(raw: object) -> str:
    ports = ports_of(raw)
    return ",".join(str(item) for item in ports)


LOCAL_V4 = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
)
LOCAL_V6 = (
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


def _is_non_global_or_unsafe(net: ipaddress._BaseNetwork) -> bool:
    if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
        return True
    if isinstance(net, ipaddress.IPv4Network):
        return any(net.overlaps(loc) for loc in LOCAL_V4)
    return any(net.overlaps(loc) for loc in LOCAL_V6)


def _extra_protected_nets(extra_protected: Iterable[str] | None) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
    p4 = list(PROTECTED_V4)
    p6 = list(PROTECTED_V6)
    for item in extra_protected or ():
        token = str(item or "").strip()
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            p4.append(net)
        else:
            p6.append(net)
    return p4, p6


def clean_entry(raw: str, *, allow_private: bool = False) -> str:
    token = str(raw or "").split("#", 1)[0].strip().lstrip("\ufeff")
    if not token or CONTROL_RE.search(token):
        return ""
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return ""
    if net.is_unspecified or net.is_multicast:
        return ""
    if not allow_private:
        if _is_non_global_or_unsafe(net):
            return ""
        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen < MIN_MANUAL_V4_PREFIX or any(net.overlaps(p) for p in PROTECTED_V4):
                return ""
        else:
            if net.prefixlen < MIN_MANUAL_V6_PREFIX or any(net.overlaps(p) for p in PROTECTED_V6):
                return ""
    else:
        if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < MIN_MANUAL_V4_PREFIX:
            return ""
        if isinstance(net, ipaddress.IPv6Network) and net.prefixlen < MIN_MANUAL_V6_PREFIX:
            return ""
    if (isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 32) or (
        isinstance(net, ipaddress.IPv6Network) and net.prefixlen == 128
    ):
        return str(net.network_address)
    return str(net)


def parse_entries(raw: Any, *, allow_private: bool = False) -> list[str]:
    if isinstance(raw, str):
        items = [part.strip() for part in raw.replace(";", ",").replace("\n", ",").split(",") if part.strip()]
    elif isinstance(raw, Iterable) and not isinstance(raw, (bytes, bytearray, dict)):
        items = [str(part).strip() for part in raw if str(part).strip()]
    else:
        items = []
    out: list[str] = []
    for item in items:
        cleaned = clean_entry(item, allow_private=allow_private)
        if cleaned and cleaned not in out:
            out.append(cleaned)
            if len(out) >= MAX_CUSTOM_ENTRIES:
                break
    return out


def entries_csv(entries: Iterable[str], *, allow_private: bool = False) -> str:
    return ",".join(parse_entries(list(entries), allow_private=allow_private))


def split_collapsed_entries(
    entries: Iterable[str],
    *,
    allow_private: bool = False,
    extra_protected: Iterable[str] | None = None,
) -> tuple[list[str], list[str]]:
    p4, p6 = _extra_protected_nets(extra_protected)
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for item in entries:
        cleaned = clean_entry(item, allow_private=allow_private)
        if not cleaned:
            continue
        net = ipaddress.ip_network(cleaned, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            if not allow_private and any(net.overlaps(p) for p in p4):
                continue
            v4.append(net)
        else:
            if not allow_private and any(net.overlaps(p) for p in p6):
                continue
            v6.append(net)
    return (
        [str(net) for net in ipaddress.collapse_addresses(v4)],
        [str(net) for net in ipaddress.collapse_addresses(v6)],
    )


def sanitize_rkn_networks(
    lines: Iterable[str],
    *,
    extra_protected: Iterable[str] | None = None,
) -> tuple[list[str], list[str]]:
    p4, p6 = _extra_protected_nets(extra_protected)
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for raw_line in lines:
        token = str(raw_line or "").split("#", 1)[0].strip().lstrip("\ufeff")
        if not token or CONTROL_RE.search(token):
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if _is_non_global_or_unsafe(net):
            continue
        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen < MIN_V4_PREFIX or any(net.overlaps(p) for p in p4):
                continue
            v4.append(net)
        else:
            if net.prefixlen < MIN_V6_PREFIX or any(net.overlaps(p) for p in p6):
                continue
            v6.append(net)
    return (
        [str(net) for net in ipaddress.collapse_addresses(v4)],
        [str(net) for net in ipaddress.collapse_addresses(v6)],
    )


def encode_rkn_zhex(v4: Iterable[str], v6: Iterable[str]) -> str:
    cv4, cv6 = sanitize_rkn_networks([*v4, *v6])
    payload = json.dumps({"v4": cv4, "v6": cv6}, separators=(",", ":")).encode("utf-8")
    return zlib.compress(payload, 9).hex()


def decode_rkn_zhex(blob: str, *, extra_protected: Iterable[str] | None = None) -> tuple[list[str], list[str]]:
    clean = str(blob or "").strip()
    if not clean or len(clean) > MAX_ZHEX_CHARS:
        return [], []
    try:
        compressed = bytes.fromhex(clean)
        decomp = zlib.decompressobj()
        raw = decomp.decompress(compressed, MAX_RKN_BYTES)
        if decomp.unconsumed_tail:
            return [], []
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, zlib.error, UnicodeDecodeError, json.JSONDecodeError):
        return [], []
    if not isinstance(parsed, dict):
        return [], []
    rv4 = parsed.get("v4") if isinstance(parsed.get("v4"), list) else []
    rv6 = parsed.get("v6") if isinstance(parsed.get("v6"), list) else []
    return sanitize_rkn_networks([*(str(x) for x in rv4), *(str(x) for x in rv6)], extra_protected=extra_protected)


@lru_cache(maxsize=1)
def _cached_seed() -> tuple[tuple[str, ...], tuple[str, ...]]:
    v4, v6 = decode_rkn_zhex(RKN_SEED_ZHEX)
    return tuple(v4), tuple(v6)


def seed_rkn_subnets(*, extra_protected: Iterable[str] | None = None) -> tuple[list[str], list[str]]:
    v4, v6 = _cached_seed()
    if not extra_protected:
        return list(v4), list(v6)
    return sanitize_rkn_networks([*v4, *v6], extra_protected=extra_protected)


def normalize_source_url(raw: str) -> str:
    text = str(raw or "").strip()
    if not text or len(text) > 512 or CONTROL_RE.search(text) or any(ch.isspace() for ch in text):
        return ""
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal", ".lan")):
        return ""
    try:
        addr = ipaddress.ip_address(host)
        if not addr.is_global:
            return ""
    except ValueError:
        pass
    path = parsed.path or "/"
    if host in {"github.com", "www.github.com"}:
        parts = [seg for seg in path.split("/") if seg]
        if len(parts) >= 5 and parts[2] == "blob":
            owner, repo = parts[0], parts[1]
            rest = parts[3:]
            if len(rest) >= 3 and rest[0] == "refs" and rest[1] == "heads":
                rest = rest[2:]
            host = "raw.githubusercontent.com"
            path = "/" + "/".join([owner, repo, *rest])
    elif host == "raw.githubusercontent.com":
        parts = [seg for seg in path.split("/") if seg]
        if len(parts) >= 5 and parts[2] == "refs" and parts[3] == "heads":
            path = "/" + "/".join([parts[0], parts[1], *parts[4:]])
    port_suffix = f":{parsed.port}" if parsed.port and parsed.port != 443 else ""
    return urllib.parse.urlunsplit(("https", host + port_suffix, path, parsed.query, ""))


def parse_source_urls(raw: Any) -> list[str]:
    if isinstance(raw, str):
        items = [part.strip() for part in raw.replace(";", ",").replace("\n", ",").split(",") if part.strip()]
    elif isinstance(raw, Iterable) and not isinstance(raw, (bytes, bytearray, dict)):
        items = [str(part).strip() for part in raw if str(part).strip()]
    else:
        items = []
    out: list[str] = []
    for item in items:
        url = normalize_source_url(item)
        if url and url not in out:
            out.append(url)
            if len(out) >= MAX_CUSTOM_SOURCES:
                break
    return out


class _NoHttpRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        target = normalize_source_url(urllib.parse.urljoin(req.full_url, newurl))
        if not target:
            raise urllib.error.HTTPError(req.full_url, code, "blocked redirect", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, target)


def _download_source_lines(url: str, timeout: float) -> list[str]:
    clean_url = normalize_source_url(url)
    if not clean_url:
        raise ValueError("invalid https source url")
    opener = urllib.request.build_opener(_NoHttpRedirect)
    request = urllib.request.Request(clean_url, headers={"User-Agent": "OBHOD-RKN-Guard/1.0"})
    with opener.open(request, timeout=max(2.0, float(timeout))) as resp:
        chunks: list[bytes] = []
        total = 0
        while True:
            block = resp.read(65536)
            if not block:
                break
            total += len(block)
            if total > MAX_RKN_BYTES:
                raise ValueError("source list exceeds size limit")
            chunks.append(block)
    return b"".join(chunks).decode("utf-8", errors="replace").splitlines()


def fetch_rkn_subnets(
    *,
    custom_sources: Iterable[str] | None = None,
    extra_protected: Iterable[str] | None = None,
    timeout: float = 10.0,
) -> tuple[list[str], list[str], int, list[str]]:
    sources: list[tuple[str, str]] = list(RKN_SOURCES)
    for index, raw_url in enumerate(parse_source_urls(custom_sources or ()), start=1):
        if all(existing_url != raw_url for _name, existing_url in sources):
            sources.append((f"custom_{index}", raw_url))
    collected: list[str] = []
    ok_sources = 0
    errors: list[str] = []
    for name, url in sources:
        try:
            lines = _download_source_lines(url, timeout=timeout)
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}")
            continue
        collected.extend(lines)
        ok_sources += 1
    v4, v6 = sanitize_rkn_networks(collected, extra_protected=extra_protected)
    if not v4 and not v6:
        sv4, sv6 = seed_rkn_subnets(extra_protected=extra_protected)
        return sv4, sv6, ok_sources, errors
    return v4, v6, ok_sources, errors


def _parse_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


@dataclass
class Policy:
    enabled: bool = True
    syn_rate: int = SYN_RATE
    syn_burst: int = SYN_BURST
    conn_rate: int = CONN_RATE
    conn_burst: int = CONN_BURST
    udp_rate: int = UDP_RATE
    udp_burst: int = UDP_BURST
    icmp_rate: int = ICMP_RATE
    icmp_burst: int = ICMP_BURST
    ban_timeout: int = BAN_TIMEOUT
    set_size: int = SET_SIZE
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    rkn_enabled: bool = True
    rkn_allow: list[str] = field(default_factory=list)
    manual_bans: list[str] = field(default_factory=list)
    unbanned: list[str] = field(default_factory=list)
    custom_sources: list[str] = field(default_factory=list)

    def normalise(self) -> "Policy":
        self.syn_rate = clamp(self.syn_rate, MIN_RATE, 100000, SYN_RATE)
        self.syn_burst = clamp(self.syn_burst, MIN_BURST, 100000, SYN_BURST)
        self.conn_rate = clamp(self.conn_rate, MIN_RATE, 100000, CONN_RATE)
        self.conn_burst = clamp(self.conn_burst, MIN_BURST, 100000, CONN_BURST)
        self.udp_rate = clamp(self.udp_rate, MIN_RATE, 200000, UDP_RATE)
        self.udp_burst = clamp(self.udp_burst, MIN_BURST, 200000, UDP_BURST)
        self.icmp_rate = clamp(self.icmp_rate, MIN_RATE, 10000, ICMP_RATE)
        self.icmp_burst = clamp(self.icmp_burst, MIN_BURST, 10000, ICMP_BURST)
        self.ban_timeout = clamp(self.ban_timeout, 60, MAX_WINDOW * 24, BAN_TIMEOUT)
        self.set_size = clamp(self.set_size, 1024, MAX_SET_SIZE, SET_SIZE)
        self.ports = ports_of(",".join(str(item) for item in self.ports)) or list(DEFAULT_PORTS)
        self.rkn_enabled = bool(self.rkn_enabled)
        self.rkn_allow = parse_entries(self.rkn_allow, allow_private=True)
        self.manual_bans = parse_entries(self.manual_bans, allow_private=False)
        self.unbanned = parse_entries(self.unbanned, allow_private=True)[:64]
        self.custom_sources = parse_source_urls(self.custom_sources)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.enabled),
            "syn_rate": int(self.syn_rate),
            "syn_burst": int(self.syn_burst),
            "conn_rate": int(self.conn_rate),
            "conn_burst": int(self.conn_burst),
            "udp_rate": int(self.udp_rate),
            "udp_burst": int(self.udp_burst),
            "icmp_rate": int(self.icmp_rate),
            "icmp_burst": int(self.icmp_burst),
            "ban_timeout": int(self.ban_timeout),
            "set_size": int(self.set_size),
            "ports": list(self.ports),
            "rkn_enabled": bool(self.rkn_enabled),
            "rkn_allow": list(self.rkn_allow),
            "manual_bans": list(self.manual_bans),
            "unbanned": list(self.unbanned),
            "custom_sources": list(self.custom_sources),
        }

    def allow_csv(self) -> str:
        return entries_csv(self.rkn_allow, allow_private=True)

    def bans_csv(self) -> str:
        return entries_csv(self.manual_bans, allow_private=False)

    def unbanned_csv(self) -> str:
        return entries_csv(self.unbanned, allow_private=True)

    def sources_csv(self) -> str:
        return ",".join(parse_source_urls(self.custom_sources))

    @staticmethod
    def from_dict(raw: Any) -> "Policy":
        data = raw if isinstance(raw, dict) else {}
        policy = Policy(
            enabled=_parse_bool(data.get("enabled"), True),
            syn_rate=clamp(data.get("syn_rate"), MIN_RATE, 100000, SYN_RATE),
            syn_burst=clamp(data.get("syn_burst"), MIN_BURST, 100000, SYN_BURST),
            conn_rate=clamp(data.get("conn_rate"), MIN_RATE, 100000, CONN_RATE),
            conn_burst=clamp(data.get("conn_burst"), MIN_BURST, 100000, CONN_BURST),
            udp_rate=clamp(data.get("udp_rate"), MIN_RATE, 200000, UDP_RATE),
            udp_burst=clamp(data.get("udp_burst"), MIN_BURST, 200000, UDP_BURST),
            icmp_rate=clamp(data.get("icmp_rate"), MIN_RATE, 10000, ICMP_RATE),
            icmp_burst=clamp(data.get("icmp_burst"), MIN_BURST, 10000, ICMP_BURST),
            ban_timeout=clamp(data.get("ban_timeout"), 60, MAX_WINDOW * 24, BAN_TIMEOUT),
            set_size=clamp(data.get("set_size"), 1024, MAX_SET_SIZE, SET_SIZE),
            ports=ports_of(raw.get("ports") if isinstance(raw, dict) else ""),
            rkn_enabled=_parse_bool(data.get("rkn_enabled"), True),
            rkn_allow=parse_entries(data.get("rkn_allow"), allow_private=True),
            manual_bans=parse_entries(data.get("manual_bans"), allow_private=False),
            unbanned=parse_entries(data.get("unbanned"), allow_private=True)[:64],
            custom_sources=parse_source_urls(data.get("custom_sources")),
        )
        return policy.normalise()


def ports_set(policy: Policy) -> str:
    ports = policy.ports or list(DEFAULT_PORTS)
    return "{ " + ", ".join(str(item) for item in ports) + " }"


def _render_interval_set(name: str, family_type: str, elements: list[str]) -> list[str]:
    if not elements:
        return []
    out = [
        "  set %s {" % name,
        "    type %s;" % family_type,
        "    flags interval;",
        "    auto-merge;",
        "    elements = {",
    ]
    for index in range(0, len(elements), 8):
        chunk = ", ".join(elements[index : index + 8])
        suffix = "," if index + 8 < len(elements) else ""
        out.append("      %s%s" % (chunk, suffix))
    out.extend(["    }", "  }"])
    return out


def nft_table(
    policy: Policy,
    *,
    rkn_v4: Iterable[str] | None = None,
    rkn_v6: Iterable[str] | None = None,
) -> str:
    policy = policy.normalise()
    allow_v4, allow_v6 = split_collapsed_entries(policy.rkn_allow, allow_private=True)
    ban_v4, ban_v6 = split_collapsed_entries(policy.manual_bans, allow_private=False)
    active_rkn_v4: list[str] = []
    active_rkn_v6: list[str] = []
    if policy.rkn_enabled:
        if rkn_v4 is None and rkn_v6 is None:
            active_rkn_v4, active_rkn_v6 = seed_rkn_subnets()
        else:
            active_rkn_v4, active_rkn_v6 = sanitize_rkn_networks([*(rkn_v4 or ()), *(rkn_v6 or ())])

    lines = ["table inet %s {" % TABLE]
    lines.extend(_render_interval_set(SET_ALLOW_V4, "ipv4_addr", allow_v4))
    lines.extend(_render_interval_set(SET_ALLOW_V6, "ipv6_addr", allow_v6))
    lines.extend(_render_interval_set(SET_BAN_V4, "ipv4_addr", ban_v4))
    lines.extend(_render_interval_set(SET_BAN_V6, "ipv6_addr", ban_v6))
    lines.extend(_render_interval_set(SET_RKN_V4, "ipv4_addr", active_rkn_v4))
    lines.extend(_render_interval_set(SET_RKN_V6, "ipv6_addr", active_rkn_v6))
    lines.extend(
        [
            "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_SYN, policy.ban_timeout, policy.set_size),
            "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_CONN, policy.ban_timeout, policy.set_size),
            "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_UDP, policy.ban_timeout, policy.set_size),
            "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_ICMP, policy.ban_timeout, policy.set_size),
            "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_SCAN, policy.ban_timeout, policy.set_size),
            "  chain input {",
            "    type filter hook input priority raw; policy accept;",
            '    iifname "lo" accept',
            "    ct state invalid counter drop",
            "    tcp flags & (fin|syn|rst|ack) == 0x0 counter drop",
            "    tcp flags & (fin|syn|psh|rst|ack|urg) == (fin|syn|psh|urg) counter drop",
        ]
    )
    if allow_v4:
        lines.append("    ip saddr @%s accept" % SET_ALLOW_V4)
    if allow_v6:
        lines.append("    ip6 saddr @%s accept" % SET_ALLOW_V6)
    if ban_v4:
        lines.append("    ip saddr @%s counter drop" % SET_BAN_V4)
    if ban_v6:
        lines.append("    ip6 saddr @%s counter drop" % SET_BAN_V6)
    if active_rkn_v4:
        lines.append("    ct state established,related ip saddr @%s accept" % SET_RKN_V4)
        lines.append("    ip saddr @%s counter drop" % SET_RKN_V4)
    if active_rkn_v6:
        lines.append("    ct state established,related ip6 saddr @%s accept" % SET_RKN_V6)
        lines.append("    ip6 saddr @%s counter drop" % SET_RKN_V6)
    lines.extend(
        [
            "    ip saddr @%s counter drop" % SET_SYN,
            "    ip saddr @%s counter drop" % SET_CONN,
            "    ip saddr @%s counter drop" % SET_UDP,
            "    ip saddr @%s counter drop" % SET_ICMP,
            "    ip saddr @%s counter drop" % SET_SCAN,
            "    ct state new tcp flags & (fin|syn|rst|ack) == syn update @%s { ip saddr limit rate over %d/second burst %d packets } counter accept"
            % (SET_SYN, policy.syn_rate, policy.syn_burst),
            "    ct state new update @%s { ip saddr limit rate over %d/second burst %d packets }" % (SET_CONN, policy.conn_rate, policy.conn_burst),
            "    udp dport %s update @%s { ip saddr limit rate over %d/second burst %d packets }" % (ports_set(policy), SET_UDP, policy.udp_rate, policy.udp_burst),
            "    icmp type echo-request update @%s { ip saddr limit rate over %d/second burst %d packets }" % (SET_ICMP, policy.icmp_rate, policy.icmp_burst),
            "    tcp dport != %s tcp flags & (fin|syn|rst|ack) == syn update @%s { ip saddr limit rate over %d/second burst %d packets }"
            % (ports_set(policy), SET_SCAN, SCAN_RATE, SCAN_RATE),
            "    counter accept",
            "  }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def sysctl_values(policy: Policy) -> dict[str, str]:
    policy = policy.normalise()
    return {
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.tcp_max_syn_backlog": "8192",
        "net.ipv4.tcp_synack_retries": "2",
        "net.ipv4.tcp_syn_retries": "3",
        "net.ipv4.tcp_fin_timeout": "15",
        "net.ipv4.tcp_keepalive_time": "600",
        "net.ipv4.tcp_max_orphans": "32768",
        "net.ipv4.tcp_rfc1337": "1",
        "net.ipv4.tcp_mtu_probing": "1",
        "net.ipv4.ip_local_port_range": "10240 65000",
        "net.ipv4.conf.all.rp_filter": "2",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.secure_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.log_martians": "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "net.ipv4.icmp_ratelimit": "200",
        "net.ipv4.icmp_ratemask": "88089",
        "net.core.somaxconn": "4096",
        "net.core.netdev_max_backlog": "16384",
        "net.core.rmem_max": "16777216",
        "net.core.wmem_max": "16777216",
        "net.core.default_qdisc": "fq",
        "net.ipv4.tcp_congestion_control": "bbr",
        "net.netfilter.nf_conntrack_max": "262144",
        "net.netfilter.nf_conntrack_tcp_timeout_syn_recv": "30",
        "net.netfilter.nf_conntrack_generic_timeout": str(max(60, min(policy.ban_timeout, 3600))),
    }


def sysctl_text(policy: Policy) -> str:
    rows = sysctl_values(policy)
    return "".join("%s = %s\n" % (key, value) for key, value in sorted(rows.items()))


def parse_counters(raw: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        name = str(key or "").strip().lower()
        if not FIELD.match(name):
            continue
        try:
            out[name] = max(0, int(value))
        except (TypeError, ValueError):
            continue
    return out


def parse_set(raw: Any, limit: int = 64) -> list[str]:
    out: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        text = str(item or "").strip()[:45]
        if not text:
            continue
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        out.append(str(address))
        if len(out) >= limit:
            break
    return out


@dataclass(frozen=True)
class IpRecord:
    address: str
    reason: str
    blocked: bool = True


@dataclass
class Status:
    installed: bool = False
    enabled: bool = True
    table: bool = False
    policy: Policy = field(default_factory=Policy)
    counters: dict[str, int] = field(default_factory=dict)
    syn_flood: list[str] = field(default_factory=list)
    conn_flood: list[str] = field(default_factory=list)
    udp_flood: list[str] = field(default_factory=list)
    icmp_flood: list[str] = field(default_factory=list)
    scan: list[str] = field(default_factory=list)
    pps: int = 0
    connections: int = 0
    conntrack: int = 0
    conntrack_max: int = 0
    kernel: str = ""
    notice: str = ""
    error: str = ""
    rkn_enabled: bool = True
    rkn_v4_count: int = 0
    rkn_v6_count: int = 0
    rkn_updated: str = ""

    @staticmethod
    def from_dict(raw: Any) -> "Status":
        data = raw if isinstance(raw, dict) else {}
        pol = Policy.from_dict(data.get("policy"))
        rkn_flag = data.get("rkn_enabled", pol.rkn_enabled)
        status = Status(
            installed=bool(data.get("installed", False)),
            enabled=bool(data.get("enabled", True)),
            table=bool(data.get("table", False)),
            policy=pol,
            counters=parse_counters(data.get("counters")),
            syn_flood=parse_set(data.get("syn_flood")),
            conn_flood=parse_set(data.get("conn_flood")),
            udp_flood=parse_set(data.get("udp_flood")),
            icmp_flood=parse_set(data.get("icmp_flood")),
            scan=parse_set(data.get("scan")),
            pps=clamp(data.get("pps"), 0, 1 << 40, 0),
            connections=clamp(data.get("connections"), 0, 1 << 32, 0),
            conntrack=clamp(data.get("conntrack"), 0, 1 << 32, 0),
            conntrack_max=clamp(data.get("conntrack_max"), 0, 1 << 32, 0),
            kernel=str(data.get("kernel", "") or "")[:32],
            notice=str(data.get("notice", "") or "")[:120],
            error=str(data.get("error", "") or "")[:160],
            rkn_enabled=_parse_bool(rkn_flag, pol.rkn_enabled),
            rkn_v4_count=clamp(data.get("rkn_v4_count"), 0, 1 << 24, 0),
            rkn_v6_count=clamp(data.get("rkn_v6_count"), 0, 1 << 24, 0),
            rkn_updated=str(data.get("rkn_updated", "") or "")[:40],
        )
        return status

    def dropped(self) -> int:
        return sum(value for key, value in self.counters.items() if "drop" in key)

    def rkn_dropped(self) -> int:
        return int(self.counters.get("rkn_drop", 0))

    def manual_dropped(self) -> int:
        return int(self.counters.get("manual_drop", 0))

    def flood_dropped(self) -> int:
        return sum(
            value
            for key, value in self.counters.items()
            if "drop" in key and key not in {"rkn_drop", "manual_drop"}
        )

    def offenders(self) -> list[str]:
        seen: list[str] = []
        for group in (self.syn_flood, self.conn_flood, self.udp_flood, self.icmp_flood, self.scan):
            for address in group:
                if address not in seen:
                    seen.append(address)
        return seen[:16]

    def attack_ips(self) -> list[str]:
        seen: list[str] = []
        for group in (self.syn_flood, self.conn_flood, self.udp_flood):
            for address in group:
                if address not in seen:
                    seen.append(address)
        return seen

    def ip_records(self) -> list[IpRecord]:
        records: list[IpRecord] = []
        seen: set[str] = set()
        buckets: tuple[tuple[list[str], str], ...] = (
            (self.syn_flood, "syn"),
            (self.conn_flood, "conn"),
            (self.udp_flood, "udp"),
            (self.icmp_flood, "icmp"),
            (self.scan, "scan"),
            (list(self.policy.manual_bans), "manual"),
        )
        for group, reason in buckets:
            for item in group:
                addr = str(item or "").strip()
                if addr and addr not in seen:
                    seen.add(addr)
                    records.append(IpRecord(addr, reason, True))
        for item in [*(self.policy.unbanned or []), *(self.policy.rkn_allow or [])]:
            addr = str(item or "").strip()
            if addr and addr not in seen:
                seen.add(addr)
                records.append(IpRecord(addr, "unbanned", False))
        return records

    def blocked_count(self) -> int:
        return sum(1 for item in self.ip_records() if item.blocked)

    def pressure(self) -> float:
        if self.conntrack_max <= 0:
            return 0.0
        return min(1.0, float(self.conntrack) / float(self.conntrack_max))

    def reasons(self) -> list[str]:
        out: list[str] = []
        if not self.installed:
            return out
        if self.error:
            out.append("agent_error")
        if self.enabled and not self.table:
            out.append("table_missing")
        if len(self.syn_flood) >= SET_WARN:
            out.append("syn_flood")
        if len(self.conn_flood) >= SET_WARN:
            out.append("conn_flood")
        if len(self.udp_flood) >= SET_WARN:
            out.append("udp_flood")
        if len(self.scan) >= SET_WARN:
            out.append("port_scan")
        if self.pps >= PPS_WARN:
            out.append("pps")
        if self.pressure() >= CONNTRACK_WARN:
            out.append("conntrack")
        if self.flood_dropped() >= DROP_WARN:
            out.append("drops")
        return out

    def level(self) -> str:
        if not self.installed:
            return "ok"
        reasons = self.reasons()
        if self.error or not self.enabled:
            return "warn" if self.enabled and not self.table else "ok"
        if "table_missing" in reasons:
            return "bad"
        if any(item in reasons for item in ("syn_flood", "udp_flood")) and len(self.syn_flood) >= SET_BAD:
            return "bad"
        if self.pps >= PPS_BAD or self.pressure() >= CONNTRACK_BAD or self.flood_dropped() >= DROP_BAD:
            return "bad"
        if len(self.conn_flood) >= SET_BAD or len(self.scan) >= SET_BAD:
            return "bad"
        return "warn" if reasons else "ok"

    def under_attack(self) -> bool:
        return bool(self.installed) and self.level() == "bad"

    def event_kind(self) -> str:
        reasons = self.reasons()
        for name in ("syn_flood", "udp_flood", "conn_flood", "pps", "conntrack", "drops", "table_missing", "agent_error"):
            if name in reasons:
                return name
        return "load"

    def headline(self) -> str:
        pieces = ["%d pps" % self.pps]
        if self.conntrack_max:
            pieces.append("conntrack %d/%d" % (self.conntrack, self.conntrack_max))
        if self.syn_flood:
            pieces.append("syn %d" % len(self.syn_flood))
        return ", ".join(pieces)

    def to_dict(self) -> dict[str, Any]:
        return {
            "installed": self.installed,
            "enabled": self.enabled,
            "table": self.table,
            "policy": self.policy.to_dict(),
            "counters": dict(self.counters),
            "syn_flood": list(self.syn_flood),
            "conn_flood": list(self.conn_flood),
            "udp_flood": list(self.udp_flood),
            "icmp_flood": list(self.icmp_flood),
            "scan": list(self.scan),
            "pps": int(self.pps),
            "connections": int(self.connections),
            "conntrack": int(self.conntrack),
            "conntrack_max": int(self.conntrack_max),
            "kernel": self.kernel,
            "notice": self.notice,
            "error": self.error,
            "rkn_enabled": bool(self.rkn_enabled),
            "rkn_v4_count": int(self.rkn_v4_count),
            "rkn_v6_count": int(self.rkn_v6_count),
            "rkn_updated": self.rkn_updated,
        }


@dataclass
class Finding:
    code: str
    port: int = 0
    proto: str = "tcp"
    process: str = ""
    address: str = ""
    severity: str = "warn"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "port": int(self.port),
            "proto": self.proto,
            "process": self.process,
            "address": self.address,
            "severity": self.severity,
        }


def socket_rows(raw: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port", 0) or 0)
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        rows.append(
            {
                "port": port,
                "proto": str(item.get("proto", "tcp") or "tcp")[:4].lower(),
                "process": str(item.get("process", "") or "")[:40].lower(),
                "address": str(item.get("address", "") or "")[:45],
            }
        )
    return rows[:512]


def listening_from_proc(tcp_text: str, tcp6_text: str = "", owners: dict[int, str] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    known = owners or {}
    for body, family in ((tcp_text, 4), (tcp6_text, 6)):
        for line in str(body or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":
                continue
            local = parts[1].split(":")
            if len(local) != 2:
                continue
            try:
                port = int(local[1], 16)
                raw = bytes.fromhex(local[0])[::-1]
            except ValueError:
                continue
            if family == 4 and len(raw) == 4:
                address = ".".join(str(item) for item in raw)
            elif family == 6 and len(raw) == 16:
                address = ipaddress.IPv6Address(raw).compressed
            else:
                continue
            inode = parts[9]
            rows.append(
                {
                    "port": port,
                    "proto": "tcp",
                    "process": known.get(_inode_key(inode), ""),
                    "address": address,
                }
            )
    return rows


def _inode_key(inode: str) -> int:
    try:
        return int(inode)
    except (TypeError, ValueError):
        return 0


DECOYS = (21, 23, 2121, 2323, 2222, 3389)
API_PORTS = (10085, 10086, 10087)


def exposure(raw: Any, allow: list[int] | None = None) -> list[Finding]:
    permitted = set(allow or [])
    findings: list[Finding] = []
    for row in socket_rows(raw):
        port = int(row["port"])
        process = str(row["process"])
        address = str(row["address"])
        wildcard = address in {"0.0.0.0", "::", "*"}
        core_name = any(name in process for name in PANEL_NAMES)
        core_api = port in API_PORTS or ("xray" in process and port in API_PORTS)
        if core_name or port in PANEL_PORTS:
            findings.append(Finding("panel", port, row["proto"], process, address, "bad"))
            continue
        if core_api:
            findings.append(Finding("core_api", port, row["proto"], process, address, "bad"))
            continue
        if port in DATASTORE_PORTS:
            findings.append(Finding("datastore", port, row["proto"], process, address, "bad"))
            continue
        if port in permitted:
            continue
        if port in RISKY_PORTS:
            findings.append(Finding("risky", port, row["proto"], process, address, "info" if port in DECOYS else "bad"))
            continue
        if port in PROXY_PORTS:
            findings.append(Finding("proxy", port, row["proto"], process, address, "warn" if wildcard else "info"))
            continue
        if probe_worthy(port):
            findings.append(Finding("unexpected", port, row["proto"], process, address, "warn"))
    return findings[:64]


def probe_worthy(port: int) -> bool:
    if port in (80, 443, 22, 25, 53, 587, 993, 995, 2525):
        return False
    if port in RISKY_PORTS or port in PANEL_PORTS or port in DATASTORE_PORTS or port in PROXY_PORTS:
        return False
    return 1024 <= port <= 65535


def exposure_level(findings: list[Finding]) -> str:
    rank = max([PROBE_RANK.get(item.severity, 0) for item in findings] or [0])
    return "bad" if rank >= 3 else ("warn" if rank == 2 else "ok")


def exposure_rows(findings: list[Finding]) -> list[tuple[str, str, str]]:
    return [(item.severity, item.code, "%d/%s" % (item.port, item.proto)) for item in findings]


def exposure_hint(findings: list[Finding]) -> str:
    codes = {item.code for item in findings}
    for code in ("core_api", "datastore", "panel", "risky", "proxy", "unexpected"):
        if code in codes:
            return code
    return ""


def valid_address(value: object) -> str:
    text = str(value or "").strip()
    if not IPV4.match(text):
        return ""
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return ""
