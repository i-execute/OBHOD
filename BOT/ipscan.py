from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import re
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import i18n, inline, ui

IP_API_URL = "http://ip-api.com/json/{query}?fields=status,message,country,countryCode,regionName,city,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
IP_API_TIMEOUT = 3.5
PORT_PROBE_TIMEOUT = 1.1
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
COMMON_PORTS: tuple[tuple[int, str], ...] = (
    (22, "SSH"),
    (80, "HTTP"),
    (443, "TLS"),
    (8443, "ALT-TLS"),
    (2053, "CF-TLS"),
    (2083, "CF-TLS"),
)
SELF_ALIASES = frozenset({"", "ip", "myip", "self", "me", "scan", "check"})


def extract_candidate(raw_query: str) -> str:
    text = str(raw_query or "").strip()
    if not text:
        return "self"
    parts = text.split()
    first = parts[0]
    if first.lower() in SELF_ALIASES:
        return parts[1].strip() if len(parts) > 1 else "self"
    return first


def clean_target(raw: object) -> tuple[str, str]:
    value = str(raw or "").strip().lower()
    if not value or len(value) > 253 or any(char in value for char in "\r\n\x00"):
        raise ValueError("bad target")
    if "://" in value:
        try:
            parts = urllib.parse.urlsplit(value)
            if parts.scheme not in {"http", "https"} or parts.username or parts.password:
                raise ValueError("bad target")
            value = (parts.hostname or "").lower()
        except ValueError:
            raise ValueError("bad target") from None
    value = value.rstrip(".")
    try:
        address = ipaddress.ip_address(value)
        return address.compressed, "ip"
    except ValueError:
        pass
    try:
        domain = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("bad target") from None
    if not domain or len(domain) > 253:
        raise ValueError("bad target")
    labels = domain.split(".")
    if len(labels) < 2 or any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("bad target")
    if len(labels[-1]) < 2 or labels[-1].isdigit():
        raise ValueError("bad target")
    return domain, "domain"


def resolve_ip(target: str) -> str:
    try:
        address = ipaddress.ip_address(target)
        return address.compressed
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return ""
    for family, _socktype, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET and sockaddr:
            return str(sockaddr[0])
    for family, _socktype, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET6 and sockaddr:
            return str(sockaddr[0])
    return ""


def fetch_ip_api(ip_or_host: str = "") -> dict[str, Any]:
    encoded = urllib.parse.quote(str(ip_or_host or "").strip(), safe=":")
    url = IP_API_URL.format(query=encoded)
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "obhod-ipscan/2.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=IP_API_TIMEOUT) as resp:
            raw = resp.read(32768)
    except (urllib.error.URLError, TimeoutError, OSError):
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        return {}
    if not isinstance(parsed, dict) or parsed.get("status") != "success":
        return {}
    return parsed


def _probe_single_port(ip_addr: str, port: int) -> tuple[int, bool, int]:
    started = time.monotonic()
    try:
        family = socket.AF_INET6 if ":" in ip_addr else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError:
        return port, False, 0
    sock.settimeout(PORT_PROBE_TIMEOUT)
    try:
        sock.connect((ip_addr, port))
        elapsed_ms = max(1, int(round((time.monotonic() - started) * 1000.0)))
        return port, True, elapsed_ms
    except OSError:
        return port, False, 0
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_ports(ip_addr: str) -> dict[str, Any]:
    if not ip_addr:
        return {"open": [], "best_ms": 0}
    label_map = dict(COMMON_PORTS)
    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as pool:
        results = [future.result() for future in (pool.submit(_probe_single_port, ip_addr, port) for port, _ in COMMON_PORTS)]
    opened = [(port, label_map[port], elapsed) for port, is_open, elapsed in results if is_open]
    opened.sort(key=lambda item: item[0])
    best_ms = min((elapsed for _port, _label, elapsed in opened if elapsed > 0), default=0)
    return {"open": opened, "best_ms": best_ms}


def resolve_self_ip(default_target: str = "") -> tuple[str, str, dict[str, Any]]:
    metadata = fetch_ip_api("")
    discovered = str(metadata.get("query") or "").strip()
    if discovered:
        try:
            host, kind = clean_target(discovered)
            return host, kind, metadata
        except ValueError:
            pass
    candidate = str(default_target or "").strip()
    if candidate and candidate not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
        try:
            host, kind = clean_target(candidate)
            return host, kind, {}
        except ValueError:
            pass
    return "", "", {}


def scan_sync(host: str, kind: str, deep: bool = True) -> dict[str, Any]:
    address = resolve_ip(host) if kind == "domain" else host
    metadata = fetch_ip_api(address) if address else {}
    ports = probe_ports(address) if deep and address else {"open": [], "best_ms": 0}
    return {
        "target": host,
        "kind": kind,
        "ip": str(metadata.get("query") or address or ""),
        "meta": metadata,
        "ports": ports,
    }


def full_scan_sync(raw_target: str, default_target: str = "", force: bool = True) -> dict[str, Any]:
    candidate = extract_candidate(raw_target)
    if candidate == "self":
        host, kind, seed_metadata = resolve_self_ip(default_target)
        if not host:
            return {"target": "self", "kind": "ip", "ip": "", "meta": {}, "ports": {"open": [], "best_ms": 0}, "error": "network"}
        data = scan_sync(host, kind)
        if seed_metadata and not data.get("meta"):
            data["meta"] = seed_metadata
            data["ip"] = str(seed_metadata.get("query") or data.get("ip") or "")
        return data
    try:
        host, kind = clean_target(candidate)
    except ValueError:
        return {"target": candidate[:64], "kind": "bad", "ip": "", "meta": {}, "ports": {"open": [], "best_ms": 0}, "error": "bad_target"}
    return scan_sync(host, kind)


async def full_scan_async(raw_target: str, default_target: str = "", force: bool = True) -> dict[str, Any]:
    return await asyncio.to_thread(full_scan_sync, raw_target, default_target, force)


def safe_cb_target(target: str) -> str:
    clean = str(target or "").strip()
    if not clean or clean.lower() in SELF_ALIASES:
        return "self"
    if len(clean.encode("utf-8")) > 44:
        return clean[:44]
    return clean


def _display_target_subtitle(raw_target: str, t: Any) -> str:
    clean = str(raw_target or "").strip()
    if not clean or clean.lower() in SELF_ALIASES:
        return t("IPSCAN_NODE_SELF")
    try:
        host, _kind = clean_target(clean)
        return host
    except ValueError:
        return clean[:64]


def start_keyboard_rows(cb_target: str, lang: str = i18n.DEFAULT_LANGUAGE) -> list[list[dict[str, Any]]]:
    t = i18n.translator(lang)
    callback_target = safe_cb_target(cb_target)
    return [[{"text": t("IPSCAN_BTN_START"), "callback_data": f"ipscan:run:{callback_target}"}]]


def after_scan_keyboard_rows(lang: str = i18n.DEFAULT_LANGUAGE) -> list[list[dict[str, Any]]]:
    t = i18n.translator(lang)
    return [[{"text": t("IPSCAN_BTN_OTHER"), "switch_inline_query_current_chat": ""}]]


def ready_screen(raw_target: str, lang: str = i18n.DEFAULT_LANGUAGE) -> ui.Rich:
    t = i18n.translator(lang)
    subtitle = _display_target_subtitle(raw_target, t)
    return ui.screen(t("IPSCAN_LAUNCH_TITLE"), ui.muted(subtitle), [ui.quote(ui.muted(t("IPSCAN_LAUNCH_PROMPT")))], [], icon="radar")


def scanning_screen(raw_target: str, lang: str = i18n.DEFAULT_LANGUAGE) -> ui.Rich:
    t = i18n.translator(lang)
    subtitle = _display_target_subtitle(raw_target, t)
    return ui.screen(t("IPSCAN_SCANNING_TITLE"), ui.muted(subtitle), [ui.quote(ui.muted(t("IPSCAN_SCANNING_BODY")))], [], icon="loading")


def rich_report(data: dict[str, Any], lang: str = i18n.DEFAULT_LANGUAGE) -> tuple[ui.Rich, list[list[dict[str, Any]]]]:
    t = i18n.translator(lang)
    target = str(data.get("target") or "")
    kind = str(data.get("kind") or "")
    shown_ip = str(data.get("ip") or "")
    metadata = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    ports = data.get("ports") if isinstance(data.get("ports"), dict) else {}
    keyboard = after_scan_keyboard_rows(lang)
    if kind == "bad" or data.get("error") == "bad_target":
        card = ui.screen(t("IPSCAN_REPORT_TITLE"), ui.muted(target), [ui.quote(ui.bold(t("IPSCAN_ERR_BAD")))], [], icon="warn")
        return card, keyboard
    if data.get("error") or (not shown_ip and not metadata):
        card = ui.screen(t("IPSCAN_REPORT_TITLE"), ui.muted(target), [ui.quote(ui.muted(t("IPSCAN_ERR_NET")))], [], icon="warn")
        return card, keyboard
    rows: list[tuple[str, str, str]] = [("target", t("IPSCAN_TARGET"), ui.code(target or "-"))]
    if shown_ip:
        rows.append(("globe", t("IPSCAN_RESOLVED_IP"), ui.code(shown_ip)))
    country = str(metadata.get("country") or "").strip()
    region = str(metadata.get("regionName") or "").strip()
    city = str(metadata.get("city") or "").strip()
    location = ", ".join(value for value in (city, region, country) if value)
    if location:
        rows.append(("globe", t("IPSCAN_COUNTRY"), ui.code(location)))
    for field, label_key, icon in (
        ("timezone", "IPSCAN_TIMEZONE", "clock"),
        ("isp", "IPSCAN_ISP", "server"),
        ("org", "IPSCAN_ORG", "server"),
        ("as", "IPSCAN_ASN", "tag"),
        ("reverse", "IPSCAN_PTR", "link"),
    ):
        value = str(metadata.get(field) or "").strip()
        if value:
            rows.append((icon, t(label_key), ui.code(value)))
    yes = t("IPSCAN_YES")
    no = t("IPSCAN_NO")
    flags = [
        f"{t('IPSCAN_HOSTING')}: {yes if metadata.get('hosting') else no}",
        f"{t('IPSCAN_PROXY')}: {yes if metadata.get('proxy') else no}",
        f"{t('IPSCAN_MOBILE')}: {yes if metadata.get('mobile') else no}",
    ]
    if metadata:
        rows.append(("shield", t("IPSCAN_FLAGS"), ui.code(" | ".join(flags))))
    raw_open = list(ports.get("open") or [])
    if raw_open:
        port_text = ", ".join(f"{int(item[0])}/{str(item[1])}" for item in raw_open if isinstance(item, (tuple, list)) and len(item) >= 2)
    else:
        port_text = t("IPSCAN_PORTS_NONE")
    rows.append(("bolt", t("IPSCAN_OPEN_PORTS"), ui.code(port_text)))
    best_ms = int(ports.get("best_ms") or 0)
    if best_ms > 0:
        rows.append(("gauge", t("IPSCAN_PING"), ui.code(t("IPSCAN_LATENCY_MS", ms=best_ms))))
    summary = t("IPSCAN_SUMMARY")
    subtitle = f"{target} ({shown_ip})" if shown_ip and shown_ip != target else (shown_ip or target)
    card = ui.screen(
        t("IPSCAN_REPORT_TITLE"),
        ui.muted(subtitle),
        [ui.quote(ui.bold(summary)), ui.table(rows)],
        [],
        icon="radar",
    )
    return card, keyboard


async def inline_results(query: str, src: str = "mt", lang: str = i18n.DEFAULT_LANGUAGE, default_target: str = "") -> list[dict]:
    _ = default_target
    t = i18n.translator(lang)
    candidate = extract_candidate(query)
    nonce = secrets.token_hex(4)
    if candidate != "self":
        try:
            host, _kind = clean_target(candidate)
        except ValueError:
            card = ui.screen(t("IPSCAN_TITLE"), "", [ui.quote(ui.bold(t("IPSCAN_ERR_BAD")))], [], icon="warn")
            return [inline.rich_article(f"ipscan:{nonce}:bad", t("IPSCAN_TITLE"), t("IPSCAN_ERR_BAD"), card, src)]
    else:
        host = "self"
    card = ready_screen(host, lang)
    keyboard = start_keyboard_rows(host, lang)
    title = t("IPSCAN_LAUNCH_TARGET_TITLE", target=host) if host != "self" else t("IPSCAN_LAUNCH_TITLE")
    return [inline.rich_article(f"ipscan:{nonce}:{safe_cb_target(host)}", title, t("IPSCAN_LAUNCH_DESC"), card, src, reply_markup=keyboard)]
