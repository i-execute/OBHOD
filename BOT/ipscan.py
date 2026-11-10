from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import html
import ipaddress
import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any

from . import chebur, i18n, inline, ui

CACHE_TTL = 120.0
ERR_CACHE_TTL = 5.0
IP_API_FIELDS = (
    "status,message,continent,country,countryCode,regionName,city,"
    "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)
IP_API_URL = "http://ip-api.com/json/%s?fields=" + IP_API_FIELDS
IP_API_SELF_URL = "http://ip-api.com/json/?fields=" + IP_API_FIELDS
IP_API_TIMEOUT = 2.8
CHEBUR_SCAN_TIMEOUT = 3.5
PORT_PROBE_TIMEOUT = 1.0
PROBE_PORTS = (22, 80, 443, 8080, 8443)
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def esc(value: Any) -> str:
    return html.escape(str(value or ""))


def clear_cache() -> None:
    _CACHE.clear()


def safe_cb_target(raw: str) -> str:
    token = "".join(ch for ch in str(raw or "").strip() if ord(ch) > 31 and ch not in "\r\n\t")
    if not token:
        return "self"
    encoded = token.encode("utf-8")[:48]
    return encoded.decode("utf-8", "ignore") or "self"


def inline_keyboard_rows(cb_target: str, lang: str, rescan: bool = False) -> list[list[dict[str, Any]]]:
    t = i18n.translator(lang)
    btn_key = "IPSCAN_BTN_RESCAN" if rescan else "IPSCAN_BTN_START"
    return [
        [
            {
                "text": t(btn_key),
                "callback_data": "ipscan:run:%s" % safe_cb_target(cb_target),
            },
            {
                "text": t("IPSCAN_BTN_OTHER"),
                "switch_inline_query_current_chat": "",
            },
        ]
    ]


def extract_target(raw: str) -> tuple[str, bool]:
    text = str(raw or "").strip()
    if not text:
        return "self", True
    lowered = text.lower()
    if lowered in {"ip", "self"}:
        return "self", True
    if lowered.startswith("ip "):
        rest = text[3:].strip()
        return (rest or "self"), True
    return text, True


def resolve_ip(target: str) -> str:
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            sample = net.network_address + (1 if net.num_addresses > 1 else 0)
            return str(sample)
        except ValueError:
            return ""
    if target.upper().startswith("AS"):
        return ""
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return str(infos[0][4][0])
    except OSError:
        return ""
    return ""


def fetch_ip_api(ip_addr: str, timeout: float = IP_API_TIMEOUT) -> dict[str, Any]:
    url = (IP_API_URL % ip_addr) if ip_addr else IP_API_SELF_URL
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "obhod-ipscan/2", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(65536)
    except (urllib.error.URLError, OSError, ValueError):
        return {}
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return {}
    if not isinstance(data, dict) or data.get("status") != "success":
        return {}
    return data


def _probe_one_port(ip_addr: str, port: int, timeout: float) -> tuple[int, int] | None:
    started = time.monotonic()
    try:
        with socket.create_connection((ip_addr, int(port)), timeout=timeout):
            elapsed = max(1, int(round((time.monotonic() - started) * 1000.0)))
            return int(port), elapsed
    except OSError:
        return None


def probe_ports(ip_addr: str, ports: tuple[int, ...] = PROBE_PORTS, timeout: float = PORT_PROBE_TIMEOUT) -> list[tuple[int, int]]:
    if not ip_addr:
        return []
    try:
        parsed = ipaddress.ip_address(ip_addr)
    except ValueError:
        return []
    if not parsed.is_global:
        return []
    found: list[tuple[int, int]] = []
    with ThreadPoolExecutor(max_workers=max(1, len(ports))) as pool:
        futs = [pool.submit(_probe_one_port, ip_addr, port, timeout) for port in ports]
        for fut in futs:
            res = fut.result()
            if res is not None:
                found.append(res)
    found.sort(key=lambda item: item[0])
    return found


def _safe_chebur(host: str) -> tuple[chebur.Registry | None, str]:
    try:
        return chebur.check(host, timeout=CHEBUR_SCAN_TIMEOUT), ""
    except chebur.CheburError as exc:
        if "429" in str(exc.message) or exc.code == "rate":
            return None, "rate"
        return None, "net"
    except Exception:
        return None, "net"


def resolve_self_ip(default_target: str = "") -> tuple[str, str, dict[str, Any]]:
    candidate = str(default_target or "").strip()
    if candidate and candidate not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
        try:
            host, kind = chebur.clean_target(candidate)
            return host, kind, {}
        except chebur.CheburError:
            pass
    self_meta = fetch_ip_api("")
    discovered = str(self_meta.get("query") or "").strip()
    if discovered:
        try:
            host, kind = chebur.clean_target(discovered)
            return host, kind, self_meta
        except chebur.CheburError:
            pass
    return "", "", {}


def scan_sync(host: str, kind: str, force: bool = False, deep: bool = False) -> dict[str, Any]:
    now = time.monotonic()
    cached = None if force else _CACHE.get(host)
    if cached and cached[0] > now:
        entry = dict(cached[1])
        if not deep or "ports" in entry:
            return entry
        ip_for_ports = str(entry.get("ip") or "")
        entry["ports"] = probe_ports(ip_for_ports) if kind in ("ip", "domain") else []
        _CACHE[host] = (cached[0], entry)
        return entry

    ip_addr = host if kind == "ip" else resolve_ip(host)
    with ThreadPoolExecutor(max_workers=3) as pool:
        fut_reg = pool.submit(_safe_chebur, host)
        fut_meta = pool.submit(fetch_ip_api, ip_addr) if ip_addr else None
        fut_ports = pool.submit(probe_ports, ip_addr) if (deep and ip_addr and kind in ("ip", "domain")) else None
        reg, reg_code = fut_reg.result()
        meta = fut_meta.result() if fut_meta is not None else {}
        ports = fut_ports.result() if fut_ports is not None else None

    if not meta and reg is not None and reg.ips:
        meta = fetch_ip_api(reg.ips[0])
    shown_ip = host if kind in ("subnet", "asn") else str(meta.get("query") or ip_addr or (reg.ips[0] if reg and reg.ips else host))
    if deep and ports is None:
        ports = probe_ports(shown_ip) if kind in ("ip", "domain") else []

    data: dict[str, Any] = {
        "target": host,
        "kind": kind,
        "ip": shown_ip,
        "registry": reg,
        "reg_code": reg_code,
        "meta": meta,
    }
    if ports is not None:
        data["ports"] = ports

    ttl = CACHE_TTL if (reg is not None or meta) else ERR_CACHE_TTL
    _CACHE[host] = (now + ttl, data)
    if len(_CACHE) > 256:
        oldest = min(_CACHE, key=lambda key: _CACHE[key][0])
        _CACHE.pop(oldest, None)
    return data


def full_scan_sync(raw_target: str, default_target: str = "", force: bool = False) -> dict[str, Any]:
    candidate, _ = extract_target(raw_target)
    if candidate == "self":
        host, kind, pre_meta = resolve_self_ip(default_target)
        if not host:
            return {"target": default_target or "self", "kind": "unknown", "ip": "", "registry": None, "reg_code": "net", "meta": pre_meta, "ports": []}
        return scan_sync(host, kind, force=force, deep=True)
    try:
        host, kind = chebur.clean_target(candidate)
    except chebur.CheburError:
        if default_target:
            host2, kind2, _ = resolve_self_ip(default_target)
            if host2:
                return scan_sync(host2, kind2, force=force, deep=True)
        return {"target": candidate[:64], "kind": "bad", "ip": "", "registry": None, "reg_code": "bad", "meta": {}, "ports": []}
    return scan_sync(host, kind, force=force, deep=True)


async def full_scan_async(raw_target: str, default_target: str = "", force: bool = False) -> dict[str, Any]:
    return await asyncio.to_thread(full_scan_sync, raw_target, default_target, force)


def _cdn_list(reg: chebur.Registry | None) -> list[str]:
    if reg is None or not reg.cdn:
        return []
    if isinstance(reg.cdn, dict):
        return sorted(str(k) for k in reg.cdn.keys() if k)[:4]
    return sorted(str(k) for k in reg.cdn if k)[:4]


def format_card(data: dict[str, Any], lang: str) -> tuple[str, str, str]:
    t = i18n.translator(lang)
    target = str(data.get("target") or "")
    shown_ip = str(data.get("ip") or target)
    reg: chebur.Registry | None = data.get("registry")
    meta: dict[str, Any] = dict(data.get("meta") or {})

    if reg is not None:
        rkn_state = t("IPSCAN_BLOCKED") if reg.blocked else t("IPSCAN_CLEAN")
        complaints = reg.complaint_total()
        rkn_line = "%s (%s)" % (rkn_state, t("IPSCAN_COMPLAINTS", count=complaints))
    else:
        rkn_state = ""
        rkn_line = t("IPSCAN_ERR_RATE") if data.get("reg_code") == "rate" else t("IPSCAN_ERR_NET")

    country = str(meta.get("country") or (reg.geo.country if reg else "") or "")
    cc = str(meta.get("countryCode") or "")
    city = str(meta.get("city") or meta.get("regionName") or "")
    loc_parts = []
    if country:
        loc_parts.append("%s (%s)" % (country, cc) if cc else country)
    if city and city != country:
        loc_parts.append(city)
    location = ", ".join(loc_parts) or "-"

    isp = str(meta.get("isp") or meta.get("org") or (reg.geo.organisation if reg else "") or "-")
    asn_raw = str(meta.get("as") or (reg.geo.asn if reg else "") or "")
    asn_code = asn_raw.split()[0] if asn_raw else ""

    reverse_val = str(meta.get("reverse") or (reg.reverse[0] if reg and reg.reverse else "") or "")
    cdn_val = ", ".join(_cdn_list(reg))
    ptr_parts = [item for item in (reverse_val, cdn_val) if item]
    ptr_line = " / ".join(ptr_parts)

    yes = t("UI_YES")
    no = t("UI_NO")
    flags_line = ""
    if meta:
        flags_line = "%s: %s | %s: %s | %s: %s" % (
            t("IPSCAN_HOSTING"),
            yes if meta.get("hosting") else no,
            t("IPSCAN_PROXY"),
            yes if meta.get("proxy") else no,
            t("IPSCAN_MOBILE"),
            yes if meta.get("mobile") else no,
        )

    header_ip = "%s (%s)" % (esc(target), esc(shown_ip)) if shown_ip and shown_ip != target else esc(target)
    isp_line = "%s (<code>%s</code>)" % (esc(isp), esc(asn_code)) if asn_code else esc(isp)
    info_rows = [
        "<b>%s:</b> %s" % (esc(t("IPSCAN_RKN")), esc(rkn_line)),
        "<b>%s:</b> %s" % (esc(t("IPSCAN_COUNTRY")), esc(location)),
        "<b>%s:</b> %s" % (esc(t("IPSCAN_ISP")), isp_line),
    ]
    if ptr_line:
        info_rows.append("<b>%s:</b> <code>%s</code>" % (esc(t("IPSCAN_PTR")), esc(ptr_line)))
    if reg is not None and reg.subnets:
        info_rows.append("<b>%s:</b> <code>%s</code>" % (esc(t("IPSCAN_SUBNETS")), esc(", ".join(reg.subnets[:3]))))
    if flags_line:
        info_rows.append("<b>%s:</b> %s" % (esc(t("IPSCAN_FLAGS")), esc(flags_line)))

    html_body = "<b>%s:</b> <code>%s</code>\n<blockquote>%s</blockquote>" % (
        esc(t("IPSCAN_TITLE")),
        header_ip,
        "\n".join(info_rows),
    )
    title = ("%s - %s" % (target, rkn_state)) if rkn_state else target
    desc_parts = [part for part in (cc or country, isp if isp != "-" else "", asn_code) if part]
    desc = " | ".join(desc_parts) or t("IPSCAN_TITLE")
    return title[:120], desc[:240], html_body


def scanning_screen(target: str, lang: str = i18n.DEFAULT_LANGUAGE) -> ui.ScreenRich:
    t = i18n.translator(lang)
    shown = target if target and target != "self" else t("IPSCAN_SELF_TITLE")
    blocks = [ui.quote(ui.muted(t("IPSCAN_SCANNING_BODY", target=shown)))]
    return ui.screen(t("IPSCAN_SCANNING_TITLE"), shown, blocks, [], icon="loading")


def rich_report(data: dict[str, Any], lang: str = i18n.DEFAULT_LANGUAGE) -> tuple[ui.ScreenRich, list[list[dict[str, Any]]]]:
    t = i18n.translator(lang)
    target = str(data.get("target") or "self")
    if data.get("reg_code") == "bad":
        kbd = inline_keyboard_rows("self", lang, rescan=False)
        blocks = [ui.quote(ui.bold(t("IPSCAN_ERR_BAD")))]
        buttons = [
            ui.row(
                ui.button(t("IPSCAN_BTN_START"), "ipscan:run:self", icon="scan"),
                ui.inline_button(t("IPSCAN_BTN_OTHER"), "", icon="radar"),
            )
        ]
        return ui.screen(t("IPSCAN_REPORT_TITLE"), target, blocks, buttons, icon="warn"), kbd

    shown_ip = str(data.get("ip") or "")
    reg: chebur.Registry | None = data.get("registry")
    meta: dict[str, Any] = dict(data.get("meta") or {})
    ports: list[tuple[int, int]] = list(data.get("ports") or [])

    if reg is not None:
        rkn_state = t("IPSCAN_BLOCKED") if reg.blocked else t("IPSCAN_CLEAN")
        complaints = reg.complaint_total()
        peak = reg.complaint_peak()
        extra_parts = [t("IPSCAN_COMPLAINTS", count=complaints)]
        if peak > 0:
            extra_parts.append(t("IPSCAN_PEAK", peak=peak))
        rkn_line = "%s (%s)" % (rkn_state, ", ".join(extra_parts))
        top_icon = "warn" if reg.blocked else "ok"
    else:
        rkn_line = t("IPSCAN_ERR_RATE") if data.get("reg_code") == "rate" else t("IPSCAN_ERR_NET")
        top_icon = "radar"

    country = str(meta.get("country") or (reg.geo.country if reg else "") or "")
    cc = str(meta.get("countryCode") or "")
    region = str(meta.get("regionName") or "")
    city = str(meta.get("city") or "")
    loc_parts = []
    if country:
        loc_parts.append("%s (%s)" % (country, cc) if cc else country)
    if region and region not in {country, city}:
        loc_parts.append(region)
    if city and city != country:
        loc_parts.append(city)
    location = ", ".join(loc_parts) or (reg.geo.location if reg and reg.geo.location else "-")

    tz_val = str(meta.get("timezone") or "").strip()
    isp = str(meta.get("isp") or (reg.geo.organisation if reg else "") or "-")
    org = str(meta.get("org") or "").strip()
    asn_raw = str(meta.get("as") or (reg.geo.asn if reg else "") or "").strip()
    as_name = str(meta.get("asname") or "").strip()
    asn_display = asn_raw or "-"
    if as_name and as_name.lower() not in asn_display.lower():
        asn_display = "%s (%s)" % (asn_display, as_name)

    reverse_val = str(meta.get("reverse") or (reg.reverse[0] if reg and reg.reverse else "") or "")
    cdn_val = ", ".join(_cdn_list(reg))
    ptr_parts = [item for item in (reverse_val, cdn_val) if item]
    ptr_line = " / ".join(ptr_parts)

    yes = t("UI_YES")
    no = t("UI_NO")
    flags_line = ""
    if meta:
        flags_line = "%s: %s | %s: %s | %s: %s" % (
            t("IPSCAN_HOSTING"),
            yes if meta.get("hosting") else no,
            t("IPSCAN_PROXY"),
            yes if meta.get("proxy") else no,
            t("IPSCAN_MOBILE"),
            yes if meta.get("mobile") else no,
        )

    rows_data: list[tuple[str, str, str]] = [
        ("target", t("IPSCAN_TARGET"), ui.code(target)),
    ]
    if shown_ip and shown_ip != target:
        rows_data.append(("world", t("IPSCAN_RESOLVED_IP"), ui.code(shown_ip)))
    elif shown_ip:
        rows_data.append(("world", t("IPSCAN_RESOLVED_IP"), ui.code(shown_ip)))
    rows_data.append(("warn" if (reg and reg.blocked) else "shield", t("IPSCAN_RKN"), ui.code(rkn_line)))
    rows_data.append(("world", t("IPSCAN_COUNTRY"), ui.code(location)))
    if tz_val:
        rows_data.append(("clock", t("IPSCAN_TIMEZONE"), ui.code(tz_val)))
    rows_data.append(("server", t("IPSCAN_ISP"), ui.code(isp)))
    if org and org != isp:
        rows_data.append(("server", t("IPSCAN_ORG"), ui.code(org)))
    rows_data.append(("tag", t("IPSCAN_ASN"), ui.code(asn_display)))
    if ptr_line:
        rows_data.append(("link", t("IPSCAN_PTR"), ui.code(ptr_line)))
    if flags_line:
        rows_data.append(("info", t("IPSCAN_FLAGS"), ui.code(flags_line)))
    if "ports" in data and data.get("kind") in ("ip", "domain"):
        if ports:
            ports_str = ", ".join("%d (%s)" % (p, t("IPSCAN_LATENCY_MS", ms=ms)) for p, ms in ports)
            best_ms = min(ms for _, ms in ports)
            rows_data.append(("plug", t("IPSCAN_OPEN_PORTS"), ui.code(ports_str)))
            rows_data.append(("speed", t("IPSCAN_PING"), ui.code(t("IPSCAN_LATENCY_MS", ms=best_ms))))
        else:
            rows_data.append(("plug", t("IPSCAN_OPEN_PORTS"), ui.code(t("IPSCAN_PORTS_NONE"))))

    blocks = [
        ui.quote(ui.bold("%s: %s" % (t("IPSCAN_RKN"), rkn_line))),
        ui.table(rows_data, (t("UI_PARAM"), t("UI_VALUE"))),
    ]
    if reg is not None and reg.subnets:
        blocks.append(ui.long_block(t("IPSCAN_SUBNETS"), "\n".join(reg.subnets[:16])))
    if reg is not None and len(reg.ips) > 1:
        blocks.append(ui.long_block(t("IPSCAN_IPS_LIST", count=len(reg.ips)), "\n".join(reg.ips[:24])))

    cb_target = safe_cb_target(target if target else shown_ip)
    kbd = inline_keyboard_rows(cb_target, lang, rescan=True)
    buttons = [
        ui.row(
            ui.button(t("IPSCAN_BTN_RESCAN"), "ipscan:run:%s" % cb_target, icon="refresh"),
            ui.inline_button(t("IPSCAN_BTN_OTHER"), "", icon="scan"),
        )
    ]
    if shown_ip:
        copy_btn = ui.copy_row(t("IPSCAN_BTN_COPY_IP"), shown_ip, icon="copy")
        if copy_btn:
            buttons.append(copy_btn)
    subtitle = ("%s (%s)" % (target, shown_ip)) if shown_ip and shown_ip != target else (shown_ip or t("IPSCAN_SUBTITLE"))
    return ui.screen(t("IPSCAN_REPORT_TITLE"), subtitle, blocks, buttons, icon=top_icon), kbd


async def inline_results(
    query: str,
    src: str = "mt",
    lang: str = i18n.DEFAULT_LANGUAGE,
    default_target: str = "",
) -> list[dict]:
    t = i18n.translator(lang)
    candidate, _matched = extract_target(query)
    if candidate == "self":
        preset = str(default_target or "").strip()
        if preset and preset not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
            try:
                host, kind = chebur.clean_target(preset)
                data = await asyncio.to_thread(scan_sync, host, kind)
                title, desc, html_body = format_card(data, lang)
                kbd = inline_keyboard_rows(host, lang, rescan=False)
                return [inline.html_article("ipscan:%s" % safe_cb_target(host), title, desc, html_body, src, reply_markup=kbd)]
            except chebur.CheburError:
                pass
        body = "<b>%s</b>\n<blockquote>%s\n%s</blockquote>" % (
            esc(t("IPSCAN_SELF_TITLE")),
            esc(t("IPSCAN_HINT_BODY")),
            esc(t("IPSCAN_READY_NOTE")),
        )
        kbd = inline_keyboard_rows("self", lang, rescan=False)
        return [inline.html_article("ipscan:self", t("IPSCAN_SELF_TITLE"), t("IPSCAN_SELF_DESC"), body, src, reply_markup=kbd)]

    try:
        host, kind = chebur.clean_target(candidate)
    except chebur.CheburError:
        body = "<b>%s</b>\n<blockquote>%s</blockquote>" % (esc(t("IPSCAN_TITLE")), esc(t("IPSCAN_ERR_BAD")))
        kbd = inline_keyboard_rows("self", lang, rescan=False)
        return [inline.html_article("ipscan:self", t("IPSCAN_TITLE"), t("IPSCAN_ERR_BAD"), body, src, reply_markup=kbd)]

    data = await asyncio.to_thread(scan_sync, host, kind)
    title, desc, html_body = format_card(data, lang)
    kbd = inline_keyboard_rows(host, lang, rescan=False)
    rid = "ipscan:%s" % safe_cb_target(host)
    return [inline.html_article(rid, title, desc, html_body, src, reply_markup=kbd)]
