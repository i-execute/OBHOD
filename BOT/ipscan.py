from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import chebur, i18n, inline, ui

IP_API_URL = "http://ip-api.com/json/{query}?fields=status,message,country,countryCode,regionName,city,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
IP_API_TIMEOUT = 3.5
CHEBUR_SCAN_TIMEOUT = 8.0
CHEBUR_PROBE_DEADLINE = 18.0
PORT_PROBE_TIMEOUT = 1.1
COMMON_PORTS: tuple[tuple[int, str], ...] = (
    (22, "SSH"),
    (80, "HTTP"),
    (443, "TLS"),
    (8443, "ALT-TLS"),
    (2053, "CF-TLS"),
    (2083, "CF-TLS"),
)

SELF_ALIASES = frozenset({"", "ip", "myip", "self", "me", "scan", "check"})


def clear_cache() -> None:
    return


def extract_candidate(raw_query: str) -> str:
    text = str(raw_query or "").strip()
    if not text:
        return "self"
    parts = text.split()
    first = parts[0]
    low = first.lower()
    if low in SELF_ALIASES:
        if len(parts) >= 2:
            return parts[1].strip()
        return "self"
    return first


def resolve_ip(target: str) -> str:
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


def fetch_ip_api(ip_or_host: str) -> dict[str, Any]:
    encoded = urllib.parse.quote(str(ip_or_host or "").strip(), safe=":")
    url = IP_API_URL.format(query=encoded)
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "obhod-ipscan/2.0",
        },
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
    family = socket.AF_INET6 if ":" in ip_addr else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
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
    open_list: list[tuple[int, str, int]] = []
    best_ms = 0
    label_map = dict(COMMON_PORTS)
    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as pool:
        futs = [pool.submit(_probe_single_port, ip_addr, port) for port, _ in COMMON_PORTS]
        for fut in futs:
            port, is_open, ms = fut.result()
            if is_open:
                open_list.append((port, label_map.get(port, ""), ms))
                if best_ms == 0 or (ms > 0 and ms < best_ms):
                    best_ms = ms
    open_list.sort(key=lambda item: item[0])
    return {"open": open_list, "best_ms": best_ms}


def _safe_chebur(target: str) -> tuple[chebur.Registry | None, str]:
    try:
        return chebur.check(target, timeout=CHEBUR_SCAN_TIMEOUT), ""
    except chebur.CheburError as exc:
        return None, exc.code


def _safe_chebur_live(reg: chebur.Registry | None, kind: str) -> chebur.Live | None:
    ctx = getattr(reg, "context", "") if reg is not None else ""
    if not ctx or not chebur.probe_supported(kind):
        return None
    try:
        return chebur.probe(ctx, deadline=CHEBUR_PROBE_DEADLINE)
    except Exception:
        return None


def resolve_self_ip(default_target: str = "") -> tuple[str, str, dict[str, Any]]:
    self_meta = fetch_ip_api("")
    discovered = str(self_meta.get("query") or "").strip()
    if discovered:
        try:
            host, kind = chebur.clean_target(discovered)
            return host, kind, self_meta
        except chebur.CheburError:
            pass
    candidate = str(default_target or "").strip()
    if candidate and candidate not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
        try:
            host, kind = chebur.clean_target(candidate)
            return host, kind, {}
        except chebur.CheburError:
            pass
    return "", "", {}


def scan_sync(host: str, kind: str, force: bool = True, deep: bool = True) -> dict[str, Any]:
    _ = force
    ip_addr = host if kind == "ip" else (resolve_ip(host) if kind == "domain" else "")
    with ThreadPoolExecutor(max_workers=3) as pool:
        fut_reg = pool.submit(_safe_chebur, host)
        fut_meta = pool.submit(fetch_ip_api, ip_addr) if ip_addr else None
        fut_ports = pool.submit(probe_ports, ip_addr) if (deep and ip_addr and kind in ("ip", "domain")) else None
        reg, reg_code = fut_reg.result()
        meta = fut_meta.result() if fut_meta is not None else {}
        ports = fut_ports.result() if fut_ports is not None else None
    reg_ips = list(getattr(reg, "ips", None) or []) if reg is not None else []
    if not meta and reg_ips:
        meta = fetch_ip_api(reg_ips[0])
    shown_ip = str(meta.get("query") or ip_addr or (reg_ips[0] if reg_ips else "")).strip()
    if deep and ports is None:
        if shown_ip and kind in ("ip", "domain"):
            ports = probe_ports(shown_ip)
        else:
            ports = {"open": [], "best_ms": 0}
    live = _safe_chebur_live(reg, kind) if deep else None
    answer = chebur.Answer(target=host, registry=reg, live=live, at=time.time())
    return {
        "target": host,
        "kind": kind,
        "ip": shown_ip,
        "registry": reg,
        "live": live,
        "answer": answer,
        "reg_code": reg_code,
        "meta": meta,
        "ports": ports or {"open": [], "best_ms": 0},
    }


def full_scan_sync(raw_target: str, default_target: str = "", force: bool = True) -> dict[str, Any]:
    _ = force
    candidate = extract_candidate(raw_target)
    seed_meta: dict[str, Any] = {}
    if candidate == "self":
        host, kind, seed_meta = resolve_self_ip(default_target)
        if not host:
            return {
                "target": "self",
                "kind": "ip",
                "ip": "",
                "registry": None,
                "live": None,
                "answer": None,
                "reg_code": "network",
                "meta": {},
                "ports": {"open": [], "best_ms": 0},
            }
    else:
        try:
            host, kind = chebur.clean_target(candidate)
        except chebur.CheburError:
            return {
                "target": candidate[:64],
                "kind": "bad",
                "ip": "",
                "registry": None,
                "live": None,
                "answer": None,
                "reg_code": "bad",
                "meta": {},
                "ports": {"open": [], "best_ms": 0},
            }
    data = scan_sync(host, kind, force=True, deep=True)
    if seed_meta and not data.get("meta"):
        data["meta"] = seed_meta
        if not data.get("ip"):
            data["ip"] = str(seed_meta.get("query") or "")
    return data


async def full_scan_async(raw_target: str, default_target: str = "", force: bool = True) -> dict[str, Any]:
    return await asyncio.to_thread(full_scan_sync, raw_target, default_target, force)


def _reg_blocked(reg: Any) -> bool:
    if reg is None:
        return False
    if hasattr(reg, "blocked"):
        return bool(reg.blocked)
    return bool(getattr(reg, "rkn_blocked", False))


def _reg_asn_and_org(reg: Any) -> tuple[str, str]:
    if reg is None:
        return "", ""
    geo = getattr(reg, "geo", None)
    asn = str((getattr(geo, "asn", "") if geo is not None else "") or getattr(reg, "asn", "") or "").strip()
    org = str((getattr(geo, "organisation", "") if geo is not None else "") or getattr(reg, "as_org", "") or "").strip()
    return asn, org


def _reg_country(reg: Any) -> str:
    if reg is None:
        return ""
    geo = getattr(reg, "geo", None)
    return str((getattr(geo, "country", "") if geo is not None else "") or getattr(reg, "country", "") or "").strip()


def _reg_reverse(reg: Any) -> str:
    if reg is None:
        return ""
    rev = getattr(reg, "reverse", None)
    if isinstance(rev, list):
        return ", ".join(str(x) for x in rev[:3] if x)
    return str(rev or "").strip()


def _reg_cdn(reg: Any) -> str:
    if reg is None:
        return ""
    cdn = getattr(reg, "cdn", None)
    if isinstance(cdn, dict):
        parts = [str(cdn.get(k) or "").strip() for k in ("provider", "name", "domain")]
        return " ".join(p for p in parts if p).strip()
    return str(cdn or "").strip()


def _reg_complaints(reg: Any) -> tuple[int | None, int]:
    if reg is None:
        return None, 0
    total_fn = getattr(reg, "complaint_total", None)
    peak_fn = getattr(reg, "complaint_peak", None)
    if callable(total_fn):
        total = int(total_fn())
        peak = int(peak_fn()) if callable(peak_fn) else 0
        return total, peak
    raw_total = getattr(reg, "complaints_total", None)
    raw_peak = int(getattr(reg, "complaints_peak", 0) or 0)
    return (int(raw_total) if raw_total is not None else None), raw_peak


def _reg_subnets(reg: Any) -> list[str]:
    if reg is None:
        return []
    subs = getattr(reg, "subnets", None)
    if subs is None:
        subs = getattr(reg, "rkn_subnets", None)
    return [str(s) for s in (subs or []) if s]


def _format_asn(reg: Any, meta: dict[str, Any]) -> tuple[str, str]:
    raw_as = str(meta.get("as") or "").strip()
    as_num = ""
    as_name = str(meta.get("asname") or "").strip()
    if raw_as:
        parts = raw_as.split(" ", 1)
        as_num = parts[0].strip()
        if len(parts) > 1 and not as_name:
            as_name = parts[1].strip()
    r_asn, r_org = _reg_asn_and_org(reg)
    if not as_num and r_asn:
        as_num = r_asn
    if not as_name and r_org:
        as_name = r_org
    return as_num, as_name


def _format_location(reg: Any, meta: dict[str, Any]) -> str:
    country = str(meta.get("country") or "").strip()
    cc = str(meta.get("countryCode") or _reg_country(reg) or "").strip()
    region = str(meta.get("regionName") or "").strip()
    city = str(meta.get("city") or "").strip()
    loc_parts: list[str] = []
    if country and cc:
        loc_parts.append(f"{country} ({cc})")
    elif country or cc:
        loc_parts.append(country or cc)
    if region and region != city:
        loc_parts.append(region)
    if city:
        loc_parts.append(city)
    if not loc_parts and reg is not None:
        geo = getattr(reg, "geo", None)
        geo_loc = str(getattr(geo, "location", "") or "").strip() if geo is not None else ""
        if geo_loc:
            loc_parts.append(geo_loc)
    return ", ".join(loc_parts)


def _format_rkn_status(reg: Any, reg_code: str, t: Any) -> tuple[str, bool, str]:
    if reg is not None:
        blocked = _reg_blocked(reg)
        label = t("IPSCAN_BLOCKED") if blocked else t("IPSCAN_CLEAN")
        extras: list[str] = []
        comp_total, comp_peak = _reg_complaints(reg)
        if comp_total is not None and (comp_total > 0 or getattr(reg, "complaints", None)):
            extras.append(t("IPSCAN_COMPLAINTS", count=comp_total))
        if comp_peak > 0:
            extras.append(t("IPSCAN_PEAK", peak=comp_peak))
        if extras:
            label = f"{label} ({', '.join(extras)})"
        return label, blocked, "warn" if blocked else "ok"
    if reg_code == "rate":
        return t("IPSCAN_ERR_RATE"), False, "warn"
    return t("IPSCAN_ERR_NET"), False, "info"


def _answer_verdict(answer: chebur.Answer | None, reg: Any, live: chebur.Live | None) -> str:
    if _reg_blocked(reg):
        return "registry"
    if live is not None and live.results:
        return live.verdict()
    if answer is not None:
        return answer.verdict()
    if reg is not None:
        return "clean"
    return "unknown"


def _status_key(verdict: str) -> str:
    if verdict == "registry":
        return "CHK_ST_REGISTRY"
    if verdict in ("tspu", "tspu_block"):
        return "CHK_ST_TSPU"
    if verdict in ("sni", "sni_block"):
        return "CHK_ST_SNI"
    if verdict in ("dns", "dns_spoofing"):
        return "CHK_ST_DNS"
    if verdict in ("cdn", "cdn_block"):
        return "CHK_ST_CDN"
    if verdict == "partial":
        return "CHK_ST_PARTIAL"
    if verdict == "clean":
        return "CHK_ST_CLEAN"
    if verdict == "uncertain":
        return "CHK_ST_UNCERTAIN"
    return "CHK_ST_UNKNOWN"


def _blocking_providers(live: chebur.Live) -> list[str]:
    found: list[str] = []
    for kind_name in chebur.BLOCKING:
        for prov in live.providers_for(kind_name):
            if prov and prov not in found:
                found.append(prov)
    return found


def _verdict_quote(verdict: str, target: str, reg: Any, live: chebur.Live | None, reg_code: str, t: Any) -> str:
    if reg is None and live is None:
        if reg_code == "bad":
            return ui.quote(ui.bold(t("IPSCAN_ERR_BAD")))
        if reg_code == "rate":
            return ui.quote(ui.muted(t("IPSCAN_ERR_RATE")))
        return ui.quote(ui.muted(t("IPSCAN_ERR_NET")))
    total = len(live.results) if live else 0
    blocked_n = live.blocking() if live else 0
    ok_n = live.counts().get("ok", 0) if live else 0
    if verdict == "registry":
        return ui.quote(ui.bold(t("CHK_QUOTE_REGISTRY")))
    if verdict in ("tspu", "tspu_block", "sni", "sni_block", "dns", "dns_spoofing", "cdn", "cdn_block"):
        return ui.quote(ui.bold(t("CHK_QUOTE_BANNED", blocked=blocked_n, total=total, target=target)))
    if verdict == "partial":
        return ui.quote(ui.bold(t("CHK_QUOTE_PARTIAL", blocked=blocked_n, total=total, target=target)))
    if verdict == "clean" and live is not None and live.results:
        return ui.quote(ui.bold(t("CHK_QUOTE_CLEAN", ok=ok_n, total=total, target=target)))
    if verdict == "uncertain":
        return ui.quote(ui.muted(t("CHK_QUOTE_UNCERTAIN", target=target)))
    if reg is not None and not _reg_blocked(reg):
        reg_kind = str(getattr(reg, "kind", None) or getattr(reg, "type", "") or "")
        if chebur.probe_supported(reg_kind):
            return ui.quote(ui.muted(t("CHK_QUOTE_REGISTRY_CLEAN", target=target)))
        return ui.quote(ui.muted(t("CHK_QUOTE_WIDE", target=target)))
    return ui.quote(ui.muted(t("CHK_QUOTE_UNKNOWN")))


def safe_cb_target(target: str) -> str:
    clean = str(target or "").strip()
    if not clean or clean in SELF_ALIASES:
        return "self"
    if len(clean.encode("utf-8")) > 44:
        return clean[:44]
    return clean


def _display_target_subtitle(raw_target: str, t: Any) -> str:
    clean = str(raw_target or "").strip()
    if not clean or clean.lower() in SELF_ALIASES:
        return t("IPSCAN_NODE_SELF")
    try:
        host, _kind = chebur.clean_target(clean)
        return host
    except chebur.CheburError:
        return clean[:64]


def start_keyboard_rows(cb_target: str, lang: str = i18n.DEFAULT_LANGUAGE) -> list[list[dict[str, Any]]]:
    t = i18n.translator(lang)
    cb = safe_cb_target(cb_target)
    return [[{"text": t("IPSCAN_BTN_START"), "callback_data": f"ipscan:run:{cb}"}]]


def after_scan_keyboard_rows(lang: str = i18n.DEFAULT_LANGUAGE) -> list[list[dict[str, Any]]]:
    t = i18n.translator(lang)
    return [[{"text": t("IPSCAN_BTN_OTHER"), "switch_inline_query_current_chat": ""}]]


def ready_screen(raw_target: str, lang: str = i18n.DEFAULT_LANGUAGE) -> ui.Rich:
    t = i18n.translator(lang)
    subtitle = _display_target_subtitle(raw_target, t)
    return ui.screen(
        t("IPSCAN_LAUNCH_TITLE"),
        ui.muted(subtitle),
        [ui.quote(ui.muted(t("IPSCAN_LAUNCH_PROMPT")))],
        [],
        icon="radar",
    )


def scanning_screen(raw_target: str, lang: str = i18n.DEFAULT_LANGUAGE) -> ui.Rich:
    t = i18n.translator(lang)
    subtitle = _display_target_subtitle(raw_target, t)
    return ui.screen(
        t("IPSCAN_SCANNING_TITLE"),
        ui.muted(subtitle),
        [ui.quote(ui.muted(t("IPSCAN_SCANNING_BODY")))],
        [],
        icon="loading",
    )


def _verdict_label(name: str, lang: str, t: Any) -> str:
    key = "CHK_V_" + str(name or "").upper()
    if i18n.has_key(key, lang):
        return t(key)
    return str(name or "")


def rich_report(
    data: dict[str, Any],
    lang: str = i18n.DEFAULT_LANGUAGE,
) -> tuple[ui.Rich, list[list[dict[str, Any]]]]:
    t = i18n.translator(lang)
    target = str(data.get("target") or "")
    kind = str(data.get("kind") or "")
    reg: Any = data.get("registry")
    live: chebur.Live | None = data.get("live")
    answer: chebur.Answer | None = data.get("answer")
    reg_code = str(data.get("reg_code") or "")
    meta: dict[str, Any] = data.get("meta") or {}
    ports_info: dict[str, Any] = data.get("ports") or {"open": [], "best_ms": 0}
    shown_ip = str(data.get("ip") or "")

    kbd = after_scan_keyboard_rows(lang)

    if kind == "bad":
        err_screen = ui.screen(
            t("IPSCAN_REPORT_TITLE"),
            ui.muted(t("IPSCAN_SUBTITLE")),
            [ui.quote(ui.bold(t("IPSCAN_ERR_BAD")))],
            [],
            icon="warn",
        )
        return err_screen, kbd

    rkn_label, rkn_blocked, rkn_icon = _format_rkn_status(reg, reg_code, t)
    verdict = _answer_verdict(answer, reg, live)
    st_key = _status_key(verdict)
    verdict_val = t(st_key)
    verdict_bad = st_key in {"CHK_ST_REGISTRY", "CHK_ST_TSPU", "CHK_ST_SNI", "CHK_ST_DNS", "CHK_ST_CDN", "CHK_ST_PARTIAL"}
    rows: list[tuple[str, str, str]] = [
        ("target", t("IPSCAN_TARGET"), ui.code(target)),
    ]
    if shown_ip:
        rows.append(("globe", t("IPSCAN_RESOLVED_IP"), ui.code(shown_ip)))
    rows.append(("warn" if verdict_bad else "ok", t("CHK_VERDICT"), ui.code(verdict_val)))
    rows.append((rkn_icon, t("IPSCAN_RKN"), ui.code(rkn_label)))

    loc = _format_location(reg, meta)
    if loc:
        rows.append(("globe", t("IPSCAN_COUNTRY"), ui.code(loc)))
    tz = str(meta.get("timezone") or "").strip()
    if tz:
        rows.append(("clock", t("IPSCAN_TIMEZONE"), ui.code(tz)))

    isp = str(meta.get("isp") or "").strip()
    org = str(meta.get("org") or "").strip()
    _r_asn, r_org = _reg_asn_and_org(reg)
    if isp:
        rows.append(("server", t("IPSCAN_ISP"), ui.code(isp)))
    if org and org.lower() != isp.lower():
        rows.append(("server", t("IPSCAN_ORG"), ui.code(org)))
    elif not isp and r_org:
        rows.append(("server", t("IPSCAN_ISP"), ui.code(r_org)))

    as_num, as_name = _format_asn(reg, meta)
    if as_num or as_name:
        as_full = f"{as_num} ({as_name})" if (as_num and as_name and as_name.lower() != isp.lower()) else (as_num or as_name)
        rows.append(("tag", t("IPSCAN_ASN"), ui.code(as_full)))

    reverse = str(meta.get("reverse") or _reg_reverse(reg) or "").strip()
    cdn = _reg_cdn(reg)
    ptr_parts = [p for p in (reverse, cdn) if p]
    if ptr_parts:
        rows.append(("link", t("IPSCAN_PTR"), ui.code(" / ".join(ptr_parts))))

    if meta:
        yes = t("CHK_NET_YES")
        no = t("CHK_NET_NO")
        flag_str = (
            f"{t('IPSCAN_HOSTING')}: {yes if meta.get('hosting') else no} | "
            f"{t('IPSCAN_PROXY')}: {yes if meta.get('proxy') else no} | "
            f"{t('IPSCAN_MOBILE')}: {yes if meta.get('mobile') else no}"
        )
        rows.append(("shield", t("IPSCAN_FLAGS"), ui.code(flag_str)))

    if kind in ("ip", "domain") and shown_ip:
        label_map = dict(COMMON_PORTS)
        if isinstance(ports_info, dict):
            raw_open = list(ports_info.get("open") or [])
            best_ms = int(ports_info.get("best_ms") or 0)
        elif isinstance(ports_info, list):
            raw_open = []
            best_ms = 0
            for entry in ports_info:
                if isinstance(entry, tuple) and len(entry) >= 2:
                    p_num = int(entry[0])
                    p_lbl = str(entry[1]) if len(entry) >= 3 else label_map.get(p_num, "")
                    p_ms = int(entry[2] if len(entry) >= 3 else entry[1])
                    raw_open.append((p_num, p_lbl, p_ms))
                    if best_ms == 0 or (0 < p_ms < best_ms):
                        best_ms = p_ms
        else:
            raw_open = []
            best_ms = 0
        if raw_open:
            ports_txt = ", ".join(f"{p}/{lbl}" if lbl else str(p) for p, lbl, _ms in raw_open)
            rows.append(("bolt", t("IPSCAN_OPEN_PORTS"), ui.code(ports_txt)))
        else:
            rows.append(("dot", t("IPSCAN_OPEN_PORTS"), ui.code(t("IPSCAN_PORTS_NONE"))))
        if best_ms > 0:
            rows.append(("gauge", t("IPSCAN_PING"), ui.code(t("IPSCAN_LATENCY_MS", ms=best_ms))))

    blocks: list[str] = [
        _verdict_quote(verdict, target, reg, live, reg_code, t),
        ui.table(rows),
    ]

    if live is not None and live.results:
        done = len(live.results)
        total = live.online or done
        share_pct = f"{round(live.share() * 100)}%"
        live_rows: list[tuple[str, str, str]] = [
            ("bolt", t("CHK_PROBES"), ui.code(f"{done} / {total}")),
            ("warn" if live.blocking() else "ok", t("CHK_SHARE"), ui.code(share_pct)),
        ]
        counts = live.counts()
        for v_key, v_ico in (
            ("tspu_block", "warn"),
            ("sni_block", "warn"),
            ("dns_spoofing", "warn"),
            ("cdn_block", "warn"),
            ("ok", "ok"),
            ("uncertain", "info"),
        ):
            if counts.get(v_key):
                live_rows.append((v_ico, _verdict_label(v_key, lang, t), ui.code(str(counts[v_key]))))
        blocks.append(ui.heading(t("CHK_LIVE_TITLE"), icon="bolt"))
        blocks.append(ui.table(live_rows))
        bad_isps = _blocking_providers(live)
        if bad_isps:
            shown_isps = ", ".join(bad_isps[:8])
            blocks.append(ui.quote(ui.bold(t("CHK_PROVIDERS", value=shown_isps))))

        region_rows: list[tuple[str, str, str]] = []
        for item in live.results[:36]:
            reg_name = item.region or "-"
            prov_name = item.provider or "?"
            asn_part = f" ({item.asn})" if item.asn else ""
            left_col = f"{reg_name} / {prov_name}{asn_part}"
            verdicts = item.verdicts or ["uncertain"]
            v_labels = [_verdict_label(v, lang, t) for v in verdicts]
            verdict_txt = ", ".join(v_labels)
            if item.dpi_hop is not None:
                verdict_txt = f"{verdict_txt} ({t('IPSCAN_DPI_HOP', hop=item.dpi_hop)})"
            is_blk = bool(set(verdicts) & set(chebur.BLOCKING))
            r_ico = "warn" if is_blk else ("ok" if "ok" in verdicts else "info")
            region_rows.append((r_ico, left_col, ui.code(verdict_txt)))
        blocks.append(
            ui.details(
                t("IPSCAN_REGIONS_SUMMARY", count=len(live.results)),
                ui.table(region_rows, (t("IPSCAN_COL_REGION"), t("IPSCAN_COL_VERDICT"))),
                open_=False,
            )
        )

    subnets = _reg_subnets(reg)
    if subnets:
        blocks.append(ui.long_block(t("IPSCAN_SUBNETS"), "\n".join(subnets[:16])))
    reg_ips = list(getattr(reg, "ips", None) or []) if reg is not None else []
    if len(reg_ips) > 1:
        blocks.append(ui.long_block(t("IPSCAN_IPS_LIST", count=len(reg_ips)), "\n".join(reg_ips[:24])))

    subtitle = f"{target} ({shown_ip})" if (shown_ip and shown_ip != target) else (shown_ip or target)
    screen = ui.screen(
        t("IPSCAN_REPORT_TITLE"),
        ui.muted(subtitle),
        blocks,
        [],
        icon="warn" if (verdict_bad or rkn_blocked) else "radar",
    )
    return screen, kbd


async def inline_results(
    query: str,
    src: str = "mt",
    lang: str = i18n.DEFAULT_LANGUAGE,
    default_target: str = "",
) -> list[dict]:
    _ = default_target
    t = i18n.translator(lang)
    candidate = extract_candidate(query)
    nonce = secrets.token_hex(4)

    if candidate == "self":
        card = ready_screen("self", lang)
        kbd = start_keyboard_rows("self", lang)
        return [
            inline.rich_article(
                f"ipscan:{nonce}:self",
                t("IPSCAN_LAUNCH_TITLE"),
                t("IPSCAN_LAUNCH_DESC"),
                card,
                src,
                reply_markup=kbd,
            )
        ]

    try:
        host, _kind = chebur.clean_target(candidate)
    except chebur.CheburError:
        card = ready_screen("self", lang)
        kbd = start_keyboard_rows("self", lang)
        return [
            inline.rich_article(
                f"ipscan:{nonce}:self",
                t("IPSCAN_LAUNCH_TITLE"),
                t("IPSCAN_ERR_BAD"),
                card,
                src,
                reply_markup=kbd,
            )
        ]

    cb_target = safe_cb_target(host)
    card = ready_screen(host, lang)
    kbd = start_keyboard_rows(cb_target, lang)
    return [
        inline.rich_article(
            f"ipscan:{nonce}:{cb_target}",
            t("IPSCAN_LAUNCH_TARGET_TITLE", target=host),
            t("IPSCAN_LAUNCH_DESC"),
            card,
            src,
            reply_markup=kbd,
        )
    ]
