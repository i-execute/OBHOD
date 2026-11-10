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

from . import chebur, i18n, inline

CACHE_TTL = 120.0
ERR_CACHE_TTL = 5.0
IP_API_URL = (
    "http://ip-api.com/json/%s"
    "?fields=status,message,country,countryCode,regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)
IP_API_TIMEOUT = 2.8
CHEBUR_SCAN_TIMEOUT = 3.5
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def esc(value: Any) -> str:
    return html.escape(str(value or ""))


def clear_cache() -> None:
    _CACHE.clear()


def extract_target(raw: str) -> tuple[str, bool]:
    text = str(raw or "").strip()
    if not text:
        return "", False
    lowered = text.lower()
    if lowered == "ip":
        return "", True
    if lowered.startswith("ip "):
        return text[3:].strip(), True
    token, _rest = inline.parse_query(text)
    if token:
        return "", False
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
    if not ip_addr:
        return {}
    req = urllib.request.Request(
        IP_API_URL % ip_addr,
        headers={"User-Agent": "obhod-ipscan/1", "Accept": "application/json"},
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


def _safe_chebur(host: str) -> tuple[chebur.Registry | None, str]:
    try:
        return chebur.check(host, timeout=CHEBUR_SCAN_TIMEOUT), ""
    except chebur.CheburError as exc:
        if "429" in str(exc.message) or exc.code == "rate":
            return None, "rate"
        return None, "net"
    except Exception:
        return None, "net"


def scan_sync(host: str, kind: str) -> dict[str, Any]:
    now = time.monotonic()
    cached = _CACHE.get(host)
    if cached and cached[0] > now:
        return dict(cached[1])
    ip_addr = host if kind == "ip" else resolve_ip(host)
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_reg = pool.submit(_safe_chebur, host)
        fut_meta = pool.submit(fetch_ip_api, ip_addr) if ip_addr else None
        reg, reg_code = fut_reg.result()
        meta = fut_meta.result() if fut_meta is not None else {}
    if not meta and reg is not None and reg.ips:
        meta = fetch_ip_api(reg.ips[0])
    shown_ip = host if kind in ("subnet", "asn") else str(meta.get("query") or ip_addr or (reg.ips[0] if reg and reg.ips else host))
    data: dict[str, Any] = {
        "target": host,
        "kind": kind,
        "ip": shown_ip,
        "registry": reg,
        "reg_code": reg_code,
        "meta": meta,
    }
    ttl = CACHE_TTL if reg is not None else ERR_CACHE_TTL
    _CACHE[host] = (now + ttl, data)
    if len(_CACHE) > 256:
        oldest = min(_CACHE, key=lambda key: _CACHE[key][0])
        _CACHE.pop(oldest, None)
    return data


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
    cdn_val = ", ".join(sorted(reg.cdn)[:3]) if reg and reg.cdn else ""
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


async def inline_results(query: str, src: str = "mt", lang: str = i18n.DEFAULT_LANGUAGE) -> list[dict]:
    t = i18n.translator(lang)
    candidate, matched = extract_target(query)
    if not matched:
        return []
    if not candidate:
        body = "<b>%s</b>\n<blockquote>%s</blockquote>" % (esc(t("IPSCAN_HINT_TITLE")), esc(t("IPSCAN_HINT_BODY")))
        return [inline.html_article("ipscan:hint", t("IPSCAN_HINT_TITLE"), t("IPSCAN_HINT_DESC"), body, src)]
    try:
        host, kind = chebur.clean_target(candidate)
    except chebur.CheburError:
        body = "<b>%s</b>\n<blockquote>%s</blockquote>" % (esc(t("IPSCAN_TITLE")), esc(t("IPSCAN_ERR_BAD")))
        return [inline.html_article("ipscan:err", t("IPSCAN_TITLE"), t("IPSCAN_ERR_BAD"), body, src)]
    data = await asyncio.to_thread(scan_sync, host, kind)
    title, desc, html_body = format_card(data, lang)
    rid = "ipscan:%s" % host[:48]
    return [inline.html_article(rid, title, desc, html_body, src)]
