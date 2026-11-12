from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import i18n, inline, subs
from .scan import ML_DSA65_CHAIN_MIN, ScanResult, canonical_kind, kind_has_mldsa, security_fit, security_fits, top_fastest_targets
from .ui import (
    bold,
    bold_html,
    bullet_list,
    button,
    code,
    copy_row,
    details,
    heading,
    inline_button,
    input_row,
    link_button,
    long_block,
    muted,
    muted_html,
    pre,
    quote,
    row,
    screen,
    table,
)
from .xray import (
    DEFAULT_DEST,
    DEFAULT_SNI,
    NETWORKS,
    VLESS_COMBOS,
    XrayError,
    XrayInbound,
    XrayState,
    inbound_link,
    relevant_fields,
    summary,
    tailnet_expiry_label,
    tailnet_expiry_stage,
)

LINK_PREVIEW = 10
MAX_LINKS = 4

FIELD_LABELS = {
    "dest": "FIELD_DEST",
    "sni": "FIELD_SNI",
    "short_id": "FIELD_SHORT_ID",
    "spider_x": "FIELD_SPIDER_X",
    "fingerprint": "FIELD_FINGERPRINT",
    "mldsa65": "FIELD_MLDSA65",
    "service": "FIELD_SERVICE",
    "path": "FIELD_PATH",
    "host_header": "FIELD_HOST_HEADER",
    "mode": "FIELD_MODE",
    "alpn": "FIELD_ALPN",
    "cert_file": "FIELD_CERT_FILE",
    "key_file": "FIELD_KEY_FILE",
}

FIELD_BUTTONS = {
    "dest": "xr_dest",
    "sni": "xr_sni",
    "short_id": "xr_short_id",
    "spider_x": "xr_spider_x",
    "fingerprint": "xr_fingerprint",
    "mldsa65": "xr_mldsa65_seed",
    "service": "xr_service",
    "path": "xr_path",
    "host_header": "xr_host_header",
    "alpn": "xr_alpn",
    "cert_file": "xr_cert_file",
    "key_file": "xr_key_file",
}

ALL_FIELDS = tuple(FIELD_LABELS)


@dataclass
class XrayView:
    state: XrayState
    core: dict[str, Any] = field(default_factory=dict)
    notice: str = ""
    error: str = ""
    busy: str = ""
    draft: dict[str, str] = field(default_factory=dict)
    lang: str = i18n.DEFAULT_LANGUAGE
    bundle: Any = None
    address: str = ""
    key_mask: str = ""
    picked_dest: str = ""
    picked_sni: str = ""
    vps_subnet: str = ""
    last_subnet: str = ""

    @property
    def installed(self) -> bool:
        return bool(self.core.get("installed", False))

    @property
    def running(self) -> bool:
        return str(self.core.get("service", "")) == "active"

    @property
    def version(self) -> str:
        return str(self.core.get("version", "") or "")

    def tr(self) -> i18n.Translator:
        return i18n.translator(self.lang)


def field_label(name: str, lang: str) -> str:
    return i18n.t(FIELD_LABELS.get(name, "FIELD_UNKNOWN"), lang)


def banner(view: XrayView, t: i18n.Translator) -> list[str]:
    out: list[str] = []
    if view.notice:
        out.append(quote(muted(view.notice)))
    if view.error:
        out.append(quote(bold(view.error)))
    if view.busy:
        out.append(quote(muted(view.busy)))
    return out


def core_line(view: XrayView, t: i18n.Translator) -> str:
    if not view.core:
        return muted(t("HOME_CORE_UNKNOWN"))
    if not view.installed:
        return bold(t("HOME_CORE_MISSING"))
    state = t("HOME_CORE_RUNNING") if view.running else t("HOME_CORE_STOPPED")
    return bold(t("HOME_CORE_STATE", version=str(view.core.get("version", "") or ""), state=state))


def back_row(target: str = "nav:home", lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    if target == "nav:home":
        return row(button(i18n.t("UI_HOME", lang), "nav:home", icon="home"))
    if target == "xr:home":
        return row(button(i18n.t("NAV_XRAY", lang), "xr:home", icon="xray"), button(i18n.t("UI_HOME", lang), "nav:home", icon="home"))
    return row(button(i18n.t("UI_BACK", lang), target, icon="back"), button(i18n.t("NAV_XRAY", lang), "xr:home", icon="xray"))


def home(view: XrayView) -> Any:
    t = view.tr()
    state = view.state
    blocks = banner(view, t)
    blocks.append(f"<p>{core_line(view, t)}</p>")
    if state.inbounds:
        rows = []
        for item in state.inbounds:
            icon_name = "ok" if item.enable else "stop"
            status_text = t("XR_DAEMON_RUNNING") if item.enable else t("XR_DAEMON_STOPPED")
            rows.append((icon_name, str(item.port), f"{transport_title(item.network)} - {status_text}"))
        blocks.append(table(rows, (t("SUM_PORT"), t("SUM_NETWORK"))))
    else:
        blocks.append(quote(muted(t("XR_HOME_EMPTY"))))
    buttons = [
        row(button(t("XR_BTN_NEW"), "xr:new", icon="add"), button(t("XR_BTN_INBOUNDS_LIST"), "xr:list", icon="folder")),
        row(button(t("NAV_SUBS"), "xr:subs", icon="link"), button(t("NAV_LOGS"), "xr:logs", icon="logs")),
        row(button(t("NAV_CORE"), "xr:core", icon="xray"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("XR_TITLE"), t("XR_SUBTITLE"), blocks, buttons, icon="xray")


def inbounds_list_screen(view: XrayView, page: int = 0) -> Any:
    t = view.tr()
    state = view.state
    blocks = banner(view, t)
    items = list(state.inbounds)
    if not items:
        blocks.append(quote(muted(t("XR_HOME_EMPTY"))))
        buttons = [
            row(button(t("XR_BTN_NEW"), "xr:new", icon="add")),
            back_row("xr:home", view.lang),
        ]
        return screen(t("XR_LIST_TITLE"), t("XR_LIST_SUBTITLE"), blocks, buttons, icon="folder")
    per_page = 10
    total_pages = max(1, (len(items) + per_page - 1) // per_page)
    cur_page = max(0, min(int(page or 0), total_pages - 1))
    chunk = items[cur_page * per_page : (cur_page + 1) * per_page]
    rows = []
    for item in chunk:
        icon_name = "ok" if item.enable else "stop"
        rows.append((icon_name, str(item.port), f"{item.remark} ({transport_title(item.network)})"))
    blocks.append(table(rows, (t("SUM_PORT"), t("SUM_NETWORK"))))
    buttons: list[str] = []
    for idx in range(0, len(chunk), 2):
        pair = chunk[idx : idx + 2]
        buttons.append(
            row(
                *[
                    button(
                        item.remark or f"#{item.id}",
                        f"xr:in:{item.id}",
                        icon="ok" if item.enable else "stop",
                    )
                    for item in pair
                ]
            )
        )
    if total_pages > 1:
        nav_btns = []
        if cur_page > 0:
            nav_btns.append(button("<", f"xr:list:{cur_page - 1}", icon="back"))
        if cur_page + 1 < total_pages:
            nav_btns.append(button(">", f"xr:list:{cur_page + 1}", icon="compass"))
        if nav_btns:
            buttons.append(row(*nav_btns))
    buttons.append(row(button(t("XR_BTN_NEW"), "xr:new", icon="add")))
    buttons.append(back_row("xr:home", view.lang))
    return screen(t("XR_LIST_TITLE"), t("XR_LIST_SUBTITLE"), blocks, buttons, icon="folder")


def transport_title(network: str) -> str:
    if network == "grpc":
        return "gRPC"
    return str(network or "raw").upper()


def compact_target_rows(items: list[ScanResult]) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for idx, item in enumerate(items[:10]):
        sni_name = (item.server_names[0] if item.server_names else "") or item.host or item.target
        base_host = item.ip or item.host or item.target
        if int(item.port or 443) != 443 and ":" not in base_host:
            base_host = f"{base_host}:{item.port}"
        elif base_host.endswith(":443"):
            base_host = base_host[:-4]
        sni_short = sni_name[:-4] if sni_name.endswith(":443") else sni_name
        if item.ip and sni_short and sni_short != base_host:
            left = f"{idx + 1}. {base_host} ({sni_short[:14]})"
        else:
            shown = sni_short or base_host
            left = f"{idx + 1}. {shown[:24]}"
        ping_part = f"{item.latency_ms} ms" if item.latency_ms > 0 else "-"
        if item.pq_hybrid and item.ml_dsa_ready:
            cert_part = "PQ+MLDSA"
        elif item.ml_dsa_ready:
            cert_part = "MLDSA"
        elif item.pq_hybrid:
            cert_part = "PQ"
        else:
            cert_part = "X25519"
        out.append(("radar" if item.feasible else "warn", left, code(f"{ping_part} · {cert_part}")))
    return out


def target_pick_rows(prefix: str, count: int) -> list[str]:
    total = max(0, min(int(count), 10))
    rows_out: list[str] = []
    if total > 0:
        first = [button(str(idx + 1), f"{prefix}:{idx}", icon="target") for idx in range(0, min(5, total))]
        rows_out.append(row(*first))
    if total > 5:
        second = [button(str(idx + 1), f"{prefix}:{idx}", icon="target") for idx in range(5, total)]
        rows_out.append(row(*second))
    return rows_out


def new_menu(view: XrayView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(t("XR_NEW_REALITY_ONLY_NOTE"))))
    buttons = [
        row(
            button("RAW", "xr:wiz:net:raw", icon="add"),
            button("XHTTP", "xr:wiz:net:xhttp", icon="add"),
            button("gRPC", "xr:wiz:net:grpc", icon="add"),
        ),
        back_row("xr:home", view.lang),
    ]
    return screen(t("XR_NEW_TITLE"), t("XR_WIZ_STEP1_SUB"), blocks, buttons, icon="add")


def wiz_scan_screen(view: XrayView, network: str = "raw", results: list[ScanResult] | None = None) -> Any:
    t = view.tr()
    state = view.state
    blocks = banner(view, t)
    rows = results if results is not None else [ScanResult.from_dict(item) for item in state.scan_results]
    top_items = top_fastest_targets(rows, limit=10, fallback_defaults=True)
    blocks.append(table(compact_target_rows(top_items), (t("XR_WIZ_COL_TARGET"), t("XR_WIZ_COL_PING"))))
    buttons = target_pick_rows("xr:wiz:pick", len(top_items))
    if view.vps_subnet:
        buttons.append(
            row(
                button(t("XR_WIZ_FAST_BTN"), "xr:wiz:scan:fast", icon="scan"),
                button(t("XR_SUBSCAN_VPS_BTN"), "xr:wiz:scan:vps", icon="radar"),
            )
        )
    else:
        buttons.append(row(button(t("XR_WIZ_FAST_BTN"), "xr:wiz:scan:fast", icon="scan")))
    buttons.append(input_row(t("XR_WIZ_MANUAL_BTN"), "xr_subnet_cidr", "wiz", view.lang))
    buttons.append(back_row("xr:new", view.lang))
    title = f"{t('XR_WIZ_STEP2_TITLE')} · {transport_title(network)}"
    return screen(title, t("XR_WIZ_STEP2_SUB"), blocks, buttons, icon="scan")


def compatible_reality_kinds(result: ScanResult | None) -> list[str]:
    if result is None:
        return ["reality"]
    out = [kind for kind, ok, _ in security_fits(result) if ok and kind.startswith("reality")]
    return out or ["reality"]


def wiz_sec_screen(view: XrayView, network: str, result: ScanResult, ctx: str = "wiz") -> Any:
    t = view.tr()
    blocks = banner(view, t)
    host = result.host or result.target.rsplit(":", 1)[0]
    port = int(result.port or 443)
    sni = (result.server_names[0] if result.server_names else "") or host
    dest = f"{host}:{port}" if ":" not in host else f"[{host}]:{port}"
    dest_view = f"{dest} ({result.latency_ms} ms)" if result.latency_ms > 0 else dest
    chain_bytes = int(result.cert_chain_bytes or 0)
    chain_view = (
        t("XR_WIZ_MLDSA_OK", size=chain_bytes)
        if result.ml_dsa_ready
        else t("XR_WIZ_MLDSA_SHORT", size=chain_bytes)
    )
    pairs = [
        ("route", t("XR_CUSTOM_NETWORK"), code(transport_title(network))),
        ("target", t("XR_SUBSCAN_SELECTED"), code(f"{dest_view} · {sni}")),
        ("shield", t("XR_WIZ_CHAIN_ROW"), code(chain_view)),
    ]
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    kinds = compatible_reality_kinds(result)
    buttons: list[str] = []
    action_prefix = "xr:wiz:make" if ctx == "wiz" else f"xr:subscan:sec:{ctx}"
    for start in range(0, len(kinds), 2):
        chunk = kinds[start : start + 2]
        buttons.append(
            row(
                *[
                    button(
                        security_label(kind, view.lang),
                        f"{action_prefix}:{kind}",
                        icon=SECURITY_ICONS.get(kind, "lock"),
                    )
                    for kind in chunk
                ]
            )
        )
    back_to = "xr:wiz:back" if ctx == "wiz" else f"xr:subscan:{ctx}"
    buttons.append(back_row(back_to, view.lang))
    return screen(t("XR_WIZ_STEP3_TITLE"), t("XR_WIZ_STEP3_SUB"), blocks, buttons, icon="shield")


def custom_menu(view: XrayView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    network = grab(view, "network") or "raw"
    port_val = grab(view, "port")
    cur_dest = view.picked_dest or DEFAULT_DEST
    cur_sni = view.picked_sni or DEFAULT_SNI
    blocks.append(
        table(
            [
                ("settings", t("XR_CUSTOM_NETWORK"), code(network)),
                ("shield", t("XR_CUSTOM_SECURITY"), code("reality")),
                ("plug", t("XR_CUSTOM_PORT"), code(port_val)),
                ("target", field_label("dest", view.lang), code(cur_dest)),
                ("world", field_label("sni", view.lang), code(cur_sni)),
            ],
            (t("UI_PARAM"), t("UI_VALUE")),
        )
    )
    fields = relevant_fields("reality", network if network in NETWORKS else "raw")
    names = ", ".join(code(field_label(item, view.lang)) for item in fields) or muted(t("XR_CUSTOM_NOTHING"))
    blocks.append(f"<p>{t('XR_CUSTOM_NEEDS', fields=names)}</p>")
    buttons = [
        row(button(t("XR_SUBSCAN_BTN"), "xr:subscan:custom", icon="radar")),
        row(button(t("XR_CUSTOM_NETWORK"), "xr:cyc:network", icon="settings"), button(t("UI_CREATE"), "xr:create", icon="add")),
        input_row(t("XR_CUSTOM_PORT"), "xr_port", "-", view.lang),
        back_row("xr:new", view.lang),
    ]
    return screen(t("XR_CUSTOM_TITLE"), t("XR_CUSTOM_SUBTITLE"), blocks, buttons, icon="tools")


def subnet_scan_screen(view: XrayView, results: list[ScanResult] | None = None, ctx: str = "new") -> Any:
    t = view.tr()
    state = view.state
    blocks = banner(view, t)
    cur_dest = view.picked_dest or DEFAULT_DEST
    cur_sni = view.picked_sni or DEFAULT_SNI
    if ctx.isdigit():
        found_inb = state.inbound(ctx)
        if found_inb is not None:
            cur_dest = found_inb.dest
            cur_sni = found_inb.sni
    meta_pairs = [
        ("target", t("XR_SUBSCAN_SELECTED"), code(f"{cur_dest} ({cur_sni})")),
    ]
    if view.last_subnet:
        meta_pairs.append(("radar", t("XR_SUBSCAN_LAST"), code(view.last_subnet)))
    elif view.vps_subnet:
        meta_pairs.append(("world", "VPS /24", code(view.vps_subnet)))
    blocks.append(table(meta_pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    raw_rows = results if results is not None else [ScanResult.from_dict(item) for item in state.scan_results]
    indexed_good = [(idx, item) for idx, item in enumerate(raw_rows) if item is not None and item.feasible]
    indexed_good.sort(key=lambda pair: (pair[1].latency_ms if pair[1].latency_ms > 0 else 10 ** 9, pair[1].target))
    top_pairs = indexed_good[:10]
    buttons: list[str] = []
    if top_pairs:
        blocks.append(table(compact_target_rows([pair[1] for pair in top_pairs]), (t("XR_WIZ_COL_TARGET"), t("XR_WIZ_COL_PING"))))
        first_row = [button(str(pos + 1), f"xr:subscan:pick:{ctx}:{orig_idx}", icon="target") for pos, (orig_idx, _) in enumerate(top_pairs[:5])]
        buttons.append(row(*first_row))
        if len(top_pairs) > 5:
            second_row = [button(str(pos + 6), f"xr:subscan:pick:{ctx}:{orig_idx}", icon="target") for pos, (orig_idx, _) in enumerate(top_pairs[5:10])]
            buttons.append(row(*second_row))
    else:
        blocks.append(quote(muted(t("XR_SUBSCAN_EMPTY"))))
    if view.vps_subnet:
        buttons.append(
            row(
                button(t("XR_SUBSCAN_VPS_BTN"), f"xr:subscan:vps:{ctx}", icon="radar"),
                button(t("XR_SUBSCAN_CAND_BTN"), f"xr:subscan:cand:{ctx}", icon="scan"),
            )
        )
    else:
        buttons.append(row(button(t("XR_SUBSCAN_CAND_BTN"), f"xr:subscan:cand:{ctx}", icon="scan")))
    buttons.append(input_row(t("XR_SUBSCAN_INPUT_BTN"), "xr_subnet_cidr", ctx, view.lang))
    back_to = "xr:custom" if ctx == "custom" else (f"xr:in:{ctx}" if ctx.isdigit() else "xr:home")
    buttons.append(back_row(back_to, view.lang))
    return screen(t("XR_SUBSCAN_TITLE"), t("XR_SUBSCAN_SUBTITLE"), blocks, buttons, icon="scan")


def grab(view: XrayView, key: str) -> str:
    return str(view.draft.get(key, ""))


FIELD_ICONS = {
    "dest": "target",
    "sni": "world",
    "short_id": "tag",
    "mldsa65": "star",
    "service": "module",
    "path": "route",
    "host_header": "world",
    "mode": "route",
    "alpn": "shield",
    "cert_file": "file",
    "key_file": "key",
    "fingerprint": "world",
    "spider_x": "compass",
}


def field_pairs(inbound: XrayInbound, names: tuple[str, ...], lang: str) -> list[tuple[str, str]]:
    data = {
        "dest": inbound.dest,
        "sni": inbound.sni,
        "short_id": (inbound.short_ids or [""])[0],
        "spider_x": inbound.spider_x,
        "fingerprint": inbound.fingerprint,
        "mldsa65": None,
        "service": inbound.service_name,
        "path": inbound.path,
        "host_header": inbound.host_header,
        "mode": inbound.xhttp_mode,
        "alpn": ", ".join(inbound.alpn),
        "cert_file": inbound.cert_file,
        "key_file": inbound.key_file,
    }
    out: list[tuple[str, str, str]] = []
    for name in names:
        if name == "mldsa65":
            value = i18n.t("UI_ON", lang) if inbound.mldsa65_seed else i18n.t("UI_OFF", lang)
        else:
            value = str(data.get(name) or i18n.t("UI_NONE", lang))
        out.append((FIELD_ICONS.get(name, "tag"), field_label(name, lang), code(value)))
    return out


def inbound_screen(view: XrayView, inbound: XrayInbound) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if not inbound.enable and not view.error:
        blocks.append(quote(bold(t("XR_INBOUND_READY_NOTE"))))
    elif inbound.enable and inbound.dirty and not view.error:
        blocks.append(quote(bold(t("XR_INBOUND_DIRTY_NOTE"))))
    blocks.append(f"<h3>{bold(inbound.remark)}</h3>")
    blocks.append(table(summary(inbound, view.lang), (t("UI_PARAM"), t("UI_VALUE"))))
    fields = relevant_fields(inbound.security, inbound.network)
    blocks.append(heading(t("XR_INBOUND_RELEVANT"), 4))
    blocks.append(table(field_pairs(inbound, fields, view.lang), (t("UI_FIELD"), t("UI_VALUE"))))
    rest = tuple(item for item in ALL_FIELDS if item not in fields)
    if rest:
        blocks.append(details(t("XR_INBOUND_REST"), table(field_pairs(inbound, rest, view.lang), (t("UI_FIELD"), t("UI_VALUE")))))
    raw_state = getattr(view.state, "xray", view.state)
    host = raw_state.address(getattr(view, "address", ""))
    direct_link = ""
    if host:
        try:
            direct_link = inbound_link(inbound, host, inbound.port)
        except XrayError:
            direct_link = ""
    copy_btn = ""
    if direct_link:
        blocks.append(long_block(t("XR_LINKS_TITLE"), direct_link))
        copy_btn = copy_row(t("SUB_COPY"), direct_link, icon="copy") or ""
    buttons = []
    if not inbound.enable:
        buttons.append(row(button(t("XR_BTN_START_INBOUND"), f"xr:instart:{inbound.id}", icon="ok")))
    elif inbound.dirty:
        buttons.append(
            row(
                button(t("XR_BTN_APPLY_CHANGES"), f"xr:inapply:{inbound.id}", icon="refresh"),
                button(t("XR_BTN_STOP_INBOUND"), f"xr:instop:{inbound.id}", icon="stop"),
            )
        )
    else:
        buttons.append(row(button(t("XR_BTN_STOP_INBOUND"), f"xr:instop:{inbound.id}", icon="stop")))
    if copy_btn:
        buttons.append(copy_btn)
    buttons.extend(
        [
            row(
                inline_button(t("XR_BTN_PORT"), inline.prefill("xr_port", str(inbound.id)), icon="plug"),
                inline_button(t("XR_BTN_NAME"), inline.prefill("xr_remark", str(inbound.id)), icon="tag"),
            ),
            row(button(t("XR_SUBSCAN_BTN"), f"xr:subscan:{inbound.id}", icon="radar")),
            field_row(inbound, view.lang),
        ]
    )
    if inbound.security == "reality":
        buttons.append(row(button(t("XR_BTN_REALITY_KEYS"), f"xr:keys:{inbound.id}", icon="key"), button(t("XR_BTN_MLDSA"), f"xr:mldsa:{inbound.id}", icon="shield")))
    buttons.extend(
        [
            row(button(t("XR_ENC_TITLE"), f"xr:enc:{inbound.id}", icon="lock"), button(t("UI_DELETE"), f"xr:del:{inbound.id}", icon="delete")),
            back_row("xr:list", view.lang),
        ]
    )
    return screen(t("XR_INBOUND_TITLE"), t("XR_INBOUND_SUBTITLE", ident=inbound.id), blocks, buttons, icon="module")


def field_row(inbound: XrayInbound, lang: str) -> str:
    names = [name for name in relevant_fields(inbound.security, inbound.network) if name in FIELD_BUTTONS]
    if not names:
        return ""
    manual = row(*[inline_button(field_label(name, lang), inline.prefill(FIELD_BUTTONS[name], str(inbound.id)), icon="tag") for name in names[:2]])
    picks = [inline_button(i18n.t("BTN_LIST", lang), inline.list_query(FIELD_BUTTONS[name], str(inbound.id)), icon="compass") for name in names if inline.has_options(FIELD_BUTTONS[name])]
    return manual + row(*picks[:2] if picks else [])


def links_screen(view: XrayView, inbound: XrayInbound, address: str, links: list[tuple[str, str]]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(f"<p>{t('XR_LINKS_ADDRESS', address=code(address or t('UI_NOT_SET')))}</p>")
    if not address:
        blocks.append(quote(bold(t("XR_LINKS_NO_ADDRESS"))))
    if not links:
        blocks.append(quote(bold(t("XR_LINKS_EMPTY"))))
    copyable = []
    for name, link in links[:MAX_LINKS]:
        button_html = copy_row(t("XR_LINKS_COPY", name=name), link)
        if button_html:
            copyable.append(button_html)
        blocks.append(long_block(name, link))
    buttons = [
        *copyable,
        row(button(t("UI_REFRESH"), f"xr:link:{inbound.id}", icon="refresh"), button(t("XR_BTN_INBOUND"), f"xr:in:{inbound.id}", icon="xray")),
        back_row("xr:home", view.lang),
    ]
    return screen(t("XR_LINKS_TITLE"), inbound.remark, blocks, buttons, icon="link")


def mldsa_screen(view: XrayView, inbound: XrayInbound) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    pairs = [
        ("settings", t("XR_MLDSA_SECURITY"), code(inbound.security)),
        ("key", t("XR_MLDSA_SEED_SET"), code(i18n.t("UI_YES" if inbound.mldsa65_seed else "UI_NO", view.lang))),
        ("info", t("XR_MLDSA_VERIFY"), code(inbound.mldsa65_verify[:24] + "..." if inbound.mldsa65_verify else t("UI_NONE"))),
        ("shield", t("XR_MLDSA_CHAIN"), code(t("XR_MLDSA_CHAIN_VALUE"))),
    ]
    blocks.append(table(pairs, (t("UI_FIELD"), t("UI_VALUE"))))
    blocks.append(quote(muted(t("XR_MLDSA_NOTE"))))
    buttons = [
        input_row(t("XR_MLDSA_SEED"), "xr_mldsa65_seed", str(inbound.id), view.lang),
        input_row(t("XR_MLDSA_VERIFY_BTN"), "xr_mldsa65_verify", str(inbound.id), view.lang),
        row(button(t("UI_GENERATE"), f"xr:mldsa:{inbound.id}:gen", icon="star"), button(t("UI_REMOVE"), f"xr:mldsa:{inbound.id}:clear", icon="delete")),
        back_row(f"xr:in:{inbound.id}", view.lang),
    ]
    return screen(t("XR_MLDSA_TITLE"), inbound.remark, blocks, buttons, icon="key")


def traffic_line(t: Any, quota: dict[str, int]) -> str:
    used = int(quota.get("up") or 0) + int(quota.get("down") or 0)
    total = int(quota.get("total") or 0)
    if not total:
        return size_text(used)
    return "%s / %s" % (size_text(used), size_text(total))


def size_text(value: int) -> str:
    number = float(max(int(value or 0), 0))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if number < 1024 or unit == "TB":
            return ("%d %s" % (number, unit)) if unit == "B" else ("%.1f %s" % (number, unit))
        number /= 1024.0
    return "0 B"


TAILSCALE_NEW_LINUX_URL = "https://login.tailscale.com/admin/machines/new-linux"
TAILSCALE_MACHINES_URL = "https://login.tailscale.com/admin/machines"


def tailscale_guide_block(t: i18n.Translator, open_: bool = False) -> str:
    body = f"<p>{t('TS_GUIDE_INTRO')}</p>"
    return details(t("TS_GUIDE_TITLE"), body, open_=open_)


def tailscale_expiry_alert(view: XrayView, stage: str, days: int) -> Any:
    t = view.tr()
    state = view.state
    if stage == "expired":
        title = t("TS_EXPIRY_ALERT_TITLE_EXPIRED")
    elif stage == "7d":
        title = t("TS_EXPIRY_ALERT_TITLE_7D", days=days)
    else:
        title = t("TS_EXPIRY_ALERT_TITLE_30D", days=days)
    host = state.tunnel_host.split(":", 1)[0] or state.public_base() or "-"
    date_label = str(state.tunnel_key_expiry or "")[:10] or "-"
    body_text = t("TS_EXPIRY_ALERT_BODY", host=host, date=date_label)
    blocks = [quote(bold(title)), f"<p>{muted(body_text)}</p>"]
    buttons = [
        row(link_button(t("TS_MACHINES_BTN"), TAILSCALE_MACHINES_URL, icon="shield")),
        row(link_button(t("TS_ROTATE_KEY_BTN"), TAILSCALE_NEW_LINUX_URL, icon="key")),
        row(button(t("NAV_SUBS"), "xr:subs", icon="link"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(title, "", blocks, buttons, icon="clock")


def approval_prompt_text(t: i18n.Translator, approval_url: str) -> str:
    low = str(approval_url or "").lower()
    if "/f/serve" in low:
        return t("TAILSCALE_SERVE_ENABLE_NOTE")
    if "/admin/dns" in low:
        return t("TAILSCALE_DNS_ENABLE_NOTE")
    return t("TAILSCALE_FUNNEL_ENABLE_NOTE")


def subs_screen(view: XrayView, rows_data: list[tuple[str, str, str]]) -> Any:
    t = view.tr()
    state = view.state
    blocks = banner(view, t)
    core_known = bool(view.core)
    xray_missing = bool(core_known and not view.installed)
    enabled_inbounds = [item for item in state.inbounds if item.enable]
    approval_url = str(getattr(state, "tunnel_approval_url", "") or "").strip()
    domain_ok = bool(state.tunnel_enabled and not state.tunnel_expired and state.public_base())
    has_live_node = bool(state.tunnel_key_expiry and not state.tunnel_expired)
    ready = bool(domain_ok or view.key_mask or state.tunnel_expired or state.tunnel_key_expiry or approval_url)
    if not ready:
        if xray_missing:
            blocks.append(quote(bold(t("XR_SUBS_NO_XRAY_NOTE"))))
        blocks.append(quote(muted(t("XR_SUBS_NO_DOMAIN"))))
        blocks.append(tailscale_guide_block(t, open_=True))
        buttons = []
        if xray_missing:
            buttons.append(row(button(t("XR_SUBS_INSTALL_XRAY"), "xr:core:install", icon="box")))
        buttons.extend(
            [
                row(link_button(t("TAILSCALE_CONSOLE_BTN"), TAILSCALE_NEW_LINUX_URL, icon="world")),
                input_row(t("DOM_KEY_INPUT"), "xr_tunnel_key", "-", view.lang),
                back_row("xr:home", view.lang),
            ]
        )
        return screen(t("XR_SUBS_TITLE"), t("XR_SUBS_SUBTITLE"), blocks, buttons, icon="link")
    if state.tunnel_expired and not view.error:
        blocks.append(quote(bold(t("TAILNET_EXPIRED_NOTE"))))
    elif approval_url and not domain_ok and not view.error:
        blocks.append(quote(bold(approval_prompt_text(t, approval_url))))
    else:
        exp_stage, exp_days = tailnet_expiry_stage(state.tunnel_key_expiry, state.tunnel_expired)
        if exp_stage == "7d":
            blocks.append(quote(bold(t("TS_EXPIRY_ALERT_TITLE_7D", days=exp_days))))
        elif exp_stage == "30d":
            blocks.append(quote(bold(t("TS_EXPIRY_ALERT_TITLE_30D", days=exp_days))))
    bundle = view.bundle
    links = [item for item in (bundle.links if bundle is not None else []) if str(item).startswith("vless://")]
    pairs = [
        ("link", t("XR_SUBS_ENABLED"), code(i18n.t("UI_YES" if state.sub_enabled else "UI_NO", view.lang))),
        ("world", t("DOM_TITLE"), code(state.public_base() or t("UI_NOT_SET"))),
        ("plug", t("XR_SUBS_LOCAL_PORT"), code("127.0.0.1:%d" % int(state.sub_port or 0))),
    ]
    if state.tunnel_key_expiry or state.tunnel_expired:
        pairs.append(("clock", t("TAILNET_EXPIRY"), code(tailnet_expiry_label(state.tunnel_key_expiry, state.tunnel_expired, view.lang))))
    if getattr(state, "tunnel_tags", ""):
        pairs.append(("tag", t("TAILSCALE_TAGS_ROW"), code(state.tunnel_tags)))
    pairs.append(("info", t("XR_HOME_INBOUNDS"), code(len(enabled_inbounds))))
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    if domain_ok:
        blocks.append(quote(muted(t("XR_SUBS_PERMANENT_NOTE"))))
    copy_btn = ""
    setup_btn = ""
    if xray_missing and len(enabled_inbounds) == 0:
        blocks.append(quote(bold(t("XR_SUBS_NO_XRAY_NOTE"))))
        setup_btn = row(button(t("XR_SUBS_INSTALL_XRAY"), "xr:core:install", icon="box"))
    elif len(state.inbounds) == 0:
        blocks.append(quote(bold(t("XR_SUBS_NO_INBOUNDS_NOTE"))))
        setup_btn = row(button(t("XR_SUBS_CREATE_INBOUND"), "xr:new", icon="add"))
    elif len(enabled_inbounds) == 0:
        blocks.append(quote(bold(t("XR_SUBS_INBOUNDS_OFF_NOTE"))))
        setup_btn = row(button(t("XR_BTN_INBOUNDS_LIST"), "xr:list", icon="folder"))
    elif domain_ok:
        host = state.address(view.address)
        if bundle is not None:
            url = subs.url_of(bundle, host, state.sub_port, state.public_base())
        else:
            sub_id, sub_key = state.ensure_sub_all()
            url = f"{state.public_base().rstrip('/')}/{sub_id}/{sub_key}"
        if url:
            blocks.append(long_block(t("XR_SUBS_JSON_TITLE"), url))
            copy_btn = copy_row(t("SUB_COPY"), url, icon="copy")
        if not host and not links:
            blocks.append(quote(muted(t("XR_SUBS_NO_IP_NOTE"))))
    if not domain_ok and not has_live_node:
        blocks.append(tailscale_guide_block(t, open_=bool(state.tunnel_expired)))
    buttons = []
    if setup_btn:
        buttons.append(setup_btn)
    if copy_btn:
        buttons.append(copy_btn)
    has_approve_btn = bool(approval_url and approval_url.startswith("https://") and not domain_ok)
    if has_approve_btn:
        buttons.append(row(link_button(t("TAILSCALE_APPROVE_BTN"), approval_url, icon="ok")))
    if domain_ok:
        buttons.append(row(button(t("DOM_OFF"), "xr:dom:off", icon="stop")))
    elif not state.tunnel_expired:
        buttons.append(row(button(t("DOM_UP"), "xr:dom:up", icon="world")))
    if not has_approve_btn and not domain_ok:
        buttons.append(row(link_button(t("TAILSCALE_CONSOLE_BTN"), TAILSCALE_NEW_LINUX_URL, icon="world")))
    buttons.append(input_row(t("DOM_KEY_INPUT"), "xr_tunnel_key", "-", view.lang))
    buttons.append(back_row("xr:home", view.lang))
    return screen(t("XR_SUBS_TITLE"), t("XR_SUBS_SUBTITLE"), blocks, buttons, icon="link")


def core_screen(view: XrayView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    core = view.core
    if core:
        pairs = [
            ("xray", t("XR_CORE_INSTALLED"), code(i18n.t("UI_YES" if core.get("installed") else "UI_NO", view.lang))),
            ("tag", t("XR_CORE_VERSION"), code(core.get("version", "") or t("UI_NONE"))),
            ("xray", t("XR_CORE_SERVICE"), code(core.get("service", "") or t("UI_NONE"))),
            ("xray", t("XR_CORE_INBOUNDS"), code(core.get("inbounds", 0))),
            ("xray", t("XR_CORE_LISTENING"), code(", ".join(str(item) for item in core.get("listening") or []) or t("UI_NONE"))),
        ]
        blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    else:
        blocks.append(quote(muted(t("XR_CORE_UNKNOWN"))))
    buttons = [
        row(button(t("XR_CORE_INSTALL"), "xr:core:install", icon="box"), button(t("XR_CORE_APPLY"), "xr:core:apply", icon="save")),
        row(button(t("XR_CORE_RESTART"), "xr:core:restart", icon="restart"), button(t("XR_CORE_STOP"), "xr:core:stop", icon="stop")),
        row(button(t("XR_CORE_PURGE"), "xr:core:purge", icon="delete"), button(t("UI_REFRESH"), "xr:check", icon="scan")),
        version_row(view.state.version, view.lang, view.state.pinned()),
        back_row("xr:home", view.lang),
    ]
    return screen(t("XR_CORE_TITLE"), t("XR_CORE_SUBTITLE"), blocks, buttons, icon="xray")


def version_row(current: str = "", lang: str = i18n.DEFAULT_LANGUAGE, pinned: str = "") -> str:
    t = i18n.translator(lang)
    return row(
        button(t("XR_VERSION_LATEST"), "xr:core:ver:latest", icon="update"),
        button(t("XR_VERSION_PINNED", version=pinned), "xr:core:ver:pin", icon="pin"),
    )


def scan_screen(view: XrayView, results: list[ScanResult] | None = None) -> Any:
    t = view.tr()
    state = view.state
    blocks = banner(view, t)
    rows = results if results is not None else [ScanResult.from_dict(item) for item in state.scan_results]
    blocks.append(f"<p>{t('XR_SCAN_TARGETS', count=code(len(state.scan_targets)))}</p>")
    blocks.append(f"<p>{t('XR_SCAN_PROBE', sni=code(state.scan_sni or t('UI_NONE')), xver=code(state.scan_xver))}</p>")
    blocks.append(pre("\n".join(state.scan_targets[:12]) or t("UI_NONE")))
    mismatch_btn = ""
    if rows:
        pairs = []
        for item in rows[:10]:
            mark = t("XR_SCAN_FEASIBLE") if item.feasible else t("XR_SCAN_INFEASIBLE")
            name = (item.server_names[0] if item.server_names else "") or item.host or item.target
            group = item.pq_group or t("XR_SCAN_NO_PQ")
            pairs.append(("radar" if item.feasible else "warn", item.target, t("XR_SCAN_ROW", mark=mark, latency=item.latency_ms, group=group, name=name)))
        blocks.append(table(pairs, (t("XR_SCAN_TARGET"), t("XR_SCAN_RESULT"))))
        best = next((item for item in rows if item.feasible), None)
        focus = best or rows[0]
        if best is not None:
            blocks.append(quote(muted(t("XR_SCAN_BEST", target=best.target, latency=best.latency_ms))))
        blocks.append(fit_table(t, focus))
        blocks.append(quote(muted(group_line(t, focus))))
        inbound = next((item for item in state.inbounds if item.security in {"reality", "tls"}), None)
        if inbound is not None:
            kind = inbound.security_kind()
            ok, _ = security_fit(focus, kind)
            blocks.append(
                table(
                    [
                        ("shield", t("XR_SEC_CURRENT"), code(security_label(kind, view.lang))),
                        ("info", t("XR_SEC_TARGET"), code(focus.target)),
                        ("lock" if ok else "warn", t("XR_SCAN_FIT"), t("XR_SCAN_FIT_YES") if ok else t("XR_SCAN_FIT_NO")),
                    ],
                    (t("XR_SCAN_FIT"), t("UI_VALUE")),
                )
            )
            if not ok:
                blocks.append(quote(muted_html(t("XR_SCAN_MISMATCH_BODY", target=bold(focus.target), security=bold(security_label(kind, view.lang))))))
                blocks.append(quote(muted(t("XR_SCAN_MISMATCH_SUBTITLE"))))
                mismatch_btn = row(button(t("XR_SCAN_SWITCH_OPEN"), f"xr:scan:fit:{rows.index(focus)}", icon="warn"))
    else:
        blocks.append(quote(muted(t("XR_SCAN_EMPTY"))))
    buttons = [
        row(button(t("XR_SCAN_RUN"), "xr:scan:run", icon="radar"), button(t("XR_SCAN_MY_TARGETS"), "xr:scan:targets", icon="target")),
        input_row(t("XR_SCAN_OWN_TARGET"), "xr_scan_manual", "-", view.lang),
        row(button(t("XR_SCAN_RESET"), "xr:scan:reset", icon="refresh")),
        input_row(t("SET_SCAN_SNI"), "xr_scan_sni", "-", view.lang),
        input_row(t("SET_SCAN_XVER"), "xr_scan_xver", "-", view.lang),
    ]
    if mismatch_btn:
        buttons.insert(1, mismatch_btn)
    if rows:
        buttons.insert(1, row(*[button(t("XR_SCAN_USE", target=item.target), f"xr:scan:use:{index}", icon="ok") for index, item in enumerate(rows[:3])]))
    buttons.append(back_row("xr:home", view.lang))
    return screen(t("XR_SCAN_TITLE"), t("XR_SCAN_SUBTITLE"), blocks, buttons, icon="scan")


SECURITY_LABELS = {
    "reality": "XR_SEC_KIND_REALITY",
    "reality-x25519mlkem768": "XR_SEC_KIND_REALITY_PQ",
    "reality-p256mlkem768": "XR_SEC_KIND_REALITY_P256",
    "reality-mldsa65": "XR_SEC_KIND_REALITY_MLDSA",
    "reality-mldsa65-x25519mlkem768": "XR_SEC_KIND_REALITY_MLDSA_PQ",
    "tls": "XR_SEC_KIND_TLS",
    "tls-x25519mlkem768": "XR_SEC_KIND_TLS_PQ",
    "tls-p256mlkem768": "XR_SEC_KIND_TLS_P256",
}
SECURITY_ICONS = {
    "reality": "lock",
    "reality-x25519mlkem768": "shield",
    "reality-p256mlkem768": "shield",
    "reality-mldsa65": "star",
    "reality-mldsa65-x25519mlkem768": "star",
    "tls": "world",
    "tls-x25519mlkem768": "world",
    "tls-p256mlkem768": "world",
}


def security_label(kind: str, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    try:
        name = canonical_kind(kind)
    except ValueError:
        name = "reality"
    return i18n.t(SECURITY_LABELS.get(name, "XR_SEC_KIND_REALITY"), lang)


def group_line(t: Any, result: ScanResult) -> str:
    names = result.pq_group_names()
    return t("XR_SCAN_GROUPS", groups=", ".join(names)) if names else t("XR_SCAN_GROUPS_NONE")


def fit_table(t: Any, result: ScanResult) -> Any:
    rows = [
        (
            SECURITY_ICONS[kind],
            t(SECURITY_LABELS[kind]),
            t("XR_SCAN_FIT_YES") if ok else (f"{t('XR_SCAN_FIT_NO')} ({note})" if note else t("XR_SCAN_FIT_NO")),
        )
        for kind, ok, note in security_fits(result)
    ]
    return table(rows, (t("XR_SCAN_FIT"), t("UI_VALUE")))


def scan_mismatch_screen(view: XrayView, result: ScanResult, inbound: XrayInbound, index: int = 0) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    current = inbound.security_kind()
    ok, note = security_fit(result, current)
    blocks.append(quote(bold(t("XR_SCAN_MISMATCH_BODY", target=result.target, security=security_label(current, view.lang)))))
    blocks.append(
        table(
            [
                ("target", t("XR_SEC_TARGET"), code(result.target)),
                ("shield", t("XR_SEC_CURRENT"), code(security_label(current, view.lang))),
                ("info", t("XR_SCAN_FIT"), muted(note)),
            ],
            (t("XR_SEC_TITLE"), t("UI_VALUE")),
        )
    )
    if kind_has_mldsa(current) and not result.ml_dsa_ready:
        blocks.append(quote(muted_html(t("XR_SCAN_MISMATCH_CHAIN", length=bold(result.cert_chain_bytes), min=bold(ML_DSA65_CHAIN_MIN)))))
    blocks.append(quote(muted(group_line(t, result))))
    blocks.append(f"<p>{bold(t('XR_SCAN_MISMATCH_FITS'))}</p>")
    blocks.append(fit_table(t, result))
    blocks.append(quote(muted(t("XR_SCAN_MISMATCH_NOTE"))))
    available = [kind for kind, ok, _ in security_fits(result) if ok and kind != current]
    buttons = []
    if available:
        for start in range(0, len(available), 2):
            buttons.append(
                row(*[button(t("XR_SCAN_SWITCH", security=security_label(kind, view.lang)), f"xr:scan:sec:{kind}:{index}", icon=SECURITY_ICONS[kind]) for kind in available[start : start + 2]])
            )
    else:
        blocks.append(quote(muted(t("XR_SCAN_SEC_NOTHING"))))
    buttons.append(row(button(t("XR_SCAN_KEEP"), "xr:scan", icon="back"), button(t("UI_HOME"), "nav:home", icon="home")))
    return screen(t("XR_SCAN_MISMATCH_TITLE"), t("XR_SCAN_MISMATCH_SUBTITLE"), blocks, buttons, icon="warn")


def domain_screen(view: XrayView, tunnel: Any = None, key_mask: str = "") -> Any:
    t = view.tr()
    state = view.state
    mask = key_mask or view.key_mask
    if not mask and not state.tunnel_enabled and not state.tunnel_expired and tunnel is None:
        return subs_screen(view, [])
    blocks = banner(view, t)
    expired = bool(getattr(tunnel, "expired", False)) if tunnel is not None else bool(state.tunnel_expired)
    expiry_raw = str(getattr(tunnel, "key_expiry", "") or state.tunnel_key_expiry)
    if expired:
        blocks.append(quote(bold(t("TAILNET_EXPIRED_NOTE"))))
    state_name = t("DOM_STATE_ON") if state.tunnel_enabled and not expired and state.tunnel_host else t("DOM_STATE_OFF")
    pairs = [
        ("world", t("DOM_STATE"), code(state_name)),
        ("link", t("DOM_HOST"), code(state.public_base() or state.tunnel_host or t("UI_NONE"))),
        ("key", t("DOM_KEY_SET"), code(mask or t("UI_NOT_SET"))),
    ]
    if expiry_raw or expired:
        pairs.append(("clock", t("TAILNET_EXPIRY"), code(tailnet_expiry_label(expiry_raw, expired, view.lang))))
    if tunnel is not None and getattr(tunnel, "url", ""):
        pairs.append(("world", t("DOM_URL"), code(tunnel.url)))
    blocks.append(table(pairs, (t("DOM_TITLE"), t("UI_VALUE"))))
    blocks.append(tailscale_guide_block(t, open_=False))
    approval_url = str(getattr(state, "tunnel_approval_url", "") or "").strip()
    buttons = []
    if approval_url and approval_url.startswith("https://"):
        buttons.append(row(link_button(t("TAILSCALE_APPROVE_BTN"), approval_url, icon="ok")))
    buttons.extend(
        [
            row(button(t("DOM_UP"), "xr:dom:up", icon="world"), button(t("DOM_OFF"), "xr:dom:off", icon="stop")),
            row(link_button(t("TAILSCALE_CONSOLE_BTN"), TAILSCALE_NEW_LINUX_URL, icon="world")),
            input_row(t("DOM_KEY_INPUT"), "xr_tunnel_key", "-", view.lang),
            back_row("xr:home", view.lang),
        ]
    )
    return screen(t("DOM_TITLE"), t("DOM_SUBTITLE"), blocks, buttons, icon="world")


def encryption_screen(view: XrayView, inbound: XrayInbound | None) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if inbound is None:
        blocks.append(quote(muted(t("XR_CHECK_MISSING"))))
        buttons = [back_row("xr:home", view.lang)]
        return screen(t("XR_ENC_TITLE"), t("XR_ENC_SUBTITLE"), blocks, buttons, icon="lock")
    enc = inbound.encryption
    active = "%s/%s" % (enc.mode, enc.auth_kind())
    pairs = [
        ("lock", t("XR_ENC_HANDSHAKE"), code(enc.label())),
        ("key", t("XR_ENC_AUTH"), code(enc.auth_kind())),
        ("tag", t("XR_ENC_MODE"), code(enc.mode)),
        ("clock", t("XR_ENC_TICKET"), code(enc.ticket)),
        ("shield", t("XR_ENC_PADDING"), code(enc.padding or t("UI_NONE"))),
        ("save", t("XR_ENC_PRIVATE"), code("%d chars" % len(enc.private_key or ""))),
        ("world", t("XR_ENC_PUBLIC"), code("%d chars" % len(enc.public_key or ""))),
    ]
    blocks.append(table(pairs, (t("XR_ENC_TITLE"), t("UI_VALUE"))))
    rows = []
    for combo in VLESS_COMBOS:
        mark = "ok" if combo == active else "info"
        rows.append((mark, combo.split("/")[0], code(combo if combo != active else combo + " " + t("XR_ENC_ACTIVE"))))
    blocks.append(table(rows, (t("XR_ENC_COMBO"), t("XR_ENC_KIND"))))
    blocks.append(quote(muted(t("XR_ENC_NOTE"))))
    buttons = []
    for combo in VLESS_COMBOS:
        mode, auth = combo.split("/")
        buttons.append(button("%s" % combo, "xr:enc:%s:%s/%s" % (inbound.id, mode, auth), icon="key" if combo == active else ""))
    rows_out = [row(buttons[index], buttons[index + 1]) for index in range(0, len(buttons), 2)]
    rows_out.append(back_row(f"xr:in:{inbound.id}", view.lang))
    return screen(t("XR_ENC_TITLE"), t("XR_ENC_SUBTITLE"), blocks, rows_out, icon="lock")


def target_check_screen(view: XrayView, inbound: XrayInbound, result: ScanResult | None = None) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if inbound is None or result is None:
        blocks.append(quote(muted(t("XR_CHECK_MISSING"))))
        buttons = [back_row("xr:home", view.lang)]
        return screen(t("XR_CHECK_TITLE"), t("XR_CHECK_SUBTITLE"), blocks, buttons, icon="scan")
    kind = inbound.security_kind()
    label = security_label(kind, view.lang)
    ok, note = security_fit(result, kind)
    head = t("XR_CHECK_OK", security=code(label)) if ok else t("XR_CHECK_BAD", security=code(label))
    blocks.append(f"<p>{bold_html(head)}</p>")
    blocks.append(
        table(
            [
                ("target", t("XR_SEC_TARGET"), code(result.target)),
                ("shield", t("XR_SEC_CURRENT"), code(label)),
                ("lock" if ok else "warn", t("XR_SCAN_FIT"), t("XR_SCAN_FIT_YES") if ok else t("XR_SCAN_FIT_NO")),
                ("info", t("UI_HINT"), muted(note)),
                ("tag", t("XR_MLDSA_CHAIN"), code("%d / %d" % (result.cert_chain_bytes, ML_DSA65_CHAIN_MIN))),
                ("world", t("XR_CHECK_PROBE"), code(result.tls_version or t("UI_NONE"))),
            ],
            (t("XR_CHECK_TITLE"), t("UI_VALUE")),
        )
    )
    blocks.append(quote(muted(group_line(t, result))))
    blocks.append(quote(muted(t("XR_CHECK_NOTE"))))
    buttons = [
        row(button(t("XR_CHECK_BTN"), f"xr:fit:{inbound.id}", icon="scan"), button(t("XR_SCAN_SWITCH_OPEN"), "xr:scan", icon="warn")),
        back_row(f"xr:in:{inbound.id}", view.lang),
    ]
    return screen(t("XR_CHECK_TITLE"), t("XR_CHECK_SUBTITLE"), blocks, buttons, icon="scan")


def scan_targets_screen(view: XrayView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(t("XR_TARGETS_NOTE"))))
    blocks.append(pre("\n".join(view.state.scan_targets) or t("UI_NONE")))
    blocks.append(f"<p>{t('XR_TARGETS_CANDIDATES', count=code(len(view.state.candidates())))}</p>")
    blocks.append(pre("\n".join(view.state.candidates()[:12])))
    buttons = [
        input_row(t("XR_TARGETS_EDIT"), "xr_scan_targets", "-", view.lang),
        input_row(t("XR_TARGETS_EDIT_CANDIDATES"), "xr_scan_candidates", "-", view.lang),
        row(button(t("XR_TARGETS_DEFAULT"), "xr:scan:reset", icon="refresh"), button(t("NAV_SCANNER"), "xr:scan", icon="scan")),
        back_row("xr:home", view.lang),
    ]
    return screen(t("XR_TARGETS_TITLE"), t("XR_TARGETS_SUBTITLE"), blocks, buttons, icon="target")


def input_screen(view: XrayView, ident: str, ctx: str = "", back: str = "xr:home") -> Any:
    from . import inline

    t = view.tr()
    item = inline.field(ident)
    blocks = banner(view, t)
    blocks.append(
        table(
            [("tag", t("UI_FIELD"), code(item.label(view.lang))), ("info", t("UI_HINT"), muted(item.hint(view.lang)))],
            (t("UI_FIELD"), t("UI_VALUE")),
        )
    )
    if item.example:
        blocks.append(f"<p>{t('PROMPT_EXAMPLE', example=code(item.example))}</p>")
    blocks.append(quote(muted(t("XR_INPUT_NOTE"))))
    buttons = [
        input_row(t("PROMPT_INPUT"), ident, ctx or "-", view.lang),
        row(button(t("UI_BACK"), back, icon="back"), button(t("NAV_XRAY"), "xr:home", icon="xray")),
    ]
    return screen(t("PROMPT_TITLE"), item.label(view.lang), blocks, buttons, icon="file")


def confirm_screen(view: XrayView, title: str, body: str, action: str, back: str = "xr:home") -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(body)))
    buttons = [row(button(t("UI_CONFIRM"), action, icon="ok"), button(t("UI_CANCEL"), back, icon="back"))]
    return screen(title, t("UI_ACTION_IRREVERSIBLE"), blocks, buttons, icon="warn")


def logs_screen(view: XrayView, lines: list[str], tail: int) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(f"<p>{t('LOGS_LAST', count=code(tail))}</p>")
    blocks.append(pre("\n".join(lines) or t("UI_EMPTY")))
    buttons = [
        row(button("50", "xr:logs:50", icon="logs"), button("200", "xr:logs:200", icon="logs"), button("500", "xr:logs:500", icon="logs")),
        row(button(t("UI_REFRESH"), f"xr:logs:{tail}", icon="refresh"), button(t("NAV_CORE"), "xr:core", icon="xray")),
        back_row("xr:home", view.lang),
    ]
    return screen(t("XR_LOGS_TITLE"), t("XR_LOGS_SUBTITLE"), blocks, buttons, icon="logs")


def busy_screen(title: str, lang: str = i18n.DEFAULT_LANGUAGE, steps: list[str] | None = None) -> Any:
    t = i18n.translator(lang)
    blocks = [quote(muted(title))]
    if steps:
        blocks.append(bullet_list([muted(item) for item in steps]))
    return screen(t("XR_TITLE"), t("BUSY_SUBTITLE"), blocks, [], icon="xray")


def default_targets() -> list[str]:
    from .scan import DEFAULT_CANDIDATES

    return list(DEFAULT_CANDIDATES)


def stat_line(inbound: XrayInbound) -> str:
    return f"{inbound.protocol} {inbound.port} {inbound.network} {inbound.security}"


