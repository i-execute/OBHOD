from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import i18n, inline, subs
from .scan import ML_DSA65_CHAIN_MIN, ScanResult, canonical_kind, kind_has_mldsa, security_fit, security_fits
from .ui import (
    bold,
    bold_html,
    bullet_list,
    button,
    code,
    input_row,
    details,
    copy_row,
    heading,
    long_block,
    inline_button,
    muted,
    muted_html,
    pre,
    quote,
    row,
    screen,
    table,
)
from .xray import (

    NETWORKS,
    SECURITIES,
    VLESS_COMBOS,
    XrayInbound,
    XrayState,
    relevant_fields,
    summary,
    tailnet_expiry_label,
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
    pairs = [
        ("info", t("XR_HOME_INBOUNDS"), code(len(state.inbounds))),
        ("users", t("XR_HOME_CLIENTS"), code(sum(len(item.clients) for item in state.inbounds))),
        ("link", t("XR_HOME_SUBS"), code(t("UI_ON") if state.sub_enabled else t("UI_OFF"))),
        ("settings", t("XR_HOME_ENCRYPTION"), code(state.encryption_label())),
    ]
    if state.public_base():
        pairs.append(("world", t("DOM_TITLE"), code(state.public_base())))
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    if state.inbounds:
        rows = []
        for item in state.inbounds:
            mark = t("UI_ON") if item.enable else t("UI_OFF")
            rows.append(("xray", f"{item.id} {item.remark}", f"{item.port} {item.network} {item.security} {mark}"))
        blocks.append(table(rows, (t("XR_HOME_TABLE"), t("XR_HOME_TABLE2"))))
    else:
        blocks.append(quote(muted(t("XR_HOME_EMPTY"))))
    core_installed = bool((view.core or {}).get("installed"))
    core_quick_btn = (
        button(t("XR_CORE_PURGE"), "xr:core:purge", icon="delete")
        if core_installed
        else button(t("XR_CORE_INSTALL"), "xr:core:install", icon="box")
    )
    buttons = [
        row(button(t("XR_BTN_NEW"), "xr:new", icon="add"), button(t("NAV_SUBS"), "xr:subs", icon="link")),
        row(button(t("NAV_CORE"), "xr:core", icon="xray"), core_quick_btn),
        row(button(t("XR_BTN_CHECK"), "xr:check", icon="scan"), button(t("NAV_LOGS"), "xr:logs", icon="logs")),
    ]
    if state.inbounds:
        buttons.insert(1, row(*[button(t("XR_BTN_OPEN", remark=item.remark), f"xr:in:{item.id}", icon="module") for item in state.inbounds[:3]]))
    buttons.append(back_row("nav:home", view.lang))
    return screen(t("XR_TITLE"), t("XR_SUBTITLE"), blocks, buttons, icon="xray")


def new_menu(view: XrayView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(t("XR_NEW_NOTE"))))
    blocks.append(
        bullet_list(
            [
                t("XR_NEW_NETWORKS", networks=" ".join(code(item) for item in NETWORKS)),
                t("XR_NEW_SECURITY", security=" ".join(code(item) for item in SECURITIES)),
                t("XR_NEW_ENCRYPTION", encryption=code("mlkem768x25519plus")),
                t("XR_NEW_SIGNATURE", signature=code("ml-dsa-65")),
            ]
        )
    )
    buttons = [
        row(button("raw reality", "xr:new:raw:reality", icon="add"), button("raw tls", "xr:new:raw:tls", icon="add")),
        row(button("grpc reality", "xr:new:grpc:reality", icon="add"), button("grpc tls", "xr:new:grpc:tls", icon="add")),
        row(button("xhttp reality", "xr:new:xhttp:reality", icon="add"), button("xhttp tls", "xr:new:xhttp:tls", icon="add")),
        row(button("raw none", "xr:new:raw:none", icon="add"), button(t("XR_BTN_CUSTOM"), "xr:custom", icon="tools")),
        back_row("xr:home", view.lang),
    ]
    return screen(t("XR_NEW_TITLE"), t("XR_NEW_SUBTITLE"), blocks, buttons, icon="add")


def custom_menu(view: XrayView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    network = grab(view, "network")
    security = grab(view, "security")
    blocks.append(
        f"<p>{t('XR_CUSTOM_STATE', network=code(network), security=code(security), port=code(grab(view, 'port')))}</p>"
    )
    fields = relevant_fields(security or "reality", network or "raw")
    names = ", ".join(code(field_label(item, view.lang)) for item in fields) or muted(t("XR_CUSTOM_NOTHING"))
    blocks.append(f"<p>{t('XR_CUSTOM_NEEDS', fields=names)}</p>")
    buttons = [
        row(button(t("XR_CUSTOM_NETWORK"), "xr:cyc:network", icon="settings"), button(t("XR_CUSTOM_SECURITY"), "xr:cyc:security", icon="shield")),
        row(button(t("UI_CREATE"), "xr:create", icon="add")),
        input_row(t("XR_CUSTOM_PORT"), "xr_port", "-", view.lang),
        back_row("xr:new", view.lang),
    ]
    return screen(t("XR_CUSTOM_TITLE"), t("XR_CUSTOM_SUBTITLE"), blocks, buttons, icon="tools")


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
    blocks.append(f"<h3>{bold(inbound.remark)}</h3>")
    blocks.append(table(summary(inbound, view.lang), (t("UI_PARAM"), t("UI_VALUE"))))
    fields = relevant_fields(inbound.security, inbound.network)
    blocks.append(heading(t("XR_INBOUND_RELEVANT"), 4))
    blocks.append(table(field_pairs(inbound, fields, view.lang), (t("UI_FIELD"), t("UI_VALUE"))))
    rest = tuple(item for item in ALL_FIELDS if item not in fields)
    if rest:
        blocks.append(details(t("XR_INBOUND_REST"), table(field_pairs(inbound, rest, view.lang), (t("UI_FIELD"), t("UI_VALUE")))))
    clients = [item.email for item in inbound.clients]
    named = ", ".join(code(item) for item in clients[:6]) or muted(t("UI_NONE"))
    blocks.append(f"<p>{t('XR_INBOUND_CLIENTS', count=code(len(clients)), names=named)}</p>")
    buttons = [
        row(button(t("XR_BTN_LINKS"), f"xr:link:{inbound.id}", icon="link"), button(t("XR_BTN_ADD_CLIENT"), f"xr:cladd:{inbound.id}", icon="add")),
        row(*[button(t("XR_BTN_CLIENT", email=item.email), f"xr:cl:{inbound.id}:{item.email}", icon="user") for item in inbound.clients[:3]]),
        row(button(t("XR_BTN_PORT"), f"xr:edit:{inbound.id}:xr_port", icon="plug"), button(t("XR_BTN_NAME"), f"xr:edit:{inbound.id}:xr_remark", icon="tag")),
        field_row(inbound, view.lang),
        row(button(t("XR_BTN_REALITY_KEYS"), f"xr:keys:{inbound.id}", icon="key"), button(t("XR_BTN_MLDSA"), f"xr:mldsa:{inbound.id}", icon="shield")),
        row(button(t("XR_ENC_TITLE"), f"xr:enc:{inbound.id}", icon="lock")),
        row(button(t("XR_BTN_TOGGLE"), f"xr:toggle:{inbound.id}", icon="update"), button(t("UI_DELETE"), f"xr:del:{inbound.id}", icon="delete")),
        back_row("xr:home", view.lang),
    ]
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


def client_screen(view: XrayView, inbound: XrayInbound, email: str, link: str, sub_url: str = "", sub_path: str = "") -> Any:
    t = view.tr()
    client = inbound.client(email)
    blocks = banner(view, t)
    if client is None:
        blocks.append(quote(bold(t("XR_CLIENT_MISSING"))))
        return screen(t("XR_CLIENT_TITLE"), email, blocks, [back_row(f"xr:in:{inbound.id}", view.lang)], icon="user")
    pairs = [
        ("user", t("XR_CLIENT_NAME"), code(client.email)),
        ("user", t("XR_CLIENT_ENABLED"), code(i18n.t("UI_YES" if client.enable else "UI_NO", view.lang))),
        ("user", t("XR_CLIENT_FLOW"), code(client.flow or t("UI_NONE"))),
        ("user", t("XR_CLIENT_LIMIT"), code(client.limit_ip)),
        ("chart", t("XR_CLIENT_TRAFFIC"), code(client.total_gb)),
    ]
    blocks.append(table(pairs, (t("UI_FIELD"), t("UI_VALUE"))))
    blocks.append(long_block(t("XR_CLIENT_ID"), client.ident))
    if link:
        blocks.append(long_block(t("XR_CLIENT_COPY"), link))
    link_button = copy_row(t("XR_CLIENT_COPY"), link)
    buttons = [
        *([link_button] if link_button else []),
        row(button(t("NAV_SUBS"), "xr:subs", icon="link")),
        row(button(t("XR_CLIENT_FLOW_BTN"), f"xr:clflow:{inbound.id}:{client.email}", icon="route"), button(t("XR_CLIENT_LIMIT_BTN"), f"xr:cllimit:{inbound.id}:{client.email}", icon="speed")),
        row(button(t("UI_DELETE_CLIENT"), f"xr:cldel:{inbound.id}:{client.email}", icon="delete"), button(t("XR_BTN_INBOUND"), f"xr:in:{inbound.id}", icon="xray")),
        back_row("xr:home", view.lang),
    ]
    return screen(t("XR_CLIENT_TITLE"), f"{inbound.remark} / {client.email}", blocks, buttons, icon="user")


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


def subs_screen(view: XrayView, rows_data: list[tuple[str, str, str]]) -> Any:
    t = view.tr()
    state = view.state
    blocks = banner(view, t)
    domain_ok = bool(state.tunnel_enabled and not state.tunnel_expired and state.public_base())
    ready = bool(domain_ok or view.key_mask or state.tunnel_expired)
    if not ready:
        blocks.append(quote(muted(t("XR_SUBS_NO_DOMAIN"))))
        buttons = [
            input_row(t("DOM_KEY_INPUT"), "xr_tunnel_key", "-", view.lang),
            back_row("xr:home", view.lang),
        ]
        return screen(t("XR_SUBS_TITLE"), t("XR_SUBS_SUBTITLE"), blocks, buttons, icon="link")
    if state.tunnel_expired:
        blocks.append(quote(bold(t("TAILNET_EXPIRED_NOTE"))))
    bundle = view.bundle
    links = [item for item in (bundle.links if bundle is not None else []) if str(item).startswith("vless://")]
    pairs = [
        ("link", t("XR_SUBS_ENABLED"), code(i18n.t("UI_YES" if state.sub_enabled else "UI_NO", view.lang))),
        ("world", t("DOM_TITLE"), code(state.public_base() or t("UI_NOT_SET"))),
    ]
    if state.tunnel_key_expiry or state.tunnel_expired:
        pairs.append(("clock", t("TAILNET_EXPIRY"), code(tailnet_expiry_label(state.tunnel_key_expiry, state.tunnel_expired, view.lang))))
    pairs.append(("users", t("XR_HOME_CLIENTS"), code(len(links))))
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    copy_btn = ""
    if bundle is not None and links and domain_ok:
        host = state.address(view.address)
        url = subs.url_of(bundle, host, state.sub_port, state.public_base())
        blocks.append(long_block(t("XR_SUBS_ONE"), url))
        blocks.append(long_block(t("XR_SUBS_LINKS_TITLE"), "\n".join(links[:LINK_PREVIEW])))
        copy_btn = copy_row(t("SUB_COPY"), url, icon="copy")
    elif not links:
        blocks.append(quote(muted(t("XR_SUBS_EMPTY"))))
    buttons = []
    if copy_btn:
        buttons.append(copy_btn)
    if domain_ok:
        buttons.append(row(button(t("XR_SUBS_APPLY"), "xr:subs:apply", icon="save"), button(t("XR_SUBS_ROTATE"), "xr:subs:rotate", icon="refresh")))
        buttons.append(row(button(t("DOM_OFF"), "xr:dom:off", icon="stop")))
    elif not state.tunnel_expired:
        buttons.append(row(button(t("DOM_UP"), "xr:dom:up", icon="world")))
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
    buttons = [
        row(button(t("DOM_UP"), "xr:dom:up", icon="world"), button(t("DOM_OFF"), "xr:dom:off", icon="stop")),
        input_row(t("DOM_KEY_INPUT"), "xr_tunnel_key", "-", view.lang),
        back_row("xr:home", view.lang),
    ]
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


