from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import i18n, inline
from .scan import ScanResult
from .ui import (
    bold,
    bullet_list,
    button,
    code,
    input_row,
    fitted,
    details,
    divider,
    heading,
    inline_button,
    muted,
    pre,
    quote,
    row,
    screen,
    table,
)
from .xray import (
    FINGERPRINTS,
    NETWORKS,
    SECURITIES,
    SUB_SEGMENT_LEN,
    XrayInbound,
    XrayState,
    relevant_fields,
    summary,
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
    return row(button(i18n.t("UI_HOME", lang), target, icon="home"), button(i18n.t("NAV_XRAY", lang), "xr:home", icon="xray"))


def home(view: XrayView) -> Any:
    t = view.tr()
    state = view.state
    blocks = banner(view, t)
    blocks.append(f"<p>{core_line(view, t)}</p>")
    pairs = [
        ("info", t("XR_HOME_INBOUNDS"), code(len(state.inbounds))),
        ("users", t("XR_HOME_CLIENTS"), code(sum(len(item.clients) for item in state.inbounds))),
        ("link", t("XR_HOME_SUBS"), code(t("UI_ON") if state.sub_enabled else t("UI_OFF"))),
        ("link", t("XR_HOME_SUB_PORT"), code(state.sub_port)),
        ("tag", t("XR_HOME_VERSION"), code(state.version)),
        ("settings", t("XR_HOME_ENCRYPTION"), code(state.encryption_label())),
    ]
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    if state.inbounds:
        rows = []
        for item in state.inbounds:
            mark = t("UI_ON") if item.enable else t("UI_OFF")
            rows.append(("xray", f"{item.id} {item.remark}", f"{item.port} {item.network} {item.security} {mark}"))
        blocks.append(table(rows, (t("XR_HOME_TABLE"), t("XR_HOME_TABLE2"))))
    else:
        blocks.append(quote(muted(t("XR_HOME_EMPTY"))))
    buttons = [
        row(button(t("XR_BTN_NEW"), "xr:new", icon="add"), button(t("NAV_SCANNER"), "xr:scan", icon="scan")),
        row(button(t("NAV_SUBS"), "xr:subs", icon="link"), button(t("NAV_CORE"), "xr:core", icon="xray")),
        row(button(t("NAV_LOGS"), "xr:logs", icon="logs"), button(t("XR_BTN_CHECK"), "xr:check", icon="scan")),
    ]
    if state.inbounds:
        buttons.insert(2, row(*[button(t("XR_BTN_OPEN", remark=item.remark), f"xr:in:{item.id}", icon="module") for item in state.inbounds[:3]]))
    buttons.append(back_row())
    return screen(t("XR_TITLE"), t("XR_SUBTITLE"), blocks, buttons, footer=t("XR_FOOTER"), icon="xray")


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
        back_row(),
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
        back_row(),
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
        row(button(t("XR_BTN_TOGGLE"), f"xr:toggle:{inbound.id}", icon="update"), button(t("UI_DELETE"), f"xr:del:{inbound.id}", icon="delete")),
        back_row("xr:home"),
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
        blocks.append(heading(name, 4))
        button_html, block_html = fitted(t("XR_LINKS_COPY", name=name), link, view.lang)
        if button_html:
            copyable.append(row(button_html))
            blocks.append(pre(link))
        elif block_html:
            blocks.append(block_html)
    buttons = [
        *copyable,
        row(button(t("UI_REFRESH"), f"xr:link:{inbound.id}", icon="refresh"), button(t("XR_BTN_INBOUND"), f"xr:in:{inbound.id}", icon="xray")),
        back_row("xr:home"),
    ]
    return screen(t("XR_LINKS_TITLE"), inbound.remark, blocks, buttons, icon="link")


def client_screen(view: XrayView, inbound: XrayInbound, email: str, link: str, sub_url: str = "", sub_path: str = "") -> Any:
    t = view.tr()
    client = inbound.client(email)
    blocks = banner(view, t)
    if client is None:
        blocks.append(quote(bold(t("XR_CLIENT_MISSING"))))
        return screen(t("XR_CLIENT_TITLE"), email, blocks, [back_row(f"xr:in:{inbound.id}")], icon="user")
    pairs = [
        ("user", t("XR_CLIENT_NAME"), code(client.email)),
        ("user", t("XR_CLIENT_ENABLED"), code(i18n.t("UI_YES" if client.enable else "UI_NO", view.lang))),
        ("user", t("XR_CLIENT_ID"), code(client.ident)),
        ("user", t("XR_CLIENT_FLOW"), code(client.flow or t("UI_NONE"))),
        ("user", t("XR_CLIENT_LIMIT"), code(client.limit_ip)),
        ("chart", t("XR_CLIENT_TRAFFIC"), code(client.total_gb)),
    ]
    if sub_path:
        pairs.append(("link", t("XR_CLIENT_SUB_PATH"), code(sub_path)))
    blocks.append(table(pairs, (t("UI_FIELD"), t("UI_VALUE"))))
    link_button, link_block = fitted(t("XR_CLIENT_COPY"), link, view.lang)
    if link_block:
        blocks.append(link_block)
    sub_button, sub_block = fitted(t("XR_CLIENT_SUB"), sub_url, view.lang)
    if sub_block:
        blocks.append(sub_block)
    buttons = [
        link_button,
        row(button(t("XR_CLIENT_SUB"), f"xr:sub:{inbound.id}:{client.email}", icon="link"), button(t("XR_CLIENT_NEW_PATH"), f"xr:subrot:{inbound.id}:{client.email}", icon="refresh")),
        row(button(t("XR_CLIENT_FLOW_BTN"), f"xr:clflow:{inbound.id}:{client.email}", icon="route"), button(t("XR_CLIENT_LIMIT_BTN"), f"xr:cllimit:{inbound.id}:{client.email}", icon="speed")),
        row(button(t("UI_DELETE_CLIENT"), f"xr:cldel:{inbound.id}:{client.email}", icon="delete"), button(t("XR_BTN_INBOUND"), f"xr:in:{inbound.id}", icon="xray")),
        back_row("xr:home"),
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
        back_row(f"xr:in:{inbound.id}"),
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
    pairs = [
        ("link", t("XR_SUBS_ENABLED"), code(i18n.t("UI_YES" if state.sub_enabled else "UI_NO", view.lang))),
        ("link", t("XR_SUBS_PORT"), code(state.sub_port)),
        ("link", t("XR_SUBS_ADDRESS"), code(state.sub_address or t("UI_NOT_SET"))),
        ("link", t("XR_SUBS_FORMAT"), code(state.sub_path_pattern())),
        ("clock", t("SET_SUB_REFRESH"), code(state.sub_refresh)),
        ("link", t("SET_SUB_SUPPORT"), code(state.support_url() or t("UI_NOT_SET"))),
        ("bell", t("SET_SUB_ANNOUNCE"), code(state.announce() or t("UI_NOT_SET"))),
    ]
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    if not rows_data:
        blocks.append(quote(muted(t("XR_SUBS_EMPTY"))))
    if not state.address(view.address):
        blocks.append(quote(bold(t("XR_SUBS_NO_ADDRESS"))))
    blocks.append(quote(muted(t("XR_SUBS_NOTE", length=SUB_SEGMENT_LEN))))
    blocks.append(f"<p>{bold(t('XR_SUBS_RAW'))} {muted(t('XR_SUBS_RAW_NOTE'))}</p>")
    bundle = view.bundle
    if bundle is not None and bundle.links:
        host = state.address(view.address)
        quota = bundle.quota()
        pairs = [
            ("link", t("XR_SUBS_ONE"), code(bundle.safe_url(host, state.sub_port) or t("UI_NOT_SET"))),
            ("file", t("XR_SUBS_JSON"), code(bundle.safe_json_url(host, state.sub_port) or t("UI_NOT_SET"))),
            ("box", t("XR_SUBS_TABLE_CLIENT"), code("%d" % len(bundle.links))),
            ("chart", t("XR_SUBS_TRAFFIC"), code(traffic_line(t, quota))),
        ]
        blocks.append(table(pairs, (t("XR_SUBS_ONE"), t("UI_VALUE"))))
        blocks.append(f"<p>{muted(t('XR_SUBS_ALL_NOTE'))}</p>")
        blocks.append(f"<p>{bold(t('XR_SUBS_LINKS_TITLE'))}</p>")
        shown = bundle.links[:LINK_PREVIEW]
        blocks.append(pre("\n".join(shown), "vless"))
        if len(bundle.links) > len(shown):
            blocks.append(quote(muted(t("XR_SUBS_LINKS_MORE", count=len(bundle.links) - len(shown)))))
    buttons = [
        row(button(t("XR_SUBS_APPLY"), "xr:subs:apply", icon="save"), button(t("XR_SUBS_STATUS"), "xr:subs:status", icon="info")),
        row(button(t("XR_SUBS_STOP"), "xr:subs:stop", icon="stop"), button(t("XR_SUBS_ROTATE"), "xr:subs:rotate", icon="refresh")),
        input_row(t("XR_SUBS_PORT"), "xr_sub_port", "-", view.lang),
        input_row(t("XR_SUBS_ADDRESS") if state.address(view.address) else t("XR_SUBS_SET_ADDRESS"), "xr_sub_address", "-", view.lang),
        row(button(t("XR_SUBS_TRAFFIC_BTN"), "xr:subs:traffic", icon="chart")),
        input_row(t("SET_SUB_REFRESH"), "xr_sub_refresh", "-", view.lang),
        input_row(t("SET_SUB_SUPPORT"), "xr_sub_support", "-", view.lang),
        input_row(t("SET_SUB_ANNOUNCE"), "xr_sub_announce", "-", view.lang),
        back_row("xr:home"),
    ]
    return screen(t("XR_SUBS_TITLE"), t("XR_SUBS_SUBTITLE"), blocks, buttons, icon="link")


def core_screen(view: XrayView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    core = view.core
    if core:
        pairs = [
            ("xray", t("XR_CORE_INSTALLED"), code(i18n.t("UI_YES" if core.get("installed") else "UI_NO", view.lang))),
            ("tag", t("XR_CORE_VERSION"), code(core.get("version", "") or t("UI_NONE"))),
            ("tag", t("XR_CORE_PINNED"), code(core.get("pinned", "") or "")),
            ("xray", t("XR_CORE_SERVICE"), code(core.get("service", "") or t("UI_NONE"))),
            ("xray", t("XR_CORE_SYSTEMD"), code(i18n.t("UI_YES" if core.get("systemd") else "UI_NO", view.lang))),
            ("xray", t("XR_CORE_ARCH"), code(core.get("arch", "") or "")),
            ("xray", t("XR_CORE_BINARY"), code(core.get("core_path", "") or "")),
            ("xray", t("XR_CORE_CONFIG"), code(core.get("config_path", "") or "")),
            ("xray", t("XR_CORE_INBOUNDS"), code(core.get("inbounds", 0))),
            ("xray", t("XR_CORE_PORTS"), code(", ".join(str(item) for item in core.get("ports") or []) or t("UI_NONE"))),
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
        back_row("xr:home"),
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
    if rows:
        pairs = []
        for item in rows[:10]:
            mark = t("XR_SCAN_FEASIBLE") if item.feasible else t("XR_SCAN_INFEASIBLE")
            name = (item.server_names[0] if item.server_names else "") or item.host or item.target
            group = item.pq_group or t("XR_SCAN_NO_PQ")
            pairs.append(("radar" if item.feasible else "warn", item.target, t("XR_SCAN_ROW", mark=mark, latency=item.latency_ms, group=group, name=name)))
        blocks.append(table(pairs, (t("XR_SCAN_TARGET"), t("XR_SCAN_RESULT"))))
        best = next((item for item in rows if item.feasible), None)
        if best is not None:
            blocks.append(quote(muted(t("XR_SCAN_BEST", target=best.target, latency=best.latency_ms))))
    else:
        blocks.append(quote(muted(t("XR_SCAN_EMPTY"))))
    buttons = [
        row(button(t("XR_SCAN_RUN"), "xr:scan:run", icon="radar"), button(t("XR_SCAN_MY_TARGETS"), "xr:scan:targets", icon="target")),
        input_row(t("XR_SCAN_OWN_TARGET"), "xr_scan_manual", "-", view.lang),
        row(button(t("XR_SCAN_RESET"), "xr:scan:reset", icon="refresh")),
        input_row(t("SET_SCAN_SNI"), "xr_scan_sni", "-", view.lang),
        input_row(t("SET_SCAN_XVER"), "xr_scan_xver", "-", view.lang),
    ]
    if rows:
        buttons.insert(1, row(*[button(t("XR_SCAN_USE", target=item.target), f"xr:scan:use:{index}", icon="ok") for index, item in enumerate(rows[:3])]))
    buttons.append(back_row("xr:home"))
    return screen(t("XR_SCAN_TITLE"), t("XR_SCAN_SUBTITLE"), blocks, buttons, icon="scan")


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
        back_row("xr:home"),
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
        back_row("xr:home"),
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


def fingerprint_note(lang: str) -> str:
    return divider() + "<p>" + i18n.t("XR_FINGERPRINTS", lang, values=", ".join(FINGERPRINTS)) + "</p>"
