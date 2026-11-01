from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import i18n
from .freeturn import FtClient, FtConfig, FtShare, FtState
from .ui import (
    bold,
    bullet_list,
    button,
    code,
    input_row,
    fitted,
    long_block,
    muted,
    pre,
    quote,
    row,
    screen,
    table,
)

MAX_CLIENT_BUTTONS = 6


@dataclass
class FtView:
    state: FtState = field(default_factory=FtState)
    draft: FtConfig | None = None
    clients: list[FtClient] = field(default_factory=list)
    share: FtShare | None = None
    notice: str = ""
    error: str = ""
    busy: str = ""
    logs: list[str] = field(default_factory=list)
    link: str = ""
    conf: str = ""
    name: str = ""
    core: str = "xray"
    guard: dict[str, Any] = field(default_factory=dict)
    lang: str = i18n.DEFAULT_LANGUAGE

    def tr(self) -> i18n.Translator:
        return i18n.translator(self.lang)

    @property
    def plan(self) -> FtConfig:
        return self.draft if self.draft is not None else self.state.config


def yes_no(lang: str, value: bool) -> str:
    return i18n.t("UI_YES" if value else "UI_NO", lang)


def banner(view: FtView, t: i18n.Translator) -> list[str]:
    out: list[str] = []
    if view.notice:
        out.append(quote(muted(view.notice)))
    if view.error:
        out.append(quote(bold(view.error)))
    return out


def back_row(lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    return row(button(i18n.t("UI_HOME", lang), "nav:home"), button(i18n.t("NAV_FREETURN", lang), "ft:home"))


def home(view: FtView) -> Any:
    t = view.tr()
    state = view.state
    blocks = banner(view, t)
    if not state.arch and not state.installed:
        blocks.append(quote(muted(t("FT_STATE_UNKNOWN"))))
    pairs = [
        (t("FT_STATE_INSTALLED"), code(yes_no(view.lang, state.installed))),
        (t("FT_STATE_RUNNING"), code(yes_no(view.lang, state.running))),
        (t("FT_STATE_METHOD"), code(state.method or state.config.method)),
        (t("FT_STATE_VERSION"), code(state.version or state.config.version)),
        (t("FT_STATE_ARCH"), code(state.arch or t("FT_STATE_UNKNOWN"))),
        (t("FT_STATE_ROOT"), code(t("FT_STATE_ROOT_YES") if state.root else t("FT_STATE_ROOT_NO"))),
        (t("FT_STATE_KEY"), code(t("FT_STATE_KEY_SERVER") if state.key_present else t("FT_STATE_KEY_MISSING"))),
    ]
    blocks.append(table(pairs, (t("FT_STATE_TITLE"), t("UI_VALUE"))))
    plan = state.config
    blocks.append(
        f"<p>{t('FT_DRAFT_STATE', method=code(plan.method), backend=code(plan.backend), port=code(plan.listen_port), mode=code(plan.mode), obf=code(plan.obf_profile))}</p>"
    )
    if view.clients:
        blocks.append(f"<p>{t('FT_CLIENTS_TITLE')}: {code(len(view.clients))}</p>")
    else:
        blocks.append(quote(muted(t("FT_CLIENTS_EMPTY"))))
    buttons = [
        row(button(t("FT_BTN_CHECK"), "ft:check"), button(t("FT_BTN_PLAN"), "ft:plan")),
        row(button(t("FT_BTN_APPLY"), "ft:apply"), button(t("FT_BTN_CLIENTS"), "ft:clients")),
        row(button(t("FT_BTN_STOP"), "ft:stop"), button(t("FT_BTN_RESTART"), "ft:restart")),
        row(button(t("FT_BTN_LOGS"), "ft:logs"), button(t("FT_BTN_SHARE"), "ft:share")),
        row(button(t("FT_BTN_FW"), "ft:fw")),
        row(button(t("CORE_NAV"), "core:show"), button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("FT_TITLE"), t("FT_SUBTITLE"), blocks, buttons, footer=t("FT_FOOTER"))


def mode_label(t: i18n.Translator, mode: str) -> str:
    name = str(mode or "unknown").strip().upper()
    key = "FT_FW_MODE_%s" % name
    if i18n.has_key(key, t.language):
        return t(key)
    return str(mode or "unknown")[:24]


def fw_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    data = dict(view.guard or {})
    if not data:
        blocks.append(quote(muted(t("FT_FW_UNKNOWN"))))
    else:
        pairs = [
            (t("FT_FW_PORT"), code("%s/%s" % (data.get("port", 0), data.get("proto", "udp")))),
            (t("FT_FW_BACKEND"), code(data.get("backend") or t("UI_NONE"))),
            (t("FT_FW_MODE"), code(mode_label(t, str(data.get("mode", "unknown"))))),
            (t("FT_FW_RULES"), code(data.get("rules", 0))),
            (t("FT_FW_CIDRS"), code(data.get("cidrs", 0))),
        ]
        blocks.append(table(pairs, (t("FT_FW_TITLE"), t("UI_VALUE"))))
        blocks.append(quote(muted(t("FT_FW_NOTE"))))
    buttons = [
        row(button(t("FT_FW_BTN_VK"), "ft:fw:vk"), button(t("FT_FW_BTN_OPEN"), "ft:fw:open")),
        row(button(t("FT_FW_BTN_CLOSE"), "ft:fw:closed"), button(t("UI_REFRESH"), "ft:fw")),
        row(button(t("FT_BTN_HOME"), "ft:home"), button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("FT_FW_TITLE"), t("FT_FW_SUBTITLE"), blocks, buttons, footer=t("FT_FOOTER"))


def plan_screen(view: FtView) -> Any:
    t = view.tr()
    plan = view.plan
    blocks = banner(view, t)
    blocks.append(quote(muted(t("FT_CONFIG_NOTE"))))
    pairs = [
        (t("FT_FIELD_METHOD"), code(plan.method)),
        (t("FT_FIELD_BACKEND"), code(plan.backend)),
        (t("FT_FIELD_LISTEN"), code(plan.listen_port)),
        (t("FT_FIELD_WG_PORT"), code(plan.wg_port)),
        (t("FT_FIELD_WG_NET"), code(plan.wg_net)),
        (t("FT_FIELD_MODE"), code(plan.mode)),
        (t("FT_FIELD_OBF"), code(plan.obf_profile)),
        (t("FT_FIELD_VERSION"), code(plan.version)),
        (t("FT_FIELD_HOST"), code(plan.host or t("FT_STATE_UNKNOWN"))),
    ]
    if plan.backend == "external" and plan.connect:
        pairs.append((t("FT_FIELD_CONNECT"), code(plan.connect)))
    blocks.append(table(pairs, (t("FT_CONFIG_TITLE"), t("UI_VALUE"))))
    blocks.append(
        bullet_list(
            [
                t("FT_HINT_METHOD"),
                t("FT_HINT_BACKEND"),
                t("FT_HINT_MODE"),
                t("FT_HINT_OBF"),
                t("FT_HINT_VERSION"),
            ]
        )
    )
    blocks.append(f"<p>{muted(t('FT_APPLY_NOTE'))}</p>")
    buttons = [
        row(button(t("FT_FIELD_METHOD"), "ft:cyc:method"), button(t("FT_FIELD_BACKEND"), "ft:cyc:backend")),
        row(button(t("FT_FIELD_MODE"), "ft:cyc:mode"), button(t("FT_FIELD_OBF"), "ft:cyc:obf_profile")),
        row(button(t("FT_FIELD_VERSION"), "ft:cyc:version"), button(t("FT_BTN_APPLY"), "ft:apply")),
        input_row(t("FT_PORT_INPUT"), "ft_port", "-", view.lang),
        input_row(t("FT_WG_PORT_INPUT"), "ft_wg_port", "-", view.lang),
        input_row(t("FT_WG_NET_INPUT"), "ft_wg_net", "-", view.lang),
        input_row(t("FT_HOST_INPUT"), "ft_host", "-", view.lang),
        input_row(t("FT_KEY_INPUT"), "ft_key", "-", view.lang),
        back_row(view.lang),
    ]
    return screen(t("FT_CONFIG_TITLE"), t("FT_CONFIG_SUBTITLE"), blocks, buttons)


def clients_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if view.clients:
        rows = []
        for item in view.clients:
            kind = t("FT_CLIENTS_OWNER") if item.owner else t("FT_CLIENTS_GUEST")
            detail = item.ip or "-"
            if item.handshake:
                detail = "%s %s" % (detail, item.handshake)
            rows.append((item.name, "%s %s" % (kind, detail)))
        blocks.append(table(rows, (t("FT_CLIENTS_TITLE"), t("FT_CLIENTS_SUBTITLE"))))
        blocks.append(f"<p>{muted(t('FT_CLIENT_LINK_NOTE'))}</p>")
    else:
        blocks.append(quote(muted(t("FT_CLIENTS_EMPTY"))))
    if view.share is not None and view.share.peer():
        blocks.append(
            table(
                [
                    (t("FT_SHARE_PEER"), code(view.share.peer())),
                    (t("FT_SHARE_MODE"), code(view.share.mode or "-")),
                    (t("FT_SHARE_OBF"), code(view.share.obf_profile or "-")),
                    (t("FT_SHARE_KEY"), code(t("FT_SHARE_KEY_HIDDEN") if view.share.key_present else t("FT_STATE_KEY_MISSING"))),
                ],
                (t("FT_SHARE_TITLE"), t("UI_VALUE")),
            )
        )
    buttons = [input_row(t("FT_BTN_CLIENT_ADD"), "ft_client", "-", view.lang), row(button(t("FT_BTN_REFRESH"), "ft:clients"))]
    for item in view.clients[:MAX_CLIENT_BUTTONS]:
        buttons.append(row(button(item.name, "ft:cl:%s" % item.name)))
    buttons.append(back_row(view.lang))
    return screen(t("FT_CLIENTS_TITLE"), t("FT_CLIENTS_SUBTITLE"), blocks, buttons)


def client_screen(view: FtView, name: str) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(f"<p>{t('FT_CLIENT_LINK_READY')}</p>")
    client = next((item for item in view.clients if item.name == name), None)
    pairs = [
        (t("FT_CLIENTS_SUBTITLE"), code(t("FT_CLIENTS_OWNER") if client is not None and client.owner else t("FT_CLIENTS_GUEST"))),
        (t("FT_CLIENT_ID"), code(client.client_id if client is not None and client.client_id else t("UI_NONE"))),
        (t("FT_CLIENTS_IP"), code(client.ip if client is not None and client.ip else "-")),
        (t("FT_CLIENTS_HANDSHAKE"), code(client.handshake if client is not None and client.handshake else t("FT_CLIENTS_NEVER"))),
    ]
    blocks.append(table(pairs, (t("FT_CLIENT_TITLE", name=name), t("UI_VALUE"))))
    blocks.append(f"<p>{muted(t('FT_CLIENT_LINK_NOTE'))}</p>")
    buttons = []
    if view.link:
        link_button, link_block = fitted(t("FT_BTN_LINK"), view.link, view.lang)
        if link_button:
            buttons.append(link_button)
        else:
            blocks.append(link_block)
    if view.conf:
        blocks.append(long_block(t("FT_BTN_CONF"), view.conf))
        blocks.append(f"<p>{muted(t('FT_CLIENT_CONF_NOTE'))}</p>")
    if client is None or not client.owner:
        buttons.append(row(button(t("FT_BTN_REMOVE"), "ft:rm:%s" % name)))
    buttons.append(row(button(t("FT_BTN_CLIENTS"), "ft:clients"), button(i18n.t("NAV_FREETURN", view.lang), "ft:home")))
    return screen(t("FT_CLIENT_TITLE", name=name), t("FT_CLIENTS_SUBTITLE"), blocks, buttons)


def share_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if view.share is None or not view.share.peer():
        blocks.append(quote(muted(t("FT_ERR_NOT_INSTALLED"))))
        return screen(t("FT_SHARE_TITLE"), "", blocks, [back_row(view.lang)])
    pairs = [
        (t("FT_SHARE_PEER"), code(view.share.peer())),
        (t("FT_SHARE_MODE"), code(view.share.mode or "-")),
        (t("FT_SHARE_OBF"), code(view.share.obf_profile or "-")),
        (t("FT_SHARE_KEY"), code(t("FT_SHARE_KEY_HIDDEN") if view.share.key_present else t("FT_STATE_KEY_MISSING"))),
    ]
    blocks.append(table(pairs, (t("FT_SHARE_TITLE"), t("UI_VALUE"))))
    blocks.append(f"<p>{muted(t('FT_CLIENT_LINK_NOTE'))}</p>")
    buttons = []
    if view.link:
        link_button, link_block = fitted(t("FT_BTN_LINK"), view.link, view.lang)
        if link_button:
            buttons.append(link_button)
        else:
            blocks.append(link_block)
    if view.conf:
        blocks.append(long_block(t("FT_BTN_CONF"), view.conf))
    buttons.append(back_row(view.lang))
    return screen(t("FT_SHARE_TITLE"), t("FT_SHARE_KEY_HIDDEN"), blocks, buttons)


def logs_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if view.logs:
        blocks.append(pre("\n".join(view.logs[-40:])))
    else:
        blocks.append(quote(muted(t("FT_LOGS_EMPTY"))))
    buttons = [row(button(t("FT_BTN_REFRESH"), "ft:logs"), button(i18n.t("NAV_FREETURN", view.lang), "ft:home"))]
    return screen(t("FT_LOGS_TITLE"), view.state.method or "", blocks, buttons)


def core_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    name = t("CORE_BTN_FREETURN") if view.core == "freeturn" else t("CORE_BTN_XRAY")
    blocks.append(f"<p>{t('CORE_CURRENT')}: {code(name)}</p>")
    blocks.append(f"<p>{muted(t('CORE_NOTE'))}</p>")
    buttons = [
        row(button(t("CORE_BTN_XRAY"), "core:set:xray"), button(t("CORE_BTN_FREETURN"), "core:set:freeturn")),
        row(button(i18n.t("NAV_XRAY", view.lang), "xr:home"), button(i18n.t("NAV_FREETURN", view.lang), "ft:home")),
        row(button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("CORE_TITLE"), t("CORE_SUBTITLE"), blocks, buttons)


def confirm_screen(view: FtView, title: str, body: str, action: str, back: str = "ft:home") -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(body)))
    buttons = [row(button(t("UI_CONFIRM"), action), button(t("UI_CANCEL"), back))]
    return screen(title, t("UI_ACTION_IRREVERSIBLE"), blocks, buttons)


def error_screen(view: FtView, title: str, message: str) -> Any:
    blocks = [quote(bold(message))]
    buttons = [row(button(i18n.t("UI_HOME", view.lang), "nav:home"), button(i18n.t("NAV_FREETURN", view.lang), "ft:home"))]
    return screen(title, i18n.t("UI_ACTION_FAILED", view.lang), blocks, buttons)
