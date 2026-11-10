from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import i18n, traffic
from .freeturn import FtClient, FtConfig, FtShare, FtState
from .ui import (
    bold,
    bullet_list,
    button,
    code,
    details,
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
    usage: list[traffic.Usage] = field(default_factory=list)
    totals: dict[str, Any] = field(default_factory=dict)
    page: int = 0
    pages: int = 1
    traffic_error: str = ""

    def tr(self) -> i18n.Translator:
        return i18n.translator(self.lang)

    def usage_of(self, name: str) -> traffic.Usage | None:
        for item in self.usage:
            if item.name == name:
                return item
        return None

    def page_rows(self) -> list[traffic.Usage]:
        if self.usage:
            rows = list(self.usage)
        else:
            rows = [traffic.Usage(name=item.name, pub=item.pub, hs=item.handshake, owner=item.owner) for item in self.clients]
        start = max(int(self.page), 0) * MAX_CLIENT_BUTTONS
        return rows[start:start + MAX_CLIENT_BUTTONS]

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
    return row(button(i18n.t("UI_HOME", lang), "nav:home", icon="home"), button(i18n.t("NAV_FREETURN", lang), "ft:home", icon="tunnel"))


def home(view: FtView) -> Any:
    t = view.tr()
    state = view.state
    plan = view.plan
    blocks = banner(view, t)
    endpoint = ("%s:%s" % (plan.host, plan.listen_port)) if plan.host else str(plan.listen_port)
    if state.installed:
        pairs = [
            ("info", t("FT_STATE_RUNNING"), code(yes_no(view.lang, state.running))),
            ("world", t("FT_SHARE_PEER"), code(endpoint)),
            ("settings", t("FT_STATE_METHOD"), code("%s / %s / %s" % (state.method or plan.method, plan.mode, plan.obf_profile))),
        ]
        if view.clients:
            pairs.append(("users", t("FT_CLIENTS_TITLE"), code(len(view.clients))))
        guard_mode = str((view.guard or {}).get("mode", "") or "")
        if guard_mode in {"vk", "open", "closed"}:
            pairs.append(("shield", t("FT_FW_MODE"), code(mode_label(t, guard_mode))))
    else:
        pairs = [
            ("info", t("FT_STATE_INSTALLED"), code(yes_no(view.lang, False))),
            ("world", t("FT_SHARE_PEER"), code(endpoint)),
            ("settings", t("FT_STATE_METHOD"), code("%s / %s / %s" % (plan.method, plan.mode, plan.obf_profile))),
        ]
    blocks.append(table(pairs, (t("FT_STATE_TITLE"), t("UI_VALUE"))))
    if state.installed:
        buttons = [
            row(button(t("FT_BTN_SHARE"), "ft:share", icon="gift"), button(t("FT_BTN_CLIENTS"), "ft:clients", icon="users")),
            row(button(t("FT_BTN_PLAN"), "ft:plan", icon="settings"), button(t("FT_BTN_RESTART"), "ft:restart", icon="restart"), button(t("FT_BTN_STOP"), "ft:stop", icon="stop")),
            row(button(t("FT_BTN_LOGS"), "ft:logs", icon="logs"), button(t("FT_BTN_UNINSTALL"), "ft:un", icon="delete"), button(t("UI_HOME"), "nav:home", icon="home")),
        ]
    else:
        buttons = [
            row(button(t("FT_BTN_INSTALL"), "ft:apply", icon="ok"), button(t("FT_BTN_PLAN"), "ft:plan", icon="settings")),
            row(button(t("FT_BTN_CHECK"), "ft:check", icon="refresh"), button(t("UI_HOME"), "nav:home", icon="home")),
        ]
    return screen(t("FT_TITLE"), t("FT_SUBTITLE"), blocks, buttons, icon="tunnel")


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
            ("shield", t("FT_FW_PORT"), code("%s/%s" % (data.get("port", 0), data.get("proto", "udp")))),
            ("shield", t("FT_FW_BACKEND"), code(data.get("backend") or t("UI_NONE"))),
            ("shield", t("FT_FW_MODE"), code(mode_label(t, str(data.get("mode", "unknown"))))),
            ("shield", t("FT_FW_RULES"), code(data.get("rules", 0))),
            ("shield", t("FT_FW_CIDRS"), code(data.get("cidrs", 0))),
        ]
        blocks.append(table(pairs, (t("FT_FW_TITLE"), t("UI_VALUE"))))
        blocks.append(quote(muted(t("FT_FW_NOTE"))))
    buttons = [
        row(button(t("FT_FW_BTN_VK"), "ft:fw:vk", icon="shield"), button(t("FT_FW_BTN_OPEN"), "ft:fw:open", icon="unlock")),
        row(button(t("FT_FW_BTN_CLOSE"), "ft:fw:closed", icon="lock"), button(t("UI_REFRESH"), "ft:fw", icon="shield")),
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("FT_BTN_HOME"), "ft:home", icon="tunnel"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("FT_FW_TITLE"), t("FT_FW_SUBTITLE"), blocks, buttons, icon="shield")


def plan_screen(view: FtView) -> Any:
    t = view.tr()
    plan = view.plan
    blocks = banner(view, t)
    if not view.error:
        blocks.append(f"<p>{muted(t('FT_CONFIG_NOTE'))}</p>")
    else:
        if view.state and getattr(view.state, "logs", None):
            last = view.state.logs[-1] if view.state.logs else ""
            if last:
                blocks.append(f"<p>{muted('log:')} {code((last or '')[:180])}</p>")
    pairs = [
        ("settings", t("FT_FIELD_METHOD"), code(plan.method)),
        ("settings", t("FT_FIELD_BACKEND"), code(plan.backend)),
        ("info", t("FT_FIELD_LISTEN"), code(plan.listen_port)),
        ("settings", t("FT_FIELD_MODE"), code(plan.mode)),
        ("link", t("FT_FIELD_TRANSPORT"), code(plan.transport)),
        ("info", t("FT_FIELD_OBF"), code(plan.obf_profile)),
        ("world", t("FT_FIELD_HOST"), code(plan.host or "auto")),
    ]
    if plan.backend == "new":
        pairs.append(("info", t("FT_FIELD_WG_NET"), code("%s (:%s)" % (plan.wg_net, plan.wg_port))))
    else:
        pairs.append(("link", t("FT_FIELD_CONNECT"), code(plan.connect or t("UI_NOT_SET"))))
    blocks.append(table(pairs, (t("FT_CONFIG_TITLE"), t("UI_VALUE"))))
    blocks.append(
        details(
            t("FT_HINTS_TITLE"),
            bullet_list(
                [
                    t("FT_HINT_METHOD"),
                    t("FT_HINT_BACKEND"),
                    t("FT_HINT_MODE"),
                    t("FT_HINT_TRANSPORT"),
                    t("FT_HINT_OBF"),
                    t("FT_HINT_VERSION"),
                ]
            ),
        )
    )
    apply_key = "FT_BTN_APPLY" if view.state.installed else "FT_BTN_INSTALL"
    buttons = [
        row(button(t("FT_FIELD_METHOD"), "ft:cyc:method", icon="tools"), button(t("FT_FIELD_BACKEND"), "ft:cyc:backend", icon="module")),
        row(button(t("FT_FIELD_MODE"), "ft:cyc:mode", icon="settings"), button(t("FT_FIELD_TRANSPORT"), "ft:cyc:transport", icon="link")),
        row(button(t("FT_FIELD_OBF"), "ft:cyc:obf_profile", icon="lock"), button(t("FT_FIELD_VERSION"), "ft:cyc:version", icon="tag")),
        row(button(t("FT_BTN_RANDOM_PORT"), "ft:rport", icon="refresh"), button(t(apply_key), "ft:apply", icon="ok")),
        input_row(t("FT_PORT_INPUT"), "ft_port", "-", view.lang),
        input_row(t("FT_HOST_INPUT"), "ft_host", "-", view.lang),
    ]
    if plan.backend == "new":
        buttons.append(input_row(t("FT_WG_PORT_INPUT"), "ft_wg_port", "-", view.lang))
        buttons.append(input_row(t("FT_WG_NET_INPUT"), "ft_wg_net", "-", view.lang))
    else:
        buttons.append(input_row(t("FT_CONNECT_INPUT"), "ft_connect", "-", view.lang))
    if plan.obf_profile != "none":
        buttons.append(input_row(t("FT_KEY_INPUT"), "ft_key", "-", view.lang))
    buttons.append(back_row(view.lang))
    return screen(t("FT_CONFIG_TITLE"), t("FT_CONFIG_SUBTITLE"), blocks, buttons, icon="settings")


def tone(usage: traffic.Usage | None, lang: str) -> str:
    if usage is None or not usage.hs:
        return i18n.t("FT_TRAFFIC_NEVER", lang)
    if usage.online:
        return i18n.t("FT_TRAFFIC_ONLINE", lang)
    return i18n.t("FT_TRAFFIC_SEEN", lang, when=traffic.ago(usage.last_seen()))


def usage_line(usage: traffic.Usage | None, lang: str) -> str:
    if usage is None:
        return i18n.t("FT_TRAFFIC_EMPTY_VALUE", lang)
    return "%s / %s" % (traffic.human(usage.rx), traffic.human(usage.tx))


def pager(view: FtView, t: i18n.Translator, prefix: str) -> list[str]:
    pages = max(int(view.pages), 1)
    page = min(max(int(view.page), 0), pages - 1)
    if pages <= 1:
        return []
    items = []
    if page > 0:
        items.append(button(t("FT_PAGE_PREV"), "%s:%d" % (prefix, page), icon="back"))
    items.append(button(t("FT_PAGE_OF", page=page + 1, pages=pages), prefix, icon="docs"))
    if page + 1 < pages:
        items.append(button(t("FT_PAGE_NEXT"), "%s:%d" % (prefix, page + 2), icon="add"))
    return [row(*items)]


def clients_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if view.clients:
        rows = []
        for item in view.page_rows():
            usage = view.usage_of(item.name)
            kind = t("FT_CLIENTS_OWNER") if item.owner else t("FT_CLIENTS_GUEST")
            rows.append(("user", item.name, "%s %s %s" % (kind, usage_line(usage, view.lang), tone(usage, view.lang))))
        blocks.append(table(rows, (t("FT_CLIENTS_TITLE"), t("FT_CLIENTS_SUBTITLE"))))
        total = view.totals or {}
        if total:
            blocks.append(
                table(
                    [
                        ("ok", t("FT_TRAFFIC_ONLINE_COUNT"), code(total.get("online", 0))),
                        ("users", t("FT_TRAFFIC_CLIENT_COUNT"), code(total.get("clients", 0))),
                        ("chart", t("FT_TRAFFIC_RX"), code(traffic.human(total.get("rx", 0)))),
                        ("chart", t("FT_TRAFFIC_TX"), code(traffic.human(total.get("tx", 0)))),
                    ],
                    (t("FT_TRAFFIC_SHORT"), t("UI_VALUE")),
                )
            )
    else:
        blocks.append(quote(muted(t("FT_CLIENTS_EMPTY"))))
    if view.traffic_error:
        blocks.append(quote(muted(view.traffic_error)))
    buttons = [input_row(t("FT_BTN_CLIENT_ADD"), "ft_client", "-", view.lang)]
    buttons.append(row(button(t("FT_BTN_REFRESH"), "ft:clients:%d" % (view.page + 1), icon="users"), button(t("FT_BTN_TRAFFIC"), "ft:tr:%d" % (view.page + 1), icon="chart")))
    for item in view.page_rows():
        usage = view.usage_of(item.name)
        label = "%s %s" % (item.name, traffic.human(usage.total) if usage is not None else "-")
        buttons.append(row(button(label, "ft:cl:%s" % item.name, icon="user")))
    buttons.extend(pager(view, t, "ft:clients"))
    buttons.append(back_row(view.lang))
    return screen(t("FT_CLIENTS_TITLE"), t("FT_CLIENTS_SUBTITLE"), blocks, buttons, icon="users")


def client_screen(view: FtView, name: str) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    client = next((item for item in view.clients if item.name == name), None)
    usage = view.usage_of(name)
    pairs = [
        ("user", t("FT_CLIENTS_SUBTITLE"), code(t("FT_CLIENTS_OWNER") if client is not None and client.owner else t("FT_CLIENTS_GUEST"))),
        ("world", t("FT_CLIENTS_IP"), code(client.ip if client is not None and client.ip else "-")),
        ("clock", t("FT_CLIENTS_HANDSHAKE"), code(client.handshake if client is not None and client.handshake else t("FT_CLIENTS_NEVER"))),
        ("chart", t("FT_TRAFFIC_TOTAL"), code(traffic.human(usage.total if usage else 0))),
    ]
    blocks.append(table(pairs, (t("FT_CLIENT_TITLE", name=name), t("UI_VALUE"))))
    traffic_pairs = [
        ("save", t("FT_TRAFFIC_RX"), code(traffic.human(usage.rx if usage else 0))),
        ("link", t("FT_TRAFFIC_TX"), code(traffic.human(usage.tx if usage else 0))),
        ("calendar", t("FT_TRAFFIC_DAY"), code("%s / %s" % (traffic.human(usage.day_rx if usage else 0), traffic.human(usage.day_tx if usage else 0)))),
        ("update", t("FT_TRAFFIC_SPEED"), code("%s / %s" % (traffic.speed(usage.down if usage else 0), traffic.speed(usage.up if usage else 0)))),
        ("clock", t("FT_TRAFFIC_LAST"), code(tone(usage, view.lang))),
        ("compass", t("FT_TRAFFIC_ENDPOINT"), code((usage.endpoint if usage and usage.endpoint else "-"))),
    ]
    if usage is not None and usage.first_at:
        traffic_pairs.append(("calendar", t("FT_TRAFFIC_FIRST"), code(traffic.stamp(usage.first_at))))
    blocks.append(details(t("FT_TRAFFIC_TITLE"), table(traffic_pairs, (t("FT_TRAFFIC_TITLE"), t("UI_VALUE")))))
    if view.traffic_error:
        blocks.append(quote(muted(view.traffic_error)))
    buttons = []
    if view.link:
        link_button, link_block = fitted(t("FT_BTN_LINK"), view.link, view.lang)
        if link_button:
            buttons.append(link_button)
        else:
            blocks.append(link_block)
    if view.conf:
        blocks.append(long_block(t("FT_BTN_CONF"), view.conf))
    buttons.append(row(button(t("FT_BTN_REFRESH_TRAFFIC"), "ft:cl:%s:t" % name, icon="refresh")))
    if client is None or not client.owner:
        buttons.append(row(button(t("FT_BTN_REMOVE"), "ft:rm:%s" % name, icon="delete")))
    buttons.append(row(button(t("FT_BTN_CLIENTS"), "ft:clients:%d" % (view.page + 1), icon="users"), button(i18n.t("NAV_FREETURN", view.lang), "ft:home", icon="tunnel")))
    return screen(t("FT_CLIENT_TITLE", name=name), client.ip if client and client.ip else "", blocks, buttons, icon="user")


def traffic_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    total = view.totals or {}
    blocks.append(
        table(
            [
                ("ok", t("FT_TRAFFIC_ONLINE_COUNT"), code(total.get("online", 0))),
                ("users", t("FT_TRAFFIC_CLIENT_COUNT"), code(total.get("clients", 0))),
                ("module", t("FT_TRAFFIC_PEER_COUNT"), code(total.get("peers", 0))),
                ("save", t("FT_TRAFFIC_RX"), code(traffic.human(total.get("rx", 0)))),
                ("link", t("FT_TRAFFIC_TX"), code(traffic.human(total.get("tx", 0)))),
                ("chart", t("FT_TRAFFIC_TOTAL"), code(traffic.human(int(total.get("rx", 0)) + int(total.get("tx", 0))))),
                ("calendar", t("FT_TRAFFIC_DAY_TOTAL"), code("%s / %s" % (traffic.human(total.get("day_rx", 0)), traffic.human(total.get("day_tx", 0))))),
                ("update", t("FT_TRAFFIC_SPEED"), code("%s / %s" % (traffic.speed(total.get("down", 0)), traffic.speed(total.get("up", 0))))),
                ("clock", t("FT_TRAFFIC_CHECKED"), code(traffic.stamp(total.get("checked_at", 0)) or "-")),
            ],
            (t("UI_FIELD"), t("FT_TRAFFIC_TITLE")),
        )
    )
    if view.usage:
        blocks.append(table([("user", item.name, "%s %s %s" % (traffic.human(item.total), traffic.human(item.rx), tone(item, view.lang))) for item in view.page_rows()], (t("FT_TRAFFIC_TOP"), t("UI_VALUE"))))
    else:
        blocks.append(quote(muted(t("FT_TRAFFIC_EMPTY"))))
    if view.traffic_error:
        blocks.append(quote(muted(view.traffic_error)))
    buttons = [row(button(t("FT_BTN_REFRESH_TRAFFIC"), "ft:tr:%d" % (view.page + 1), icon="refresh"))]
    for item in view.page_rows()[:4]:
        buttons.append(row(button(item.name, "ft:cl:%s:t" % item.name, icon="user")))
    buttons.extend(pager(view, t, "ft:tr"))
    buttons.append(row(button(t("FT_BTN_CLIENTS"), "ft:clients:%d" % (view.page + 1), icon="users"), button(i18n.t("NAV_FREETURN", view.lang), "ft:home", icon="tunnel")))
    return screen(t("FT_TRAFFIC_TITLE"), t("FT_TRAFFIC_SUBTITLE"), blocks, buttons, icon="chart")


def share_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if view.share is None or not view.share.peer():
        blocks.append(quote(muted(t("FT_ERR_NOT_INSTALLED"))))
        return screen(t("FT_SHARE_TITLE"), "", blocks, [back_row(view.lang)], icon="gift")
    pairs = [
        ("link", t("FT_SHARE_PEER"), code(view.share.peer())),
        ("settings", t("FT_SHARE_MODE"), code("%s / %s" % (view.share.mode or "-", view.share.obf_profile or "-"))),
    ]
    blocks.append(table(pairs, (t("FT_SHARE_TITLE"), t("UI_VALUE"))))
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
    return screen(t("FT_SHARE_TITLE"), view.share.peer(), blocks, buttons, icon="gift")


def logs_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if view.logs:
        blocks.append(pre("\n".join(view.logs[-40:])))
    else:
        blocks.append(quote(muted(t("FT_LOGS_EMPTY"))))
    buttons = [row(button(t("FT_BTN_REFRESH"), "ft:logs", icon="logs"), button(i18n.t("NAV_FREETURN", view.lang), "ft:home", icon="tunnel"))]
    return screen(t("FT_LOGS_TITLE"), view.state.method or "", blocks, buttons, icon="logs")


def core_screen(view: FtView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    name = t("CORE_BTN_FREETURN") if view.core == "freeturn" else t("CORE_BTN_XRAY")
    blocks.append(f"<p>{t('CORE_CURRENT')}: {code(name)}</p>")
    blocks.append(f"<p>{muted(t('CORE_NOTE'))}</p>")
    buttons = [
        row(button(t("CORE_BTN_XRAY"), "core:set:xray", icon="xray"), button(t("CORE_BTN_FREETURN"), "core:set:freeturn", icon="tunnel")),
        row(button(i18n.t("NAV_XRAY", view.lang), "xr:home", icon="xray"), button(i18n.t("NAV_FREETURN", view.lang), "ft:home", icon="tunnel")),
        row(button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("CORE_TITLE"), t("CORE_SUBTITLE"), blocks, buttons, icon="module")


def confirm_screen(view: FtView, title: str, body: str, action: str, back: str = "ft:home") -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(body)))
    buttons = [row(button(t("UI_CONFIRM"), action, icon="ok"), button(t("UI_CANCEL"), back, icon="back"))]
    return screen(title, t("UI_ACTION_IRREVERSIBLE"), blocks, buttons, icon="warn")


def busy_screen(title: str, lang: str = i18n.DEFAULT_LANGUAGE, steps: list[str] | None = None) -> Any:
    t = i18n.translator(lang)
    blocks = [quote(muted(title))]
    if steps:
        blocks.append(bullet_list([muted(item) for item in steps]))
    return screen(t("FT_TITLE"), t("BUSY_SUBTITLE"), blocks, [], icon="tunnel")


def error_screen(view: FtView, title: str, message: str) -> Any:
    blocks = [quote(bold(message))]
    buttons = [row(button(i18n.t("UI_HOME", view.lang), "nav:home", icon="home"), button(i18n.t("NAV_FREETURN", view.lang), "ft:home", icon="tunnel"))]
    return screen(title, i18n.t("UI_ACTION_FAILED", view.lang), blocks, buttons, icon="fail")
