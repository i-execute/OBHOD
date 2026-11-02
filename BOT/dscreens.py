from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import i18n, net, scripts
from .ui import (
    bold,
    button,
    code,
    heading,
    input_row,
    muted,
    pre,
    quote,
    row,
    rows,
    screen,
    table,
)


@dataclass
class DbgView:
    scan: net.Answer | None = None
    trace: net.Answer | None = None
    vk: dict[str, Any] = field(default_factory=dict)
    report: scripts.Report = field(default_factory=scripts.Report)
    target: str = ""
    ports: str = ""
    hops: int = 0
    notice: str = ""
    error: str = ""
    trace_text: str = ""
    emoji: bool = False
    owners: list[Any] = field(default_factory=list)
    lang: str = i18n.DEFAULT_LANGUAGE

    def tr(self) -> i18n.Translator:
        return i18n.translator(self.lang)


def banner(view: DbgView, t: i18n.Translator) -> list[str]:
    out: list[str] = []
    if view.notice:
        out.append(quote(muted(view.notice)))
    if view.error:
        out.append(quote(bold(view.error)))
    return out


def home(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    stats = [
        ("radar", t("DBG_SCAN_TITLE"), code(view.target)),
        ("plug", t("DBG_SCAN_PORTS_LABEL"), code(view.ports or "-")),
        ("route", t("DBG_TRACE_HOPS_LABEL"), code(view.hops)),
        ("bell", t("DBG_EMOJI_TITLE"), code(t("UI_ON") if view.emoji else t("UI_OFF"))),
        ("file", t("SCR_TITLE"), code(len(view.report.cached()))),
    ]
    blocks.append(table(stats, (t("DBG_TITLE"), t("UI_VALUE"))))
    blocks.append(f"<p>{muted(t('DBG_SUBTITLE'))}</p>")
    buttons = [
        row(button(t("DBG_SCAN_BTN"), "dbg:scan", icon="radar"), button(t("DBG_TRACE_BTN"), "dbg:trace", icon="route")),
        row(button(t("DBG_VK_BTN"), "dbg:vk", icon="world"), button(t("DBG_SCRIPTS_BTN"), "dbg:scr", icon="file")),
        row(button(t("DBG_PORTS_BTN"), "dbg:ports", icon="plug"), button(t("DBG_SCRIPTS_BTN"), "dbg:scr", icon="file")),
        row(button(t("DBG_EMOJI_BTN"), "dbg:emoji", icon="star"), button(t("DBG_INFO_BTN"), "dbg:info", icon="server")),
        row(button(i18n.t("UI_HOME", view.lang), "nav:home", icon="home")),
    ]
    return screen(t("DBG_TITLE"), t("DBG_SUBTITLE"), blocks, buttons, icon="bug")


def scan_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(
        table(
            [
                ("radar", t("DBG_SCAN_TARGET_LABEL"), code(view.target or "-")),
                ("plug", t("DBG_SCAN_PORTS_LABEL"), code(view.ports or "-")),
            ],
            (t("DBG_SCAN_TITLE"), t("UI_VALUE")),
        )
    )
    answer = view.scan
    if answer is not None and answer.error:
        blocks.append(quote(bold(answer.error)))
    if answer is not None and not answer.error:
        blocks.append(
            table(
                [
                    ("ok", t("DBG_SCAN_HOSTS"), code(answer.hosts)),
                    ("users", t("DBG_SCAN_ALIVE"), code(answer.alive)),
                    ("scan", t("DBG_SCAN_OPEN"), code(len(answer.open_ports))),
                    ("clock", t("DBG_SCAN_TAKEN"), code("%.2fs" % answer.spent)),
                ],
                (t("DBG_SCAN_TITLE"), t("UI_VALUE")),
            )
        )
        if answer.open_ports:
            blocks.append(table([("plug", t("DBG_SCAN_OPEN"), item) for item in answer.open_ports[:40]], (t("DBG_SCAN_OPEN"), t("UI_VALUE"))))
        else:
            blocks.append(quote(muted(t("DBG_SCAN_NONE"))))
    buttons = [
        row(button(t("DBG_SCAN_BTN"), "dbg:scan:go", icon="scan"), button(t("DBG_SCAN_PORTS_LABEL"), "dbg:scan", icon="plug")),
        inline_inputs(view, t),
        row(button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug"), button(i18n.t("UI_HOME", view.lang), "nav:home", icon="home")),
    ]
    return screen(t("DBG_SCAN_TITLE"), t("DBG_SCAN_SUBTITLE"), blocks, buttons, icon="radar")


def inline_inputs(view: DbgView, t: i18n.Translator) -> str:
    return rows(
        [
            input_row(t("DBG_SCAN_TARGET_LABEL"), "dbg_target", "-", view.lang),
            input_row(t("DBG_SCAN_PORTS_LABEL"), "dbg_ports", "-", view.lang),
        ]
    )


def trace_screen_view(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(
        table(
            [
                ("radar", t("DBG_SCAN_TARGET_LABEL"), code(view.target or "-")),
                ("route", t("DBG_TRACE_HOPS_LABEL"), code(view.hops)),
            ],
            (t("DBG_TRACE_TITLE"), t("UI_VALUE")),
        )
    )
    answer = view.trace
    if answer is not None and answer.error:
        blocks.append(quote(bold(answer.error)))
    if answer is not None and not answer.error:
        if answer.hops:
            blocks.append(pre("\n".join(item.line() for item in answer.hops)))
        else:
            blocks.append(quote(muted(t("DBG_TRACE_EMPTY"))))
        blocks.append(f"<p>{muted(t('DBG_SCAN_TAKEN') + ': ' + ('%.2fs' % answer.spent))}</p>")
    buttons = [
        row(button(t("DBG_TRACE_BTN"), "dbg:trace:go", icon="route"), button(t("DBG_SCAN_BTN"), "dbg:scan", icon="radar")),
        rows(
            [
                input_row(t("DBG_SCAN_TARGET_LABEL"), "dbg_target", "-", view.lang),
                input_row(t("DBG_TRACE_HOPS_LABEL"), "dbg_hops", "-", view.lang),
            ]
        ),
        row(button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug"), button(i18n.t("UI_HOME", view.lang), "nav:home", icon="home")),
    ]
    return screen(t("DBG_TRACE_TITLE"), t("DBG_TRACE_SUBTITLE"), blocks, buttons, icon="route")


def vk_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    data = view.vk or {}
    cidrs = data.get("cidrs") or []
    blocks.append(
        table(
            [
                ("world", t("DBG_VK_DOMAINS"), code(len(data.get("domains") or []))),
                ("module", t("DBG_VK_PREFIXES"), code(len(cidrs))),
                ("add", t("DBG_VK_ADDED"), code(len(data.get("added") or []))),
                ("clock", t("DBG_INFO_TITLE"), code(str(data.get("reason") or "-")[:24])),
            ],
            (t("DBG_VK_TITLE"), t("UI_VALUE")),
        )
    )
    if cidrs:
        blocks.append(pre("\n".join(cidrs[:40])))
    else:
        blocks.append(quote(muted(t("DBG_SCAN_NONE"))))
    buttons = [
        row(button(t("DBG_VK_BTN"), "dbg:vk:go", icon="refresh"), button(t("DBG_VK_APPLY"), "dbg:vk:apply", icon="shield")),
        row(button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug"), button(i18n.t("UI_HOME", view.lang), "nav:home", icon="home")),
    ]
    return screen(t("DBG_VK_TITLE"), t("DBG_VK_SUBTITLE"), blocks, buttons, icon="world")


def ports_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    owners = view.owners
    if owners:
        blocks.append(
            table(
                [(("shield" if item.protected else "plug"), "%d/%s" % (item.port, item.proto or "?"), "%s %s" % (item.process or "-", t("DBG_PORTS_PROTECTED") if item.protected else t("DBG_PORTS_FREE"))) for item in owners[:40]],
                (t("DBG_PORTS_TITLE"), t("UI_VALUE")),
            )
        )
    else:
        blocks.append(quote(muted(t("DBG_PORTS_NONE"))))
    blocks.append(f"<p>{muted(t('DBG_PORTS_NOTE'))}</p>")
    buttons = [
        row(button(t("DBG_PORTS_BTN"), "dbg:ports:go", icon="refresh"), button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug")),
    ]
    return screen(t("DBG_PORTS_TITLE"), t("DBG_PORTS_SUBTITLE"), blocks, buttons, icon="plug")


def scripts_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    report = view.report
    rows = []
    for item in report.records:
        rows.append((("file" if item.cached else "warn"), "%s %s" % (item.name, item.short()), t(item.state_key())))
    if rows:
        blocks.append(table(rows, (t("SCR_TITLE"), t("DBG_VK_PREFIXES"))))
    else:
        blocks.append(quote(muted(t("SCR_EMPTY"))))
    pending = report.pending()
    if pending:
        blocks.append(heading(t("SCR_LIST"), 3, icon="warn"))
        blocks.append(quote(bold(t("SCR_WARN"))))
        blocks.append(table([("link", item.name, item.url) for item in pending], (t("SCR_TITLE"), t("SCR_SOURCE"))))
    blocks.append(f"<p>{muted(t('SCR_NOTE'))}</p>")
    buttons = [
        row(button(t("SCR_REFRESH"), "dbg:scr", icon="refresh"), button(t("SCR_FETCH"), "dbg:scr:fetch", icon="save")),
        row(button(t("SCR_KEEP"), "dbg:scr:keep", icon="back"), button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug")),
    ]
    return screen(t("SCR_TITLE"), t("SCR_SUBTITLE"), blocks, buttons, icon="file")


def emoji_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(table([("star", t("DBG_EMOJI_TITLE"), code(t("UI_ON") if view.emoji else t("UI_OFF")))], (t("DBG_EMOJI_TITLE"), t("UI_VALUE"))))
    blocks.append(f"<p>{muted(t('DBG_EMOJI_SUBTITLE'))}</p>")
    buttons = [
        row(button(t("DBG_EMOJI_BTN"), "dbg:emoji", icon="star"), button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug")),
    ]
    return screen(t("DBG_EMOJI_TITLE"), t("DBG_EMOJI_SUBTITLE"), blocks, buttons, icon="star")


def info_screen(view: DbgView, info: dict[str, Any]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    uptime = int(info.get("uptime", 0) or 0)
    blocks.append(
        table(
            [
                ("server", t("DBG_INFO_TITLE"), code(str(info.get("address") or "-")[:64])),
                ("clock", t("DBG_SCAN_TAKEN"), code("%dd %02dh %02dm" % (uptime // 86400, (uptime % 86400) // 3600, (uptime % 3600) // 60))),
                ("module", t("HOME_SUMMARY_TITLE"), code(len(info.get("cores") or []))),
            ],
            (t("DBG_INFO_TITLE"), t("UI_VALUE")),
        )
    )
    cards = info.get("cores") or []
    if cards:
        blocks.append(table([(item.icon, t(item.name), "%s %s" % (item.state_text(t), item.ports_text())) for item in cards], (t("DBG_INFO_TITLE"), t("UI_VALUE"))))
    blocks.append(f"<p>{muted(t('DBG_INFO_SUBTITLE'))}</p>")
    buttons = [
        row(button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug"), button(i18n.t("UI_HOME", view.lang), "nav:home", icon="home")),
    ]
    return screen(t("DBG_INFO_TITLE"), t("DBG_INFO_SUBTITLE"), blocks, buttons, icon="server")


def busy(view: DbgView, text: str) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(text or t("LOADING_BODY"))))
    return screen(t("LOADING_TITLE"), t("BUSY_SUBTITLE"), blocks, [row(button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug"))], icon="loading")


def crash_screen(view: DbgView, route: str, trace: str) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(view.error or t("DBG_ERR_TITLE"))))
    blocks.append(f"<p>{muted(t('DBG_ERR_TRACE'))}</p>")
    blocks.append(f"<p>{code(route[:48])}</p>")
    blocks.append(pre((trace or t("UI_NONE"))[-600:]))
    buttons = [
        row(button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug"), button(i18n.t("UI_HOME", view.lang), "nav:home", icon="home")),
    ]
    return screen(t("DBG_ERR_TITLE"), t("DBG_SUBTITLE"), blocks, buttons, icon="fail")


def trace_screen(view: DbgView, route: str, trace: str) -> Any:
    t = view.tr()
    blocks = [quote(bold(view.error or t("DBG_ERR_TITLE"))), f"<p>{code(route[:48])}</p>", pre((trace or t("UI_NONE"))[-3400:])]
    buttons = [row(button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug"), button(i18n.t("UI_HOME", view.lang), "nav:home", icon="home"))]
    return screen(t("DBG_ERR_TITLE"), t("DBG_ERR_TRACE"), blocks, buttons, icon="fail")
