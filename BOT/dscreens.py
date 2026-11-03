from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import chebur, i18n, net, scripts
from .ui import (
    bold,
    button,
    code,
    details,
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
    chebur: Any = None
    chebur_target: str = ""
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
        row(button(t("CHK_BTN_OPEN"), "dbg:chk", icon="shield")),
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
                ("world", t("DBG_VK_DOMAINS"), code(data.get("asns") or t("UI_NONE"))),
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


def chebur_status_key(verdict: str) -> str:
    return {
        "registry": "CHK_ST_REGISTRY",
        "tspu_block": "CHK_ST_TSPU",
        "sni_block": "CHK_ST_SNI",
        "dns_spoofing": "CHK_ST_DNS",
        "cdn_block": "CHK_ST_CDN",
        "clean": "CHK_ST_CLEAN",
        "partial": "CHK_ST_PARTIAL",
        "uncertain": "CHK_ST_UNCERTAIN",
        "unknown": "CHK_ST_UNKNOWN",
    }.get(verdict or "unknown", "CHK_ST_UNKNOWN")


def chebur_quote(t: Any, answer: Any, target: str) -> str:
    if answer is None:
        return t("CHK_QUOTE_UNKNOWN")
    probe = answer.reach
    if probe is not None and not probe.reachable():
        detail = probe.error or (t("CHK_NET_TCP_FAIL") if probe.dns_ok else t("CHK_NET_DNS_FAIL"))
        return t("CHK_QUOTE_API_DOWN", value=detail[:90])
    if answer.error and answer.registry is None:
        return t("CHK_QUOTE_API_DOWN", value=answer.error[:90])
    if answer.registry is not None and answer.registry.blocked:
        return t("CHK_QUOTE_REGISTRY")
    live = answer.live
    if live is not None and live.results:
        total = len(live.results)
        blocked = live.blocking()
        counts = live.counts()
        if live.blocked():
            return t("CHK_QUOTE_BANNED", blocked=blocked, total=total, target=target)
        if live.blocking():
            return t("CHK_QUOTE_PARTIAL", blocked=blocked, total=total, target=target)
        if not counts.get("ok", 0):
            return t("CHK_QUOTE_UNCERTAIN", target=target)
        return t("CHK_QUOTE_CLEAN", ok=counts.get("ok", 0), total=total, target=target)
    if answer.registry is not None:
        if not chebur.probe_supported(answer.registry.kind):
            return t("CHK_QUOTE_WIDE", target=target)
        return t("CHK_QUOTE_REGISTRY_CLEAN", target=target)
    return t("CHK_QUOTE_UNKNOWN")


def chebur_net_rows(t: Any, probe: Any) -> list[tuple[str, str, str]]:
    rows = [("world", t("CHK_NET_HOST"), code("%s:%d" % (probe.host, chebur.PORT)))]
    if probe.addresses:
        dns_row = ", ".join(probe.addresses)
    else:
        dns_row = t("CHK_NET_YES") if probe.dns_ok else t("CHK_NET_DNS_FAIL")
    rows.append(("link", t("CHK_NET_DNS"), code(dns_row)))
    rows.append(("plug", t("CHK_NET_TCP"), code(t("CHK_NET_YES") if probe.tcp_ok else t("CHK_NET_TCP_FAIL"))))
    rows.append(("clock", t("CHK_NET_LATENCY"), code("%.2f s" % probe.latency)))
    rows.append(("ok" if probe.reachable() else "fail", t("CHK_NET_STATE"), code(t("CHK_NET_YES") if probe.reachable() else t("CHK_NET_NO"))))
    return rows


def chebur_screen(view: "DbgView") -> Any:
    t = view.tr()
    blocks = banner(view, t)
    answer = view.chebur
    target = (answer.target if answer is not None and answer.target else view.chebur_target) or "-"
    status_key = chebur_status_key(answer.verdict() if answer is not None else "unknown")
    head_pairs = [
        ("target", t("CHK_TARGET"), code(target)),
        ("shield", t("CHK_VERDICT"), code(t(status_key))),
    ]
    if answer is not None and answer.registry is not None:
        head_pairs.append(("world", t("CHK_SOURCE"), code(t("CHK_SOURCE_API"))))
    blocks.append(table(head_pairs, (t("CHK_TITLE"), t("UI_VALUE"))))
    blocks.append(quote(bold(chebur_quote(t, answer, target))))
    if answer is None:
        blocks.append(quote(muted(t("CHK_NO_ANSWER"))))
    down = answer is not None and answer.reach is not None and not answer.reach.reachable()
    if answer is not None and answer.error and not down:
        key = chebur.error_key(answer.code)
        if i18n.has_key(key, view.lang):
            blocks.append(quote(bold(t(key, value=answer.error[:120]))))
        else:
            blocks.append(quote(bold(answer.error[:200])))
    if answer is not None and answer.reach is not None:
        blocks.append(table(chebur_net_rows(t, answer.reach), (t("CHK_NET_TITLE"), t("UI_VALUE"))))
    registry = answer.registry if answer is not None else None
    if registry is not None:
        shown = ", ".join(registry.ips[:4])
        if registry.ip_count and registry.ip_count > len(registry.ips[:4]):
            shown = "%s %s" % (shown, t("CHK_IPS_MORE", count=registry.ip_count - len(registry.ips[:4])))
        rows_data = [
            ("file", t("CHK_REGISTRY"), code(t("CHK_BLOCKED") if registry.blocked else t("CHK_CLEAN"))),
            ("tag", t("CHK_KIND"), code(t("CHK_KIND_" + (registry.kind or "ip").upper()))),
            ("world", t("CHK_GEO"), code(registry.geo.label())),
            ("target", t("CHK_IPS"), code(shown or "-")),
            ("module", t("CHK_SUBNETS"), code(", ".join(registry.subnets[:4]) or t("UI_NONE"))),
            ("link", t("CHK_REVERSE"), code(", ".join(registry.reverse[:3]) or t("UI_NONE"))),
            ("bell", t("CHK_COMPLAINTS"), code(registry.complaint_total())),
        ]
        if registry.cdn:
            rows_data.append(("world", t("CHK_CDN"), code(", ".join(sorted(registry.cdn)[:4]))))
        blocks.append(table(rows_data, (t("CHK_REGISTRY_TITLE"), t("UI_VALUE"))))
        spark = registry.complaint_spark()
        if spark and registry.complaint_total():
            blocks.append(pre(t("CHK_SPARK") + "  " + " ".join(spark)))
    live = answer.live if answer is not None else None
    if live is not None:
        counts = live.counts()
        pairs = [
            ("radar", t("CHK_PROBES"), code("%d / %d" % (len(live.results), live.online or 0))),
            ("clock", t("CHK_ELAPSED"), code("%.1f s" % live.elapsed)),
            ("chart", t("CHK_SHARE"), code("%d%%" % round(live.share() * 100))),
            ("route", t("CHK_STREAM"), code(t("CHK_STREAM_DONE") if live.finished else t("CHK_STREAM_CUT"))),
        ]
        for name in chebur.VERDICT_ORDER:
            if counts.get(name):
                mark = "shield" if name in chebur.BLOCKING else ("ok" if name == "ok" else "warn")
                pairs.append((mark, t("CHK_V_" + name.upper()), code(counts[name])))
        blocks.append(table(pairs, (t("CHK_LIVE_TITLE"), t("UI_VALUE"))))
        blocking: list[str] = []
        for kind in live.blocking_kinds():
            for name in live.providers_for(kind):
                if name not in blocking:
                    blocking.append(name)
        if blocking:
            blocks.append(quote(muted(t("CHK_PROVIDERS", value=", ".join(blocking[:8])))))
        if live.error:
            blocks.append(quote(bold(t("CHK_ERR_PROBE", value=live.error[:120]))))
        if live.results:
            lines = []
            for item in live.results:
                lines.append("%s %s (%s): %s" % (item.provider or "?", item.region or "-", item.asn or "-", ", ".join(item.verdicts) or "uncertain"))
            blocks.append(details(t("CHK_DETAILS", count=len(live.results)), pre("\n".join(lines[:40]))))
    blocks.append(quote(muted(t("CHK_NOTE"))))
    buttons = [
        row(button(t("CHK_BTN_CHECK"), "dbg:chk:check", icon="file")),
        row(button(t("CHK_BTN_PROBE"), "dbg:chk:probe", icon="radar"), button(t("CHK_BTN_BOTH"), "dbg:chk:both", icon="scan")),
        row(button(t("CHK_BTN_NET"), "dbg:chk:net", icon="plug")),
        input_row(t("CHK_INPUT"), "dbg_chk_target", "-", view.lang),
        row(button(i18n.t("NAV_DEBUG", view.lang), "dbg:home", icon="bug"), button(i18n.t("UI_HOME", view.lang), "nav:home", icon="home")),
    ]
    return screen(t("CHK_TITLE"), t("CHK_SUBTITLE"), blocks, buttons, icon="shield")
