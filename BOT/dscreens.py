from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import antiddos, chebur, dpi, i18n, net, notify, scripts
from .ui import (
    bold,
    button,
    code,
    details,
    heading,
    input_row,
    muted,
    muted_html,
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
    dpi: Any = None
    notify: Any = None
    honeypot: Any = None
    honey_busy: bool = False
    ddos: Any = None
    ddos_exposure: Any = None
    ddos_busy: bool = False
    ddos_page: int = 0
    ddos_alerts: bool = True
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
    buttons = [
        row(button(t("FT_FW_TITLE"), "ft:fw", icon="shield"), button(t("DDOS_BTN_OPEN"), "dbg:dd", icon="shield"), button(t("NAV_FAIL2BAN"), "nav:ban", icon="shield")),
        row(button(t("NAV_SSHD"), "nav:sshd", icon="key"), button(t("HP_BTN_OPEN"), "dbg:hp", icon="target"), button(t("NTF_BTN_OPEN"), "dbg:ntf", icon="bell")),
        row(button(t("CHK_BTN_OPEN"), "dbg:chk", icon="shield"), button(t("DPI_BTN_OPEN"), "dbg:dpi", icon="warn"), button(t("DBG_VK_BTN"), "dbg:vk", icon="world")),
        row(button(t("DBG_SCAN_BTN"), "dbg:scan", icon="radar"), button(t("DBG_TRACE_BTN"), "dbg:trace", icon="route"), button(t("DBG_PORTS_BTN"), "dbg:ports", icon="plug")),
        row(button(t("DBG_SCRIPTS_BTN"), "dbg:scr", icon="file"), button(t("DBG_INFO_BTN"), "dbg:info", icon="server"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("TOOLS_TITLE"), t("DBG_SUBTITLE"), blocks, buttons, icon="tools")


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
        row(button(t("DBG_SCAN_BTN"), "dbg:scan:go", icon="scan"), button(t("DBG_TRACE_BTN"), "dbg:trace", icon="route")),
        input_row(t("DBG_SCAN_TARGET_LABEL"), "dbg_target", "-", view.lang),
        input_row(t("DBG_SCAN_PORTS_LABEL"), "dbg_ports", "-", view.lang),
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
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
        input_row(t("DBG_SCAN_TARGET_LABEL"), "dbg_target", "-", view.lang),
        input_row(t("DBG_TRACE_HOPS_LABEL"), "dbg_hops", "-", view.lang),
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("DBG_TRACE_TITLE"), t("DBG_TRACE_SUBTITLE"), blocks, buttons, icon="route")


def vk_screen(view: DbgView) -> Any:
    from . import fwguard

    t = view.tr()
    blocks = banner(view, t)
    data = view.vk or {}
    cidrs = data.get("cidrs") or []
    asn_list = ", ".join("AS%d" % asn for asn, _label in fwguard.ASNS)
    blocks.append(
        table(
            [
                ("world", t("DBG_VK_DOMAINS"), code(asn_list)),
                ("module", t("DBG_VK_PREFIXES"), code(len(cidrs))),
                ("clock", t("TOOLS_STATUS"), code(str(data.get("reason") or "ok")[:24] if cidrs or data.get("reason") else "-")),
            ],
            (t("DBG_VK_TITLE"), t("UI_VALUE")),
        )
    )
    if cidrs:
        blocks.append(details("%s (%d)" % (t("DBG_VK_PREFIXES"), len(cidrs)), pre("\n".join(cidrs[:60]))))
    else:
        blocks.append(quote(muted(t("DBG_SCAN_NONE"))))
    blocks.append(quote(muted(t("DBG_PORTS_NOTE"))))
    buttons = [
        row(button(t("DBG_VK_BTN"), "dbg:vk:go", icon="refresh"), button(t("DBG_VK_APPLY"), "dbg:vk:apply", icon="shield")),
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
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
        row(button(t("DBG_PORTS_BTN"), "dbg:ports:go", icon="refresh"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools")),
    ]
    return screen(t("DBG_PORTS_TITLE"), t("DBG_PORTS_SUBTITLE"), blocks, buttons, icon="plug")


def scripts_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    report = view.report
    rows_list = []
    for item in report.records:
        rows_list.append((("file" if item.cached else "warn"), "%s %s" % (item.name, item.short()), t(item.state_key())))
    if rows_list:
        blocks.append(table(rows_list, (t("SCR_TITLE"), t("TOOLS_STATUS"))))
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
        row(button(t("SCR_KEEP"), "dbg:scr:keep", icon="back"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools")),
    ]
    return screen(t("SCR_TITLE"), t("SCR_SUBTITLE"), blocks, buttons, icon="file")


def info_screen(view: DbgView, info: dict[str, Any]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    uptime = int(info.get("uptime", 0) or 0)
    blocks.append(
        table(
            [
                ("server", t("FT_SHARE_PEER"), code(str(info.get("address") or "-")[:64])),
                ("clock", t("TOOLS_STATUS"), code("%dd %02dh %02dm" % (uptime // 86400, (uptime % 86400) // 3600, (uptime % 3600) // 60))),
                ("module", t("HOME_SUMMARY_TITLE"), code(len(info.get("cores") or []))),
            ],
            (t("DBG_INFO_TITLE"), t("UI_VALUE")),
        )
    )
    cards = info.get("cores") or []
    if cards:
        blocks.append(table([(item.icon, t(item.name), "%s %s" % (item.state_text(t), item.ports_text())) for item in cards], (t("HOME_SUMMARY_TITLE"), t("UI_VALUE"))))
    buttons = [
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("DBG_INFO_TITLE"), t("DBG_INFO_SUBTITLE"), blocks, buttons, icon="server")


def busy(view: DbgView, text: str) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(text or t("LOADING_BODY"))))
    return screen(t("LOADING_TITLE"), t("BUSY_SUBTITLE"), blocks, [], icon="loading")


def stub_screen(view: DbgView, name: str, reason: str, host: str, retry: str = "") -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(t("DBG_STUB_TITLE"))))
    blocks.append(f"<p>{t('DBG_STUB_BODY', name=code(name[:40]), reason=code(reason[:120]))}</p>")
    if host:
        blocks.append(quote(muted_html(t("DBG_STUB_HINT", host=bold(host[:64])))))
    buttons = []
    if retry:
        buttons.append(row(button(t("DBG_STUB_RETRY"), retry, icon="refresh"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools")))
        buttons.append(row(button(t("UI_HOME"), "nav:home", icon="home")))
    else:
        buttons.append(row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")))
    return screen(t("DBG_STUB_TITLE"), t("DBG_SUBTITLE"), blocks, buttons, icon="warn")


def crash_screen(view: DbgView, route: str, trace: str) -> Any:

    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(view.error or t("DBG_ERR_TITLE"))))
    blocks.append(f"<p>{muted(t('DBG_ERR_TRACE'))}</p>")
    blocks.append(table([("bug", t("DBG_TITLE"), code(route[:48]))], (t("UI_PARAM"), t("UI_VALUE"))))
    blocks.append(pre((trace or t("UI_NONE"))[-600:]))
    blocks.append(quote(muted(t("DBG_CRASH_HINT"))))
    buttons = [
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("DBG_ERR_TITLE"), t("DBG_SUBTITLE"), blocks, buttons, icon="fail")


def trace_screen(view: DbgView, route: str, trace: str) -> Any:
    t = view.tr()
    blocks = [quote(bold(view.error or t("DBG_ERR_TITLE"))), f"<p>{code(route[:48])}</p>", pre((trace or t("UI_NONE"))[-3400:])]
    buttons = [row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home"))]
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
            ("world", t("CHK_GEO"), code(registry.geo.label())),
            ("target", t("CHK_IPS"), code(shown or "-")),
            ("module", t("CHK_SUBNETS"), code(", ".join(registry.subnets[:4]) or t("UI_NONE"))),
            ("bell", t("CHK_COMPLAINTS"), code(registry.complaint_total())),
        ]
        if registry.cdn:
            rows_data.append(("world", t("CHK_CDN"), code(", ".join(sorted(registry.cdn)[:4]))))
        blocks.append(table(rows_data, (t("CHK_REGISTRY_TITLE"), t("UI_VALUE"))))
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
        row(button(t("CHK_BTN_CHECK"), "dbg:chk:check", icon="file"), button(t("CHK_BTN_NET"), "dbg:chk:net", icon="plug")),
        row(button(t("CHK_BTN_PROBE"), "dbg:chk:probe", icon="radar"), button(t("CHK_BTN_BOTH"), "dbg:chk:both", icon="scan")),
        input_row(t("CHK_INPUT"), "dbg_chk_target", "-", view.lang),
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("CHK_TITLE"), t("CHK_SUBTITLE"), blocks, buttons, icon="shield")

def dpi_value(t: Any, item: Any) -> str:
    return t("DPI_F_" + str(item.key).upper(), value=item.value, min=dpi.MIN_CORE_TAG)


def dpi_quote(t: Any, report: Any) -> str:
    if report is None:
        return t("DPI_QUOTE_EMPTY")
    level = report.level()
    if level == "ok":
        return t("DPI_QUOTE_OK")
    first = ""
    for item in report.findings:
        if item.level != "ok":
            first = dpi_value(t, item)
            break
    key = "DPI_QUOTE_BAD" if level == "bad" else "DPI_QUOTE_WARN"
    return t(key, value=first[:110])


def dpi_flag(t: Any, flag: int) -> str:
    if flag < 0:
        return "-"
    return t("DPI_ON") if flag == 1 else t("DPI_OFF")


def core_state(t: Any, report: Any) -> str:
    if not report.core:
        return "-"
    return t("DPI_LEVEL_OK") if report.core_ok else t("DPI_LEVEL_BAD")


def dpi_screen(view: "DbgView") -> Any:
    t = view.tr()
    report = view.dpi
    blocks = banner(view, t)
    level = report.level() if report is not None else "warn"
    mark = {"bad": "shield", "warn": "warn"}.get(level, "ok")
    blocks.append(
        table(
            [(mark, t("DPI_LEVEL"), code(t("DPI_LEVEL_" + level.upper())))],
            (t("DPI_TITLE"), t("UI_VALUE")),
        )
    )
    blocks.append(quote(bold(dpi_quote(t, report))))
    if report is not None:
        kernel = report.kernel
        if kernel.fixed:
            state = t("DPI_KERNEL_FIXED", value=kernel.series or "-")
        elif kernel.known:
            state = t("DPI_KERNEL_OLD")
        else:
            state = "-"
        if kernel.listeners > 0:
            listeners = kernel.listener_ports or str(kernel.listeners)
        elif kernel.listeners == 0:
            listeners = t("DPI_NONE")
        else:
            listeners = "-"
        blocks.append(
            table(
                [
                    (mark, t("DPI_KERNEL"), code(kernel.release or "-")),
                    ("ok" if kernel.fixed else "warn", t("DPI_KERNEL_STATE"), code(state)),
                    ("plug", t("DPI_MPTCP"), code(dpi_flag(t, kernel.mptcp))),
                    ("plug", t("DPI_MIGRATE"), code(dpi_flag(t, kernel.migrate))),
                    ("radar", t("DPI_LISTENERS"), code(listeners)),
                ],
                (t("DPI_KERNEL_TITLE"), t("UI_VALUE")),
            )
        )
        extra_tables = [
            table(
                [
                    ("module", t("DPI_CORE"), code(report.core or "-")),
                    ("module", t("DPI_CORE_MIN"), code(dpi.MIN_CORE_TAG)),
                    ("bell", t("DPI_CORE_STATE"), code(core_state(t, report))),
                    ("key", t("DPI_FINGERPRINTS"), code(", ".join(report.fingerprints) or t("DPI_NONE"))),
                    ("route", t("DPI_NETWORKS"), code(", ".join(report.networks) or t("DPI_NONE"))),
                ],
                (t("DPI_CORE_TITLE"), t("UI_VALUE")),
            ),
            table(
                [
                    ("world", t("DPI_ORG"), code(" ".join(part for part in (report.asn, report.organisation) if part) or "-")),
                    ("warn" if report.hoster else "ok", t("DPI_HOSTER"), code(report.hoster or t("DPI_NONE"))),
                    ("world", t("DPI_COUNTRY"), code(report.country or "-")),
                ],
                (t("DPI_HOST_TITLE"), t("UI_VALUE")),
            ),
        ]
        blocks.append(details(t("HOME_DETAILS"), "\n".join(extra_tables)))
        found = [item for item in report.findings if item.level != "ok"]
        if found:
            blocks.append(
                table(
                    [
                        ("shield" if item.level == "bad" else "warn", t("DPI_FIND_STATE"), code(dpi_value(t, item)))
                        for item in found[:12]
                    ],
                    (t("DPI_FIND_TITLE"), t("UI_VALUE")),
                )
            )
        blocks.append(details(t("DPI_FIX_TITLE"), pre(dpi.fix_text())))
    blocks.append(quote(muted(t("DPI_NOTE"))))
    buttons = [
        row(button(t("DPI_BTN_RUN"), "dbg:dpi:scan", icon="scan"), button(t("CHK_BTN_OPEN"), "dbg:chk", icon="shield")),
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("DPI_TITLE"), t("DPI_SUBTITLE"), blocks, buttons, icon="shield")


def ddos_level(t: Any, status: Any) -> str:
    level = "ok"
    try:
        level = str(status.level() if status is not None else "ok")
    except Exception:
        level = "ok"
    return t({"ok": "DDOS_LEVEL_OK", "warn": "DDOS_LEVEL_WARN", "bad": "DDOS_LEVEL_BAD"}.get(level, "DDOS_LEVEL_OK"))


def ddos_exposure_text(t: Any, findings: Any) -> str:
    code = ""
    try:
        code = antiddos.exposure_hint(findings or [])
    except Exception:
        code = ""
    return t({"panel": "DDOS_EXPOSURE_PANEL", "core_api": "DDOS_EXPOSURE_CORE_API", "datastore": "DDOS_EXPOSURE_DATASTORE",
              "risky": "DDOS_EXPOSURE_RISKY", "proxy": "DDOS_EXPOSURE_PROXY", "unexpected": "DDOS_EXPOSURE_UNEXPECTED"}.get(code, "DDOS_EXPOSURE_EMPTY"))


def _compact_entries(entries: list[str], cap: int = 4) -> str:
    if not entries:
        return "-"
    shown = ", ".join(entries[:cap])
    if len(entries) > cap:
        return "%s (+%d)" % (shown, len(entries) - cap)
    return shown


DDOS_IPS_PAGE_SIZE = 6


def _ddos_reason_label(t: Any, reason: str) -> str:
    key = {
        "syn": "DDOS_RSN_SYN",
        "conn": "DDOS_RSN_CONN",
        "udp": "DDOS_RSN_UDP",
        "icmp": "DDOS_RSN_ICMP",
        "scan": "DDOS_RSN_SCAN",
        "manual": "DDOS_RSN_MANUAL",
        "unbanned": "DDOS_RSN_UNBANNED",
    }.get(str(reason or ""), "DDOS_RSN_MANUAL")
    return t(key)


def _ddos_cb_token(address: str, index: int) -> str:
    clean = str(address or "").strip()
    if clean and len(clean) <= 42:
        return clean
    return "@%d" % index


def _ddos_short_ip(address: str) -> str:
    clean = str(address or "").strip()
    if len(clean) <= 18:
        return clean
    return clean[:15] + ".."


def ddos_screen(view: DbgView) -> Any:
    t = view.tr()
    status = view.ddos
    blocks = banner(view, t)
    if status is None:
        blocks.append(f"<p>{muted(t('DDOS_EMPTY'))}</p>")
        if view.ddos_exposure is not None:
            blocks.append(table([("scan", t("DDOS_EXPOSURE"), ddos_exposure_text(t, view.ddos_exposure))], (t("DDOS_EXPOSURE"), t("UI_VALUE"))))
        buttons = [
            row(button(t("DDOS_BTN_INSTALL"), "dbg:dd:install", icon="shield"), button(t("DDOS_BTN_PROBE"), "dbg:dd:probe", icon="scan")),
            row(button(t("DDOS_BTN_RKN_SYNC"), "dbg:dd:rkn_sync", icon="refresh"), button(t("DDOS_BTN_REFRESH"), "dbg:dd:refresh", icon="refresh")),
            row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
        ]
        return screen(t("DDOS_TITLE"), t("DDOS_SUBTITLE"), blocks, buttons, icon="shield")
    level = "ok"
    try:
        level = str(status.level())
    except Exception:
        level = "ok"
    mark = {"ok": "shield", "warn": "warn", "bad": "fail"}.get(level, "shield")
    policy = status.policy
    rkn_on = bool(getattr(status, "rkn_enabled", policy.rkn_enabled))
    v4_count = int(getattr(status, "rkn_v4_count", 0) or 0)
    v6_count = int(getattr(status, "rkn_v6_count", 0) or 0)
    if rkn_on and v4_count == 0 and v6_count == 0:
        sv4, sv6 = antiddos.seed_rkn_subnets()
        v4_count, v6_count = len(sv4), len(sv6)
    records = status.ip_records()
    blocked_total = status.blocked_count()
    active_state = (t("UI_ON") + " · " + ddos_level(t, status)) if (status.enabled and status.table) else t("UI_OFF")
    rkn_state = ("%s · %d IPv4, %d IPv6" % (t("UI_ON"), v4_count, v6_count)) if rkn_on else t("UI_OFF")
    total_drops = int(status.dropped())
    rkn_drops = int(status.rkn_dropped())
    flood_drops = max(0, total_drops - rkn_drops)
    state_rows = [
        (mark, t("DDOS_STATE"), code(active_state)),
        ("shield", t("DDOS_RKN_STATE"), code(rkn_state)),
        ("bell", t("DDOS_ALERTS"), code(t("UI_ON") if view.ddos_alerts else t("UI_OFF"))),
        ("speed", t("DDOS_TRAFFIC"), code(t("DDOS_TRAFFIC_VAL", pps=status.pps, conns=status.connections))),
        ("stop", t("DDOS_DROPS"), code(t("DDOS_DROPS_VAL", total=total_drops, rkn=rkn_drops, flood=flood_drops))),
        ("plug", t("DDOS_PORTS"), code(",".join(str(item) for item in policy.ports))),
    ]
    if not records:
        state_rows.append(("ok", t("DDOS_BLOCKED_IPS"), code("0")))
    blocks.append(table(state_rows, (t("DDOS_TITLE"), t("UI_VALUE"))))
    if records:
        ip_rows = [
            ("stop" if rec.blocked else "ok", code(rec.address), _ddos_reason_label(t, rec.reason))
            for rec in records[:6]
        ]
        blocks.append(table(ip_rows, (t("DDOS_IPS_TITLE"), t("DDOS_COL_STATUS"))))
    if view.ddos_exposure is not None:
        findings = view.ddos_exposure
        rows = [(item.severity if item.severity in {"warn", "bad"} else "info", ddos_exposure_text(t, [item]), code("%d/%s" % (item.port, item.proto))) for item in findings[:8]]
        if not rows:
            rows = [("ok", t("DDOS_EXPOSURE_EMPTY"), code("-"))]
        blocks.append(table(rows, (t("DDOS_EXPOSURE"), t("UI_VALUE"))))
    if status.notice:
        blocks.append(quote(muted(str(status.notice)[:120])))
    rkn_btn_label = t("DDOS_BTN_RKN_ON") if rkn_on else t("DDOS_BTN_RKN_OFF")
    ntf_btn_label = t("DDOS_BTN_NTF_ON") if view.ddos_alerts else t("DDOS_BTN_NTF_OFF")
    buttons = [
        row(button(t("DDOS_BTN_IPS", count=blocked_total), "dbg:dd:ips", icon="target"), button(t("DDOS_BTN_REFRESH"), "dbg:dd:refresh", icon="refresh")),
        row(button(rkn_btn_label, "dbg:dd:rkn", icon="shield"), button(ntf_btn_label, "dbg:dd:ntf", icon="bell")),
        input_row(t("DDOS_BTN_BAN"), "dbg_ddos_ban", "-", view.lang),
        row(button(t("DDOS_BTN_RKN_SYNC"), "dbg:dd:rkn_sync", icon="refresh"), button(t("DDOS_BTN_PROBE"), "dbg:dd:probe", icon="scan")),
        row(button(t("DDOS_BTN_INSTALL"), "dbg:dd:install", icon="shield"), button(t("DDOS_BTN_REMOVE"), "dbg:dd:remove", icon="delete")),
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("DDOS_TITLE"), t("DDOS_SUBTITLE"), blocks, buttons, icon="shield")


def ddos_ips_screen(view: DbgView) -> Any:
    t = view.tr()
    status = view.ddos
    blocks = banner(view, t)
    records = status.ip_records() if status is not None else []
    blocked_total = sum(1 for item in records if item.blocked)
    unbanned_total = sum(1 for item in records if not item.blocked)
    max_page = max(0, (len(records) - 1) // DDOS_IPS_PAGE_SIZE) if records else 0
    page = max(0, min(int(view.ddos_page or 0), max_page))
    start = page * DDOS_IPS_PAGE_SIZE
    slice_records = list(enumerate(records[start : start + DDOS_IPS_PAGE_SIZE], start=start))
    if slice_records:
        rows = [
            ("stop" if rec.blocked else "ok", code(rec.address), _ddos_reason_label(t, rec.reason))
            for _idx, rec in slice_records
        ]
    else:
        rows = [("ok", muted(t("DDOS_IPS_EMPTY")), code("-"))]
    blocks.append(table(rows, (t("DDOS_IPS_TITLE"), t("DDOS_COL_STATUS"))))
    buttons: list[Any] = []
    action_btns: list[Any] = []
    for idx, rec in slice_records:
        token = _ddos_cb_token(rec.address, idx)
        short = _ddos_short_ip(rec.address)
        if rec.blocked:
            action_btns.append(button(t("DDOS_BTN_UNBAN_IP", ip=short), f"dbg:dd:ub:{page}:{token}", icon="unlock"))
        else:
            action_btns.append(button(t("DDOS_BTN_REBAN_IP", ip=short), f"dbg:dd:rb:{page}:{token}", icon="stop"))
    for pos in range(0, len(action_btns), 2):
        buttons.append(row(*action_btns[pos : pos + 2]))
    if max_page > 0:
        nav_btns: list[Any] = []
        if page > 0:
            nav_btns.append(button(t("DDOS_PAGE_PREV", cur=page, total=max_page + 1), f"dbg:dd:ips:{page - 1}", icon="back"))
        if page < max_page:
            nav_btns.append(button(t("DDOS_PAGE_NEXT", cur=page + 2, total=max_page + 1), f"dbg:dd:ips:{page + 1}", icon="route"))
        if nav_btns:
            buttons.append(row(*nav_btns))
    buttons.append(input_row(t("DDOS_BTN_BAN"), "dbg_ddos_ban", "-", view.lang))
    buttons.append(input_row(t("DDOS_BTN_ALLOW"), "dbg_ddos_allow", "-", view.lang))
    buttons.append(row(button(t("DDOS_BTN_BACK_DDOS"), "dbg:dd", icon="shield"), button(t("DDOS_BTN_REFRESH"), f"dbg:dd:ips:{page}", icon="refresh")))
    subtitle = t("DDOS_IPS_SUB", blocked=blocked_total, unbanned=unbanned_total)
    return screen(t("DDOS_IPS_TITLE"), subtitle, blocks, buttons, icon="shield")


def notify_kind_key(kind: str) -> str:
    name = str(kind).upper()
    if name == "SSH_BRUTE":
        name = "SSH"
    return "NTF_KIND_" + name


def notify_kind_label(t: Any, kind: str) -> str:
    return t(notify_kind_key(kind))


def notify_hint(t: Any, kind: str) -> str:
    if kind == notify.KIND_PORTSCAN:
        return t("NTF_HINT_PORTSCAN", ports=notify.PORT_SCAN_PORTS, window=int(notify.PORT_SCAN_WINDOW))
    if kind == notify.KIND_SSH:
        return t("NTF_HINT_SSH", count=notify.SSH_FAILS, window=int(notify.SSH_WINDOW))
    if kind == notify.KIND_BAN:
        return t("NTF_HINT_BAN", days=7)
    if kind == notify.KIND_HONEYPOT:
        return t("NTF_HINT_HONEYPOT")
    if kind == notify.KIND_SUBS:
        return t("NTF_HINT_SUBS")
    if kind == notify.KIND_DDOS:
        return t("NTF_HINT_DDOS")
    return t("NTF_HINT_CORE")


def notify_message(event: Any, t: Any) -> Any:
    days = 7
    shown = ", ".join(str(item) for item in (getattr(event, "evidence", None) or [])[:8]) or "-"
    address = notify.mask(getattr(event, "address", ""))
    count = int(getattr(event, "count", 1) or 1)
    kind = getattr(event, "kind", notify.KIND_CORE)
    if kind == notify.KIND_PORTSCAN:
        body = t("NTF_MSG_PORTSCAN", address=address, count=count, ports=shown)
    elif kind == notify.KIND_SSH:
        body = t("NTF_MSG_SSH", address=address, count=count, days=days)
    elif kind == notify.KIND_BAN:
        body = t("NTF_MSG_BAN", address=address, days=days)
    elif kind == notify.KIND_HONEYPOT:
        body = t("NTF_MSG_HONEYPOT", address=address, ports=shown)
    elif kind == notify.KIND_SUBS:
        body = t("NTF_MSG_SUBS", address=address, count=count)
    elif kind == notify.KIND_DDOS:
        body = t("NTF_MSG_DDOS", address=address, value=str(getattr(event, "detail", "") or "-")[:60])
    else:
        body = t("NTF_MSG_CORE", value=str(getattr(event, "detail", "") or "-")[:60])
    mark = {"bad": "shield", "warn": "warn"}.get(getattr(event, "severity", lambda: "warn")(), "bell")
    blocks = [
        table([(mark, notify_kind_label(t, kind), code(body))], (t("NTF_MSG_TITLE"), notify_kind_label(t, kind))),
    ]
    btns = [row(button(t("DDOS_BTN_IPS_OPEN"), "dbg:dd:ips", icon="shield"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools"))]
    return screen(t("NTF_MSG_TITLE"), t("NTF_TITLE"), blocks, btns, icon="bell")


def notify_screen(view: "DbgView") -> Any:
    t = view.tr()
    centre = view.notify
    settings = getattr(centre, "settings", None) if centre is not None else None
    summary = centre.summary() if hasattr(centre, "summary") else {}
    blocks = banner(view, t)
    any_on = bool(settings.any_on()) if settings is not None else False
    rows_data = [
        ("bell" if any_on else "mute", t("NTF_STATE"), code(t("NTF_STATE_ON") if any_on else t("NTF_STATE_OFF"))),
        ("clock", t("NTF_QUEUE"), code(int(summary.get("queued", 0)))),
        ("target", t("NTF_TRACKED"), code(int(summary.get("tracked", 0)))),
    ]
    if settings is not None and settings.muted():
        rows_data.append(("mute", t("NTF_STATE"), code(t("NTF_MUTED"))))
    blocks.append(table(rows_data, (t("NTF_TITLE"), t("UI_VALUE"))))
    kinds = []
    for kind in notify.KINDS:
        on = settings.on(kind) if settings is not None else notify.DEFAULT_ON.get(kind, False)
        kinds.append(("bell" if on else "mute", notify_kind_label(t, kind), code(t("NTF_STATE_ON") if on else t("NTF_STATE_OFF"))))
    blocks.append(table(kinds, (t("NTF_TITLE"), t("UI_VALUE"))))
    hints = []
    for kind in notify.KINDS:
        hints.append((notify.SEVERITY.get(kind, "warn"), notify_kind_label(t, kind), notify_hint(t, kind)))
    blocks.append(details(t("HOME_DETAILS"), table(hints, (t("NTF_TITLE"), t("UI_VALUE")))))
    blocks.append(quote(muted(t("NTF_OWNER_RULE"))))
    buttons = []
    kind_btns = []
    for kind in notify.KINDS:
        on = settings.on(kind) if settings is not None else notify.DEFAULT_ON.get(kind, False)
        kind_btns.append(button(notify_kind_label(t, kind), "dbg:ntf:" + kind, icon="mute" if on else "bell"))
    for idx in range(0, len(kind_btns), 2):
        buttons.append(row(*kind_btns[idx:idx + 2]))
    buttons.append(row(button(t("NTF_BTN_TEST"), "dbg:ntf:test", icon="bell"), button(t("NTF_BTN_ALL_ON"), "dbg:ntf:on", icon="bell"), button(t("NTF_BTN_ALL_OFF"), "dbg:ntf:off", icon="mute")))
    buttons.append(row(button(t("HP_BTN_OPEN"), "dbg:hp", icon="target"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")))
    return screen(t("NTF_TITLE"), t("NTF_SUBTITLE"), blocks, buttons, icon="bell")


def honey_quote(t: Any, state: Any, error: str = "", busy: bool = False) -> str:
    if error:
        return t("HP_ERR", value=error[:90])
    if busy:
        return t("HP_QUOTE_BUSY")
    if state is None or not getattr(state, "installed", False):
        return t("HP_QUOTE_OFF")
    return t("HP_QUOTE_ON", days=7)


def honeypot_screen(view: "DbgView") -> Any:
    t = view.tr()
    state = view.honeypot
    blocks = banner(view, t)
    blocks.append(quote(bold(honey_quote(t, state, view.error, view.honey_busy))))
    if state is not None:
        ports = ", ".join(str(item) for item in state.ports) or "-"
        profiles = ", ".join("%s %s" % (key, value) for key, value in sorted(state.profiles.items())) or "-"
        blocks.append(
            table(
                [
                    ("target" if state.active else "mute", t("HP_INSTALLED"), code(t("HP_ON") if state.installed else t("HP_OFF"))),
                    ("radar" if state.running else "mute", t("HP_RUNNING"), code(t("HP_ON") if state.running else t("HP_OFF"))),
                    ("plug", t("HP_PORTS"), code(ports)),
                    ("route", t("HP_PROFILES"), code(profiles)),
                    ("logs", t("HP_TOTAL"), code(int(state.total))),
                ],
                (t("HP_TITLE"), t("UI_VALUE")),
            )
        )
        counts = sorted((state.events or {}).items(), key=lambda item: (-item[1], item[0]))
        if counts:
            blocks.append(table([("chart", key, code(value)) for key, value in counts[:8]], (t("HP_EVENTS"), t("UI_VALUE"))))
        if state.top:
            blocks.append(table([("target", notify.mask(item[0]), code(item[1])) for item in state.top[:8]], (t("HP_TOP"), t("UI_VALUE"))))
        if state.log:
            blocks.append(quote(muted(t("HP_LOG") + " " + state.log)))
    blocks.append(quote(muted(t("HP_NOTE"))))
    blocks.append(quote(muted(t("HP_BANNER"))))
    buttons = [
        row(button(t("HP_BTN_INSTALL"), "dbg:hp:install", icon="add"), button(t("HP_BTN_REFRESH"), "dbg:hp:refresh", icon="refresh")),
        row(button(t("HP_BTN_START"), "dbg:hp:start", icon="restart"), button(t("HP_BTN_STOP"), "dbg:hp:stop", icon="stop")),
        row(button(t("HP_BTN_SELFCHECK"), "dbg:hp:check", icon="ok"), button(t("HP_BTN_REMOVE"), "dbg:hp:remove", icon="delete")),
        row(
            button(t("NTF_BTN_OPEN"), "dbg:ntf", icon="bell"),
            button(t("TOOLS_TITLE"), "dbg:home", icon="tools"),
        ),
    ]
    return screen(t("HP_TITLE"), t("HP_SUBTITLE"), blocks, buttons, icon="target")
