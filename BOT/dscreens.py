from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from datetime import datetime, timezone
from typing import Any

from . import antiddos, dpi, i18n, ipscan, net, notify, scripts
from .ui import (
    MAX_CALLBACK,
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
    dpi: Any = None
    notify: Any = None
    honeypot: Any = None
    honey_busy: bool = False
    ddos: Any = None
    ddos_exposure: Any = None
    ddos_busy: bool = False
    ddos_page: int = 0
    ddos_alerts: bool = True
    ddos_bot_mismatch: bool = False
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


def back_row(t: i18n.Translator, target: str) -> str:
    return row(button(t("UI_BACK"), target, icon="back"))


def home(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    buttons = [
        row(button(t("TOOLS_NETWORK"), "dbg:network", icon="radar"), button(t("TOOLS_DIAGNOSTICS"), "dbg:diagnostics", icon="scan")),
        row(button(t("VKCALLS_BTN"), "vk:home", icon="calls")),
        back_row(t, "nav:home"),
    ]
    return screen(t("TOOLS_TITLE"), t("DBG_SUBTITLE"), blocks, buttons, icon="tools")


def network_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    buttons = [
        row(button(t("DBG_SCAN_BTN"), "dbg:scan", icon="radar"), button(t("DBG_TRACE_BTN"), "dbg:trace", icon="route")),
        row(button(t("DBG_PORTS_BTN"), "dbg:ports", icon="plug")),
        back_row(t, "dbg:home"),
    ]
    return screen(t("TOOLS_NETWORK"), t("TOOLS_SCAN_SUB"), blocks, buttons, icon="radar")


def diagnostics_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    buttons = [
        row(button(t("DPI_BTN_OPEN"), "dbg:dpi", icon="warn"), button(t("DBG_VK_BTN"), "dbg:vk", icon="world")),
        row(button(t("DBG_SCRIPTS_BTN"), "dbg:scr", icon="file"), button(t("DBG_INFO_BTN"), "dbg:info", icon="server")),
        back_row(t, "dbg:home"),
    ]
    return screen(t("TOOLS_DIAGNOSTICS"), t("DBG_SUBTITLE"), blocks, buttons, icon="scan")


def protection_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    buttons = [
        row(button(t("DDOS_BTN_OPEN"), "dbg:dd", icon="shield"), button(t("FT_FW_TITLE"), "ft:fw", icon="shield")),
        row(button(t("NAV_FAIL2BAN"), "nav:ban", icon="shield"), button(t("NAV_SSHD"), "nav:sshd", icon="key")),
        row(button(t("HP_BTN_OPEN"), "dbg:hp", icon="target"), button(t("NTF_BTN_OPEN"), "dbg:ntf", icon="bell")),
        back_row(t, "nav:home"),
    ]
    return screen(t("NAV_PROTECTION"), t("DDOS_SUBTITLE"), blocks, buttons, icon="shield")


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
        back_row(t, "dbg:network"),
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
        back_row(t, "dbg:network"),
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
        back_row(t, "dbg:diagnostics"),
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
        row(button(t("DBG_PORTS_BTN"), "dbg:ports:go", icon="refresh")),
        back_row(t, "dbg:network"),
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
        row(button(t("SCR_KEEP"), "dbg:scr:keep", icon="back")),
        back_row(t, "dbg:diagnostics"),
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
    buttons = [back_row(t, "dbg:diagnostics")]
    return screen(t("DBG_INFO_TITLE"), t("DBG_INFO_SUBTITLE"), blocks, buttons, icon="server")


def busy(view: DbgView, text: str = "") -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if text:
        blocks.append(quote(muted(text)))
    return screen(t("BUSY_TITLE"), "", blocks, [], icon="loading")


def stub_screen(view: DbgView, name: str, reason: str, host: str, retry: str = "") -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(t("DBG_STUB_TITLE"))))
    blocks.append(f"<p>{t('DBG_STUB_BODY', name=code(name[:40]), reason=code(reason[:120]))}</p>")
    if host:
        blocks.append(quote(muted_html(t("DBG_STUB_HINT", host=bold(host[:64])))))
    buttons = []
    if retry:
        buttons.append(row(button(t("DBG_STUB_RETRY"), retry, icon="refresh")))
    buttons.append(back_row(t, "dbg:home"))
    return screen(t("DBG_STUB_TITLE"), t("DBG_SUBTITLE"), blocks, buttons, icon="warn")


def crash_screen(view: DbgView, route: str, trace: str) -> Any:

    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(view.error or t("DBG_ERR_TITLE"))))
    blocks.append(f"<p>{muted(t('DBG_ERR_TRACE'))}</p>")
    blocks.append(table([("bug", t("DBG_TITLE"), code(route[:48]))], (t("UI_PARAM"), t("UI_VALUE"))))
    blocks.append(pre((trace or t("UI_NONE"))[-3400:]))
    buttons = [back_row(t, "dbg:home")]
    return screen(t("DBG_ERR_TITLE"), t("DBG_SUBTITLE"), blocks, buttons, icon="fail")


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
        row(button(t("DPI_BTN_RUN"), "dbg:dpi:scan", icon="scan")),
        back_row(t, "dbg:diagnostics"),
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
    return str(address or "").strip()


def _ddos_ipscan_callback(address: str, page: int) -> str:
    target = ipscan.ip_target(address)
    callback = f"dbg:dd:ipscan:{max(int(page), 0)}:{target}"
    return callback if target and len(callback.encode("utf-8")) <= MAX_CALLBACK else ""


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
            row(button(t("DDOS_SOURCES"), "dbg:dd:src", icon="world"), button(t("DDOS_LOGS"), "dbg:dd:logs", icon="file"), button(t("DDOS_FW_DIAG"), "dbg:dd:fwdiag", icon="scan")),
            back_row(t, "nav:protect"),
        ]
        return screen(t("DDOS_TITLE"), t("DDOS_SUBTITLE"), blocks, buttons, icon="shield")
    level = "ok"
    try:
        level = str(status.level())
    except Exception:
        level = "ok"
    mark = {"ok": "shield", "warn": "warn", "bad": "fail"}.get(level, "shield")
    policy = status.policy
    rkn_on = bool(getattr(status, "rkn_enabled", policy.rkn_enabled) and status.enabled and status.table)
    v4_count = int(getattr(status, "rkn_v4_count", 0) or 0)
    v6_count = int(getattr(status, "rkn_v6_count", 0) or 0)
    records = status.ip_records()
    blocked_total = status.blocked_count()
    table_unknown = getattr(status, "table_inspection", "not_checked") == "unknown"
    if table_unknown:
        active_state = t("DDOS_FW_UNKNOWN")
    elif status.enabled and status.table:
        active_state = t("UI_ON") + " · " + ddos_level(t, status)
    elif status.table:
        active_state = t("UI_OFF") + " · " + t("DDOS_FW_PRESENT")
    else:
        active_state = t("UI_OFF")
    rkn_state = t("DDOS_FW_UNKNOWN") if table_unknown else (("%s · %d IPv4, %d IPv6" % (t("UI_ON"), v4_count, v6_count)) if rkn_on else t("UI_OFF"))
    total_drops = int(status.dropped())
    rkn_drops = int(status.rkn_dropped())
    flood_drops = max(0, total_drops - rkn_drops)
    state_rows = [
        (mark, t("DDOS_STATE"), code(active_state)),
        ("shield", t("DDOS_BACKEND"), code("nftables" if status.table else "-")),
        ("shield", t("DDOS_RKN_STATE"), code(rkn_state)),
        ("bell", t("DDOS_ALERTS"), code(t("UI_ON") if view.ddos_alerts else t("UI_OFF"))),
        ("speed", t("DDOS_TRAFFIC"), code(t("DDOS_TRAFFIC_VAL", pps=status.pps, conns=status.connections))),
        ("stop", t("DDOS_DROPS"), code(t("DDOS_DROPS_VAL", total=total_drops, rkn=rkn_drops, flood=flood_drops))),
        ("plug", t("DDOS_PORTS"), code(",".join(str(item) for item in policy.ports))),
    ]
    if not records:
        state_rows.append(("ok", t("DDOS_BLOCKED_IPS"), code("0")))
    blocks.append(table(state_rows, (t("DDOS_TITLE"), t("UI_VALUE"))))
    if table_unknown:
        blocks.append(quote(t("DDOS_TABLE_UNKNOWN")))
    elif status.table and not status.enabled:
        blocks.append(quote(t("DDOS_TABLE_UNEXPECTED")))
    elif status.table and not status.installed:
        blocks.append(quote(t("DDOS_TABLE_UNMANAGED")))
    if view.ddos_bot_mismatch:
        blocks.append(quote(t("DDOS_BOT_POLICY_MISMATCH")))
    transaction = getattr(status, "transaction_state", "none")
    if transaction in ("automatic", "manual"):
        blocks.append(quote(t("DDOS_WAL_PENDING")))
    elif transaction != "none":
        blocks.append(quote(t("DDOS_WAL_INVALID")))
    consistency = getattr(status, "saved_policy_consistency", "not_checked")
    if status.enabled and consistency == "mismatch":
        blocks.append(quote(t("DDOS_SAVED_MISMATCH")))
    elif status.enabled and consistency == "unknown":
        blocks.append(quote(t("DDOS_SAVED_UNKNOWN")))
    live_rates = getattr(status, "live_rate_consistency", "not_checked")
    if status.enabled and status.table and live_rates == "mismatch":
        blocks.append(quote(t("DDOS_LIVE_RATE_MISMATCH")))
    elif status.enabled and status.table and live_rates == "unknown":
        blocks.append(quote(t("DDOS_LIVE_RATE_UNKNOWN")))
    if rkn_on:
        blocks.append(quote(muted(t("DDOS_RKN_COUNTS_CACHE"))))
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
        row(button(t("DDOS_BTN_IPS", count=blocked_total), "dbg:dd:ips", icon="target"), button(t("DDOS_BTN_REFRESH"), "dbg:dd:refresh", icon="refresh"), button(t("UI_BACK"), "nav:protect", icon="back")),
        row(button(rkn_btn_label, "dbg:dd:rkn", icon="shield"), button(ntf_btn_label, "dbg:dd:ntf", icon="bell")),
        row(button(t("DDOS_BTN_RKN_SYNC"), "dbg:dd:rkn_sync", icon="refresh"), button(t("DDOS_SOURCES"), "dbg:dd:src", icon="world"), button(t("DDOS_LOGS"), "dbg:dd:logs", icon="file")),
        row(button(t("DDOS_BTN_PROBE"), "dbg:dd:probe", icon="scan"), button(t("DDOS_FW_DIAG"), "dbg:dd:fwdiag", icon="scan")),
    ]
    maintenance: list[Any] = []
    if view.ddos_bot_mismatch and transaction == "none" and len(getattr(status, "policy_sha256", "")) == 64:
        maintenance.append(button(t("DDOS_ADOPT"), "dbg:dd:adopt_policy", icon="save"))
    if transaction in ("automatic", "manual") and len(getattr(status, "transaction_digest", "")) == 64:
        maintenance.append(button(t("DDOS_WAL_RECOVER"), "dbg:dd:wal_recover", icon="refresh"))
    if status.enabled and status.installed and getattr(status, "reconcile_fingerprint", ""):
        maintenance.append(button(t("DDOS_RECONCILE"), "dbg:dd:reconcile", icon="refresh"))
    if not maintenance:
        if status.installed and status.enabled:
            maintenance.append(button(t("DDOS_BTN_REMOVE"), "dbg:dd:remove", icon="delete"))
        else:
            maintenance.append(button(t("DDOS_BTN_INSTALL"), "dbg:dd:install", icon="shield"))
    buttons.append(row(*maintenance))
    return screen(t("DDOS_TITLE"), t("DDOS_SUBTITLE"), blocks, buttons, icon="shield")


def ddos_reconcile_screen(view: DbgView, status: antiddos.Status, token: str) -> Any:
    t = view.tr()
    p = status.policy
    blocks = banner(view, t)
    blocks.append(quote(t("DDOS_RECONCILE_NOTE")))
    blocks.append(table([
        ("plug", t("DDOS_PORTS"), code(",".join(str(item) for item in p.ports))),
        ("shield", t("DDOS_RKN_STATE"), code(t("UI_ON") if p.rkn_enabled else t("UI_OFF"))),
        ("speed", "SYN / UDP", code("%d/%d · %d/%d" % (p.syn_rate, p.syn_burst, p.udp_rate, p.udp_burst))),
        ("file", "SHA-256", code(status.reconcile_fingerprint[:16])),
    ], (t("UI_PARAM"), t("UI_VALUE"))))
    buttons = [row(button(t("DDOS_RECONCILE_CONFIRM"), "dbg:dd:reconcile_do:" + token, icon="save"), button(t("UI_BACK"), "dbg:dd", icon="back"))]
    return screen(t("DDOS_RECONCILE"), t("DDOS_SUBTITLE"), blocks, buttons, icon="warn")


def ddos_adopt_screen(view: DbgView, status: antiddos.Status, token: str) -> Any:
    t = view.tr()
    p = status.policy
    blocks = banner(view, t)
    blocks.append(quote(t("DDOS_ADOPT_NOTE")))
    blocks.append(table([
        ("plug", t("DDOS_PORTS"), code(",".join(str(item) for item in p.ports))),
        ("shield", t("DDOS_RKN_STATE"), code(t("UI_ON") if p.rkn_enabled else t("UI_OFF"))),
        ("speed", "SYN / UDP", code("%d/%d · %d/%d" % (p.syn_rate, p.syn_burst, p.udp_rate, p.udp_burst))),
        ("file", "SHA-256", code(status.policy_sha256[:16])),
    ], (t("UI_PARAM"), t("UI_VALUE"))))
    buttons = [row(button(t("DDOS_ADOPT_CONFIRM"), "dbg:dd:adopt_do:" + token, icon="save"), button(t("UI_BACK"), "dbg:dd", icon="back"))]
    return screen(t("DDOS_ADOPT"), t("DDOS_SUBTITLE"), blocks, buttons, icon="warn")


def ddos_wal_screen(view: DbgView, status: antiddos.Status, token: str) -> Any:
    t = view.tr()
    p = status.transaction_policy
    blocks = banner(view, t)
    blocks.append(quote(t("DDOS_WAL_CONFIRM_NOTE")))
    blocks.append(table([
        ("plug", t("DDOS_PORTS"), code(",".join(str(item) for item in p.ports))),
        ("shield", t("DDOS_RKN_STATE"), code(t("UI_ON") if p.rkn_enabled else t("UI_OFF"))),
        ("speed", "SYN / UDP", code("%d/%d · %d/%d" % (p.syn_rate, p.syn_burst, p.udp_rate, p.udp_burst))),
        ("file", "SHA-256", code(status.transaction_digest[:16])),
    ], (t("UI_PARAM"), t("UI_VALUE"))))
    buttons = [row(button(t("DDOS_WAL_CONFIRM"), "dbg:dd:wal_do:" + token, icon="save"), button(t("UI_BACK"), "dbg:dd", icon="back"))]
    return screen(t("DDOS_WAL_RECOVER"), t("DDOS_SUBTITLE"), blocks, buttons, icon="warn")


def ddos_sources_screen(view: DbgView, policy: antiddos.Policy, page: int = 0, cache: dict[str, Any] | None = None) -> Any:
    t = view.tr()
    entries = [(name, url, False) for name, url in antiddos.RKN_SOURCES]
    entries.extend(("custom_%d" % (idx + 1), url, True) for idx, url in enumerate(policy.custom_sources) if all(url != base[1] for base in antiddos.RKN_SOURCES))
    pages = max(1, (len(entries) + 2) // 3)
    page = max(0, min(page, pages - 1))
    blocks = banner(view, t)
    blocks.append(quote(muted(t("DDOS_SOURCES_NOTE"))))
    buttons = []
    for name, url, custom in entries[page * 3:page * 3 + 3]:
        enabled = url not in policy.disabled_sources
        state = t("UI_ON") if enabled else t("UI_OFF")
        short_url = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        source_rows = [("world", name + " · " + state, code(short_url[:36] or url[:36]))]
        saved = (cache or {}).get(url, {})
        if isinstance(saved, dict):
            count = len(saved.get("v4") or []) + len(saved.get("v6") or [])
            try:
                stamp = datetime.fromtimestamp(int(saved.get("updated_at") or 0), timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if saved.get("updated_at") else "-"
            except (TypeError, ValueError, OverflowError, OSError):
                stamp = "-"
            source_rows.append(("clock", t("DDOS_SOURCE_CACHE"), code("%d · %s" % (count, stamp))))
            if saved.get("error"):
                source_rows.append(("warn", t("DDOS_SOURCE_ERROR"), code(str(saved["error"])[:80])))
        blocks.append(table(source_rows, (t("DDOS_SOURCES"), t("UI_VALUE"))))
        blocks.append(details(t("DDOS_SOURCE_URL"), pre(url)))
        key = sha256(url.encode("utf-8")).hexdigest()[:12]
        controls = [button((t("DDOS_SOURCE_DISABLE") if enabled else t("DDOS_SOURCE_ENABLE")) + " · " + name, "dbg:dd:src:t:" + key, icon="shield")]
        if custom:
            controls.append(button(t("DDOS_SOURCE_REMOVE") + " · " + name, "dbg:dd:src:d:" + key, icon="delete"))
        buttons.append(row(*controls))
    buttons.append(row(button("<", "dbg:dd:src:p:%d" % max(0, page - 1), icon="back"), button("%d / %d" % (page + 1, pages), "dbg:dd:src:p:%d" % page, icon="file"), button(">", "dbg:dd:src:p:%d" % min(pages - 1, page + 1), icon="route")))
    buttons.append(input_row(t("DDOS_SOURCE_ADD"), "dbg_rkn_source", "-", view.lang))
    buttons.append(back_row(t, "dbg:dd"))
    return screen(t("DDOS_SOURCES"), t("DDOS_SUBTITLE"), blocks, buttons, icon="world")


def ddos_schedule_screen(view: DbgView, schedule: dict[str, Any]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    mode = str(schedule.get("mode", "off"))
    mode = {"hours": t("DDOS_SCHEDULE_HOURS"), "calendar": t("DDOS_SCHEDULE_CALENDAR"), "off": t("UI_OFF")}.get(mode, mode)
    value = str(schedule.get("value", ""))
    active = t("UI_ON") if schedule.get("active") else t("UI_OFF")
    blocks.append(table([("clock", t("DDOS_SCHEDULE"), code(mode + (" " + value if value else ""))), ("shield", t("DDOS_TIMER_STATE"), code(active))], (t("DDOS_TITLE"), t("UI_VALUE"))))
    blocks.append(quote(muted(t("DDOS_SCHEDULE_NOTE"))))
    buttons = [input_row(t("DDOS_SCHEDULE_CHANGE"), "dbg_rkn_schedule", "-", view.lang), row(button(t("DDOS_SCHEDULE_12"), "dbg:dd:sched12", icon="clock"), button("06:00 MSK", "dbg:dd:sched6", icon="clock"), button(t("DDOS_SCHEDULE_OFF"), "dbg:dd:schedoff", icon="stop")), row(button(t("DDOS_BTN_REFRESH"), "dbg:dd:schedule", icon="refresh")), back_row(t, "dbg:dd")]
    return screen(t("DDOS_SCHEDULE"), t("DDOS_SUBTITLE"), blocks, buttons, icon="clock")


def ddos_exceptions_screen(view: DbgView, policy: antiddos.Policy) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(t("DDOS_EXCEPTION_NOTE"))))
    blocks.append(pre("\n".join(policy.rkn_exceptions)[:3000] or "-"))
    buttons = [input_row(t("DDOS_EXCEPTION_EDIT"), "dbg_rkn_exception", "-", view.lang), back_row(t, "dbg:dd")]
    return screen(t("DDOS_EXCEPTIONS"), t("DDOS_SUBTITLE"), blocks, buttons, icon="key")


def ddos_logs_screen(view: DbgView, text: str, kind: str = "v4", logging_enabled: bool = True, live: bool = False, stream: bool = False) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(t("DDOS_LOGS_NOTE") if kind in ("service", "update") else (t("DDOS_TOP_NOTE") if kind == "top" else t("DDOS_PACKET_LOG_NOTE")))))
    if live:
        blocks.append(quote(muted(t("DDOS_STREAM_NOTE" if stream else "DDOS_LIVE_NOTE"))))
    blocks.append(pre(text[-3000:] or "-"))
    state = t("UI_ON") if logging_enabled else t("UI_OFF")
    buttons = [
        row(button("IPv4", "dbg:dd:logs:v4", icon="file"), button("IPv6", "dbg:dd:logs:v6", icon="file"), button(t("DDOS_TOP"), "dbg:dd:logs:top", icon="target")),
        row(button(t("DDOS_SERVICE_LOGS"), "dbg:dd:logs:service", icon="file"), button(t("DDOS_UPDATE_LOGS"), "dbg:dd:logs:update", icon="file"), button(t("DDOS_FW_DIAG"), "dbg:dd:fwdiag", icon="scan")),
        row(button(t("DDOS_LOG_SWITCH", state=state), "dbg:dd:log_toggle", icon="shield"), button(t("DDOS_EXCEPTIONS"), "dbg:dd:exceptions", icon="key"), button(t("DDOS_SCHEDULE"), "dbg:dd:schedule", icon="clock")),
        row(button(t("DDOS_BTN_REFRESH"), "dbg:dd:logs:" + kind, icon="refresh"), button(t("DDOS_LIVE_STOP" if live else "DDOS_LIVE_START"), "dbg:dd:" + ("live_stop:" if live else "live:") + kind, icon="clock")),
        back_row(t, "dbg:dd"),
    ]
    if kind == "top":
        buttons.insert(-1, row(button(t("DDOS_STATS_RESET"), "dbg:dd:stats_reset", icon="delete")))
    return screen(t("DDOS_LOGS"), t("DDOS_SUBTITLE"), blocks, buttons, icon="file")


def ddos_firewall_diag_screen(view: DbgView, data: dict[str, Any]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(t("DDOS_FW_DIAG_NOTE"))))
    rows_data = []
    for name, label in (("backend", "OBHOD"), ("ufw", "UFW"), ("firewalld", "firewalld"), ("nft", "nft"), ("iptables", "iptables"), ("ip6tables", "ip6tables"), ("ipset", "ipset")):
        value = str(data.get(name, "unknown"))[:100]
        value = {"active": t("DDOS_FW_ACTIVE"), "inactive": t("DDOS_FW_INACTIVE"), "unknown": t("DDOS_FW_UNKNOWN"), "unavailable": t("DDOS_FW_UNAVAILABLE")}.get(value, value)
        rows_data.append(("shield", label, code(value)))
    upstream = data.get("upstream_state_present")
    upstream_text = t("DDOS_FW_UNKNOWN") if upstream is None else t("UI_ON") if upstream else t("UI_OFF")
    rows_data.append(("warn" if upstream else "info", "rkn-guard", code(upstream_text)))
    for key, label in (("upstream_nft_table", "rkn nft table"), ("upstream_iptables_nft", "rkn iptables-nft"), ("upstream_ip6tables_nft", "rkn ip6tables-nft"), ("upstream_iptables_legacy", "rkn iptables-legacy"), ("upstream_ip6tables_legacy", "rkn ip6tables-legacy")):
        value = data.get(key, "unknown")
        text = {"present": t("DDOS_FW_PRESENT"), "absent": t("DDOS_FW_ABSENT"), "unknown": t("DDOS_FW_UNKNOWN"), "unavailable": t("DDOS_FW_UNAVAILABLE")}.get(value, t("DDOS_FW_UNKNOWN"))
        rows_data.append(("warn" if value == "present" else "info", label, code(text)))
    blocks.append(table(rows_data, (t("DDOS_BACKEND"), t("UI_VALUE"))))
    if any(data.get(key) == "present" for key in ("upstream_nft_table", "upstream_iptables_nft", "upstream_ip6tables_nft", "upstream_iptables_legacy", "upstream_ip6tables_legacy")):
        blocks.append(quote(t("DDOS_FW_UPSTREAM_PRESENT")))
    if data.get("conflict"):
        blocks.append(quote(muted(t("DDOS_FW_CONFLICT"))))
    buttons = [
        row(button(t("DDOS_UPSTREAM_TITLE"), "dbg:dd:upstream", icon="file")),
        row(button(t("DDOS_BTN_REFRESH"), "dbg:dd:fwdiag", icon="refresh")),
        back_row(t, "dbg:dd"),
    ]
    return screen(t("DDOS_FW_DIAG"), t("DDOS_SUBTITLE"), blocks, buttons, icon="scan")


def ddos_upstream_screen(view: DbgView, data: dict[str, Any], confirm: bool = False) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(t("DDOS_UPSTREAM_NOTE"))))
    if confirm:
        blocks.append(quote(muted(t("DDOS_UPSTREAM_CONFIRM_NOTE"))))
        buttons = [row(button(t("DDOS_UPSTREAM_CONFIRM"), "dbg:dd:upstream_install", icon="save")), back_row(t, "dbg:dd:upstream")]
    else:
        if "installed" not in data:
            state = t("DDOS_FW_UNKNOWN")
        elif not data.get("installed"):
            state = t("DDOS_UPSTREAM_MISSING")
        elif data.get("verified"):
            state = t("DDOS_UPSTREAM_VERIFIED")
        else:
            state = t("DDOS_UPSTREAM_INVALID")
        version = str(data.get("version", "") or data.get("expected_version", "v3.0.0"))[:40]
        arch = str(data.get("architecture", "-"))[:24]
        blocks.append(table([("shield", t("DDOS_STATE"), code(state)), ("file", t("DDOS_UPSTREAM_VERSION"), code(version)), ("info", t("DDOS_UPSTREAM_ARCH"), code(arch))], (t("DDOS_UPSTREAM_TITLE"), t("UI_VALUE"))))
        buttons = [
            row(button(t("DDOS_UPSTREAM_INSTALL"), "dbg:dd:upstream_confirm", icon="save")),
            row(button(t("DDOS_BTN_REFRESH"), "dbg:dd:upstream", icon="refresh"), button(t("DDOS_FW_DIAG"), "dbg:dd:fwdiag", icon="scan")),
            back_row(t, "dbg:dd"),
        ]
    return screen(t("DDOS_UPSTREAM_TITLE"), t("DDOS_SUBTITLE"), blocks, buttons, icon="file")


def ddos_stats_reset_screen(view: DbgView) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(muted(t("DDOS_STATS_RESET_NOTE"))))
    buttons = [
        row(button(t("DDOS_STATS_RESET_CONFIRM"), "dbg:dd:stats_reset_confirm", icon="delete")),
        back_row(t, "dbg:dd:logs:top"),
    ]
    return screen(t("DDOS_STATS_RESET"), t("DDOS_SUBTITLE"), blocks, buttons, icon="shield")


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
    for idx, rec in slice_records:
        controls: list[Any] = []
        token = _ddos_cb_token(rec.address, idx)
        action = "ub" if rec.blocked else "rb"
        callback = f"dbg:dd:{action}:{page}:{token}"
        if token and len(callback.encode("utf-8")) <= MAX_CALLBACK:
            if rec.blocked:
                controls.append(button(t("DDOS_BTN_UNBAN_IP", ip=rec.address), callback, icon="unlock"))
            else:
                controls.append(button(t("DDOS_BTN_REBAN_IP", ip=rec.address), callback, icon="stop"))
        scan_callback = _ddos_ipscan_callback(rec.address, page)
        if scan_callback:
            controls.append(button(t("IPSCAN_BTN_SCAN_IP", ip=rec.address), scan_callback, icon="radar"))
        if controls:
            buttons.append(row(*controls))
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
    buttons.append(row(button(t("DDOS_BTN_REFRESH"), f"dbg:dd:ips:{page}", icon="refresh")))
    buttons.append(back_row(t, "dbg:dd"))
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


def notify_message(event: Any, t: Any, scan_data: dict[str, Any] | None = None) -> Any:
    days = 7
    shown = ", ".join(str(item) for item in (getattr(event, "evidence", None) or [])[:8]) or "-"
    address = str(getattr(event, "address", "") or "").strip() or "-"
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
    if scan_data is not None:
        blocks.extend(ipscan.notification_blocks(scan_data, t.language))
    btns = []
    target = ipscan.scan_ip(address)
    if target:
        btns.append(row(button(t("IPSCAN_BTN_RESCAN"), "ipscan:run:" + target, icon="radar")))
    btns.extend(
        [
            row(button(t("DDOS_BTN_IPS_OPEN"), "dbg:dd:ips", icon="shield")),
            back_row(t, "nav:protect"),
        ]
    )
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
    buttons.append(row(button(t("HP_BTN_OPEN"), "dbg:hp", icon="target")))
    buttons.append(back_row(t, "nav:protect"))
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
    scan_ips: list[str] = []
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
            top_rows = list(state.top[:8])
            blocks.append(table([("target", str(item[0] or "-"), code(item[1])) for item in top_rows], (t("HP_TOP"), t("UI_VALUE"))))
            scan_ips = [target for item in top_rows if (target := ipscan.scan_ip(item[0]))]
        if state.log:
            blocks.append(quote(muted(t("HP_LOG") + " " + state.log)))
    blocks.append(quote(muted(t("HP_NOTE"))))
    blocks.append(quote(muted(t("HP_BANNER"))))
    buttons = [
        row(button(t("HP_BTN_INSTALL"), "dbg:hp:install", icon="add"), button(t("HP_BTN_REFRESH"), "dbg:hp:refresh", icon="refresh")),
        row(button(t("HP_BTN_START"), "dbg:hp:start", icon="restart"), button(t("HP_BTN_STOP"), "dbg:hp:stop", icon="stop")),
        row(button(t("HP_BTN_SELFCHECK"), "dbg:hp:check", icon="ok"), button(t("HP_BTN_REMOVE"), "dbg:hp:remove", icon="delete")),
        row(button(t("NTF_BTN_OPEN"), "dbg:ntf", icon="bell")),
    ]
    for start in range(0, len(scan_ips), 2):
        buttons.append(row(*[button(t("IPSCAN_BTN_SCAN_IP", ip=target), "ipscan:run:" + target, icon="radar") for target in scan_ips[start:start + 2]]))
    buttons.append(back_row(t, "nav:protect"))
    return screen(t("HP_TITLE"), t("HP_SUBTITLE"), blocks, buttons, icon="target")
