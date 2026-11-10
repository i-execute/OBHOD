from __future__ import annotations

from typing import Any

from . import dscreens, i18n
from .ui import bold, button, code, muted, quote, row, screen, table


def banner(v: Any, t: Any) -> list[str]:
    out: list[str] = []
    if getattr(v, "notice", ""):
        out.append(quote(muted(v.notice)))
    if getattr(v, "error", ""):
        out.append(quote(bold(v.error)))
    return out


def _t(v: Any) -> Any:
    return v.tr() if hasattr(v, "tr") else i18n.translator(getattr(v, "lang", i18n.DEFAULT_LANGUAGE))


def home(v: Any) -> Any:
    if isinstance(v, dscreens.DbgView):
        return dscreens.home(v)
    t = _t(v)
    blocks = banner(v, t)
    buttons = [
        row(button(t("FT_FW_TITLE"), "ft:fw", icon="shield"), button(t("DDOS_BTN_OPEN"), "dbg:dd", icon="shield"), button(t("NAV_FAIL2BAN"), "nav:ban", icon="shield")),
        row(button(t("NAV_SSHD"), "nav:sshd", icon="key"), button(t("HP_BTN_OPEN"), "dbg:hp", icon="target"), button(t("NTF_BTN_OPEN"), "dbg:ntf", icon="bell")),
        row(button(t("CHK_BTN_OPEN"), "dbg:chk", icon="shield"), button(t("DPI_BTN_OPEN"), "dbg:dpi", icon="warn"), button(t("DBG_VK_BTN"), "dbg:vk", icon="world")),
        row(button(t("DBG_SCAN_BTN"), "dbg:scan", icon="radar"), button(t("DBG_TRACE_BTN"), "dbg:trace", icon="route"), button(t("DBG_PORTS_BTN"), "dbg:ports", icon="plug")),
        row(button(t("DBG_SCRIPTS_BTN"), "dbg:scr", icon="file"), button(t("DBG_INFO_BTN"), "dbg:info", icon="server"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("TOOLS_TITLE"), t("DBG_SUBTITLE"), blocks, buttons, icon="tools")


def scan_screen(v: Any) -> Any:
    t = _t(v)
    blocks = banner(v, t)
    blocks.append(table([("radar", t("TOOLS_TARGET"), code(getattr(v, "target", "-") or "-")), ("plug", t("TOOLS_PORTS"), code(getattr(v, "ports", "-") or "-"))], (t("TOOLS_SCAN"), t("TOOLS_VALUE"))))
    ans = getattr(v, "scan", None)
    if ans and getattr(ans, "error", None):
        blocks.append(quote(bold(ans.error)))
    if ans and not getattr(ans, "error", None):
        blocks.append(table([("ok", t("TOOLS_HOSTS"), code(ans.hosts)), ("users", t("TOOLS_ALIVE"), code(ans.alive)), ("scan", t("TOOLS_OPEN"), code(len(ans.open_ports))), ("clock", t("TOOLS_SPENT"), code("%.2fs" % ans.spent))], (t("TOOLS_RESULT"), t("TOOLS_VALUE"))))
        if getattr(ans, "open_ports", None):
            blocks.append(table([("plug", t("TOOLS_OPEN"), code(item)) for item in ans.open_ports[:40]], (t("TOOLS_OPEN"), t("TOOLS_VALUE"))))
    buttons = [row(button(t("TOOLS_RUN"), "dbg:scan:go", icon="scan"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools"))]
    return screen(t("TOOLS_SCAN"), t("TOOLS_SCAN_SUB"), blocks, buttons, icon="radar")


def chebur_screen(v: Any) -> Any:
    t = _t(v)
    blocks = banner(v, t)
    if getattr(v, "chebur", None):
        blocks.append(table([("shield", t("TOOLS_VERDICT"), code(getattr(v.chebur, "verdict", "-"))), ("world", t("TOOLS_TARGET"), code(getattr(v, "chebur_target", "-") or "-"))], (t("TOOLS_CHEBUR"), t("TOOLS_VALUE"))))
    buttons = [row(button(t("TOOLS_CHECK"), "dbg:chk", icon="radar"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools"))]
    return screen(t("TOOLS_CHEBUR"), t("TOOLS_CHEBUR_SUB"), blocks, buttons, icon="shield")


def dpi_screen(v: Any) -> Any:
    t = _t(v)
    blocks = banner(v, t)
    if getattr(v, "dpi", None):
        blocks.append(table([("warn", t("TOOLS_REPORT"), code(str(getattr(v.dpi, "core", "-") if hasattr(v.dpi, "core") else str(v.dpi))[:80]))], (t("TOOLS_DPI"), t("TOOLS_VALUE"))))
    buttons = [row(button(t("TOOLS_RUN"), "dbg:dpi:scan", icon="scan"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools"))]
    return screen(t("TOOLS_DPI"), t("TOOLS_DPI_SUB"), blocks, buttons, icon="warn")


def ddos_screen(v: Any) -> Any:
    t = _t(v)
    blocks = banner(v, t)
    ddos_obj = getattr(v, "ddos", None)
    if ddos_obj is not None:
        lvl = ddos_obj.level() if callable(getattr(ddos_obj, "level", None)) else getattr(ddos_obj, "level", "-")
        blocks.append(table([("shield", t("TOOLS_LEVEL"), code(lvl))], (t("TOOLS_DDOS"), t("TOOLS_VALUE"))))
    buttons = [row(button(t("TOOLS_CHECK"), "dbg:dd:probe", icon="scan"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools"))]
    return screen(t("TOOLS_DDOS"), t("TOOLS_DDOS_SUB"), blocks, buttons, icon="shield")


def fw_screen(v: Any) -> Any:
    t = _t(v)
    blocks = banner(v, t)
    blocks.append(f"<p>{muted(t('TOOLS_FW_TEXT'))}</p>")
    buttons = [row(button(t("TOOLS_STATUS"), "ft:fw", icon="shield"), button(t("TOOLS_TITLE"), "dbg:home", icon="tools"))]
    return screen(t("TOOLS_FW"), t("TOOLS_FW_SUB"), blocks, buttons, icon="shield")


def fortress_screen(v: Any) -> Any:
    t = _t(v)
    blocks = banner(v, t)
    blocks.append(f"<p>{muted(t('TOOLS_FORTRESS_TEXT'))}</p>")
    blocks.append(table([("ok", t("TOOLS_RKN"), code(t("TOOLS_FORTRESS_RKN"))), ("ok", t("TOOLS_SERVER"), code(t("TOOLS_FORTRESS_SRV"))), ("ok", t("TOOLS_IMPORTS"), code("<100ms, 0 heavy"))], (t("TOOLS_CHECK"), t("TOOLS_VALUE"))))
    buttons = [row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home"))]
    return screen(t("TOOLS_FORTRESS"), t("TOOLS_FORTRESS_SUB"), blocks, buttons, icon="shield")
