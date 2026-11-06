from __future__ import annotations
from typing import Any
from . import i18n
from .ui import button, code, muted, quote, row, screen, table, bold


def banner(v: Any, t) -> list[str]:
    out=[]
    if getattr(v, "notice", ""): out.append(quote(muted(v.notice)))
    if getattr(v, "error", ""): out.append(quote(bold(v.error)))
    return out

def _t(v: Any):
    return v.tr() if hasattr(v, "tr") else i18n.translator(getattr(v, "lang", i18n.DEFAULT_LANGUAGE))

def home(v: Any) -> Any:
    t=_t(v)
    blocks=banner(v,t)
    stats=[
        ("radar", t("TOOLS_SCAN"), code(getattr(v, "target", "-") or "-")),
        ("shield", t("TOOLS_CHEBUR"), code(getattr(getattr(v, "chebur", None), "verdict", "-") if getattr(v, "chebur", None) else "-")),
        ("warn", t("TOOLS_DPI"), code("OK" if getattr(v, "dpi", None) else "-")),
        ("shield", t("TOOLS_DDOS"), code(getattr(getattr(v, "ddos", None), "level", "-") if getattr(v, "ddos", None) else "-")),
        ("plug", t("TOOLS_PORTS"), code(getattr(v, "ports", "-") or "-")),
    ]
    blocks.append(table(stats, (t("TOOLS_TITLE"), t("TOOLS_STATUS"))))
    blocks.append(f"<p>{muted(t('TOOLS_SUBTITLE'))}</p>")
    buttons=[
        row(button(t("TOOLS_SCAN"), "tools:scan", icon="radar"), button(t("TOOLS_CHEBUR"), "tools:chebur", icon="shield")),
        row(button(t("TOOLS_DPI"), "tools:dpi", icon="warn"), button(t("TOOLS_DDOS"), "tools:ddos", icon="shield")),
        row(button(t("TOOLS_FW"), "tools:fw", icon="shield"), button(t("TOOLS_FORTRESS"), "tools:fortress", icon="shield")),
        row(button(t("NAV_DEBUG"), "dbg:home", icon="bug"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("TOOLS_TITLE"), t("TOOLS_SCREEN_SUB"), blocks, buttons, icon="tools")

def scan_screen(v: Any) -> Any:
    t=_t(v)
    blocks=banner(v,t)
    blocks.append(table([("radar", t("TOOLS_TARGET"), code(getattr(v,"target","-") or "-")), ("plug", t("TOOLS_PORTS"), code(getattr(v,"ports","-") or "-"))], (t("TOOLS_SCAN"), t("TOOLS_VALUE"))))
    ans=getattr(v, "scan", None)
    if ans and getattr(ans,"error",None): blocks.append(quote(bold(ans.error)))
    if ans and not getattr(ans,"error",None):
        blocks.append(table([("ok", t("TOOLS_HOSTS"), code(ans.hosts)), ("users", t("TOOLS_ALIVE"), code(ans.alive)), ("scan", t("TOOLS_OPEN"), code(len(ans.open_ports))), ("clock", t("TOOLS_SPENT"), code("%.2fs"%ans.spent))], (t("TOOLS_RESULT"),"")))
        if getattr(ans,"open_ports",None): blocks.append(table([("plug", t("TOOLS_OPEN"), code(item)) for item in ans.open_ports[:40]], (t("TOOLS_OPEN"),"")))
    buttons=[row(button(t("TOOLS_RUN"), "tools:scan:go", icon="scan"), button(t("UI_BACK"), "tools:home", icon="back"))]
    return screen(t("TOOLS_SCAN"), t("TOOLS_SCAN_SUB"), blocks, buttons, icon="radar")

def chebur_screen(v: Any) -> Any:
    t=_t(v)
    blocks=banner(v,t)
    if getattr(v,"chebur",None):
        blocks.append(table([("shield", t("TOOLS_VERDICT"), code(getattr(v.chebur,"verdict","-"))), ("world", t("TOOLS_TARGET"), code(getattr(v,"chebur_target","-") or "-"))], (t("TOOLS_CHEBUR"),"")))
    buttons=[row(button(t("TOOLS_CHECK"), "tools:chebur:probe", icon="radar"), button(t("UI_BACK"), "tools:home", icon="back"))]
    return screen(t("TOOLS_CHEBUR"), t("TOOLS_CHEBUR_SUB"), blocks, buttons, icon="shield")

def dpi_screen(v: Any) -> Any:
    t=_t(v)
    blocks=banner(v,t)
    if getattr(v,"dpi",None):
        blocks.append(table([("warn", t("TOOLS_REPORT"), code(str(getattr(v.dpi,"core","-") if hasattr(v.dpi,"core") else str(v.dpi))[:80]))], (t("TOOLS_DPI"),"")))
    buttons=[row(button(t("TOOLS_RUN"), "tools:dpi:scan", icon="scan"), button(t("UI_BACK"), "tools:home", icon="back"))]
    return screen(t("TOOLS_DPI"), t("TOOLS_DPI_SUB"), blocks, buttons, icon="warn")

def ddos_screen(v: Any) -> Any:
    t=_t(v)
    blocks=banner(v,t)
    if getattr(v,"ddos",None):
        blocks.append(table([("shield", t("TOOLS_LEVEL"), code(getattr(v.ddos,"level","-")))], (t("TOOLS_DDOS"),"")))
    buttons=[row(button(t("TOOLS_CHECK"), "tools:ddos:probe", icon="scan"), button(t("UI_BACK"), "tools:home", icon="back"))]
    return screen(t("TOOLS_DDOS"), t("TOOLS_DDOS_SUB"), blocks, buttons, icon="shield")

def fw_screen(v: Any) -> Any:
    t=_t(v)
    blocks=banner(v,t)
    blocks.append(f"<p>{muted(t('TOOLS_FW_TEXT'))}</p>")
    buttons=[row(button(t("TOOLS_STATUS"), "tools:fw:status", icon="shield"), button(t("UI_BACK"), "tools:home", icon="back"))]
    return screen(t("TOOLS_FW"), t("TOOLS_FW_SUB"), blocks, buttons, icon="shield")

def fortress_screen(v: Any) -> Any:
    t=_t(v)
    blocks=banner(v,t)
    blocks.append(f"<p>{muted(t('TOOLS_FORTRESS_TEXT'))}</p>")
    blocks.append(table([("ok", t("TOOLS_RKN"), code(t("TOOLS_FORTRESS_RKN"))), ("ok", t("TOOLS_SERVER"), code(t("TOOLS_FORTRESS_SRV"))), ("ok", t("TOOLS_IMPORTS"), code("<100ms, 0 heavy"))], (t("TOOLS_CHECK"), "")))
    buttons=[row(button(t("TOOLS_PENTEST"), "tools:pentest", icon="scan"), button(t("UI_BACK"), "tools:home", icon="back"))]
    return screen(t("TOOLS_FORTRESS"), t("TOOLS_FORTRESS_SUB"), blocks, buttons, icon="shield")
