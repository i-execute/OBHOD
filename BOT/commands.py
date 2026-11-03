from __future__ import annotations

import re
from dataclasses import dataclass

from .ui import bold, bullet_list, button, heading, link_button, muted, row, screen

MAX_COMMAND = 32
MAX_NAME = 64
NAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")
MENU_RE = re.compile(r"^[a-z0-9_]{1,32}$")


@dataclass(frozen=True)
class Command:
    name: str
    desc_key: str
    menu: str = ""

    def menu_name(self) -> str:
        return self.menu or self.name[:MAX_COMMAND]

    def valid(self) -> bool:
        return bool(NAME_RE.match(self.name))

    def valid_menu(self) -> bool:
        return bool(MENU_RE.match(self.menu_name()))


COMMANDS: tuple[Command, ...] = (
    Command("start", "CMD_START_DESC"),
    Command("wg", "CMD_WG_DESC"),
    Command("vless", "CMD_VLESS_DESC"),
)
ALIASES = {
    "whitelist_bypass_wg_vk_call": "wg",
    "whitelist_bypass_wg_vk_call_raskur": "wg",
    "vless_rkn_raw_tcp_xhttp_ws_raskur": "vless",
    "vless_rkn_bypass_raskur": "vless",
}


def canonical(raw: object) -> str:
    text = str(raw or "").strip().lower().lstrip("/")
    text = text.split("@", 1)[0]
    return ALIASES.get(text, text)


def known(raw: object) -> Command | None:
    name = canonical(raw)
    for item in COMMANDS:
        if item.name == name:
            return item
    return None


def menu(translate) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in COMMANDS:
        name = item.menu_name()
        if not MENU_RE.match(name):
            continue
        out.append({"command": name, "description": str(translate(item.desc_key))[:256]})
    return out


def start_screen(t, cards, lang: str = "en"):
    blocks = [f"<p>{muted(t('CMD_START_BODY'))}</p>"]
    if cards:
        rows_data = [(card.icon, card.label(t), card.detail(t)) for card in cards]
        from .ui import table

        blocks.append(table(rows_data, (t("HOME_CORE_TABLE"), t("HOME_CORE_TABLE2"))))
    buttons = [row(button(card.label(t), card.route, icon=card.icon)) for card in cards]
    buttons.append(row(button(t("NAV_HELP"), "nav:help", icon="docs"), button(t("UI_HOME"), "nav:home", icon="home")))
    return screen(t("CMD_START_TITLE"), t("CMD_START_DESC"), blocks, buttons, icon="bot")


CLIENTS = {
    "CMD_WHITELIST_TITLE": (
        ("calls", "CMD_CLIENT_FT_ANDROID", "https://github.com/hackdiaz-dev/turn-proxy-android"),
        ("calls", "CMD_CLIENT_FT_IOS", "https://github.com/anton48/vk-turn-proxy-ios"),
    ),
    "CMD_VLESS_TITLE": (
        ("world", "CMD_CLIENT_INCY", "https://github.com/INCY-DEV/incy-platforms"),
    ),
}


def clients_buttons(t, title_key: str) -> list[str]:
    rows = [link_button(t(key), url, icon=icon) for icon, key, url in CLIENTS.get(title_key, ())]
    return [row(*rows)] if rows else []


def transport_screen(t, title_key: str, body_key: str, steps: list[str], cards, icon: str = "tunnel", command: str = ""):
    blocks = [
        f"<p>{bold(t(body_key))}</p>",
        heading(t("CMD_TRANSPORT_HOW"), 3, icon="idea"),
        bullet_list([muted(item) for item in steps]),
    ]
    buttons = [row(button("%s %s" % (t("CMD_TRANSPORT_CORES"), card.label(t)), card.route, icon=card.icon)) for card in cards]
    buttons.extend(clients_buttons(t, title_key))
    buttons.append(row(button(t("NAV_HELP"), "nav:help", icon="docs"), button(t("UI_HOME"), "nav:home", icon="home")))
    subtitle = "/%s" % command if command else t("CMD_TRANSPORT_CORES")
    return screen(t(title_key), subtitle, [item for item in blocks if item], buttons, icon=icon)


def whitelist_screen(t, cards):
    steps = [t("CMD_WL_STEP_PEER"), t("CMD_WL_STEP_TURN"), t("CMD_WL_STEP_OBF"), t("CMD_WL_STEP_FW")]
    return transport_screen(t, "CMD_WHITELIST_TITLE", "CMD_WHITELIST_BODY", steps, cards, icon="calls", command="wg")


def vless_screen(t, cards):
    steps = [t("CMD_VLESS_STEP_TLS"), t("CMD_VLESS_STEP_PQ"), t("CMD_VLESS_STEP_TRANSPORT"), t("CMD_VLESS_STEP_FALLBACK")]
    return transport_screen(t, "CMD_VLESS_TITLE", "CMD_VLESS_BODY", steps, cards, icon="xray", command="vless")
