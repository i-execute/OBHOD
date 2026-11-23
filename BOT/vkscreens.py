from __future__ import annotations

from typing import Any

from . import i18n
from .ui import bold, button, code, copy_row, link_button, long_block, muted, quote, row, screen, table


def back_row(t: i18n.Translator, target: str = "dbg:home") -> str:
    return row(button(t("UI_BACK"), target, icon="back"))


def home_screen(lang: str, authorized: bool = False, user_id: int = 0, notice: str = "", error: str = "") -> Any:
    t = i18n.translator(lang)
    blocks = []
    if notice:
        blocks.append(quote(muted(notice)))
    if error:
        blocks.append(quote(bold(error)))
    status = t("VKCALLS_AUTH_SET") if authorized else t("VKCALLS_AUTH_REQUIRED")
    value = "%s%s" % (status, " (%s)" % user_id if user_id else "")
    blocks.append(table([("user", t("VKCALLS_AUTH_STATUS"), code(value))], (t("UI_FIELD"), t("UI_VALUE"))))
    buttons = [
        row(button(t("VKCALLS_BTN_CREATE"), "vk:create", icon="calls"), button(t("VKCALLS_BTN_ACTIVE"), "vk:active", icon="users")),
        row(button(t("VKCALLS_BTN_AUTH"), "vk:auth", icon="key")),
        back_row(t),
    ]
    return screen(t("VKCALLS_TITLE"), t("VKCALLS_SUBTITLE"), blocks, buttons, icon="calls")


def auth_screen(lang: str, authorized: bool = False, user_id: int = 0, notice: str = "", error: str = "", deeplink: str = "") -> Any:
    t = i18n.translator(lang)
    blocks = []
    if notice:
        blocks.append(quote(muted(notice)))
    if error:
        blocks.append(quote(bold(error)))
    blocks.append(quote(muted(t("VKCALLS_AUTH_INSTRUCTIONS"))))
    status = t("VKCALLS_AUTH_SET") if authorized else t("VKCALLS_AUTH_REQUIRED")
    blocks.append(table([("key", t("VKCALLS_AUTH_STATUS"), code("%s%s" % (status, " (%s)" % user_id if user_id else "")))], (t("UI_FIELD"), t("UI_VALUE"))))
    buttons = [row(link_button(t("VKCALLS_OPEN_VKHOST"), "https://vkhost.github.io/", icon="world"))]
    if deeplink:
        buttons.append(row(link_button(t("VKCALLS_TG_DEEPLINK"), deeplink, icon="bot")))
    if authorized:
        buttons.append(row(button(t("VKCALLS_BTN_CHECK_TOKEN"), "vk:auth:check", icon="shield")))
        buttons.append(row(button(t("VKCALLS_AUTH_CLEAR"), "vk:auth:clear", icon="delete")))
    buttons.append(row(button(t("UI_BACK"), "vk:home", icon="back")))
    return screen(t("VKCALLS_AUTH_TITLE"), t("VKCALLS_AUTH_PROMPT"), blocks, buttons, icon="key")


def busy_screen(lang: str, message: str) -> Any:
    t = i18n.translator(lang)
    return screen(t("VKCALLS_TITLE"), t("VKCALLS_SUBTITLE"), [quote(muted(message))], [], icon="calls")


def calls_screen(lang: str, calls: list[dict[str, Any]], error: str = "") -> Any:
    t = i18n.translator(lang)
    blocks = [quote(bold(error))] if error else []
    if not calls:
        blocks.append(quote(muted(t("VKCALLS_NO_ACTIVE"))))
    else:
        blocks.append(table([("calls", t("VKCALLS_ACTIVE_COUNT"), code(len(calls)))], (t("UI_FIELD"), t("UI_VALUE"))))
    buttons = []
    for record in calls[:40]:
        call_id = str(record.get("call_id", ""))
        credentials = record.get("short_credentials") if isinstance(record.get("short_credentials"), dict) else {}
        label = str(credentials.get("id", "") or call_id[:8])[:32]
        buttons.append(row(button(label, "vk:detail:" + call_id, icon="calls")))
    buttons.extend([
        row(button(t("VKCALLS_BTN_CREATE"), "vk:create", icon="add"), button(t("UI_REFRESH"), "vk:active", icon="refresh")),
        row(button(t("UI_BACK"), "vk:home", icon="back")),
    ])
    return screen(t("VKCALLS_ACTIVE_TITLE"), t("VKCALLS_SUBTITLE"), blocks, buttons, icon="calls")


def _call_blocks(t, record: dict[str, Any]) -> tuple[str, str, str, str, str]:
    call_id = str(record.get("call_id", ""))
    join_link = str(record.get("join_link", ""))
    credentials = record.get("short_credentials") if isinstance(record.get("short_credentials"), dict) else {}
    short_id = str(credentials.get("id", "") or "-")
    password = str(credentials.get("password", "") or "-")
    short_link = str(credentials.get("link_with_password", "") or "")
    return call_id, join_link, short_id, password, short_link


def call_screen(lang: str, record: dict[str, Any], error: str = "") -> Any:
    t = i18n.translator(lang)
    call_id, join_link, short_id, password, short_link = _call_blocks(t, record)
    blocks = []
    if error:
        blocks.append(quote(bold(error)))
    blocks.append(table([
        ("calls", t("VKCALLS_CALL_ID"), code(call_id)),
        ("key", t("VKCALLS_SHORT_ID"), code(short_id)),
        ("key", t("VKCALLS_SHORT_PASSWORD"), code(password)),
    ], (t("UI_FIELD"), t("UI_VALUE"))))
    if join_link:
        blocks.append(long_block(t("VKCALLS_JOIN_LINK"), join_link))
    if short_link:
        blocks.append(long_block(t("VKCALLS_SHORT_LINK"), short_link))
    buttons = []
    if join_link:
        buttons.append(row(link_button(t("VKCALLS_JOIN"), join_link, icon="calls")))
        buttons.append(copy_row(t("VKCALLS_COPY_JOIN"), join_link))
    if short_link:
        buttons.append(row(link_button(t("VKCALLS_JOIN_SHORT"), short_link, icon="link")))
        buttons.append(copy_row(t("VKCALLS_COPY_SHORT"), short_link))
    buttons.extend([
        row(button(t("VKCALLS_BTN_ACTIVE"), "vk:active", icon="users")),
        row(button(t("UI_BACK"), "vk:home", icon="back")),
    ])
    return screen(t("VKCALLS_CREATED_TITLE"), t("VKCALLS_SUBTITLE"), blocks, buttons, icon="calls")


def detail_screen(lang: str, record: dict[str, Any] | None, error: str = "") -> Any:
    t = i18n.translator(lang)
    if not record:
        blocks = [quote(bold(error or t("VKCALLS_NOT_FOUND")))]
        return screen(t("VKCALLS_DETAIL_TITLE"), t("VKCALLS_SUBTITLE"), blocks, [back_row(t, "vk:active")], icon="calls")
    call_id = str(record.get("call_id", ""))
    credentials = record.get("short_credentials") if isinstance(record.get("short_credentials"), dict) else {}
    short_id = str(credentials.get("id", "") or "-")
    password = str(credentials.get("password", "") or "-")
    short_link = str(credentials.get("link_with_password", "") or "")
    join_link = str(record.get("join_link", "") or "")
    return screen(t("VKCALLS_DETAIL_TITLE"), t("VKCALLS_SUBTITLE"), [
        table([
            ("calls", t("VKCALLS_CALL_ID"), code(call_id)),
            ("key", t("VKCALLS_SHORT_ID"), code(short_id)),
            ("key", t("VKCALLS_SHORT_PASSWORD"), code(password)),
        ], (t("UI_FIELD"), t("UI_VALUE"))),
        long_block(t("VKCALLS_JOIN_LINK"), join_link),
        long_block(t("VKCALLS_SHORT_LINK"), short_link),
        quote(bold(error)) if error else "",
    ], [
        row(link_button(t("VKCALLS_JOIN"), join_link, icon="calls")) if join_link else "",
        row(link_button(t("VKCALLS_JOIN_SHORT"), short_link, icon="link")) if short_link else "",
        row(button(t("VKCALLS_BTN_FINISH"), "vk:finish:" + call_id, icon="stop")),
        row(button(t("VKCALLS_BTN_ACTIVE"), "vk:active", icon="users"), button(t("UI_BACK"), "vk:home", icon="back")),
    ], icon="calls")
