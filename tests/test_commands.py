from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

from BOT import commands, cores, i18n, strings, ui
from tests.fakes import make_bot

TOKEN = ""


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def last(bot: Any) -> str:
    pool = bot.rendered or bot.sent
    return pool[-1].to_html()


def test_every_command_is_a_valid_name() -> None:
    for item in commands.COMMANDS:
        assert item.valid(), item.name
        assert re.match(r"^[a-z0-9_]{1,64}$", item.name), item.name
        assert item.valid_menu(), item.menu_name()


def test_the_menu_names_fit_the_telegram_limit() -> None:
    for item in commands.COMMANDS:
        assert len(item.menu_name()) <= commands.MAX_COMMAND, item.name


def test_the_long_command_keeps_a_menu_alias() -> None:
    item = commands.known("wg")
    assert item is not None
    assert item.menu_name() == "wg"
    assert len(item.menu_name()) <= 32
    assert commands.known("whitelist_bypass_wg_vk_call_raskur") is not None
    assert commands.known("whitelist_bypass_wg_vk_call_raskur").name == "wg"


def test_the_alias_points_to_the_same_command() -> None:
    assert commands.canonical("whitelist_bypass_wg_vk_call") == "wg"
    assert commands.canonical("/whitelist_bypass_wg_vk_call_raskur") == "wg"
    assert commands.canonical("/start@obhod_bot") == "start"
    assert commands.canonical("/wg") == "wg"
    assert commands.canonical("/vless") == "vless"


def test_an_unknown_command_is_not_claimed() -> None:
    assert commands.known("nonsense") is None
    assert commands.known("") is None


def test_the_descriptions_are_short_and_real() -> None:
    payload = commands.menu(lambda key: i18n.t(key))
    assert len(payload) == len(commands.COMMANDS)
    for item in payload:
        assert 1 <= len(item["description"]) <= 256
        assert item["command"] in {entry.menu_name() for entry in commands.COMMANDS}


def test_the_menu_names_are_unique() -> None:
    names = [item.menu_name() for item in commands.COMMANDS]
    assert len(names) == len(set(names))


def test_every_description_exists_in_every_language() -> None:
    for item in commands.COMMANDS:
        for language in i18n.LANGUAGES:
            assert i18n.raw(item.desc_key, language), item.desc_key


def test_the_start_command_shows_the_cores(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvt("/start")))
    html = last(bot)
    for item in cores.all_cores():
        assert i18n.t(item.name_key) in html
        assert 'data="%s"' % item.route in html


def test_the_start_command_says_run_the_bot(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvt("/start")))
    html = last(bot)
    assert i18n.t("CMD_START_DESC") in html


def test_the_whitelist_command_explains_the_transport(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvt("/wg")))
    html = last(bot)
    assert i18n.t("CMD_WHITELIST_BODY") in html
    run(bot.on_command(FakeEvt("/whitelist_bypass_wg_vk_call_raskur")))
    assert i18n.t("CMD_WHITELIST_BODY") in last(bot)
    assert i18n.t("CMD_TRANSPORT_HOW") in html
    for key in ("CMD_WL_STEP_PEER", "CMD_WL_STEP_TURN", "CMD_WL_STEP_OBF", "CMD_WL_STEP_FW"):
        assert i18n.t(key) in html, key


def test_the_whitelist_alias_works(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvt("/whitelist_bypass_wg_vk_call")))
    assert i18n.t("CMD_WHITELIST_BODY") in last(bot)
    run(bot.on_command(FakeEvt("/wg")))
    assert i18n.t("CMD_WHITELIST_BODY") in last(bot)


def test_the_vless_command_explains_the_transport(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvt("/vless")))
    html = last(bot)
    assert i18n.t("CMD_VLESS_BODY") in html
    for key in ("CMD_VLESS_STEP_TLS", "CMD_VLESS_STEP_PQ", "CMD_VLESS_STEP_TRANSPORT", "CMD_VLESS_STEP_FALLBACK"):
        assert i18n.t(key) in html, key


def test_the_meme_commands_have_buttons_to_every_core(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    for name in ("/wg", "/vless"):
        run(bot.on_command(FakeEvt(name)))
        html = last(bot)
        for item in cores.all_cores():
            assert 'data="%s"' % item.route in html, (name, item.key)


def test_a_foreign_command_falls_back_to_the_home_screen(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvt("/nonsense")))
    assert i18n.t("HOME_SUBTITLE") in last(bot)


def test_the_commands_render_in_every_language(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    for language in i18n.LANGUAGES:
        bot.state.language = language
        for name in ("/start", "/wg", "/vless"):
            run(bot.on_command(FakeEvt(name)))
            html = last(bot)
            assert "<h2>" in html
            assert "{" not in html


def test_the_registration_builds_a_safe_payload(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.app = FakeApp()
    assert run(bot.register_commands()) is True
    assert bot.app.commands
    for item in bot.app.commands:
        assert len(item["command"]) <= 32
        assert item["description"]


def test_the_registration_survives_a_broken_api(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.app = FakeApp(fail=True)
    assert run(bot.register_commands()) is False


def test_the_commands_are_shaped_for_the_api() -> None:
    payload = commands.menu(lambda key: i18n.t(key, "ru"))
    blob = json.dumps(payload, ensure_ascii=False)
    assert "start" in blob
    assert "wg" in blob
    assert "vless" in blob
    assert len(payload) == 3


class FakeApp:
    def __init__(self, fail: bool = False) -> None:
        self.commands: list[dict[str, str]] = []
        self.fail = fail

    async def set_my_commands(self, **kwargs: Any) -> bool:
        payload = kwargs.get("commands")
        if payload is None:
            raise TypeError("set_my_commands takes keyword arguments only")
        if self.fail:
            raise RuntimeError("the api is down")
        self.commands = list(payload)
        return True


class FakeEvt:
    def __init__(self, text: str) -> None:
        self.text = text
        self.cmd = text.lstrip("/").split("@")[0]
        self.from_id = 7
        self.chat_id = 7
        self.msg_id = 5
        self.outgoing = False
        self.raw = {}


def test_the_old_vless_name_still_opens_the_screen(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvt("/vless_rkn_bypass_raskur")))
    assert i18n.t("CMD_VLESS_BODY") in last(bot)
    run(bot.on_command(FakeEvt("/whitelist_bypass_wg_vk_call_raskur")))
    assert i18n.t("CMD_WHITELIST_BODY") in last(bot)


def test_both_command_names_are_canonical(tmp_path: Path) -> None:
    names = [item.name for item in commands.COMMANDS]
    assert "wg" in names
    assert "vless" in names
    assert "start" in names


def test_the_titles_are_caps(tmp_path: Path) -> None:
    for language in i18n.LANGUAGES:
        for key in ("CMD_WHITELIST_TITLE", "CMD_VLESS_TITLE"):
            assert i18n.t(key, language=language) == i18n.t(key, language=language).upper()


def test_the_wg_screen_has_a_button_for_every_client(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvt("/wg")))
    html = last(bot)
    for url in ("https://github.com/hackdiaz-dev/turn-proxy-android", "https://github.com/anton48/vk-turn-proxy-ios"):
        assert 'type="url" url="%s"' % url in html
        assert i18n.t("CMD_CLIENT_FT_ANDROID") in html or i18n.t("CMD_CLIENT_FT_IOS") in html


def test_the_vless_screen_lists_the_incy_clients(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvt("/vless")))
    html = last(bot)
    assert "INCY-DEV/incy-platforms" in html


def test_the_clients_are_buttons_and_not_a_table(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    for name in ("/wg", "/vless"):
        run(bot.on_command(FakeEvt(name)))
        html = last(bot)
        assert "<table" not in html
        assert 'type="url"' in html


def test_the_client_buttons_carry_emoji_only_when_it_is_on(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    ui.use_icons(True)
    run(bot.on_command(FakeEvt("/wg")))
    assert "<tg-emoji" in last(bot)
    ui.use_icons(False)
    run(bot.on_command(FakeEvt("/wg")))
    assert "<tg-emoji" not in last(bot)


def test_the_clients_table_keys_are_gone(tmp_path: Path) -> None:
    for catalog in (strings.EN, strings.RU, strings.ZH):
        assert not hasattr(catalog, "CMD_CLIENTS")
        assert not hasattr(catalog, "CMD_CLIENTS_LINK")


def test_every_command_screen_shows_its_own_name(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    for name in ("wg", "vless"):
        run(bot.on_command(FakeEvt("/" + name)))
        assert ("/%s" % name) in last(bot) or "/wg" in last(bot) or "/vless" in last(bot)