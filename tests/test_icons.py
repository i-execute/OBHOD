from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

from BOT import i18n, icons, screens, ui
from BOT.store import State, Store
from BOT.xray import XrayState
from tests.fakes import make_bot
from tests.test_screens import render_all

TAG = re.compile(r'<tg-emoji emoji-id="(\d+)">([^<]+)</tg-emoji>')


def view(**kwargs: object) -> screens.View:
    return screens.View(state=State(xray=XrayState()), **kwargs)


def test_the_pack_is_the_ios_one() -> None:
    assert icons.PACK == "tgiosicons"
    assert icons.PACK_ID == 7489288727785635936
    assert icons.PACK_LINK == "https://t.me/addemoji/tgiosicons"
    assert 40 <= len(icons.ICONS) <= 401


def test_every_icon_is_a_number_and_a_fallback() -> None:
    for name, (ident, alt) in icons.ICONS.items():
        assert isinstance(ident, int) and ident > 0, name
        assert alt.strip(), name
        assert len(alt) <= 4, name


def test_the_source_stays_ascii() -> None:
    text = (Path(__file__).resolve().parent.parent / "BOT" / "icons.py").read_text(encoding="utf-8")
    assert all(ord(char) < 128 for char in text)
    assert "\\U" in text


def test_markup_carries_the_id_and_the_fallback() -> None:
    assert icons.markup("xray").startswith("<tg-emoji emoji-id=")
    assert icons.markup("xray").endswith("</tg-emoji>")
    assert icons.markup("does-not-exist") == ""
    assert icons.markup("") == ""
    assert icons.markup(None) == ""


def test_the_switch_is_off_by_default() -> None:
    assert ui.icons_on() is False
    assert ui.ico("home") == ""
    assert ui.ico("home", "") == ""


def test_the_switch_turns_the_tags_on() -> None:
    ui.use_icons(True)
    try:
        assert ui.icons_on() is True
        assert ui.ico("home").endswith(" ")
        assert "<tg-emoji" in ui.ico("home")
        assert ui.ico("unknown-icon") == ""
        assert ui.ico(None) == ""
    finally:
        ui.use_icons(False)


def test_the_button_carries_the_icon_only_when_enabled() -> None:
    plain = ui.button("xray", "xr:home", icon="xray").html()
    assert "<tg-emoji" not in plain
    ui.use_icons(True)
    try:
        rich = ui.button("xray", "xr:home", icon="xray").html()
        assert rich.count("<tg-emoji") == 1
        assert rich.count("</tg-emoji>") == 1
        assert ">xray</tg-button>" in rich
        assert 'data="xr:home"' in rich
    finally:
        ui.use_icons(False)


def test_the_button_keeps_the_callback_data_short() -> None:
    ui.use_icons(True)
    try:
        html = ui.button("label", "xr:home", icon="xray").html()
        assert 'data="xr:home"' in html
        assert len("xr:home") <= ui.MAX_CALLBACK
    finally:
        ui.use_icons(False)


def test_every_screen_takes_at_least_one_icon() -> None:
    ui.use_icons(True)
    try:
        for name, rich in render_all():
            html = rich.build()
            assert TAG.search(html), name
    finally:
        ui.use_icons(False)


def test_no_screen_shows_a_tag_when_the_switch_is_off() -> None:
    for name, rich in render_all():
        assert "<tg-emoji" not in rich.build(), name


def test_every_screen_renders_in_every_language_with_icons() -> None:
    ui.use_icons(True)
    try:
        for lang in i18n.LANGUAGES:
            for name, rich in render_all(lang):
                html = rich.build()
                assert TAG.search(html), (lang, name)
                assert "{" not in html or "}" not in html or "code" in html, (lang, name)
    finally:
        ui.use_icons(False)


def test_the_icons_do_not_break_the_button_limit() -> None:
    ui.use_icons(True)
    try:
        for name, rich in render_all():
            assert ui.count_buttons(rich.build()) <= ui.MAX_BUTTONS, name
    finally:
        ui.use_icons(False)


def test_the_setting_is_off_and_follows_the_config(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    assert bot.emoji_enabled is False
    bot.cfg.emoji_default = True
    assert bot.emoji_enabled is True


def test_the_button_does_not_toggle_anything(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.cfg.admin_id = 7
    bot.state.admin_id = 7
    asyncio.run(bot.route(1, 5, "set:emoji"))
    assert bot.emoji_enabled is False
    assert ui.icons_on() is False
    assert "<tg-emoji" not in bot.rendered[-1].to_html()
    path = Path(tmp_path / "state.json")
    if path.is_file():
        assert "emoji" not in json.loads(path.read_text(encoding="utf-8"))
    assert i18n.t("TOAST_EMOJI_CONFIG", "en") in bot.rendered[-1].to_html()


def test_the_pack_only_turns_on_from_the_config(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    asyncio.run(bot.route(1, 5, "set:emoji"))
    assert ui.icons_on() is False
    bot.cfg.emoji_default = True
    assert bot.apply_emoji() is True
    asyncio.run(bot.route(1, 5, "nav:home"))
    assert "<tg-emoji" in bot.rendered[-1].to_html()
    ui.use_icons(False)


def test_an_unknown_setting_just_shows_the_screen(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    asyncio.run(bot.route(1, 5, "set:whatever"))
    assert bot.rendered


def test_the_settings_screen_shows_the_state(tmp_path: Path) -> None:
    state = State(xray=XrayState())
    off = screens.settings(screens.View(state=state)).to_html()
    assert i18n.t("SET_EMOJI_OFF") in off
    on = screens.settings(screens.View(state=state, emoji_default=True)).to_html()
    assert i18n.t("SET_EMOJI_ON") in on
    assert "data=\"set:emoji\"" not in on and "data=\"set:emoji\"" not in off


def test_the_emoji_is_not_state(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    store = Store(path)
    state = State(xray=XrayState())
    store.save(state)
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert "emoji" not in raw
    path.write_text(json.dumps({**raw, "emoji": True}), encoding="utf-8")
    assert not hasattr(Store(path).load(), "emoji")


def test_the_config_reads_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT.config import Config

    monkeypatch.setenv("BOT_TOKEN", "1:abc")
    monkeypatch.setenv("API_ID", "1")
    monkeypatch.setenv("API_HASH", "hash")
    monkeypatch.setenv("OBHOD_STATE_DIR", "/tmp/obhod-icons-state")
    monkeypatch.delenv("OBHOD_EMOJI", raising=False)
    assert Config.load().emoji_default is False
    for value in ("1", "on", "yes", "true", "ON"):
        monkeypatch.setenv("OBHOD_EMOJI", value)
        assert Config.load().emoji_default is True, value
    for value in ("0", "off", "no", ""):
        monkeypatch.setenv("OBHOD_EMOJI", value)
        assert Config.load().emoji_default is False, value


def test_every_catalog_names_the_setting() -> None:
    for lang in i18n.LANGUAGES:
        for key in ("SET_EMOJI", "SET_EMOJI_ON", "SET_EMOJI_OFF", "SET_EMOJI_BTN_ON", "SET_EMOJI_BTN_OFF", "SET_EMOJI_NOTE", "TOAST_EMOJI_ON", "TOAST_EMOJI_OFF"):
            assert i18n.t(key, lang).strip(), (lang, key)


def test_every_alias_used_by_a_screen_exists() -> None:
    pattern = re.compile(r'icon="([a-z0-9_]+)"|^\s*\("([a-z0-9_]+)", t\(', re.M)
    unknown = []
    for name in ("screens.py", "ftscreens.py", "xscreens.py"):
        path = Path(screens.__file__).parent / name
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            name = match.group(1) or match.group(2)
            if name not in icons.ICONS:
                unknown.append("%s: %s" % (path.name, name))
    assert unknown == []


def test_every_mode_screen_carries_a_heading_icon() -> None:
    from BOT import xscreens

    ui.use_icons(True)
    try:
        page = view().state.xray
        xview = xscreens.XrayView(state=page, lang=i18n.DEFAULT_LANGUAGE)
        pages = [screens.home(view()), screens.settings(view()), xscreens.home(xview)]
        for rich in pages:
            assert rich.build().count("<tg-emoji") >= 2
    finally:
        ui.use_icons(False)
