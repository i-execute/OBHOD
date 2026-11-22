from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from BOT import icons, i18n, ui

ROOT = Path(__file__).resolve().parents[1]
TG_EMOJI = re.compile(r'<tg-emoji emoji-id="(\d+)">')


def pack_items() -> dict[str, str]:
    return {str(ident): str(alt) for ident, alt in icons.ALL_EMOJI.items()}


def test_the_pack_is_vendored_and_matches_the_declared_id() -> None:
    assert not (ROOT / "Storage" / "emoji-pack.json").exists()
    assert icons.PACK_ID == 7489288727785635936
    assert icons.PACK == "tgiosicons"
    assert icons.PACK_LINK == "https://t.me/addemoji/tgiosicons"
    assert len(icons.ALL_EMOJI) >= 400
    assert all(isinstance(k, int) and k > 0 and isinstance(v, str) for k, v in icons.ALL_EMOJI.items())


def test_every_icon_id_exists_in_the_pack() -> None:
    known = pack_items()
    missing = [name for name, (ident, _alt) in icons.ICONS.items() if str(ident) not in known]
    assert missing == []
    assert all(str(ident).isdigit() for ident, _alt in icons.ICONS.values())


def test_a_borrowed_sticker_is_declared_as_borrowed() -> None:
    known = pack_items()
    wrong = sorted(
        name
        for name, (ident, alt) in icons.ICONS.items()
        if str(ident) in known and known[str(ident)] != alt and name not in icons.BORROWED
    )
    assert wrong == []
    assert set(icons.BORROWED) <= set(icons.ICONS)
    for name in icons.BORROWED:
        ident, alt = icons.ICONS[name]
        assert str(ident) in known
        assert known[str(ident)] != alt


def test_the_markup_is_well_formed() -> None:
    for name in icons.ICONS:
        markup = icons.markup(name)
        assert markup.startswith('<tg-emoji emoji-id="')
        assert markup.endswith("</tg-emoji>")
        assert TG_EMOJI.search(markup)
    assert icons.markup("nope") == ""
    assert icons.markup("") == ""
    assert icons.markup(None) == ""


def test_emoji_are_off_by_default() -> None:
    ui.use_icons(False)
    assert ui.icons_on() is False
    assert ui.ico("bell") == ""
    from BOT.config import Config

    assert Config.__dataclass_fields__["emoji_default"].default is False


def test_the_switch_turns_every_text_on() -> None:
    ui.use_icons(True)
    try:
        assert ui.ico("bell").startswith('<tg-emoji emoji-id="')
        row = ui.table([("bell", "key", ui.code("value"))], ("a", "b"))
        assert "<tg-emoji" in row
        button = ui.button("label", "data", icon="bell").html()
        assert "<tg-emoji" in button and "label" in button
        copy = ui.copy_button("copy", "text", icon="copy")
        assert "<tg-emoji" in copy
        link = ui.link_button("open", "https://example.com", icon="link")
        assert "<tg-emoji" in link
    finally:
        ui.use_icons(False)


def test_no_screen_builds_a_naked_button() -> None:
    helpers = {"button", "link_button", "copy_button", "inline_button", "big"}
    offenders = []
    for path in sorted((ROOT / "BOT").glob("*.py")):
        if path.name in {"ui.py"}:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name in helpers and not any(keyword.arg == "icon" for keyword in node.keywords):
                offenders.append("%s:%d %s" % (path.name, node.lineno, name))
    assert offenders == []


def test_every_table_row_names_a_known_icon() -> None:
    offenders = []
    for path in sorted((ROOT / "BOT").glob("*.py")):
        if path.name in {"ui.py", "icons.py"}:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name not in {"table", "row_parts"}:
                continue
            for arg in node.args:
                if isinstance(arg, (ast.List, ast.Tuple)):
                    for item in ast.walk(arg):
                        if isinstance(item, ast.Tuple) and item.elts:
                            head = item.elts[0]
                            if isinstance(head, ast.Constant) and isinstance(head.value, str) and head.value:
                                if not icons.known(head.value):
                                    offenders.append("%s:%d %s" % (path.name, item.lineno, head.value))
    assert offenders == []


@pytest.mark.parametrize("key", ["NAV_DEBUG", "UI_HOME"])
def test_the_navigation_labels_stay_short_enough_for_a_button(key: str) -> None:
    for lang in i18n.LANGUAGES:
        assert len(i18n.t(key, lang)) <= 24


SHOUT_ALLOWED = {"HOME_TITLE", "CMD_START_TITLE", "CMD_VLESS_TITLE", "CMD_WHITELIST_TITLE"}


def button_keys() -> set[str]:
    keys: set[str] = set()
    for path in sorted((ROOT / "BOT").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name not in {"button", "link_button", "copy_button", "inline_button", "big"}:
                continue
            for arg in node.args[:1]:
                for inner in ast.walk(arg):
                    if isinstance(inner, ast.Call):
                        for item in inner.args[:1]:
                            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                                keys.add(item.value)
    return keys


def shouted(value: str) -> bool:
    letters = [char for char in value if char.isalpha()]
    if len(letters) <= 5:
        return False
    return all(char.isupper() for char in letters)


def test_no_button_label_shouts() -> None:
    offenders = []
    for key in sorted(button_keys()):
        if key in SHOUT_ALLOWED or not i18n.has_key(key):
            continue
        for lang in i18n.LANGUAGES:
            value = i18n.t(key, lang)
            if shouted(value):
                offenders.append("%s/%s %s" % (key, lang, value))
    assert offenders == []


def test_button_labels_stay_short() -> None:
    long = []
    for key in sorted(button_keys()):
        if not i18n.has_key(key):
            continue
        for lang in i18n.LANGUAGES:
            value = i18n.t(key, lang)
            if len(value) > 28:
                long.append("%s/%s %s" % (key, lang, value))
    assert long == []
