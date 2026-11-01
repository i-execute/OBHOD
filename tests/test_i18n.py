from __future__ import annotations

import re

import pytest

from BOT import i18n, strings

CJK = re.compile(r"[\u4e00-\u9fff]")
CYRILLIC = re.compile(r"[\u0400-\u04ff]")
PLACEHOLDER = re.compile(r"\{[a-z_][a-z0-9_]*\}")


def names(catalog: object) -> set[str]:
    return {name for name in dir(catalog) if name.isupper() and not name.startswith("_")}


def test_three_catalogs_with_identical_names() -> None:
    en = names(strings.EN)
    assert en == names(strings.RU)
    assert en == names(strings.ZH)
    assert i18n.RESERVED <= en


def test_languages_and_default() -> None:
    assert i18n.LANGUAGES == ("en", "ru", "zh")
    assert i18n.DEFAULT_LANGUAGE == "en"
    assert sorted(i18n.CATALOGS) == ["en", "ru", "zh"]


@pytest.mark.parametrize("code", i18n.LANGUAGES)
def test_every_key_has_a_value(code: str) -> None:
    catalog = i18n.catalog(code)
    for name in names(catalog):
        value = getattr(catalog, name)
        assert isinstance(value, str)
        assert value.strip()


def test_placeholders_match_between_catalogs() -> None:
    for name in names(strings.EN):
        reference = set(PLACEHOLDER.findall(getattr(strings.EN, name)))
        for code in ("ru", "zh"):
            current = set(PLACEHOLDER.findall(getattr(i18n.catalog(code), name)))
            assert current == reference, (name, code)


def test_check_catalogs_reports_nothing() -> None:
    assert i18n.check_catalogs() == []


def test_chinese_catalog_is_really_chinese() -> None:
    values = [getattr(strings.ZH, name) for name in names(strings.ZH) if name not in i18n.RESERVED]
    translated = [value for value in values if CJK.search(value)]
    assert len(translated) >= len(values) - 40
    assert not any(CYRILLIC.search(value) for value in values)


def test_russian_catalog_is_really_russian() -> None:
    values = [getattr(strings.RU, name) for name in names(strings.RU) if name not in i18n.RESERVED]
    translated = [value for value in values if CYRILLIC.search(value)]
    assert len(translated) >= 300


def test_english_catalog_has_no_cyrillic_or_cjk() -> None:
    for name in names(strings.EN):
        value = getattr(strings.EN, name)
        assert not CYRILLIC.search(value), name
        assert not CJK.search(value), name


def test_language_name_and_code() -> None:
    assert strings.EN.LANG_NAME == "English"
    assert CYRILLIC.search(strings.RU.LANG_NAME)
    assert CJK.search(strings.ZH.LANG_NAME)
    assert [code for code, _ in i18n.language_names()] == ["en", "ru", "zh"]
    assert i18n.language_names()[2][1] == strings.ZH.LANG_NAME


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("en", "en"),
        ("EN", "en"),
        ("ru-RU", "ru"),
        ("zh_CN", "zh"),
        ("zh-hans", "zh"),
        ("de", "en"),
        ("", "en"),
        (None, "en"),
        (42, "en"),
    ],
)
def test_normalize(raw: object, expected: str) -> None:
    assert i18n.normalize(raw) == expected


def test_translate_with_values() -> None:
    assert i18n.t("HOME_CORE_STATE", "en", version="v1", state="running") == "xray v1 running"
    assert "v1" in i18n.t("HOME_CORE_STATE", "ru", version="v1", state="ok")
    assert "v1" in i18n.t("HOME_CORE_STATE", "zh", version="v1", state="ok")


def test_translate_falls_back_to_english() -> None:
    class Fake:
        pass

    assert i18n.raw("UI_YES", "de") == i18n.raw("UI_YES", "en")


def test_unknown_key_raises_english() -> None:
    with pytest.raises(i18n.I18nError) as info:
        i18n.t("NO_SUCH_KEY")
    assert str(info.value) == "the string key NO_SUCH_KEY is missing in every catalog"
    with pytest.raises(i18n.I18nError):
        i18n.t("")


def test_missing_value_raises() -> None:
    with pytest.raises(i18n.I18nError) as info:
        i18n.t("HOME_CORE_STATE", "en", version="v1")
    assert "state" in str(info.value)


def test_translator_switches_language() -> None:
    item = i18n.translator("ru")
    assert item.language == "ru"
    assert item("UI_YES") == strings.RU.UI_YES
    item.change("zh")
    assert item("UI_YES") == strings.ZH.UI_YES
    assert item.change("unknown").language == "en"
    assert i18n.translator("zh").language_name() == strings.ZH.LANG_NAME


def test_keys_and_has_key() -> None:
    keys = i18n.keys("en")
    assert keys == sorted(keys)
    assert "UI_YES" in keys
    assert "LANG_NAME" not in keys
    assert "LANG_CODE" not in keys
    assert i18n.has_key("UI_YES", "zh")
    assert not i18n.has_key("UI_YES_NEVER")


def test_placeholders_helper() -> None:
    assert i18n.placeholders("a {one} b {two} c {one}") == {"one", "two"}
    assert i18n.placeholders("") == set()


def test_catalog_size_is_large() -> None:
    assert len(i18n.keys("en")) >= 550


def test_every_catalog_value_is_reachable() -> None:
    public = set(i18n.keys("en"))
    for name in names(strings.EN):
        assert name in public or name in i18n.RESERVED


def test_every_key_formats_with_its_own_values() -> None:
    for name in i18n.keys():
        for code_value in i18n.LANGUAGES:
            template = i18n.raw(name, code_value)
            values = {item: "x" for item in i18n.placeholders(template)}
            assert i18n.t(name, code_value, **values)


def test_error_titles_exist_in_every_catalog() -> None:
    for name in ("ERR_TITLE", "ERR_INPUT_TITLE", "ERR_CRASH_TITLE"):
        for code_value in i18n.LANGUAGES:
            assert i18n.t(name, code_value).strip()


def test_the_new_screens_speak_every_catalog() -> None:
    from BOT import ftscreens, screens
    from BOT.store import State
    from BOT.xray import XrayState

    view = screens.View(state=State(xray=XrayState()))
    info = {"root": "/opt/obhod-src", "git": True, "branch": "main", "commit": "1111aaa", "subject": "work", "tag": "v1.0.0", "dirty": 0, "behind": 2, "ahead": 0, "release": "v1.1.0", "release_error": "", "unit": "obhod.service", "unit_state": "active"}
    preview = {"commits": 2, "files": ["M BOT/app.py"], "total": 3}
    result = {"ok": True, "target": "2222bbb", "subject": "fix", "steps": ["reset"], "message": "updated", "restarted": True}
    def ft(lang: str):
        item = ftscreens.FtView(state=State(xray=XrayState()).freeturn, lang=lang)
        item.guard = {"port": 56272, "backend": "firewalld", "mode": "vk", "rules": 96, "cidrs": 95}
        return item

    builders = {
        "update": lambda lang: screens.update_screen(screens.View(state=view.state, lang=lang), info),
        "update_confirm": lambda lang: screens.update_confirm_screen(screens.View(state=view.state, lang=lang), info, preview, "body", "upd:commit:go"),
        "update_result": lambda lang: screens.update_result_screen(screens.View(state=view.state, lang=lang), info, result),
        "firewall": lambda lang: ftscreens.fw_screen(ft(lang)),
    }
    cyrillic = re.compile(r"[\u0400-\u04ff]")
    cjk = re.compile(r"[\u4e00-\u9fff]")
    for name, build in builders.items():
        english = build("en").to_html()
        russian = build("ru").to_html()
        chinese = build("zh").to_html()
        assert not cyrillic.search(english) and not cjk.search(english), name
        assert cyrillic.search(russian), name
        assert cjk.search(chinese), name
        for html in (english, russian, chinese):
            assert "{" not in html, name
