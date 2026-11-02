from __future__ import annotations

import re
from pathlib import Path

import pytest

from BOT import cores, i18n, screens
from BOT.freeturn import FtConfig, FtState
from BOT.store import State, Store
from BOT.xray import XrayState
from tests.fakes import make_bot


def view(**kwargs: object) -> screens.View:
    state = State(xray=XrayState(), freeturn=FtState(config=FtConfig(listen_port=56000), installed=True, running=True, version="4.1.2"))
    return screens.View(state=state, core={"installed": True, "service": "active", "version": "26.10.31", "listening": [443]}, **kwargs)


def test_the_registry_is_not_a_single_core() -> None:
    assert len(cores.all_cores()) >= 2
    assert "xray" in cores.keys()
    assert "freeturn" in cores.keys()


def test_the_registry_is_ordered() -> None:
    orders = [item.order for item in cores.all_cores()]
    assert orders == sorted(orders)


def test_every_core_names_itself_in_every_language() -> None:
    for item in cores.all_cores():
        for language in i18n.LANGUAGES:
            assert i18n.raw(item.name_key, language)
            assert i18n.raw(item.note_key, language)


def test_every_core_points_to_a_known_route() -> None:
    known = {"xr:home", "ft:home"}
    for item in cores.all_cores():
        assert item.route in known, item.key
        assert item.icon and cores.all_cores()


def test_a_card_reads_the_xray_state() -> None:
    card = cores.xray_card({"installed": True, "service": "active", "version": "26.10.31", "listening": [443]}, 4, "xray")
    assert card.state == cores.STATE_RUNNING
    assert card.version == "26.10.31"
    assert card.ports == ["443"]
    assert card.clients == 4
    assert card.active is True


def test_a_card_reads_the_stopped_and_missing_states() -> None:
    assert cores.xray_card({"installed": True, "service": "inactive"}, 0, "freeturn").state == cores.STATE_STOPPED
    assert cores.xray_card({}, 0, "freeturn").state == cores.STATE_MISSING
    assert cores.freeturn_card(FtState(), 0, "xray").state == cores.STATE_MISSING
    assert cores.freeturn_card(FtState(installed=True), 0, "xray").state == cores.STATE_STOPPED
    assert cores.freeturn_card(FtState(installed=True, running=True), 0, "xray").state == cores.STATE_RUNNING


def test_a_snapshot_holds_every_core() -> None:
    state = State(xray=XrayState(), freeturn=FtState(installed=True, running=True))
    cards = cores.snapshot(state, {"installed": True, "service": "active"})
    assert [item.key for item in cards] == list(cores.keys())
    assert cores.running_count(cards) == 2
    assert cores.installed_count(cards) == 2


def test_the_snapshot_reads_the_active_core_from_the_state() -> None:
    state = State(xray=XrayState(), freeturn=FtState(), core="freeturn")
    cards = cores.snapshot(state, {})
    active = [item.key for item in cards if item.active]
    assert active == ["freeturn"]


def test_the_state_only_accepts_a_registered_core() -> None:
    assert State.from_dict({"core": "nonsense"}).core == cores.default_key()
    assert State.from_dict({"core": "freeturn"}).core == "freeturn"
    saved = State.from_dict({"core": "freeturn"}).to_dict()
    assert saved["core"] == "freeturn"


def test_an_unknown_core_name_falls_back() -> None:
    assert cores.normalize("") == cores.default_key()
    assert cores.normalize("nonsense") == cores.default_key()
    assert cores.normalize("FREETURN") == "freeturn"
    assert cores.core("nonsense") is None


def test_a_new_core_can_be_registered() -> None:
    before = cores.all_cores()
    cores.register(cores.Core("probe", "xr:home", "scan", "CORE_NAME_XRAY", "CORE_NOTE_XRAY", 30))
    try:
        assert "probe" in cores.keys()
        assert cores.all_cores()[-1].key == "probe"
    finally:
        cores.REGISTRY = before


def test_the_registry_has_a_ceiling() -> None:
    before = cores.REGISTRY
    try:
        room = cores.MAX_CORES - len(before)
        for index in range(room):
            cores.register(cores.Core("extra%d" % index, "xr:home", "scan", "CORE_NAME_XRAY", "CORE_NOTE_XRAY", 40 + index))
        assert len(cores.keys()) == cores.MAX_CORES
        with pytest.raises(ValueError):
            cores.register(cores.Core("overflow", "xr:home", "scan", "CORE_NAME_XRAY", "CORE_NOTE_XRAY", 99))
    finally:
        cores.REGISTRY = before


def test_the_home_screen_lists_every_core() -> None:
    html = screens.home(view()).build()
    for item in cores.all_cores():
        assert i18n.t(item.name_key) in html


def test_the_home_screen_has_a_button_for_every_core() -> None:
    html = screens.home(view()).build()
    for item in cores.all_cores():
        assert 'data="%s"' % item.route in html, item.key


def test_the_home_screen_does_not_hardcode_a_single_core() -> None:
    source = Path(screens.__file__).read_text(encoding="utf-8")
    body = source.split("def home(")[1].split("\ndef ", 1)[0]
    assert "xr:home" not in body
    assert "ft:home" not in body
    assert "core_rows" in body


def test_the_home_screen_shows_the_summary() -> None:
    html = screens.home(view()).build()
    assert i18n.t("HOME_SUMMARY_TITLE") in html
    assert i18n.t("HOME_CORE_TABLE2") in html


def test_the_home_screen_survives_an_empty_state() -> None:
    html = screens.home(screens.View(state=State(xray=XrayState()))).build()
    assert i18n.t("CORE_STATE_MISSING") in html


def test_the_home_screen_marks_the_active_core() -> None:
    state = State(xray=XrayState(), core="freeturn")
    html = screens.home(screens.View(state=state, core={})).build()
    assert i18n.t("UI_ACTIVE_MARK") in html


def test_the_core_count_survives_a_reload(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    state = State(xray=XrayState(), core="freeturn")
    store.save(state)
    assert store.load().core == "freeturn"


def test_the_bot_passes_the_freeturn_client_count(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.freeturn.clients = [object(), object(), object()]
    assert bot.view().ft_clients == 3


def test_xray_always_comes_first() -> None:
    cards = cores.snapshot(State(xray=XrayState()), {"installed": True, "running": True, "inbounds": []}, 0)
    assert [card.key for card in cards] == ["xray", "freeturn"]
    assert cards[0].route == "xr:home"
    assert cards[1].route == "ft:home"


def test_the_card_detail_lists_the_state_version_ports_and_clients() -> None:
    card = cores.xray_card({"installed": True, "running": True, "version": "26.10.31", "listening": [443]}, 4, "xray")
    detail = card.detail(lambda key: i18n.t(key, "en"))
    assert "26.10.31" in detail
    assert "443" in detail
    assert "4" in detail
    assert i18n.t("CORE_ROW_CLIENTS", "en") in detail
    assert i18n.t("CORE_ROW_PORTS", "en") in detail
    assert card.state_text(lambda key: i18n.t(key, "en")) in detail


def test_the_card_label_marks_the_active_core() -> None:
    card = cores.freeturn_card(None, 0, "freeturn")
    assert card.active is True
    assert i18n.t("UI_ACTIVE_MARK") in card.label(lambda key: i18n.t(key, "en"))


def test_the_home_buttons_stack_one_core_per_row() -> None:
    board = view()
    html = screens.home(board).to_html()
    rows = re.findall(r'<tg-button-row align="left">(.*?)</tg-button-row>', html)
    assert '<tg-button type="callback_data" data="xr:home">' in rows[0]
    assert '<tg-button type="callback_data" data="ft:home">' in rows[1]
    assert rows[0].count("<tg-button ") == 1
    assert rows[1].count("<tg-button ") == 1


def test_the_home_tables_and_buttons_carry_emoji() -> None:
    from BOT import ui

    ui.use_icons(True)
    try:
        board = view()
        html = screens.home(board).to_html()
    finally:
        ui.use_icons(False)
    buttons = re.findall(r"<tg-button[^>]*>(.*?)</tg-button>", html)
    assert buttons
    assert all("<tg-emoji" in item for item in buttons)
    rows = re.findall(r"<tr>(.*?)</tr>", html)
    assert any("<tg-emoji" in item for item in rows)
