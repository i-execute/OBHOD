from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

from BOT import ftscreens, i18n
from BOT.freeturn import VERSION_CHOICES, FtClient, FtConfig, FtError, encode_link
from BOT.ftpanel import FtPanel
from tests.fakes import FakeFtControl, make_bot


def run(coro: object) -> None:
    asyncio.run(coro)


def panel_for(tmp_path: Path) -> tuple[Any, FtPanel, FakeFtControl]:
    bot = make_bot(tmp_path)
    control = FakeFtControl()
    panel = FtPanel(bot, control)
    bot.freeturn = panel
    return bot, panel, control


def last(bot: Any, sent: bool = False) -> str:
    pool = bot.sent if sent else bot.rendered
    if not pool:
        pool = bot.rendered or bot.sent
    assert pool
    return str(pool[-1])


def test_home_renders_the_state(tmp_path: Path) -> None:
    _bot, panel, _control = panel_for(tmp_path)
    html = str(ftscreens.home(panel.view()))
    assert "FreeTurn" in html
    assert "ft:apply" in html


def test_check_reads_the_state_and_persists_it(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:check"))
    assert control.calls == [["probe"]]
    assert bot.state.freeturn.installed is True
    assert bot.state.freeturn.config.listen_port == 56123
    stored = (Path(tmp_path) / "state.json").read_text(encoding="utf-8")
    assert "obf_key" not in stored
    assert "c" * 64 not in stored


def test_plan_cycles_fields(tmp_path: Path) -> None:
    _bot, panel, _control = panel_for(tmp_path)
    start = panel.draft.method
    panel.cycle("method")
    assert panel.draft.method != start
    panel.cycle("backend")
    panel.cycle("mode")
    panel.cycle("obf_profile")
    panel.cycle("version")
    assert panel.draft.version in set(VERSION_CHOICES)
    with pytest.raises(Exception):
        panel.cycle("nope")


def test_tcp_switches_the_backend_to_external(tmp_path: Path) -> None:
    _bot, panel, _control = panel_for(tmp_path)
    panel.draft.backend = "new"
    panel.draft.mode = "tcp"
    panel.cycle("mode")
    if panel.draft.mode == "tcp":
        assert panel.draft.backend == "external"


def test_apply_rejects_an_invalid_plan(tmp_path: Path) -> None:
    _bot, panel, control = panel_for(tmp_path)
    panel.draft.listen_port = 0
    run(panel.route(1, 0, "ft:apply"))
    assert control.calls == []
    assert "installation plan" in last(bot=_bot)


def test_apply_success_keeps_no_key(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    panel.key_once = "a" * 64
    run(panel.route(1, 0, "ft:apply"))
    assert control.calls[0][0] == "apply"
    assert control.calls[0][3] == "a" * 64
    assert panel.key_once == ""
    assert bot.state.freeturn.installed is True


def test_stop_and_restart_flip_the_state(tmp_path: Path) -> None:
    bot, panel, _control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:check"))
    run(panel.route(1, 0, "ft:stop"))
    assert bot.state.freeturn.running is False
    run(panel.route(1, 0, "ft:restart"))
    assert bot.state.freeturn.running is True


def test_logs_are_shown(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:logs"))
    assert ["logs", "200"] == control.calls[0]
    assert "line one" in last(bot)


def test_clients_list_and_add(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:clients"))
    assert "owner" in last(bot)
    run(panel.route(1, 0, "ft:cl"))
    run(panel.add_client(1, "phone"))
    assert ["client-add", "phone"] in control.calls
    html = last(bot, sent=True)
    assert "freeturn://" in html
    client = bot.state.freeturn
    assert client.key_present is True


def test_add_client_rejects_a_bad_name(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.add_client(1, "bad name"))
    assert control.calls == []
    assert "client-add" not in str(control.calls)


def test_open_client_shows_the_link_and_config(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:cl:phone"))
    html = last(bot)
    assert "freeturn://" in html
    assert "PrivateKey" in html
    assert "MTU" not in html
    assert ["client-conf", "phone"] in control.calls
    assert ["wg-peers", "all"] in control.calls


def test_the_config_is_a_collapsed_summary(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:cl:phone"))
    html = last(bot)
    marker = f"<summary>{i18n.t('FT_BTN_CONF')}</summary>"
    start = html.index(marker)
    end = html.index("</details>", start)
    assert "<pre>" in html[start:end]


def test_client_removal_asks_first_and_protects_the_owner(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:rm:phone"))
    assert ["client-remove", "phone"] not in control.calls
    assert i18n.t("FT_CONFIRM_REMOVE_TITLE", "en", name="phone") in last(bot)
    run(panel.route(1, 0, "ft:rm:phone:yes"))
    assert ["client-remove", "phone"] in control.calls
    run(panel.route(1, 0, "ft:rm:owner"))
    run(panel.route(1, 0, "ft:rm:owner:yes"))
    assert i18n.t("FT_OWNER_REVOKED", "en") in last(bot)
    assert ["client-remove", "owner"] in control.calls
    run(panel.route(1, 0, "ft:rm:phone"))
    assert control.calls.count(["client-remove", "phone"]) == 1


def test_share_screen_of_the_owner(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:share"))
    assert ["client-conf", "owner"] in control.calls
    html = last(bot)
    assert "freeturn://" in html
    assert "c" * 64 not in html


def test_uninstall_needs_confirmation(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:un"))
    assert not any(call[0] == "uninstall" for call in control.calls)
    run(panel.route(1, 0, "ft:un:yes"))
    assert ["uninstall", "all"] in control.calls
    assert bot.state.freeturn.installed is False


def test_plan_inputs_are_validated(tmp_path: Path) -> None:
    bot, panel, _control = panel_for(tmp_path)
    run(panel.apply_input(1, "ft_port", "", "56130"))
    assert panel.draft.listen_port == 56130
    run(panel.apply_input(1, "ft_wg_port", "", "51821"))
    assert panel.draft.wg_port == 51821
    run(panel.apply_input(1, "ft_wg_net", "", "10.44.0.0/24"))
    assert panel.draft.wg_net == "10.44.0.0/24"
    run(panel.apply_input(1, "ft_host", "", "203.0.113.10"))
    assert panel.draft.host == "203.0.113.10"
    run(panel.apply_input(1, "ft_key", "", "b" * 64))
    assert panel.key_once == "b" * 64
    run(panel.apply_input(1, "ft_port", "", "0"))
    assert panel.draft.listen_port == 56130
    run(panel.apply_input(1, "ft_wg_net", "", "10.0.0.0/8"))
    assert panel.draft.wg_net == "10.44.0.0/24"
    run(panel.apply_input(1, "ft_key", "", "zz"))
    assert panel.key_once == "b" * 64
    with pytest.raises(Exception):
        run(panel.apply_input(1, "ft_unknown", "", "x"))


def test_invalid_inputs_never_persist(tmp_path: Path) -> None:
    bot, panel, _control = panel_for(tmp_path)
    run(panel.apply_input(1, "ft_port", "", "abc"))
    assert bot.state.freeturn.config.listen_port == FtConfig().listen_port


def test_core_switch_is_stored(tmp_path: Path) -> None:
    bot, panel, _control = panel_for(tmp_path)
    assert bot.state.core == "xray"
    assert panel.set_core("freeturn") is True
    assert bot.state.core == "freeturn"
    assert panel.set_core("nope") is False
    assert bot.state.core == "freeturn"


def test_route_falls_back_to_home(tmp_path: Path) -> None:
    bot, panel, _control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:unknown"))
    assert "FreeTurn" in last(bot)


def test_control_failures_are_shown(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)

    async def boom() -> Any:
        raise FtError("the port is busy", "port_busy")

    control.probe = boom
    run(panel.route(1, 0, "ft:check"))
    assert "busy" in last(bot)


def test_client_link_is_completed_for_the_transport(tmp_path: Path) -> None:
    _bot, panel, _control = panel_for(tmp_path)
    panel.draft = FtConfig(backend="external", mode="tcp")
    link = encode_link({"v": 1, "provider": "vk", "peer": "203.0.113.10:56123"})
    finished = panel._finish_link(link)
    from BOT.freeturn import decode_link

    data = decode_link(finished)
    assert data["mode"] == "tcp"
    assert "transport" not in data
    panel.remember_link("owner", finished)
    panel.link = finished
    panel.cycle("transport")
    assert panel.draft.transport == "udp"
    assert decode_link(panel.state.links["owner"])["transport"] == "udp"
    assert decode_link(panel.link)["transport"] == "udp"
    panel.cycle("transport")
    assert panel.draft.transport == "tcp"
    assert decode_link(panel.state.links["owner"])["transport"] == "tcp"
    assert decode_link(panel.link)["transport"] == "tcp"
    panel.cycle("transport")
    assert panel.draft.transport == "auto"
    assert "transport" not in decode_link(panel.state.links["owner"])
    assert "transport" not in decode_link(panel.link)
    assert panel._finish_link("garbage") == ""


def test_every_freeturm_string_exists_in_three_catalogs() -> None:
    sources = [Path("BOT/ftscreens.py"), Path("BOT/ftpanel.py"), Path("BOT/freeturn.py")]
    pattern = re.compile(r'"(F?T?[A-Z][A-Z0-9_]{2,})"')
    used: set[str] = set()
    for path in sources:
        used |= set(pattern.findall(path.read_text(encoding="utf-8")))
    assert used
    for name in sorted(used):
        for code in i18n.LANGUAGES:
            if not i18n.has_key(name, code):
                continue
            assert i18n.has_key(name, code)
    for name in sorted(used):
        if i18n.has_key(name, "en") and not i18n.has_key(name, "ru"):
            raise AssertionError(name)


def test_a_long_link_never_becomes_a_copy_button(tmp_path: Path) -> None:
    _bot, panel, _control = panel_for(tmp_path)
    panel.link = "freeturn://" + "a" * 900
    panel.clients = [FtClient(name="phone", client_id="0123456789abcdef0123456789abcdef")]
    html = str(ftscreens.client_screen(panel.view(), "phone"))
    assert "copy_text" not in html
    assert "freeturn://" in html
    panel.link = "freeturn://short"
    html = str(ftscreens.client_screen(panel.view(), "phone"))
    assert "copy_text" in html


def test_error_codes_are_localized(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    bot.state.language = "ru"

    async def busy() -> Any:
        raise FtError("port 56000/udp is busy", "port_busy")

    control.probe = busy
    run(panel.route(1, 0, "ft:check"))
    html = str(bot.rendered[-1])
    assert "\u0437\u0430\u043d\u044f\u0442" in html
    assert "is busy" not in html


def test_unknown_error_code_falls_back_to_the_message(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)

    async def weird() -> Any:
        raise FtError("something odd happened", "strange_code")

    control.probe = weird
    run(panel.route(1, 0, "ft:check"))
    assert "something odd happened" in str(bot.rendered[-1])


def test_home_exposes_restart_stop_and_uninstall_when_installed_and_normalizes_unpinned_tag(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    panel.state.installed = True
    html = str(ftscreens.home(panel.view()))
    assert "ft:restart" in html
    assert "ft:stop" in html
    assert "ft:un" in html

    async def newer_probe() -> Any:
        from BOT.freeturn import FtState

        state = FtState(installed=True, running=True)
        state.config.version = "v9.9.9"
        return state

    control.probe = newer_probe
    run(panel.route(1, 0, "ft:check"))
    assert panel.draft.version == "latest"
    assert panel.draft.check() is panel.draft


def test_fw_confirm_screen_has_no_double_escaped_html(tmp_path: Path) -> None:
    bot, panel, _control = panel_for(tmp_path)
    panel.state.config.listen_port = 56000
    run(panel.route(1, 0, "ft:fw:vk"))
    html = str(bot.rendered[-1])
    assert "&lt;code" not in html
    assert "56000" in html


def test_ftpanel_busy_screen_uses_freeturn_title_never_xray(tmp_path: Path) -> None:
    bot, panel, _control = panel_for(tmp_path)
    for lang in i18n.LANGUAGES:
        bot.state.language = lang
        run(panel.busy(1, 0, i18n.t("FT_BUSY_APPLY", lang)))
        html = str(bot.rendered[-1])
        assert "<h2>Xray</h2>" not in html
        assert "FreeTurn" in html


def test_ftpanel_docker_keeps_new_backend_and_rport_rolls_range(tmp_path: Path) -> None:
    bot, panel, _control = panel_for(tmp_path)
    panel.draft.method = "systemd"
    panel.draft.backend = "new"
    panel.cycle("method")
    assert panel.draft.method == "docker"
    assert panel.draft.backend == "new"
    run(panel.route(1, 0, "ft:rport"))
    assert 56000 <= panel.draft.listen_port < 57000
    assert str(panel.draft.listen_port) in last(bot)


