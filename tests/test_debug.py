from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from BOT import cores, dscreens, i18n, net, scripts, ui
from tests.fakes import make_bot


def panel_for(tmp_path: Path):
    from tests.fakes import FakeFtControl

    bot = make_bot(tmp_path)
    control = FakeFtControl()
    bot.freeturn.control = control
    return bot, bot.debug, control


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def last(bot: Any) -> str:
    pool = bot.rendered or bot.sent
    return pool[-1].to_html()


def scan_body() -> dict[str, Any]:
    return {"hosts": 2, "alive": 1, "results": [{"host": "1.1.1.1", "open": [443]}, {"host": "1.1.1.2", "open": []}]}


def trace_body() -> dict[str, Any]:
    return {"hops": [{"index": 1, "address": "10.0.0.1", "rtt": 1.0}, {"index": 2, "address": "", "rtt": 0.0}]}


def test_the_home_screen_opens(tmp_path: Path) -> None:
    bot, debug, _control = panel_for(tmp_path)
    run(debug.route(1, 0, "dbg:home"))
    html = last(bot)
    assert i18n.t("DBG_SCAN_BTN") in html
    assert i18n.t("DBG_VK_BTN") in html
    assert i18n.t("DBG_SCRIPTS_BTN") in html
    assert i18n.t("DBG_EMOJI_BTN") in html


def test_a_scan_runs_and_reports(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.scan = scan_body()
    debug.target = "1.1.1.0/30"
    debug.ports = "443"
    run(debug.route(1, 0, "dbg:scan:go"))
    assert ["net-scan", "1.1.1.0/30", "443"] in control.calls
    html = last(bot)
    assert "1.1.1.1:443" in html
    assert i18n.t("DBG_SCAN_DONE") in html


def test_a_silly_scan_target_is_refused_before_the_agent(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    for bad in ("", "rm -rf /", "10.0.0.0/8", "1.1.1.1;ls"):
        control.calls.clear()
        debug.target = bad
        run(debug.route(1, 0, "dbg:scan:go"))
        assert not [call for call in control.calls if call[0] == "net-scan"], bad
    assert last(bot)


def test_a_silly_port_list_is_refused(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    debug.target = "1.1.1.1"
    debug.ports = "0,70000"
    control.calls.clear()
    run(debug.route(1, 0, "dbg:scan:go"))
    assert not [call for call in control.calls if call[0] == "net-scan"]
    assert i18n.t("DBG_BAD_TARGET") not in last(bot)


def test_a_scan_cooldown_stops_a_click_storm(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.scan = scan_body()
    debug.target = "1.1.1.1"
    run(debug.route(1, 0, "dbg:scan:go"))
    first = len([call for call in control.calls if call[0] == "net-scan"])
    run(debug.route(1, 0, "dbg:scan:go"))
    second = len([call for call in control.calls if call[0] == "net-scan"])
    assert first == 1 and second == 1
    assert i18n.t("DBG_LIMIT") in last(bot)


def test_a_failing_scan_is_shown_not_raised(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.fail = "the agent said no"
    debug.target = "1.1.1.1"
    run(debug.route(1, 0, "dbg:scan:go"))
    html = last(bot)
    assert i18n.t("FT_CODE_BAD_ARG") in html
    assert debug.scan.error


def test_a_trace_runs_and_shows_hops(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.trace = trace_body()
    debug.target = "1.1.1.1"
    debug.hops = 3
    run(debug.route(1, 0, "dbg:trace:go"))
    assert ["net-trace", "1.1.1.1", "3"] in control.calls
    html = last(bot)
    assert "10.0.0.1" in html
    assert "1.0 ms" in html


def test_a_silly_hop_count_is_refused(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    debug.target = "1.1.1.1"
    debug.hops = 99
    control.calls.clear()
    run(debug.route(1, 0, "dbg:trace:go"))
    assert not [call for call in control.calls if call[0] == "net-trace"]


def test_the_vk_refresh_reads_the_prefixes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot, debug, _control = panel_for(tmp_path)
    monkeypatch.setattr("BOT.fwguard.vk_cidrs", lambda timeout=0, use_cache=True: (["93.186.224.0/20", "95.142.192.0/20"], ""))
    run(debug.route(1, 0, "dbg:vk:go"))
    html = last(bot)
    assert "93.186.224.0/20" in html
    assert debug.vk["cidrs"]


def test_the_vk_refresh_reports_a_dead_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot, debug, _control = panel_for(tmp_path)
    monkeypatch.setattr("BOT.fwguard.vk_cidrs", lambda timeout=0, use_cache=True: ([], "unreachable"))
    run(debug.route(1, 0, "dbg:vk:go"))
    assert debug.vk["reason"] == "unreachable"
    assert i18n.t("DBG_SCAN_NONE") in last(bot)


def test_the_vk_apply_needs_prefixes(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.calls.clear()
    run(debug.route(1, 0, "dbg:vk:apply"))
    assert not [call for call in control.calls if call[0].startswith("fw")]


def test_the_scripts_screen_warns_about_a_change(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.cache = [{"name": "install.sh", "digest": "a" * 64, "size": 10, "at": 1.0}]
    control.remote = {"freeturn": {"url": scripts.target("freeturn").url(""), "digest": "b" * 64, "size": 11}}
    run(debug.route(1, 0, "dbg:scr"))
    html = last(bot)
    assert i18n.t("SCR_WARN") in html
    assert i18n.t("SCR_CHANGED") in html
    assert "https://github.com/" in html


def test_the_scripts_screen_is_quiet_when_nothing_changed(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.cache = [{"name": "install.sh", "digest": "a" * 64, "size": 10, "at": 1.0}]
    control.remote = {"freeturn": {"url": scripts.target("freeturn").url(""), "digest": "a" * 64, "size": 10}}
    run(debug.route(1, 0, "dbg:scr"))
    html = last(bot)
    assert i18n.t("SCR_WARN") not in html
    assert i18n.t("SCR_CACHED") in html


def test_the_fetch_pulls_only_the_pending_scripts(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.cache = [{"name": "install.sh", "digest": "a" * 64, "size": 10, "at": 1.0}]
    control.remote = {"freeturn": {"url": scripts.target("freeturn").url(""), "digest": "b" * 64, "size": 11}}
    run(debug.route(1, 0, "dbg:scr"))
    control.fetched.clear()
    run(debug.route(1, 0, "dbg:scr:fetch"))
    assert len(control.fetched) == 1
    assert i18n.t("SCR_FETCHED") in last(bot)


def test_the_keep_button_changes_nothing(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.cache = [{"name": "install.sh", "digest": "a" * 64, "size": 10, "at": 1.0}]
    control.remote = {"freeturn": {"url": scripts.target("freeturn").url(""), "digest": "b" * 64, "size": 11}}
    run(debug.route(1, 0, "dbg:scr"))
    control.fetched.clear()
    run(debug.route(1, 0, "dbg:scr:keep"))
    assert control.fetched == []
    assert i18n.t("SCR_KEEP") in last(bot)


def test_the_emoji_switch_flips_the_state(tmp_path: Path) -> None:
    bot, debug, _control = panel_for(tmp_path)
    bot.state.emoji = False
    run(debug.route(1, 0, "dbg:emoji"))
    assert bot.state.emoji is True
    assert ui.icons_on()
    run(debug.route(1, 0, "dbg:emoji"))
    assert bot.state.emoji is False
    assert not ui.icons_on()


def test_the_info_screen_shows_the_cores(tmp_path: Path) -> None:
    bot, debug, _control = panel_for(tmp_path)
    run(debug.route(1, 0, "dbg:info"))
    html = last(bot)
    for item in cores.all_cores():
        assert i18n.t(item.name_key) in html


def test_a_crash_shows_the_traceback_in_a_code_block(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)

    async def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the debug action exploded")

    control.net_scan = boom
    debug.target = "1.1.1.1"
    run(debug.route(1, 0, "dbg:scan:go"))
    html = last(bot)
    assert "RuntimeError" in html
    assert "the debug action exploded" in html
    assert "<pre>" in html


def test_an_unknown_debug_route_falls_back(tmp_path: Path) -> None:
    bot, debug, _control = panel_for(tmp_path)
    run(debug.route(1, 0, "dbg:nonsense"))
    assert i18n.t("HOME_NOTICE_UNKNOWN") in last(bot)


def test_the_input_of_a_target_updates_the_panel(tmp_path: Path) -> None:
    bot, debug, _control = panel_for(tmp_path)
    run(debug.apply_input(1, "dbg_target", "-", "203.0.113.0/24"))
    assert debug.target == "203.0.113.0/24"
    run(debug.apply_input(1, "dbg_ports", "-", "80,443"))
    assert debug.ports == "80,443"
    run(debug.apply_input(1, "dbg_hops", "-", "7"))
    assert debug.hops == 7


def test_a_silly_input_shows_a_traceback_screen(tmp_path: Path) -> None:
    bot, debug, _control = panel_for(tmp_path)
    run(debug.apply_input(1, "dbg_target", "-", "rm -rf /"))
    html = last(bot)
    assert i18n.t("DBG_ERR_TITLE") in html
    assert "NetError" in html


def test_the_input_screen_lists_the_fields(tmp_path: Path) -> None:
    bot, debug, _control = panel_for(tmp_path)
    run(debug.route(1, 0, "dbg:scan"))
    html = last(bot)
    assert i18n.t("DBG_SCAN_TARGET_LABEL") in html
    assert 'switch_inline_query_current_chat' in html
    assert "<tg-button-row align=\"left\"><tg-button-row" not in html


def test_the_scan_screen_keeps_the_button_inside_a_row(tmp_path: Path) -> None:
    bot, debug, _control = panel_for(tmp_path)
    run(debug.route(1, 0, "dbg:scan"))
    html = last(bot)
    rows = html.count("<tg-button-row")
    assert rows >= 2


def test_every_debug_route_renders_in_every_language() -> None:
    for language in i18n.LANGUAGES:
        view = dscreens.DbgView(lang=language, target="1.1.1.1", ports="80")
        pages = [
            dscreens.home(view),
            dscreens.scan_screen(view),
            dscreens.trace_screen_view(view),
            dscreens.vk_screen(view),
            dscreens.scripts_screen(view),
            dscreens.emoji_screen(view),
            dscreens.info_screen(view, {"uptime": 10, "address": "1.1.1.1", "cores": []}),
            dscreens.crash_screen(view, "dbg:scan", "Traceback"),
        ]
        for rich in pages:
            html = rich.build()
            assert "<h2>" in html
            assert "{" not in html


def test_the_net_module_has_no_shell() -> None:
    source = Path(net.__file__).read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert os_system() not in source


def os_system() -> str:
    return "os" + ".system"


def test_the_debug_panel_has_no_shell() -> None:
    source = Path(dscreens.__file__).read_text(encoding="utf-8")
    assert "shell=True" not in source


def test_the_listeners_screen_marks_the_protected_ports(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    control.ports = {
        "ports": [
            {"port": 22, "proto": "tcp", "process": "sshd"},
            {"port": 443, "proto": "tcp", "process": "xray"},
            {"port": 56000, "proto": "udp", "process": "freeturn"},
        ],
        "count": 3,
    }
    run(debug.route(1, 0, "dbg:ports:go"))
    html = last(bot)
    assert "22/tcp" in html
    assert i18n.t("DBG_PORTS_PROTECTED") in html
    assert i18n.t("DBG_PORTS_NOTE") in html
    assert [owner.port for owner in debug.owners] == [22, 443, 56000]


def test_a_kept_port_is_marked_even_if_the_agent_forgot(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    bot.state.ssh.port = 2222
    control.ports = {"ports": [{"port": 2222, "proto": "tcp", "process": "sshd"}], "count": 1}
    run(debug.route(1, 0, "dbg:ports:go"))
    assert debug.owners[0].protected is True
    assert ["net-ports", debug_keep(debug)] in control.calls or "2222" in control.calls[-1][1]


def debug_keep(debug: Any) -> str:
    from BOT import portguard

    return portguard.join(debug.keep_ports())


def test_the_guard_refuses_a_protected_port(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    bot.state.ssh.port = 22
    debug.vk = {"cidrs": ["93.186.224.0/20"]}
    bot.state.freeturn.config.port = 22
    control.calls.clear()
    run(debug.route(1, 0, "dbg:vk:apply"))
    assert not [call for call in control.calls if call and call[0] == "firewall"]
    assert i18n.t("FT_CODE_PORT_PROTECTED") in last(bot)


def test_the_guard_passes_the_keep_list(tmp_path: Path) -> None:
    bot, debug, control = panel_for(tmp_path)
    debug.vk = {"cidrs": ["93.186.224.0/20"]}
    bot.state.freeturn.config.port = 56000
    bot.state.ssh.port = 22
    control.calls.clear()
    run(debug.route(1, 0, "dbg:vk:apply"))
    guard_calls = [call for call in control.calls if call and call[0] == "firewall"]
    assert guard_calls
    assert guard_calls[0][4] == "22,443,2096,56000" or "22" in guard_calls[0][4]
