from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from BOT import i18n, inline, screens, xscreens
from BOT.config import ConfigError
from BOT.guard import SshState
from BOT.models import ModelError
from BOT.xray import API_PORT, SUB_PORT, new_inbound
from tests.fakes import FakeEvent, FakeFtControl, make_bot, make_config


def run(coro: object) -> None:
    asyncio.run(coro)


def test_admin_is_claimed_on_first_contact(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.cfg.admin_id = 0
    evt = FakeEvent(from_id=55, chat_id=55)
    assert run(bot.guard_admin(evt)) is None
    run(bot.guard_admin(evt))
    assert bot.state.admin_id == 55


def test_foreign_user_is_denied(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)

    async def scenario() -> bool:
        return await bot.guard_admin(FakeEvent(from_id=99))

    assert asyncio.run(scenario()) is False
    assert len(bot.sent) == 1
    assert i18n.t("DENIED_BODY") in bot.sent[0].to_html()


def test_denial_does_not_reply_to_its_own_update(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    asyncio.run(bot.on_message(FakeEvent(text="hello", from_id=99, chat_id=99)))
    asyncio.run(bot.on_message(FakeEvent(text="Access denied", from_id=1, chat_id=99, raw={"out": True})))
    assert len(bot.sent) == 1
    assert i18n.t("DENIED_BODY") in bot.sent[0].to_html()


@pytest.mark.parametrize("event", [
    {"from_id": 1},
    {"from_id": 7, "raw": {"out": True}},
    {"from_id": 0},
])
def test_outgoing_or_unknown_sender_is_ignored(tmp_path: Path, event: dict) -> None:
    bot = make_bot(tmp_path)
    asyncio.run(bot.on_message(FakeEvent(text="/start", **event)))
    assert not bot.sent


def test_start_is_registered_once(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    app = asyncio.run(bot.boot())
    evt = FakeEvent(text="/start", chat_id=7)

    async def dispatch() -> None:
        for hook in app.hook:
            await hook(evt)

    asyncio.run(dispatch())
    assert len(bot.sent) == 1


def test_navigation_renders_every_page(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    for page in ("home", "server", "ssh", "settings", "ban", "sshd", "help", "xray", "other"):
        run(bot.route(1, 0, f"nav:{page}"))
    assert len(bot.rendered) == 9


def test_unknown_callback_falls_back(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.route(1, 0, "zzz:none"))
    assert bot.rendered


def test_help_and_id_commands(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvent(cmd="help")))
    run(bot.on_command(FakeEvent(cmd="id")))
    run(bot.on_command(FakeEvent(cmd="start")))
    assert len(bot.sent) == 3


def test_text_message_shows_home(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_message(FakeEvent(text="hello")))
    assert bot.sent


def test_ssh_fields_are_validated(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    with pytest.raises(ModelError):
        run(bot.ssh_input(1, "ssh_new_port", "0"))
    with pytest.raises(ConfigError):
        run(bot.ssh_input(1, "ssh_unknown", "x"))
    for ident in ("ssh_host", "ssh_port", "ssh_user", "ssh_password", "ssh_key", "ssh_sudo"):
        with pytest.raises(ConfigError):
            run(bot.ssh_input(1, ident, "x"))


def test_credential_fields_are_gone(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    values = bot.input_values()
    for ident in ("ssh_host", "ssh_port", "ssh_user", "ssh_password", "ssh_key", "ssh_sudo"):
        assert ident not in values
        assert ident not in inline.FIELDS
    assert "ssh_new_port" in values
    assert not hasattr(bot.state.ssh, "password")
    assert not hasattr(bot.state.ssh, "key")


def test_ssh_screen_reports_a_local_shell(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    html = screens.ssh_settings(bot.view()).to_html()
    assert i18n.t("SSH_LOCAL_MODE") in html
    assert i18n.t("SSH_NO_PASSWORD") in html


def test_ban_actions_use_the_guard(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.ban_action(1, 0, "install"))
    assert "install" in bot.guard.calls
    assert bot.state.xray.fail2ban_enabled is True
    run(bot.ban_action(1, 0, "status"))
    assert bot.ban is not None
    run(bot.ban_action(1, 0, "reset"))
    run(bot.ban_action(1, 0, "remove"))
    assert bot.state.xray.fail2ban_enabled is False


def test_ban_actions_need_no_credentials(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.ban_action(1, 0, "install"))
    assert "install" in bot.guard.calls


def test_sshd_actions_use_the_guard(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.sshd_action(1, 0, "status", ""))
    assert "ssh_status" in bot.guard.calls
    run(bot.sshd_action(1, 0, "auth", "no"))
    assert "ssh_apply" in bot.guard.calls
    run(bot.sshd_action(1, 0, "root", "no"))
    run(bot.sshd_action(1, 0, "remove", ""))
    assert "ssh_remove" in bot.guard.calls


def test_ssh_new_port_and_pubkey_inputs(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.ssh_input(1, "ssh_new_port", "2200"))
    assert "ssh_apply" in bot.guard.calls
    run(bot.ssh_input(1, "ssh_pubkey", "ssh-ed25519 AAAA test"))
    assert "ssh_add_key" in bot.guard.calls


def test_inline_answers_only_the_admin(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    evt = FakeEvent(query="", from_id=7)
    run(bot.on_inline(evt))
    assert evt.results
    assert evt.answers[0]["is_personal"] is True
    assert evt.answers[0]["cache_time"] == 0
    stranger = FakeEvent(query="", from_id=99)
    run(bot.on_inline(stranger))
    assert stranger.results == []


def test_inline_token_round_trip_through_the_bot(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    query = inline.prefill("xr_sub_port") + "3331 "
    evt = FakeEvent(query=query, from_id=7)
    run(bot.on_inline(evt))
    assert len(evt.results) == 1
    chosen = FakeEvent(
        update_type="chosen_inline_result",
        from_id=7,
        raw={"chosen_inline_result": {"result_id": evt.results[0]["id"], "from": {"id": 7}, "query": query}},
    )
    run(bot.on_chosen(chosen))
    assert bot.state.xray.sub_port == 3331


def test_chosen_option_applies_the_value(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    evt = FakeEvent(query=inline.list_query("xr_fingerprint", str(inbound.id)), from_id=7)
    run(bot.on_inline(evt))
    picked = evt.results[3]
    chosen = FakeEvent(
        update_type="chosen_inline_result",
        from_id=7,
        raw={"chosen_inline_result": {"result_id": picked["id"], "from": {"id": 7}, "query": "list"}},
    )
    run(bot.on_chosen(chosen))
    assert inbound.fingerprint == inline.options("xr_fingerprint")[2]


def test_chosen_result_of_a_stranger_is_ignored(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    evt = FakeEvent(query=inline.list_query("xr_fingerprint", str(inbound.id)), from_id=7)
    run(bot.on_inline(evt))
    before = inbound.fingerprint
    chosen = FakeEvent(
        update_type="chosen_inline_result",
        from_id=99,
        raw={"chosen_inline_result": {"result_id": evt.results[2]["id"], "from": {"id": 99}, "query": "list"}},
    )
    run(bot.on_chosen(chosen))
    assert inbound.fingerprint == before


def test_chosen_update_of_another_type_is_skipped(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    evt = FakeEvent(update_type="inline_query", from_id=7, raw={})
    run(bot.on_chosen(evt))
    assert bot.sent == []


def test_marker_message_is_processed_and_deleted(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    token = inline.token_for("xr_sub_port")
    marker = inline.payload_text(token, "i", -1, "2096")
    evt = FakeEvent(text=marker, msg_id=10, from_id=7)
    run(bot.on_message(evt))
    assert bot.state.xray.sub_port == 2096
    assert bot.app.deleted == [(1, 10)]


def test_unknown_marker_is_dropped_silently(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    before = bot.state.xray.sub_port
    evt = FakeEvent(text=inline.MARKER + inline.SEPARATOR + "aaaaaaaaaaix", msg_id=11, from_id=7)
    run(bot.on_message(evt))
    assert bot.app.deleted == [(1, 11)]
    assert bot.state.xray.sub_port == before
    assert len(bot.sent) == 1
    assert i18n.t("INL_STALE") in bot.sent[0].to_html()


def test_input_for_inbound_field(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    token = inline.token_for("xr_sni", str(inbound.id))
    marker = inline.payload_text(token, "i", -1, "www.microsoft.com")
    run(bot.on_message(FakeEvent(text=marker, msg_id=12, from_id=7)))
    assert inbound.sni == "www.microsoft.com"


def test_input_error_is_reported(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    token = inline.token_for("xr_sub_port")
    marker = inline.payload_text(token, "i", -1, "bad")
    run(bot.on_message(FakeEvent(text=marker, msg_id=13, from_id=7)))
    assert bot.sent


def test_duplicate_marker_is_ignored(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    token = inline.token_for("xr_sub_port")
    marker = inline.payload_text(token, "i", -1, "2096")
    run(bot.on_message(FakeEvent(text=marker, msg_id=14, from_id=7)))
    bot.state.xray.sub_port = 0
    run(bot.on_message(FakeEvent(text=marker, msg_id=15, from_id=7)))
    assert bot.state.xray.sub_port == 0


def test_busy_flag_blocks_callbacks(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.busy = True
    evt = FakeEvent(data="fb:install")
    run(bot.on_callback(evt))
    assert evt.answers and evt.answers[0]["alert"] is True


def test_callback_pipeline_registers_admin(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    evt = FakeEvent(data="nav:home")
    run(bot.on_callback(evt))
    assert bot.rendered


def test_ban_and_sshd_callbacks(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    for data in ("fb:install", "fb:status", "fb:reset", "fb:remove", "sshd:status", "sshd:auth:no", "sshd:root:no", "sshd:remove"):
        run(bot.route(1, 0, data))
    assert bot.rendered


def test_address_prefers_sub_address(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    monkeypatch.setattr("BOT.app.public_address", lambda: "")
    assert bot.address() == ""
    bot.state.xray.sub_address = "198.51.100.5"
    assert bot.address() == "198.51.100.5"


def test_address_falls_back_to_the_detected_interface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    monkeypatch.setattr("BOT.app.public_address", lambda: "203.0.113.77")
    assert bot.address() == "203.0.113.77"


def test_input_values_are_prefilled(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.remark = "main"
    bot.state.xray.add(inbound)
    values = bot.input_values()
    assert values["ssh_new_port"] == "22"
    assert values["xr_remark"] == "main"
    assert values["xr_port"] == "443"
    assert values["xr_bantime"] == "30"


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    bot.save()
    again = make_bot(tmp_path)
    assert again.state.xray.inbounds[0].clients[0].email == "owner"


def test_language_menu_renders_three_choices(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.route(1, 0, "nav:lang"))
    html = bot.rendered[-1].to_html()
    for code_value in ("en", "ru", "zh"):
        assert f"lang:set:{code_value}" in html
    assert bot.language == "en"


def test_language_switch_is_persisted(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.route(1, 0, "lang:set:zh"))
    assert bot.state.language == "zh"
    again = make_bot(tmp_path)
    assert again.state.language == "zh"
    assert again.language == "zh"
    html = bot.rendered[-1].to_html()
    assert i18n.t("LANG_TITLE", "zh") in html


def test_language_switch_changes_every_screen(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.xray.add(new_inbound("vless", 443, "raw", "reality"))
    for code_value in i18n.LANGUAGES:
        bot.state.language = code_value
        bot.save()
        for page in ("home", "ssh", "settings", "ban", "sshd", "help", "lang", "xray"):
            run(bot.route(1, 0, f"nav:{page}"))
        html = bot.rendered[-1].to_html()
        assert i18n.t("NAV_CORE", code_value) in html


def test_language_command_and_unknown_choice(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvent(cmd="language")))
    assert bot.sent
    run(bot.route(1, 0, "lang:set:de"))
    assert bot.state.language == "en"
    run(bot.route(1, 0, "lang:show"))
    assert bot.rendered


def test_language_reaches_views_and_panel(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    assert bot.view().lang == "ru"
    assert bot.xray.view().lang == "ru"
    assert i18n.t("NAV_SETTINGS", "ru") in screens.settings(bot.view()).to_html()
    bot.state.language = "zh"
    assert bot.xray.view().lang == "zh"
    assert i18n.t("NAV_CORE", "zh") in xscreens.core_screen(bot.xray.view()).to_html()


def test_denied_screen_uses_the_chosen_language(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "zh"
    run(bot.guard_admin(FakeEvent(from_id=99)))
    assert i18n.t("DENIED_BODY", "zh") in bot.sent[-1].to_html()


def test_toast_and_notice_are_localized(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    bot.busy = True
    evt = FakeEvent(data="fb:install")
    run(bot.on_callback(evt))
    assert evt.answers[0]["text"] == i18n.t("TOAST_BUSY", "ru")
    bot.busy = False
    evt_two = FakeEvent(text="what")
    run(bot.on_message(evt_two))
    assert i18n.t("HOME_NOTICE_PICK", "ru") in bot.sent[-1].to_html()


def test_sshd_password_switch_is_blocked_without_a_key(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)

    async def empty_status(cfg: object) -> SshState:
        bot.guard.calls.append("ssh_status")
        return SshState(
            ports=[22],
            permit_root_login="prohibit-password",
            service="active",
            keys=0,
            key_user="root",
            key_path="/root/.ssh/authorized_keys",
            key_list=[],
        )

    bot.guard.ssh_status = empty_status
    sent: list[object] = []

    async def grab(chat_id: int, rich: object) -> None:
        sent.append(rich)

    bot.send = grab
    run(bot.sshd_action(1, 0, "auth", "no"))
    assert "ssh_apply" not in bot.guard.calls
    assert sent
    blob = str(sent[-1])
    assert "/root/.ssh/authorized_keys" in blob
    assert "SSHD_PW_BLOCKED" not in blob


def test_sshd_password_switch_passes_when_a_key_exists(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.sshd_action(1, 0, "auth", "no"))
    assert "ssh_apply" in bot.guard.calls


def test_freeturm_is_reachable_from_the_router(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.freeturn.control = FakeFtControl()
    run(bot.route(1, 0, "ft:home"))
    assert "FreeTurn" in str(bot.rendered[-1])
    run(bot.route(1, 0, "ft:check"))
    assert bot.state.freeturn.installed is True


def test_core_switch_between_the_two_engines(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.route(1, 0, "core:show"))
    assert "core" in str(bot.rendered[-1]).lower()
    run(bot.route(1, 0, "core:set:freeturn"))
    assert bot.state.core == "freeturn"
    run(bot.route(1, 0, "core:set:xray"))
    assert bot.state.core == "xray"
    run(bot.route(1, 0, "core:set:other"))
    assert bot.state.core == "xray"


def test_freeturm_inline_inputs_are_routed(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.freeturn.control = FakeFtControl()
    run(bot.dispatch_input(7, "ft_port", "-", "56140"))
    assert bot.state.freeturn.config.listen_port == 56140


def test_a_new_inbound_is_pushed_to_the_live_subscription(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    bot.state.xray.sub_address = "203.0.113.10"
    bot.state.xray.sub_enabled = True
    bot.state.xray.tunnel_host = "obhod-test.tail1234.ts.net"
    bot.state.xray.tunnel_enabled = True
    control = bot.control
    first = asyncio.run(bot.subs_sync())
    assert first is True
    assert control.calls[-1][0] == "sub-sync"
    again = asyncio.run(bot.subs_sync())
    assert again is False
    extra = new_inbound("vless", 8443, "grpc", "tls")
    extra.make_client("owner")
    bot.state.xray.add(extra)
    assert asyncio.run(bot.subs_sync()) is True
    assert control.calls[-1][0] == "sub-sync"


def test_the_subscription_push_is_off_without_a_permanent_domain(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    bot.state.xray.sub_address = "203.0.113.10"
    bot.state.xray.sub_enabled = True
    bot.state.xray.tunnel_host = "obhod-test.tail1234.ts.net"
    bot.state.xray.tunnel_enabled = False
    before = len(bot.control.calls)
    assert asyncio.run(bot.subs_sync()) is False
    assert asyncio.run(bot.subs_sync(force=True)) is False
    assert len(bot.control.calls) == before
    bot.state.xray.tunnel_enabled = True
    assert asyncio.run(bot.subs_sync()) is True
    assert bot.control.calls[-1][-1] == "obhod-test.tail1234.ts.net"


def test_the_subscription_push_is_off_until_it_is_enabled(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    bot.state.xray.sub_enabled = False
    before = len(bot.control.calls)
    assert asyncio.run(bot.subs_sync()) is False
    assert len(bot.control.calls) == before


def make_ports_config(state_dir: Path, sub_port: int, api_port: int) -> SimpleNamespace:
    cfg = make_config(state_dir)
    cfg.sub_port = sub_port
    cfg.api_port = api_port
    return cfg


def test_the_env_ports_seed_the_state(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.cfg = make_ports_config(tmp_path, 2097, 62790)
    bot.seed_ports()
    assert bot.state.sub_port == 2097
    assert bot.state.xray.sub_port == 2097
    assert bot.state.xray.api_port == 62790


def test_the_seed_never_overwrites_a_choice(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.sub_port = 9443
    bot.state.xray.sub_port = 9443
    bot.state.xray.api_port = 40000
    bot.cfg = make_ports_config(tmp_path, 2097, 62790)
    bot.seed_ports()
    assert bot.state.sub_port == 9443
    assert bot.state.xray.api_port == 40000


def test_without_env_ports_the_defaults_stay(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.seed_ports()
    assert bot.state.sub_port == SUB_PORT
    assert bot.state.xray.api_port == API_PORT
