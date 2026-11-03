from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from BOT import dscreens, i18n, notify
from tests.fakes import make_bot


def centre(**kwargs) -> notify.Centre:
    settings = notify.Settings()
    for kind, value in kwargs.items():
        settings.enabled[kind] = value
    return notify.Centre(settings)


def test_the_kind_list_is_closed_and_documented() -> None:
    assert notify.KINDS == ("portscan", "ssh_brute", "fail2ban", "honeypot", "sub_abuse", "core")
    assert set(notify.DEFAULT_ON) == set(notify.KINDS)
    assert set(notify.SEVERITY) == set(notify.KINDS)
    assert set(notify.COOLDOWN) == set(notify.KINDS)
    assert notify.DEFAULT_ON[notify.KIND_PORTSCAN] is True
    assert notify.DEFAULT_ON[notify.KIND_SSH] is True
    assert notify.DEFAULT_ON[notify.KIND_SUBS] is False


def test_a_port_scan_needs_enough_distinct_ports() -> None:
    centre_instance = centre()
    raised = []
    for index in range(notify.PORT_SCAN_PORTS - 1):
        raised.extend(centre_instance.observe(notify.Observation(notify.KIND_PORTSCAN, "203.0.113.5", 1000 + index), 100.0 + index))
    assert raised == []
    raised.extend(centre_instance.observe(notify.Observation(notify.KIND_PORTSCAN, "203.0.113.5", 2000), 120.0))
    assert [item.kind for item in raised] == [notify.KIND_PORTSCAN]
    assert raised[0].count == notify.PORT_SCAN_PORTS
    assert raised[0].ports == notify.PORT_SCAN_PORTS


def test_repeats_of_one_port_are_not_a_scan() -> None:
    centre_instance = centre()
    raised = []
    for index in range(40):
        raised.extend(centre_instance.observe(notify.Observation(notify.KIND_PORTSCAN, "203.0.113.5", 443), 100.0 + index))
    assert raised == []


def test_an_old_scan_window_expires() -> None:
    centre_instance = centre()
    raised = []
    for index in range(notify.PORT_SCAN_PORTS - 1):
        raised.extend(centre_instance.observe(notify.Observation(notify.KIND_PORTSCAN, "203.0.113.5", 1000 + index), 100.0 + index))
    raised.extend(centre_instance.observe(notify.Observation(notify.KIND_PORTSCAN, "203.0.113.5", 2000), 100.0 + notify.PORT_SCAN_WINDOW + 60))
    assert raised == []


def test_an_ssh_brute_needs_enough_failures() -> None:
    centre_instance = centre()
    raised = []
    for index in range(notify.SSH_FAILS - 1):
        raised.extend(centre_instance.observe(notify.Observation(notify.KIND_SSH, "198.51.100.9"), 100.0 + index))
    assert raised == []
    raised.extend(centre_instance.observe(notify.Observation(notify.KIND_SSH, "198.51.100.9"), 130.0))
    assert [item.kind for item in raised] == [notify.KIND_SSH]
    assert raised[0].count == notify.SSH_FAILS


def test_one_address_cannot_flood_the_owner() -> None:
    centre_instance = centre()
    first = centre_instance.observe(notify.Observation(notify.KIND_HONEYPOT, "198.51.100.7", 2222, "auth"), 100.0)
    assert first
    again = centre_instance.observe(notify.Observation(notify.KIND_HONEYPOT, "198.51.100.7", 2323, "auth"), 160.0)
    assert again == []
    later = centre_instance.observe(notify.Observation(notify.KIND_HONEYPOT, "198.51.100.7", 2323, "auth"), 100.0 + notify.PER_IP[notify.KIND_HONEYPOT] + 10)
    assert later


def test_one_source_cannot_exceed_the_cooldown() -> None:
    centre_instance = centre()
    assert centre_instance.observe(notify.Observation(notify.KIND_BAN, "203.0.113.1"), 100.0)
    assert centre_instance.observe(notify.Observation(notify.KIND_BAN, "203.0.113.2"), 110.0) == []
    assert centre_instance.observe(notify.Observation(notify.KIND_BAN, "203.0.113.3"), 100.0 + notify.COOLDOWN[notify.KIND_BAN] + 5)


def test_a_switched_off_kind_stays_silent() -> None:
    centre_instance = centre(portscan=False)
    raised = []
    for index in range(notify.PORT_SCAN_PORTS + 2):
        raised.extend(centre_instance.observe(notify.Observation(notify.KIND_PORTSCAN, "203.0.113.5", 1000 + index), 100.0 + index))
    assert raised == []
    assert centre_instance.summary()["enabled"][notify.KIND_PORTSCAN] is False


def test_the_toggle_round_trips_and_survives_a_reload() -> None:
    settings = notify.Settings()
    assert settings.on(notify.KIND_SSH) is True
    assert settings.toggle(notify.KIND_SSH) is False
    assert settings.toggle(notify.KIND_SSH) is True
    with pytest.raises(ValueError):
        settings.toggle("rm -rf /")
    settings.enabled[notify.KIND_SUBS] = True
    restored = notify.Settings.from_dict(settings.to_dict())
    assert restored.enabled == settings.enabled
    assert notify.Settings.from_dict("junk").on(notify.KIND_PORTSCAN) is True


def test_the_settings_are_bounded() -> None:
    settings = notify.Settings.from_dict({"cooldown": {kind: 10 ** 12 for kind in notify.KINDS}, "mute_until": "junk"})
    for kind in notify.KINDS:
        assert 0.0 <= settings.cooldown[kind] <= 86400.0
    assert settings.mute_until == 0.0


def test_muting_silences_everything_until_it_expires() -> None:
    centre_instance = centre()
    centre_instance.settings.silence(60.0)
    assert centre_instance.settings.muted()
    assert centre_instance.observe(notify.Observation(notify.KIND_BAN, "203.0.113.1"), 0.0) == []
    assert centre_instance.observe(notify.Observation(notify.KIND_BAN, "203.0.113.2"), __import__("time").time() + 120)


def test_the_queue_is_bounded_and_drainable() -> None:
    centre_instance = centre()
    for index in range(200):
        centre_instance.push(notify.Event(notify.KIND_CORE, "203.0.113.%d" % (index % 250)))
    assert len(centre_instance.queue) <= notify.MAX_QUEUE
    centre_instance.queue = centre_instance.queue[:2]
    rows = centre_instance.drain()
    assert len(rows) == 2
    assert centre_instance.drain() == []


def test_the_tracking_tables_stay_bounded() -> None:
    centre_instance = centre(portscan=True, fail2ban=True)
    for index in range(notify.MAX_TRACKED + 40):
        centre_instance.observe(notify.Observation(notify.KIND_PORTSCAN, "10.%d.%d.1" % (index // 250, index % 250), 2000 + index), 100.0 + index * 0.001)
    assert len(centre_instance.ports) <= notify.MAX_TRACKED + 1
    for index in range(notify.MAX_TRACKED + 40):
        centre_instance.observe(notify.Observation(notify.KIND_SSH, "10.%d.%d.2" % (index // 250, index % 250)), 100.0 + index * 0.001)
    assert len(centre_instance.fails) <= notify.MAX_TRACKED + 1


def test_an_event_without_an_address_is_dropped() -> None:
    centre_instance = centre()
    assert centre_instance.observe(notify.Observation(notify.KIND_BAN, "")) == []
    assert centre_instance.observe(notify.Observation(notify.KIND_BAN, "   ")) == []
    assert centre_instance.observe(notify.Observation("nonsense", "203.0.113.1")) == []


def test_the_owner_is_the_only_recipient(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.cfg.admin_id = 0
    bot.state.admin_id = 0
    assert notify.owner_of(bot) == 0
    assert notify.delivery_target(bot) == 0
    bot.state.admin_id = 7610246474
    assert notify.delivery_target(bot) == 7610246474
    bot.cfg.admin_id = 111
    bot.state.admin_id = 222
    assert notify.delivery_target(bot) == 0
    bot.state.admin_id = 111
    assert notify.delivery_target(bot) == 111
    assert notify.delivery_target(object()) == 0


def test_parse_events_ignores_foreign_lines_and_loopback() -> None:
    payload = {
        "rows": [
            "honeypot ip=203.0.113.9 port=2222 proto=ssh event=auth role=user user=root",
            "honeypot ip=127.0.0.1 port=2222 proto=raw event=start ports=1",
            "honeypot ip=0.0.0.0 port=2222 proto=ssh event=probe",
            "garbage",
            "honeypot ip=198.51.100.4 port=bogus proto=ftp event=probe",
            12,
        ]
    }
    rows = notify.parse_events(payload)
    assert [item.address for item in rows] == ["203.0.113.9", "198.51.100.4"]
    assert rows[0].port == 2222
    assert rows[1].port == 0
    assert notify.parse_events({}) == []
    assert notify.parse_events(None) == []


def test_parse_banning_keeps_valid_rows() -> None:
    rows = notify.parse_banning({"banned": ["203.0.113.5", "", " 198.51.100.2 "]})
    assert [item.address for item in rows] == ["203.0.113.5", "198.51.100.2"]
    assert notify.parse_banning({}) == []


def test_the_address_is_masked_in_messages() -> None:
    assert notify.mask("203.0.113.99") == "203.x.x.99"
    assert notify.mask("") == "-"
    assert "113" not in notify.mask("203.0.113.99").split(".")[1]


@pytest.mark.parametrize("lang", ["en", "ru", "zh"])
def test_every_message_renders_in_every_language(lang: str) -> None:
    t = i18n.translator(lang)
    for kind in notify.KINDS:
        event = notify.Event(kind, "203.0.113.9", detail="probe", count=12, evidence=["22", "80"])
        html = str(dscreens.notify_message(event, t))
        assert html
        assert "{" not in html
        assert "203.0.113.9" not in html
        assert "dbg:ntf" not in html


@pytest.mark.parametrize("lang", ["en", "ru", "zh"])
def test_the_notify_screen_renders_and_carries_a_button_per_kind(lang: str) -> None:
    view = dscreens.DbgView(lang=lang, notify=notify.Centre())
    html = str(dscreens.notify_screen(view))
    for kind in notify.KINDS:
        assert "dbg:ntf:" + kind in html
    assert "dbg:ntf:off" in html and "dbg:ntf:on" in html and "dbg:ntf:test" in html
    assert i18n.translator(lang)("NTF_OWNER_RULE") in html


def test_the_poller_delivers_only_to_the_owner(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.cfg.admin_id = 0
    bot.state.admin_id = 0
    sent: list[Any] = []

    async def fake_send(chat_id: int, rich: Any) -> None:
        sent.append((chat_id, rich))

    bot.send = fake_send
    event = notify.Event(notify.KIND_BAN, "203.0.113.4", detail="jail")
    assert asyncio.run(bot.notify_send(event)) is False
    assert sent == []
    bot.cfg.admin_id = 4242
    assert asyncio.run(bot.notify_send(event)) is True
    assert [item[0] for item in sent] == [4242]


def test_the_poller_turns_agent_rows_into_events(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    bot.cfg.admin_id = 4242
    sent: list[Any] = []

    async def fake_send(chat_id: int, rich: Any) -> None:
        sent.append((chat_id, rich))

    async def fake_events(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"rows": ["honeypot ip=203.0.113.9 port=2222 proto=ssh event=auth role=user user=root"]}

    class FakeBan:
        banned = ["203.0.113.50"]
        honey_banned: list[str] = []
        sub_banned: list[str] = []
        ssh_banned = ["198.51.100.60"]

    async def fake_status(*args: Any, **kwargs: Any) -> FakeBan:
        return FakeBan()

    monkeypatch.setattr("BOT.app.honey_events", fake_events)
    monkeypatch.setattr(bot.guard, "status", fake_status)
    bot.send = fake_send
    raised = asyncio.run(bot.notify_poll())
    kinds = sorted(item.kind for item in raised)
    assert kinds == ["fail2ban", "honeypot", "ssh_brute"]
    assert len(sent) == len(raised)
    assert {item[0] for item in sent} == {4242}
    again = asyncio.run(bot.notify_poll())
    assert again == []


def test_the_screen_of_the_honeypot_renders_everywhere() -> None:
    for lang in ("en", "ru", "zh"):
        view = dscreens.DbgView(lang=lang)
        body = str(dscreens.honeypot_screen(view))
        assert "dbg:hp:install" in body
        assert "dbg:hp:check" in body
        assert i18n.translator(lang)("HP_NOTE") in body
        assert "{" not in body
