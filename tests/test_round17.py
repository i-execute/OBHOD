from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

from BOT import chebur, commands, dscreens, freeturn, ftscreens, fwguard, i18n, inline, ipscan, screens, xscreens
from BOT.ui import count_buttons
from Storage import obhod_setup
from tests.test_app import FakeEvent, make_bot, run


def button_datas(doc: Any) -> list[str]:
    return re.findall(r'<tg-button[^>]*\bdata="([^"]+)"', doc.to_html())


def button_labels(doc: Any) -> list[str]:
    return re.findall(r"<tg-button[^>]*>(.*?)</tg-button>", doc.to_html())


def test_round17_home_clean_no_selected_tag_and_no_emoji_toggle(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    bot.state.core = "xray"
    doc = screens.home(bot.view())
    datas = button_datas(doc)
    labels = button_labels(doc)
    assert "nav:emoji" not in datas
    for label in labels:
        assert "\u0432\u044b\u0431\u0440\u0430\u043d\u043e" not in label.lower()
        assert "selected" not in label.lower()
    assert any("\u0418\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u044b" in label for label in labels)

    set_doc = screens.settings(bot.view())
    assert "nav:emoji" in button_datas(set_doc)


def test_round17_all_busy_screens_have_no_buttons(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    assert count_buttons(screens.busy_screen("work", "ru").to_html()) == 0
    assert count_buttons(xscreens.busy_screen("work", "ru").to_html()) == 0
    assert count_buttons(ftscreens.busy_screen("work", "ru").to_html()) == 0
    assert count_buttons(dscreens.busy(bot.debug.view(), "work").to_html()) == 0


def test_round17_commands_and_menu() -> None:
    items = commands.menu(i18n.translator("ru"))
    assert [(item["command"], item["description"]) for item in items] == [
        ("start", i18n.t("CMD_START_DESC", "ru")),
        ("wg_whitelist_bypass_raskur", "FreeTurn"),
        ("vless_raw_xhttp_reality_raskur", "Xray"),
    ]
    assert commands.known("/wireguard_whitelist_bypass_raskur") is not None
    assert commands.known("/wireguard_whitelist_bypass_raskur").name == "wireguard_whitelist_bypass_raskur"
    assert commands.known("/wg_whitelist_bypass_raskur") is not None
    assert commands.known("/wg_whitelist_bypass_raskur").name == "wireguard_whitelist_bypass_raskur"
    assert commands.known("/vless_raw_xhttp_reality_raskur") is not None
    assert commands.known("/vless_raw_xhttp_reality_raskur").name == "vless_raw_xhttp_reality_raskur"


def test_round17_no_triple_dots_in_russian_strings() -> None:
    from BOT.strings import RU

    offenders = []
    for name, value in vars(RU).items():
        if isinstance(value, str) and "..." in value:
            offenders.append(name)
    assert offenders == []


def test_round17_chebur_net_check_fast_and_rerunnable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    calls = {"count": 0}

    def fake_reach() -> chebur.Reach:
        calls["count"] += 1
        return chebur.Reach(host=chebur.HOST, ip="1.1.1.1", ms=18, status=200)

    monkeypatch.setattr(chebur, "reach", fake_reach)

    evt1 = FakeEvent(data="dbg:chk:net", msg_id=42, chat_id=1, from_id=7)
    run(bot.on_callback(evt1))
    assert calls["count"] == 1
    assert len(bot.rendered) >= 2
    assert count_buttons(bot.rendered[0].to_html()) == 0
    assert count_buttons(bot.rendered[-1].to_html()) > 0

    before = len(bot.rendered)
    evt2 = FakeEvent(data="dbg:chk:net", msg_id=42, chat_id=1, from_id=7)
    run(bot.on_callback(evt2))
    assert calls["count"] == 2
    assert len(bot.rendered) > before
    assert count_buttons(bot.rendered[-1].to_html()) > 0


def test_round17_inline_sends_pure_notepad_emoji_and_deletes_message(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    token = inline.token_for("xr_sub_port", "-")
    cards = inline.results_for("%s 8443" % token, src="mt", current=bot.input_values(), lang="ru")
    assert len(cards) == 1
    sent_text = cards[0]["send_message"]["message"]
    assert sent_text == inline.MARKER
    assert len(sent_text) == 1
    assert inline.SEPARATOR not in sent_text

    chosen_evt = FakeEvent(
        update_type="updateBotInlineSend",
        from_id=7,
        raw={
            "kind": "update",
            "src": "mt",
            "update_type": "updateBotInlineSend",
            "result_id": cards[0]["id"],
            "from_id": 7,
            "query": "%s 8443" % token,
        },
    )
    run(bot.on_chosen(chosen_evt))
    assert bot.state.xray.sub_port == 8443

    marker_evt = FakeEvent(text=inline.MARKER, msg_id=77, chat_id=1, from_id=7)
    run(bot.on_message(marker_evt))
    assert (1, 77) in bot.app.deleted


def test_round17_inline_pure_marker_fallback_without_chosen_feedback(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    token = inline.token_for("xr_sub_port", "-")
    cards = inline.results_for("%s 9443" % token, src="bot", current=bot.input_values(), lang="ru")
    assert cards[0]["input_message_content"]["message_text"] == inline.MARKER

    marker_evt = FakeEvent(text=inline.MARKER, msg_id=88, chat_id=1, from_id=7)
    run(bot.on_message(marker_evt))
    assert (1, 88) in bot.app.deleted
    assert bot.state.xray.sub_port == 9443


def test_round17_inline_ip_scanner_combines_chebur_and_ip_meta(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    ipscan.clear_cache()

    monkeypatch.setattr(
        chebur,
        "check",
        lambda host, timeout=3.5: chebur.Registry(
            target=host,
            kind="domain",
            ips=["77.88.55.242"],
            blocked=False,
            subnets=["77.88.0.0/18"],
            cdn={"provider": "Yandex CDN"},
            reverse=["ya.ru"],
            complaints=[chebur.Complaint("2026-11-04", 2)],
            geo=chebur.Geo(country="RU", asn="AS13238", organisation="YANDEX LLC"),
            context="ctx_yaru",
        ),
    )
    monkeypatch.setattr(
        chebur,
        "probe",
        lambda ctx, deadline=18.0: chebur.Live(
            target="ya.ru",
            online=1,
            finished=True,
            results=[chebur.Probe(provider="MTS", region="Moscow", asn="AS8359", verdicts=["ok"])],
        ),
    )
    monkeypatch.setattr(
        ipscan,
        "fetch_ip_api",
        lambda ip_addr, timeout=2.8: {
            "status": "success",
            "query": "77.88.55.242",
            "country": "Russia",
            "countryCode": "RU",
            "city": "Moscow",
            "isp": "Yandex LLC",
            "as": "AS13238 YANDEX LLC",
            "reverse": "ya.ru",
            "hosting": True,
            "proxy": False,
            "mobile": False,
        },
    )
    monkeypatch.setattr(ipscan, "probe_ports", lambda ip_addr: {"open": [(443, "TLS", 9)], "best_ms": 9})

    answered: list[list[dict]] = []

    class InlineEvt:
        query = "ya.ru"
        src = "mt"
        from_id = 7

        async def answer(self, results: list[dict], cache_time: int = 0, is_personal: bool = True) -> None:
            answered.append(results)

    run(bot.handle_inline(InlineEvt()))
    assert len(answered) == 1
    assert len(answered[0]) == 1
    card = answered[0][0]
    assert card["id"].startswith("ipscan:")
    assert card["send_message"]["_"] == "inputBotInlineMessageRichMessage"
    launch_html = card["send_message"]["rich_message"]["html"]
    assert "AS13238" not in launch_html
    assert "Yandex" not in launch_html
    rows = card["send_message"]["reply_markup"]["rows"]
    assert len(rows) == 1 and len(rows[0]["buttons"]) == 1

    report = ipscan.full_scan_sync("ya.ru", force=True)
    rich_card, after_kbd = ipscan.rich_report(report, "ru")
    rep_html = rich_card.build()
    assert "ya.ru" in rep_html
    assert "77.88.55.242" in rep_html
    assert "AS13238" in rep_html
    assert "Yandex" in rep_html
    assert "<details><summary>" in rep_html
    assert len(after_kbd) == 1 and "switch_inline_query_current_chat" in after_kbd[0][0]


def test_round17_tui_inline_disabled_warning_text_and_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    expected = "THE BOT IS ALIVE AND WILL BE CONFIGURED, BUT ENABLE INLINE MODE"
    assert obhod_setup.INLINE_WARN_TEXT == expected
    assert i18n.t("TUI_INLINE_WARN", "en") == expected
    assert obhod_setup.INLINE_WARN_TEXT.isascii()

    bot = make_bot(tmp_path)

    async def fake_get_me(refresh: bool = False) -> dict[str, Any]:
        return {"id": 123, "is_bot": True, "username": "demo_bot", "supports_inline_queries": False}

    bot.app.get_me = fake_get_me
    ok = asyncio.run(bot.check_inline_mode())
    err = capsys.readouterr().err
    assert ok is False
    assert expected in err
    assert err.isascii()
    assert "\033[1;31m" in err


def test_round17_auto_protect_syncs_vk_udp_guard_and_ip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import BOT.app

    bot = make_bot(tmp_path)
    bot.freeturn.state = freeturn.FtState(installed=True, running=True)
    bot.freeturn.state.config.listen_port = 39871
    bot.freeturn.draft.listen_port = 39871

    called: dict[str, Any] = {}

    async def fake_fw(mode: str, port: int, cidrs: str = "", proto: str = "udp", keep: str = "", timeout: float = 0) -> freeturn.FtGuard:
        called["mode"] = mode
        called["port"] = port
        called["proto"] = proto
        called["cidrs"] = cidrs
        called["keep"] = keep
        return freeturn.FtGuard(port=port, proto=proto, backend="nft", mode="vk", rules=4, cidrs=2)

    monkeypatch.setattr(BOT.app, "public_address", lambda: "203.0.113.77")
    monkeypatch.setattr(bot.freeturn.control, "firewall", fake_fw)
    monkeypatch.setitem(fwguard.CACHE, "vk", (9999999999.0, ["95.142.192.0/21", "5.61.16.0/21"], ""))

    outcomes = asyncio.run(bot.auto_protect())
    assert outcomes.get("vk_fw") == "vk"
    assert called["mode"] == "vk"
    assert called["port"] == 39871
    assert called["proto"] == "udp"
    assert bot.state.xray.sub_address == "203.0.113.77"
    assert bot.freeturn.draft.host == "203.0.113.77"
    assert bot.debug.vk["guard"]["mode"] == "vk"
    assert bot.debug.vk["guard"]["port"] == 39871
