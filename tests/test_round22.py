from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from goygram import GoyGram

from BOT import chebur, i18n, ipscan
from BOT.app import Bot
from tests.fakes import FakeApp, FakeControl, FakeEvent, FakeGuard, make_config
from tests.test_html import Checker


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_round22_real_goygram_instance_never_triggers_dynamic_method_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bot = Bot(make_config(tmp_path), control=FakeControl(), guard=FakeGuard())
    real_app = GoyGram(
        bot_token="123456:" + "A" * 20,
        api_id=12345,
        api_hash="0" * 32,
    )
    mt_captured: list[tuple[str, dict[str, Any]]] = []

    async def fake_mt_req(act: str, **kw: Any) -> dict[str, Any]:
        mt_captured.append((act, dict(kw)))
        return {"_": "boolTrue"}

    monkeypatch.setattr(real_app.core, "mt_req", fake_mt_req)
    bot.app = real_app
    bot.state.language = "ru"

    monkeypatch.setattr(
        chebur,
        "check",
        lambda host, timeout=8.0: chebur.Registry(
            target=host,
            kind="ip",
            ips=[host],
            blocked=False,
            geo=chebur.Geo(country="DE", asn="AS24940", organisation="Hetzner Online GmbH", location="Falkenstein"),
            context="ctx_hetzner",
        ),
    )
    monkeypatch.setattr(
        chebur,
        "probe",
        lambda ctx, deadline=18.0: chebur.Live(
            target="203.0.113.55",
            online=3,
            finished=True,
            results=[
                chebur.Probe(provider="MTS", region="Moscow", asn="AS8359", verdicts=["tspu_block"], dpi_hop=5),
                chebur.Probe(provider="Beeline", region="Kazan", asn="AS3216", verdicts=["ok"]),
                chebur.Probe(provider="MegaFon", region="Novosibirsk", asn="AS31133", verdicts=["sni_block"], dpi_hop=7),
            ],
        ),
    )
    monkeypatch.setattr(
        ipscan,
        "fetch_ip_api",
        lambda q: {
            "status": "success",
            "query": "203.0.113.55",
            "country": "Germany",
            "countryCode": "DE",
            "city": "Falkenstein",
            "isp": "Hetzner Online GmbH",
            "as": "AS24940 Hetzner Online GmbH",
            "hosting": True,
            "proxy": False,
            "mobile": False,
        },
    )
    monkeypatch.setattr(ipscan, "probe_ports", lambda ip_addr: {"open": [(443, "TLS", 14)], "best_ms": 14})

    mt_msg_id = {"_": "inputBotInlineMessageID64", "dc_id": 2, "owner_id": 7, "id": 1001, "access_hash": 555666777}
    chosen_evt = FakeEvent(
        src="mt",
        update_type="updateBotInlineSend",
        from_id=7,
        msg_id=mt_msg_id,
        raw={"raw_update": {"_": "updateBotInlineSend", "user_id": 7, "id": "ipscan:aa11bb22:203.0.113.55", "query": "203.0.113.55", "msg_id": mt_msg_id}},
    )
    run(bot.on_chosen(chosen_evt))
    assert mt_captured == []

    cb_evt = FakeEvent(
        src="mt",
        update_type="updateInlineBotCallbackQuery",
        chat_id=None,
        msg_id=mt_msg_id,
        from_id=7,
        data="ipscan:run:203.0.113.55",
        raw={"raw_update": {"_": "updateInlineBotCallbackQuery", "user_id": 7, "msg_id": mt_msg_id, "data": b"ipscan:run:203.0.113.55"}},
    )
    run(bot.on_callback(cb_evt))
    assert len(mt_captured) == 2

    act1, kw1 = mt_captured[0]
    assert act1 == "messages.editInlineBotMessage"
    assert kw1["id"] == mt_msg_id
    assert kw1["rich_message"]["_"] == "inputRichMessageHTML"
    assert i18n.t("IPSCAN_SCANNING_TITLE", "ru") in kw1["rich_message"]["html"]
    assert "reply_markup" not in kw1

    act2, kw2 = mt_captured[1]
    assert act2 == "messages.editInlineBotMessage"
    rep_html = kw2["rich_message"]["html"]
    checker = Checker()
    checker.feed(rep_html)
    checker.close()
    assert checker.errors == []
    assert checker.stack == []
    assert "<details><summary>" in rep_html
    assert "<details open>" not in rep_html
    assert "Moscow / MTS (AS8359)" in rep_html
    assert "Novosibirsk / MegaFon (AS31133)" in rep_html
    rows = kw2["reply_markup"]["rows"]
    assert len(rows) == 1 and len(rows[0]["buttons"]) == 1
    only_btn = rows[0]["buttons"][0]
    assert only_btn["text"] == i18n.t("IPSCAN_BTN_OTHER", "ru")
    assert only_btn["type"] == {"_": "inlineButtonTypeSwitchInline", "query": "", "same_peer": True}


def test_round22_inline_card_is_rich_with_zero_hosting_info_and_single_start_button(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    net_calls: list[str] = []
    monkeypatch.setattr(chebur, "check", lambda *a, **kw: net_calls.append("chebur") or None)
    monkeypatch.setattr(ipscan, "fetch_ip_api", lambda *a, **kw: net_calls.append("ipapi") or {})
    monkeypatch.setattr(ipscan, "probe_ports", lambda *a, **kw: net_calls.append("ports") or {})

    bot = Bot(make_config(tmp_path), control=FakeControl(), guard=FakeGuard())
    bot.app = FakeApp()
    bot.state.language = "ru"
    bot.state.xray.sub_address = "192.0.2.111"

    for src in ("mt", "bot"):
        for query in ("", "8.8.8.8", "ya.ru"):
            evt = FakeEvent(query=query, src=src, from_id=7)
            run(bot.handle_inline(evt))
            assert net_calls == []
            assert len(evt.results) == 1
            res = evt.results[0]
            assert res["id"].startswith("ipscan:")
            assert "192.0.2.111" not in res["title"]
            assert "192.0.2.111" not in res["description"]
            assert "Hetzner" not in res["description"]
            assert "AS" not in res["description"]
            if src == "mt":
                sm = res["send_message"]
                assert sm["_"] == "inputBotInlineMessageRichMessage"
                html = sm["rich_message"]["html"]
                assert "192.0.2.111" not in html
                assert "<tg-button" not in html
                rows = sm["reply_markup"]["rows"]
                assert len(rows) == 1 and len(rows[0]["buttons"]) == 1
                btn = rows[0]["buttons"][0]
                assert btn["text"] == i18n.t("IPSCAN_BTN_START", "ru")
                assert btn["type"]["_"] == "inlineButtonTypeCallback"
            else:
                imc = res["input_message_content"]
                assert "rich_message" in imc and "message_text" not in imc
                html = imc["rich_message"]["html"]
                assert "192.0.2.111" not in html
                assert "<tg-button" not in html
                ik = res["reply_markup"]["inline_keyboard"]
                assert len(ik) == 1 and len(ik[0]) == 1
                assert ik[0][0]["text"] == i18n.t("IPSCAN_BTN_START", "ru")
                assert ik[0][0]["callback_data"].startswith("ipscan:run:")


def test_round22_no_ip_caching_across_inline_queries_or_changing_server_ip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bot = Bot(make_config(tmp_path), control=FakeControl(), guard=FakeGuard())
    bot.app = FakeApp()
    bot.state.language = "ru"
    bot.state.xray.sub_address = "192.0.2.250"

    evt1 = FakeEvent(query="1.1.1.1", src="mt", from_id=7)
    evt2 = FakeEvent(query="1.1.1.1", src="mt", from_id=7)
    evt3 = FakeEvent(query="9.9.9.9", src="mt", from_id=7)
    run(bot.handle_inline(evt1))
    run(bot.handle_inline(evt2))
    run(bot.handle_inline(evt3))
    assert evt1.results[0]["id"] != evt2.results[0]["id"]
    assert evt3.results[0]["id"].endswith(":9.9.9.9")
    assert "1.1.1.1" not in evt3.results[0]["send_message"]["rich_message"]["html"]
    assert "9.9.9.9" in evt3.results[0]["send_message"]["rich_message"]["html"]

    current_ip = {"val": "198.51.100.10"}
    monkeypatch.setattr(
        ipscan,
        "fetch_ip_api",
        lambda q: {"status": "success", "query": q or current_ip["val"], "country": "NL", "countryCode": "NL", "isp": "ISP-" + (q or current_ip["val"])},
    )
    monkeypatch.setattr(
        chebur,
        "check",
        lambda host, timeout=8.0: chebur.Registry(target=host, kind="ip", ips=[host], blocked=False),
    )
    monkeypatch.setattr(ipscan, "probe_ports", lambda ip_addr: {"open": [], "best_ms": 0})

    rep1 = ipscan.full_scan_sync("self", default_target=bot.default_scan_target())
    assert rep1["target"] == "198.51.100.10"
    assert rep1["ip"] == "198.51.100.10"

    current_ip["val"] = "203.0.113.77"
    rep2 = ipscan.full_scan_sync("self", default_target=bot.default_scan_target())
    assert rep2["target"] == "203.0.113.77"
    assert rep2["ip"] == "203.0.113.77"


def test_round22_hybrid_mt_failure_falls_back_to_bot_api_packed_inline_id(
    tmp_path: Path,
) -> None:
    bot = Bot(make_config(tmp_path), control=FakeControl(), guard=FakeGuard())
    app = FakeApp()
    app.bot = object()

    async def failing_mt_req(method: str, **kw: Any) -> dict[str, Any]:
        raise RuntimeError("DC_MIGRATE_ERROR")

    setattr(app, "mt_req", failing_mt_req)
    bot.app = app

    mt_id = {"_": "inputBotInlineMessageID64", "dc_id": 2, "owner_id": 7, "id": 88, "access_hash": 1234567890123}
    packed = bot.pack_inline_id(mt_id)
    assert bot.unpack_inline_id(packed) == mt_id

    ok = run(bot.edit_inline_rich(mt_id, ipscan.scanning_screen("8.8.8.8", "ru")))
    assert ok is True
    assert len(app.bot_calls) == 1
    meth, payload = app.bot_calls[0]
    assert meth == "editMessageText"
    assert payload["inline_message_id"] == packed
    assert i18n.t("IPSCAN_SCANNING_TITLE", "ru") in payload["rich_message"]["html"]
