from __future__ import annotations

import asyncio
import base64
import struct
from pathlib import Path
from typing import Any

import pytest

from BOT import chebur, i18n, inline, ipscan
from BOT.app import Bot
from BOT.ui import use_icons
from tests.fakes import FakeApp, FakeControl, FakeEvent, FakeGuard, make_bot, make_config


def run(coro):
    return asyncio.run(coro)


def install_scan_fakes(monkeypatch: pytest.MonkeyPatch, calls: list[str] | None = None) -> None:
    ipscan.clear_cache()

    def fake_chebur(host: str, timeout: float = 3.5) -> chebur.Registry:
        if calls is not None:
            calls.append("chebur:" + host)
        return chebur.Registry(
            target=host,
            kind="domain" if any(c.isalpha() for c in host) else "ip",
            blocked=False,
            ips=["77.88.55.242", "77.88.55.243"],
            ip_count=2,
            subnets=["77.88.0.0/18"],
            cdn={"Yandex CDN": True},
            reverse=["ya.ru"],
            complaints=[chebur.Complaint("2026-11-04", 3)],
            geo=chebur.Geo(country="RU", asn="AS13238", organisation="YANDEX LLC", location="Moscow"),
        )

    def fake_ip_api(ip_addr: str, timeout: float = 2.8) -> dict[str, Any]:
        if calls is not None:
            calls.append("ipapi:" + (ip_addr or "self"))
        return {
            "status": "success",
            "query": ip_addr if ip_addr and ip_addr[0].isdigit() else "77.88.55.242",
            "continent": "Europe",
            "country": "Russia",
            "countryCode": "RU",
            "regionName": "Moscow",
            "city": "Moscow",
            "timezone": "Europe/Moscow",
            "isp": "Yandex LLC",
            "org": "Yandex Cloud",
            "as": "AS13238 YANDEX LLC",
            "asname": "YANDEX",
            "reverse": "ya.ru",
            "hosting": True,
            "proxy": False,
            "mobile": False,
        }

    def fake_ports(ip_addr: str) -> dict[str, Any]:
        if calls is not None:
            calls.append("ports:" + ip_addr)
        return {"open": [(80, "HTTP", 12), (443, "TLS", 9)], "best_ms": 9}

    def fake_probe(ctx: str, deadline: float = 18.0) -> chebur.Live:
        if calls is not None:
            calls.append("probe:" + ctx)
        return chebur.Live(
            target="ya.ru",
            online=2,
            finished=True,
            results=[
                chebur.Probe(provider="MTS", region="Moscow", asn="AS8359", verdicts=["ok"]),
                chebur.Probe(provider="RTK", region="SPb", asn="AS12389", verdicts=["tspu_block"], dpi_hop=6),
            ],
        )

    monkeypatch.setattr(chebur, "check", fake_chebur)
    monkeypatch.setattr(chebur, "probe", fake_probe)
    monkeypatch.setattr(ipscan, "fetch_ip_api", fake_ip_api)
    monkeypatch.setattr(ipscan, "probe_ports", fake_ports)


def test_inline_without_hash_never_registers_tokens_and_returns_single_ipscan_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_scan_fakes(monkeypatch)
    bot = make_bot(tmp_path)
    bot.state.language = "ru"

    inline._REGISTRY.clear()
    for raw_query in ("", "   ", "77.88.55.242", "ya.ru", "cloudflare", "zzzzzzzzzz", "not a valid target!"):
        evt = FakeEvent(query=raw_query, src="mt", from_id=7)
        run(bot.handle_inline(evt))
        assert inline._REGISTRY == {}, f"unexpected token registration for query={raw_query!r}"
        assert len(evt.results) == 1, f"expected strictly 1 result for query={raw_query!r}"
        card = evt.results[0]
        assert card["id"].startswith("ipscan:")
        markup = card["send_message"].get("reply_markup")
        assert isinstance(markup, dict)
        assert markup.get("_") == "replyInlineMarkup"
        first_btn = markup["rows"][0]["buttons"][0]
        assert first_btn["text"] == i18n.t("IPSCAN_BTN_START", "ru")
        assert first_btn["type"]["_"] == "inlineButtonTypeCallback"
        assert first_btn["type"]["data"].startswith(b"ipscan:run:")


def test_inline_with_valid_registered_hash_still_works(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inline._REGISTRY.clear()
    prefilled = inline.prefill("xr_sub_port")
    token = prefilled.strip()
    assert inline.resolve(token)[0] == "xr_sub_port"

    evt = FakeEvent(query=prefilled + "4567", src="bot", from_id=7)
    run(bot.handle_inline(evt))
    assert len(evt.results) == 1
    assert evt.results[0]["id"] == f"i:{token}"


def test_chosen_inline_result_waits_for_button_click_before_running_full_rich_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    install_scan_fakes(monkeypatch, calls)

    for idx, lang in enumerate(("en", "ru", "zh")):
        sub_dir = tmp_path / f"lang_{idx}"
        sub_dir.mkdir(parents=True, exist_ok=True)
        bot = Bot(make_config(sub_dir), control=FakeControl(), guard=FakeGuard())
        bot.app = FakeApp()
        bot.state.language = lang

        inline_evt = FakeEvent(query="ya.ru", src="mt", from_id=7)
        run(bot.handle_inline(inline_evt))
        assert len(inline_evt.results) == 1
        card0 = inline_evt.results[0]
        rid = card0["id"]
        assert card0["send_message"]["_"] == "inputBotInlineMessageRichMessage"
        assert calls == []

        mt_msg_id = {"_": "inputBotInlineMessageID", "dc_id": 2, "id": 777 + idx, "access_hash": 123456789}
        chosen_mt = FakeEvent(
            src="mt",
            update_type="updateBotInlineSend",
            from_id=7,
            msg_id=mt_msg_id,
            raw={"raw_update": {"_": "updateBotInlineSend", "user_id": 7, "id": rid, "query": "ya.ru", "msg_id": mt_msg_id}},
        )
        run(bot.on_chosen(chosen_mt))
        assert bot.app.mt_calls == []

        cb_mt = FakeEvent(
            src="mt",
            update_type="updateInlineBotCallbackQuery",
            chat_id=None,
            msg_id=mt_msg_id,
            from_id=7,
            data="ipscan:run:ya.ru",
            raw={"raw_update": {"_": "updateInlineBotCallbackQuery", "user_id": 7, "msg_id": mt_msg_id, "data": b"ipscan:run:ya.ru"}},
        )
        use_icons(True)
        try:
            run(bot.on_callback(cb_mt))
        finally:
            use_icons(False)

        assert len(bot.app.mt_calls) == 2
        loading_method, loading_payload = bot.app.mt_calls[0]
        assert loading_method == "messages.editInlineBotMessage"
        assert i18n.t("IPSCAN_SCANNING_TITLE", lang) in loading_payload["rich_message"]["html"]
        assert "reply_markup" not in loading_payload

        method, payload = bot.app.mt_calls[1]
        assert method == "messages.editInlineBotMessage"
        assert payload["id"] == mt_msg_id
        assert payload["rich_message"]["_"] == "inputRichMessageHTML"
        html = payload["rich_message"]["html"]
        assert i18n.t("IPSCAN_REPORT_TITLE", lang) in html
        assert "77.88.55.242" in html
        assert "AS13238" in html
        assert "Europe/Moscow" in html
        assert "443" in html
        assert 'align="center"' in html
        assert "<tg-emoji" in html
        after_rows = payload["reply_markup"]["rows"]
        assert len(after_rows) == 1 and len(after_rows[0]["buttons"]) == 1
        assert after_rows[0]["buttons"][0]["type"]["_"] == "inlineButtonTypeSwitchInline"
        calls.clear()

    packed_id = base64.urlsafe_b64encode(struct.pack("<iqq", 2, 5555, 987654321)).decode("ascii").rstrip("=")
    bot_dir = tmp_path / "bot_mode"
    bot_dir.mkdir(parents=True, exist_ok=True)
    bot2 = Bot(make_config(bot_dir), control=FakeControl(), guard=FakeGuard())
    bot2.app = FakeApp()
    bot2.app.bot = object()
    bot2.state.language = "ru"
    cb_bot = FakeEvent(
        src="bot",
        update_type="callback_query",
        chat_id=None,
        msg_id=0,
        from_id=7,
        inline_message_id=packed_id,
        data="ipscan:run:ya.ru",
        raw={"callback_query": {"id": "cb1", "from": {"id": 7}, "inline_message_id": packed_id, "data": "ipscan:run:ya.ru"}},
    )
    run(bot2.on_callback(cb_bot))
    assert len(bot2.app.bot_calls) == 2
    assert i18n.t("IPSCAN_SCANNING_TITLE", "ru") in bot2.app.bot_calls[0][1]["rich_message"]["html"]
    b_method, b_payload = bot2.app.bot_calls[1]
    assert b_method == "editMessageText"
    assert b_payload["inline_message_id"] == packed_id
    assert i18n.t("IPSCAN_REPORT_TITLE", "ru") in b_payload["rich_message"]["html"]
    assert b_payload["reply_markup"]["inline_keyboard"] == [
        [{"text": i18n.t("IPSCAN_BTN_OTHER", "ru"), "switch_inline_query_current_chat": ""}]
    ]


def test_clicking_start_scan_inline_button_runs_fresh_scan_and_edits_inline_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    install_scan_fakes(monkeypatch, calls)

    bot = Bot(make_config(tmp_path), control=FakeControl(), guard=FakeGuard())
    bot.app = FakeApp()
    bot.state.language = "ru"

    mt_msg_id = {"_": "inputBotInlineMessageID64", "dc_id": 2, "owner_id": 7, "id": 42, "access_hash": 999888777}
    cb_evt = FakeEvent(
        src="mt",
        update_type="updateInlineBotCallbackQuery",
        chat_id=None,
        msg_id=mt_msg_id,
        from_id=7,
        data="ipscan:run:77.88.55.242",
        raw={"raw_update": {"_": "updateInlineBotCallbackQuery", "user_id": 7, "msg_id": mt_msg_id, "data": b"ipscan:run:77.88.55.242"}},
    )
    run(bot.on_callback(cb_evt))
    run(bot.idle())

    assert cb_evt.answers and i18n.t("IPSCAN_TOAST_START", "ru") in cb_evt.answers[0]["text"]
    assert len(bot.app.mt_calls) == 2
    loading_call = bot.app.mt_calls[0]
    final_call = bot.app.mt_calls[1]
    assert loading_call[0] == "messages.editInlineBotMessage"
    assert i18n.t("IPSCAN_SCANNING_TITLE", "ru") in loading_call[1]["rich_message"]["html"]
    assert final_call[0] == "messages.editInlineBotMessage"
    final_html = final_call[1]["rich_message"]["html"]
    assert i18n.t("IPSCAN_REPORT_TITLE", "ru") in final_html
    assert "77.88.55.242" in final_html
    assert "ports:77.88.55.242" in calls

    stranger_cb = FakeEvent(
        src="mt",
        update_type="updateInlineBotCallbackQuery",
        chat_id=None,
        msg_id=mt_msg_id,
        from_id=999,
        data="ipscan:run:77.88.55.242",
    )
    run(bot.on_callback(stranger_cb))
    assert stranger_cb.answers and stranger_cb.answers[0]["alert"] is True
    assert len(bot.app.mt_calls) == 2


def test_mtproto_tl_binary_serialization_of_inline_ipscan_and_edit_rich(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from goygram import ext, schema_manager

    install_scan_fakes(monkeypatch)
    schema_manager.init_schema(ext)

    results = run(ipscan.inline_results("ya.ru", src="mt", lang="ru"))
    assert len(results) == 1
    packed_inline = ext.serialize_method(
        "messages.setInlineBotResults",
        {"query_id": 123456, "gallery": False, "private": True, "cache_time": 0, "results": results},
    )
    assert isinstance(packed_inline, (bytes, bytearray)) and len(packed_inline) > 40

    report_data = ipscan.full_scan_sync("ya.ru", force=True)
    card, _kbd = ipscan.rich_report(report_data, "ru")
    packed_edit = ext.serialize_method(
        "messages.editInlineBotMessage",
        {
            "id": {"_": "inputBotInlineMessageID", "dc_id": 2, "id": 101, "access_hash": 202},
            "message": "",
            "rich_message": card.to_tl(),
        },
    )
    assert isinstance(packed_edit, (bytes, bytearray)) and len(packed_edit) > 80
