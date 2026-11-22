from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.parse
from pathlib import Path

import pytest

from BOT import commands
from BOT.vkcalls import (
    VK_API_BASE,
    VK_API_VERSION,
    VKCallsAPIClient,
    VKCallsAPIError,
    VKCallsNetworkError,
    VKCallsPanel,
    VKCallsService,
    extract_vk_token,
    safe_vk_url,
)
from tests.fakes import FakeEvent, make_bot

TOKEN = "vk1.a." + "a" * 48
CALL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
JOIN_LINK = "https://vk.ru/call/join/abc"


class StubAPI:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.finish_wait = asyncio.Event()
        self.response = {"call_id": CALL_ID, "join_link": JOIN_LINK}

    async def call(self, token: str, method: str, **params):
        self.calls.append((token, method, params))
        await asyncio.sleep(0)
        if method == "users.get":
            return [{"id": 42}]
        if method == "calls.start":
            return dict(self.response)
        if method == "calls.forceFinish":
            return 1
        raise AssertionError(method)


class FakeResponse:
    status = 200

    def __init__(self, payload: dict) -> None:
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, size: int) -> bytes:
        return self.payload[:size]


def run(coro):
    return asyncio.run(coro)


def test_extracts_raw_tokens_and_full_authorization_urls() -> None:
    url = "https://oauth.vk.ru/blank.html#access_token=" + TOKEN + "&expires_in=0"
    assert extract_vk_token(TOKEN) == TOKEN
    assert extract_vk_token(url) == TOKEN
    assert extract_vk_token("https://example.org/?access_token=bad token") == ""
    assert extract_vk_token("https://example.org/?other=" + TOKEN) == ""


def test_join_url_allowlist_rejects_external_hosts_and_credentials() -> None:
    assert safe_vk_url(JOIN_LINK) == JOIN_LINK
    assert safe_vk_url("https://vk.ru.evil.example/call") == ""
    assert safe_vk_url("https://user@vk.ru/call") == ""
    assert safe_vk_url("http://vk.ru/call") == ""
    assert safe_vk_url("https://vk.ru:444/call") == ""


def test_vk_api_request_uses_expected_host_method_version_and_token() -> None:
    captured = {}

    def opener(request, timeout):
        captured["url"] = request.full_url
        captured["body"] = urllib.parse.parse_qs(request.data.decode())
        captured["timeout"] = timeout
        return FakeResponse({"response": [{"id": 42}]})

    client = VKCallsAPIClient(opener=opener)
    result = run(client.call(TOKEN, "users.get"))
    assert result == [{"id": 42}]
    assert captured["url"] == VK_API_BASE + "users.get"
    assert captured["body"]["access_token"] == [TOKEN]
    assert captured["body"]["v"] == [VK_API_VERSION]
    assert captured["timeout"] <= 30


def test_vk_api_errors_are_structured_without_echoing_token() -> None:
    client = VKCallsAPIClient(opener=lambda *args, **kwargs: FakeResponse({"error": {"error_code": 5}}))
    with pytest.raises(VKCallsAPIError) as caught:
        run(client.call(TOKEN, "users.get"))
    assert caught.value.vk_code == 5
    assert TOKEN not in str(caught.value)


def test_vk_api_transport_errors_are_sanitized() -> None:
    def fail(*args, **kwargs):
        raise TimeoutError(TOKEN)

    with pytest.raises(VKCallsNetworkError) as caught:
        run(VKCallsAPIClient(opener=fail).call(TOKEN, "users.get"))
    assert str(caught.value) == "network"
    assert TOKEN not in str(caught.value)


def test_vk_api_error_codes_map_to_actionable_messages(tmp_path: Path) -> None:
    from BOT import i18n

    panel = VKCallsPanel(make_bot(tmp_path), service=VKCallsService(tmp_path, api=StubAPI()))
    for code, key in (
        (5, "VKCALLS_TOKEN_EXPIRED"),
        (6, "VKCALLS_RATE_LIMIT"),
        (9, "VKCALLS_RATE_LIMIT"),
        (14, "VKCALLS_CAPTCHA"),
        (29, "VKCALLS_RATE_LIMIT"),
    ):
        assert panel.error_text(VKCallsAPIError("api_error", code)) == i18n.t(key)


def test_check_token_always_queries_vk_even_when_user_id_is_cached(tmp_path: Path) -> None:
    api = StubAPI()
    service = VKCallsService(tmp_path, api=api)
    service.token = TOKEN
    service.user_id = 13
    assert run(service.check_token()) == 42
    assert service.user_id == 42
    assert [method for _, method, _ in api.calls] == ["users.get"]


def test_authorization_and_calls_survive_restart_without_unverified_fields(tmp_path: Path) -> None:
    api = StubAPI()
    api.response["short_credentials"] = {
        "id": "short-7",
        "password": "secret-7",
        "link_with_password": "https://vk.ru/call/join/abc?pwd=secret-7",
    }
    service = VKCallsService(tmp_path, api=api)
    assert run(service.authorize("https://oauth.vk.ru/#access_token=" + TOKEN)) == 42
    call = run(service.create_call())
    assert call["call_id"] == CALL_ID
    assert call["join_link"] == JOIN_LINK
    assert call["short_credentials"]["id"] == "short-7"
    assert call["short_credentials"]["password"] == "secret-7"
    assert os.stat(service.token_path).st_mode & 0o777 == 0o600
    assert os.stat(service.calls_path).st_mode & 0o777 == 0o600
    restored = VKCallsService(tmp_path, api=api)
    assert restored.token == TOKEN
    assert restored.get_call(CALL_ID)["join_link"] == JOIN_LINK
    assert restored.latest_join_link() == JOIN_LINK
    assert restored.user_id == 0


def test_short_credentials_are_optional_and_unsafe_links_are_dropped(tmp_path: Path) -> None:
    api = StubAPI()
    api.response = {"call_id": CALL_ID, "join_link": "https://attacker.example/"}
    service = VKCallsService(tmp_path, api=api)
    service.token = TOKEN
    service.user_id = 42
    call = run(service.create_call())
    assert call["join_link"] == ""
    api.response = {"call_id": CALL_ID, "join_link": JOIN_LINK}
    api.response["call_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    call = run(service.create_call())
    assert call["short_credentials"] == {"id": "", "password": "", "link_with_password": ""}


def test_concurrent_finish_calls_hit_vk_once(tmp_path: Path) -> None:
    api = StubAPI()
    service = VKCallsService(tmp_path, api=api)
    service.token = TOKEN
    service.user_id = 42
    service._calls[CALL_ID] = service._normalize_call({"call_id": CALL_ID, "join_link": JOIN_LINK})
    async def finish_both():
        return await asyncio.gather(service.finish_call(CALL_ID), service.finish_call(CALL_ID))

    results = run(finish_both())
    assert results == [True, True]
    assert sum(method == "calls.forceFinish" for _, method, _ in api.calls) == 1
    assert service.get_call(CALL_ID) is None


def test_vk_token_message_is_removed_after_delay(tmp_path: Path, monkeypatch) -> None:
    from BOT import vkcalls

    bot = make_bot(tmp_path)
    bot.vkcalls = VKCallsPanel(bot, service=VKCallsService(tmp_path, api=StubAPI()))
    bot.vkcalls.auth_pending[7] = time.monotonic() + 600
    monkeypatch.setattr(vkcalls, "TOKEN_DELETE_DELAY", 0)
    event = FakeEvent(text=TOKEN, from_id=7, chat_id=7, msg_id=91)
    run(bot.handle_message(event))
    run(bot.idle())
    assert (7, 91) in bot.app.deleted
    assert bot.vkcalls.service.token == TOKEN


def test_tailscale_secret_during_vk_auth_is_left_for_existing_handler(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.vkcalls = VKCallsPanel(bot, service=VKCallsService(tmp_path, api=StubAPI()))
    bot.vkcalls.auth_pending[7] = time.monotonic() + 600
    tailscale_key = "tskey-api-" + "0" * 16 + "-" + "0" * 24
    event = FakeEvent(text=tailscale_key, from_id=7, chat_id=7, msg_id=92)
    assert run(bot.vkcalls.handle_message(event, tailscale_key)) is False
    run(bot.handle_message(event))
    assert (7, 92) in bot.app.deleted
    assert bot.vkcalls.service.token == ""


def test_vk_command_is_available_without_changing_telegram_command_menu() -> None:
    assert commands.known("vkcall") is None
    items = commands.menu(lambda key: key)
    assert all(item["command"] != "vkcall" for item in items)


def test_non_admin_vk_token_url_is_deleted_without_authentication(tmp_path: Path, monkeypatch) -> None:
    from BOT import vkcalls

    bot = make_bot(tmp_path)
    monkeypatch.setattr(vkcalls, "TOKEN_DELETE_DELAY", 0)
    url = "https://oauth.vk.ru/blank.html#access_token=" + TOKEN

    async def reject_and_wait():
        await bot.handle_message(FakeEvent(text=url, from_id=99, chat_id=99, msg_id=93))
        await bot.idle()

    run(reject_and_wait())
    assert (99, 93) in bot.app.deleted
    assert bot.vkcalls.service.token == ""


def test_non_admin_cannot_route_vk_callbacks(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    calls = []

    async def blocked_route(*args):
        calls.append(args)

    bot.vkcalls.route = blocked_route
    run(bot.on_callback(FakeEvent(data="vk:create", from_id=99, chat_id=99)))
    run(bot.idle())
    assert calls == []
    assert bot.sent


def test_admin_vk_command_and_navigation_are_integrated(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_command(FakeEvent(cmd="vkcall", from_id=7, chat_id=7)))
    assert bot.sent
    run(bot.on_callback(FakeEvent(data="vk:active", from_id=7, chat_id=7)))
    run(bot.idle())
    assert bot.rendered


def test_vk_calls_stay_in_the_admin_private_chat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT import vkcalls

    bot = make_bot(tmp_path)
    api = StubAPI()
    service = VKCallsService(tmp_path, api=api)
    service._calls[CALL_ID] = service._normalize_call({"call_id": CALL_ID, "join_link": JOIN_LINK})
    bot.vkcalls = VKCallsPanel(bot, service=service)
    sleep_calls = []

    async def immediate_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    monkeypatch.setattr(vkcalls.asyncio, "sleep", immediate_sleep)

    async def scenario() -> None:
        await bot.on_command(FakeEvent(cmd="vkcall", from_id=7, chat_id=-100))
        await bot.vkcalls.route(-100, 77, "vk:detail:" + CALL_ID)
        bot.vkcalls.auth_pending[7] = time.monotonic() + 600
        await bot.handle_message(FakeEvent(text=TOKEN, from_id=7, chat_id=-100, msg_id=94))
        await bot.idle()

    run(scenario())
    assert api.calls == []
    assert service.token == ""
    assert (-100, 94) in bot.app.deleted
    assert sleep_calls == [0.0]
    rendered = [item.to_html() for item in bot.sent + bot.rendered]
    assert all(JOIN_LINK not in item for item in rendered)


def test_nonprivate_unsolicited_vk_token_is_deleted_immediately(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT import vkcalls

    bot = make_bot(tmp_path)
    api = StubAPI()
    service = VKCallsService(tmp_path, api=api)
    bot.vkcalls = VKCallsPanel(bot, service=service)
    sleep_calls = []

    async def immediate_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    monkeypatch.setattr(vkcalls.asyncio, "sleep", immediate_sleep)
    url = "https://oauth.vk.ru/blank.html#access_token=" + TOKEN + "&expires_in=0"

    async def scenario() -> None:
        await bot.handle_message(FakeEvent(text=url, from_id=7, chat_id=-101, msg_id=95))
        await bot.idle()

    run(scenario())
    assert api.calls == []
    assert service.token == ""
    assert (-101, 95) in bot.app.deleted
    assert sleep_calls == [0.0]


def test_auth_check_route_validates_the_stored_token(tmp_path: Path) -> None:
    from BOT import i18n

    bot = make_bot(tmp_path)
    api = StubAPI()
    service = VKCallsService(tmp_path, api=api)
    service.token = TOKEN
    service.user_id = 42
    bot.vkcalls = VKCallsPanel(bot, service=service)
    run(bot.vkcalls.route(7, 0, "vk:auth:check"))
    assert [method for _, method, _ in api.calls] == ["users.get"]
    assert i18n.t("VKCALLS_TOKEN_VALID", user_id=42) in bot.rendered[-1].to_html()


def test_freeturn_home_contains_vk_create_and_token_check_controls(tmp_path: Path) -> None:
    from BOT import ftscreens, i18n

    bot = make_bot(tmp_path)
    html = ftscreens.home(bot.freeturn.view()).to_html()
    assert i18n.t("VKCALLS_BTN_CREATE") in html
    assert i18n.t("VKCALLS_BTN_CHECK_TOKEN") in html
    assert i18n.t("VKCALLS_BTN_ACTIVE") in html
    assert i18n.t("VKCALLS_BTN_AUTH") in html


def test_call_creation_cooldown_blocks_repeated_actions(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    api = StubAPI()
    bot.vkcalls = VKCallsPanel(bot, service=VKCallsService(tmp_path, api=api))
    bot.vkcalls.last_create = time.monotonic()
    run(bot.vkcalls.route(7, 0, "vk:create"))
    from BOT import i18n

    assert not api.calls
    assert i18n.t("VKCALLS_COOLDOWN") in bot.rendered[-1].to_html()


def test_vk_join_link_is_shown_with_client_details(tmp_path: Path) -> None:
    from BOT.ftscreens import client_screen
    from BOT.freeturn import FtClient

    bot = make_bot(tmp_path)
    bot.vkcalls.service._calls[CALL_ID] = bot.vkcalls.service._normalize_call({"call_id": CALL_ID, "join_link": JOIN_LINK})
    view = bot.freeturn.view()
    view.clients = [FtClient(name="alice", ip="10.0.0.2")]
    html = client_screen(view, "alice").to_html()
    assert JOIN_LINK in html
