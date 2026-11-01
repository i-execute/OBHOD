from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from BOT import app as appmod
from BOT.app import Bot
from BOT.freeturn import FtGuard
from tests.fakes import FakeControl, FakeEvent, FakeGuard, make_config


class Wire:
    def __init__(self) -> None:
        self.edits = 0
        self.sent: list[str] = []
        self.fail_edit = False

    async def edit_rich(self, chat_id: int, msg_id: int, rich: Any, via: str | None = None, **kw: Any) -> None:
        if self.fail_edit:
            raise RuntimeError("message is not modified")
        self.edits += 1

    async def send_rich(self, chat_id: int, rich: Any, via: str | None = None, **kw: Any) -> None:
        self.sent.append(str(rich))

    async def delete_msg(self, chat_id: int, msg_ids: Any, **kw: Any) -> bool:
        return True


class IdleControl:
    async def firewall(self, mode: str, port: int, cidrs: str = "", proto: str = "udp", timeout: float = 0) -> FtGuard:
        return FtGuard(port=port, proto=proto, backend="ufw", mode=mode)

    async def __getattr__(self, name: str) -> Any:
        async def _any(*a: Any, **k: Any) -> dict:
            return {}

        return _any


class CountingUpdater:
    def __init__(self, delay: float = 0.0) -> None:
        self.checks = 0
        self.applied = 0
        self.delay = delay

    async def check_all(self) -> Any:
        self.checks += 1

        class Info:
            def to_dict(self) -> dict:
                return {"branch": "main", "remote": "abc1234", "release": "v1.0.0"}

        return Info()

    async def preview(self, mode: str) -> dict:
        return {"commits": 1, "files": ["BOT/app.py"], "total": 1}

    async def apply(self, mode: str) -> Any:
        self.applied += 1
        if self.delay:
            await asyncio.sleep(self.delay)

        class Result:
            ok = True
            state = "active"

            def to_dict(self) -> dict:
                return {"ok": True, "state": "active"}

        return Result()

    async def verify(self) -> dict:
        return {}


def make_wire_bot(tmp_path: Path, updater: Any = None) -> tuple[Bot, Wire]:
    bot = Bot(make_config(tmp_path), control=FakeControl(), guard=FakeGuard())
    bot.cfg.admin_id = 7
    bot.state.admin_id = 7
    wire = Wire()
    bot.app = wire
    bot.freeturn.control = IdleControl()
    bot.updater = updater or CountingUpdater()
    return bot, wire


def press(bot: Bot, data: str, msg_id: int = 5, from_id: int = 7) -> None:
    asyncio.run(bot.on_callback(FakeEvent(data=data, msg_id=msg_id, from_id=from_id)))


def test_a_repeated_callback_edits_the_screen_once(tmp_path: Path) -> None:
    bot, wire = make_wire_bot(tmp_path)
    for _ in range(20):
        press(bot, "nav:settings")
    assert wire.edits == 1
    assert wire.sent == []


def test_a_failing_edit_does_not_flood_new_messages(tmp_path: Path) -> None:
    bot, wire = make_wire_bot(tmp_path)
    wire.fail_edit = True
    for _ in range(20):
        press(bot, "nav:settings")
    assert len(wire.sent) == 1


def test_a_callback_without_a_message_id_is_not_repeated(tmp_path: Path) -> None:
    bot, wire = make_wire_bot(tmp_path)
    for _ in range(20):
        press(bot, "nav:settings", msg_id=0)
    assert len(wire.sent) == 1


def test_navigation_is_rate_limited(tmp_path: Path) -> None:
    bot, wire = make_wire_bot(tmp_path)
    answers = 0
    for index in range(appmod.NAVIGATE_LIMIT + 60):
        evt = FakeEvent(data="nav:home", msg_id=index + 1, from_id=7)
        asyncio.run(bot.on_callback(evt))
        answers += len(evt.answers)
    assert answers <= 2
    assert wire.edits <= appmod.NAVIGATE_LIMIT + 1


def test_a_stranger_is_answered_once_a_minute(tmp_path: Path) -> None:
    bot, wire = make_wire_bot(tmp_path)
    for _ in range(30):
        asyncio.run(bot.on_message(FakeEvent(text="hi", from_id=99, chat_id=99, msg_id=0)))
    assert len(wire.sent) == 1


def test_an_admin_flood_gets_one_home_screen(tmp_path: Path) -> None:
    bot, wire = make_wire_bot(tmp_path)
    for _ in range(30):
        asyncio.run(bot.on_message(FakeEvent(text="hi", from_id=7, chat_id=7, msg_id=0)))
    assert len(wire.sent) == 1


def test_two_actions_do_not_run_at_the_same_time(tmp_path: Path) -> None:
    updater = CountingUpdater(delay=0.2)
    bot, wire = make_wire_bot(tmp_path, updater=updater)
    first = FakeEvent(data="upd:commit:go", msg_id=5, from_id=7)
    second = FakeEvent(data="upd:release:go", msg_id=6, from_id=7)

    async def both() -> None:
        await asyncio.gather(bot.on_callback(first), bot.on_callback(second))

    asyncio.run(both())
    assert updater.applied == 1
    assert any(item["alert"] for item in second.answers)


def test_a_second_action_waits_for_the_first(tmp_path: Path) -> None:
    updater = CountingUpdater(delay=0.4)
    bot, wire = make_wire_bot(tmp_path, updater=updater)

    async def scenario() -> list:
        task = asyncio.create_task(bot.on_callback(FakeEvent(data="upd:commit:go", msg_id=5, from_id=7)))
        await asyncio.sleep(0.1)
        second = FakeEvent(data="ft:fw", msg_id=6, from_id=7)
        await bot.on_callback(second)
        await task
        return second.answers

    answers = asyncio.run(scenario())
    assert updater.applied == 1
    assert answers and answers[0]["alert"] is True
    assert wire.edits >= 1
    assert bot.is_busy() is False


def test_a_lock_left_behind_by_a_crash_expires(tmp_path: Path) -> None:
    bot, wire = make_wire_bot(tmp_path)
    bot.busy = True
    bot.busy_until = time.monotonic() - 1
    assert bot.is_busy() is False
    press(bot, "fb:status")
    assert bot.is_busy() is False
    assert wire.edits >= 1


def test_the_busy_notice_is_not_repeated(tmp_path: Path) -> None:
    bot, wire = make_wire_bot(tmp_path)
    bot.busy = True
    answers = 0
    for _ in range(20):
        evt = FakeEvent(data="fb:status", msg_id=5, from_id=7)
        asyncio.run(bot.on_callback(evt))
        answers += len(evt.answers)
    assert answers == 1


def test_the_render_memory_has_a_bound(tmp_path: Path) -> None:
    bot, wire = make_wire_bot(tmp_path)
    for index in range(appmod.RENDER_CACHE * 4):
        asyncio.run(bot.render(10, index, {"n": index}))
    assert len(bot.render_seen) <= appmod.RENDER_CACHE


def test_the_update_check_is_not_repeated_on_each_navigation(tmp_path: Path) -> None:
    updater = CountingUpdater()
    bot, wire = make_wire_bot(tmp_path, updater=updater)
    for index in range(6):
        press(bot, "nav:update", msg_id=index + 1)
    assert updater.checks <= 2
