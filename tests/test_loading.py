from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from BOT import i18n
from tests.fakes import make_bot


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def last(bot: Any) -> str:
    return bot.rendered[-1].to_html() if bot.rendered else ""


class Evt:
    def __init__(self, data: str) -> None:
        self.data = data
        self.from_id = 7
        self.chat_id = 7
        self.msg_id = 9
        self.outgoing = False
        self.raw = {}

    async def answer(self, text: str = "", alert: bool = False) -> None:
        self.answered = (text, alert)


def test_a_slow_route_shows_the_loading_screen_first(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_callback(Evt("xr:subs")))
    first = bot.rendered[0].to_html()
    assert i18n.t("LOADING_BODY") in first
    assert i18n.t("BUSY_TITLE") in first


def test_a_fast_navigation_does_not_flash_loading(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_callback(Evt("nav:settings")))
    for rich in bot.rendered:
        assert i18n.t("LOADING_BODY") not in rich.to_html()


def test_the_loading_screen_is_not_shown_twice(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    run(bot.on_callback(Evt("upd:show")))
    marks = [rich.to_html().count(i18n.t("LOADING_BODY")) for rich in bot.rendered]
    assert marks[0] == 1
    assert sum(marks) == 1


def test_every_heavy_prefix_is_marked_as_slow() -> None:
    bot = make_bot("/tmp/loading-prefix")
    for data in ("xr:new", "ft:apply", "dbg:scan:go", "upd:show", "fb:ban", "sshd:apply", "ssh:set"):
        assert bot.slow_action(data), data
    for data in ("nav:home", "lang:set", "set:emoji", "dbg:home", "dbg:emoji", "ft:home", "xr:home", ""):
        assert not bot.slow_action(data), data


def test_the_loading_text_exists_in_every_language() -> None:
    for language in i18n.LANGUAGES:
        for key in ("LOADING_TITLE", "LOADING_BODY", "LOADING_STEP"):
            assert i18n.raw(key, language), key


def test_a_failing_slow_route_still_ends_on_an_error_screen(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)

    async def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the route exploded")

    bot.xray.route = boom
    run(bot.on_callback(Evt("xr:subs")))
    assert i18n.t("LOADING_BODY") in bot.rendered[0].to_html()
    assert "RuntimeError" in bot.rendered[-1].to_html()


def test_the_loading_mark_list_has_no_navigation() -> None:
    from BOT import app

    for mark in app.LOADING_MARKS:
        assert mark.endswith(":")
    assert "nav:" not in app.LOADING_MARKS
    assert "lang:" not in app.LOADING_MARKS


def test_the_busy_screen_keeps_the_steps(tmp_path: Path) -> None:
    from BOT import screens

    html = screens.busy_screen("working", "en", ["one", "two"]).build()
    assert "one" in html and "two" in html
    assert "<ul>" in html


def test_the_loading_helper_renders() -> None:
    from BOT import ui

    html = ui.loading("title", "body", ["step"]).build()
    assert "title" in html and "step" in html
