from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from BOT import app as app_mod
from BOT import releases, strings
from BOT.app import Bot
from BOT.ui import ScreenRich, use_icons
from BOT.update import Updater
from tests.fakes import FakeApp, FakeControl, FakeFtControl, FakeGuard, make_bot, make_config, make_inbound
from tests.test_update import BASE, FakeShell, build, release


def test_default_step_delay_is_half_second(tmp_path: Path) -> None:
    bot = Bot(make_config(tmp_path), control=FakeControl(), guard=FakeGuard())
    assert bot.update_step_delay == pytest.approx(0.5)


def test_detached_timer_restart_does_not_invoke_empty_systemd_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    class StrictSystemdShell(FakeShell):
        async def run_argv(self, argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> Any:
            calls.append(list(argv))
            if argv and argv[0] == "systemd-run":
                if "--property=Type=oneshot" in argv and argv[-1].startswith("--property="):
                    from BOT.shell import ShellOutput

                    return ShellOutput(text="missing command", code=1)
            return await super().run_argv(argv, stdin=stdin, timeout=timeout)

    monkeypatch.setattr("BOT.update.shutil.which", lambda binary: f"/usr/bin/{binary}")
    shell = StrictSystemdShell(dict(BASE))
    root = tmp_path / "src"
    (root / ".git").mkdir(parents=True)
    updater = Updater(shell=shell, root=root, state_dir=tmp_path / "state")
    restarted = asyncio.run(updater._restart())
    assert restarted is True
    systemd_calls = [item for item in calls if item and item[0] == "systemd-run"]
    assert len(systemd_calls) == 1
    assert "restart" in systemd_calls[0]
    assert "obhod.service" in systemd_calls[0]


def test_live_update_streams_progressive_steps_with_half_second_cadence_and_pre_restart_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    monkeypatch.setattr("BOT.update.shutil.which", lambda binary: f"/usr/bin/{binary}")
    answers = dict(BASE)
    answers["diff --name-only"] = (0, "requirements.txt")
    updater, shell = build(tmp_path / "src", answers)

    bot = Bot(make_config(tmp_path / "state"), control=FakeControl(), guard=FakeGuard())
    bot.app = FakeApp()
    bot.updater = updater
    bot.state.language = "ru"
    bot.update_info = {"git": True, "repo": "https://github.com/i-execute/OBHOD", "branch": "main", "commit": "1111aaa"}

    sleeps: list[float] = []
    events: list[str] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    orig_edit = bot.app.edit_rich

    async def spy_edit(chat_id: int, message_id: int, rich: Any, via: str = "mt") -> None:
        html = rich.to_html() if hasattr(rich, "to_html") else str(rich)
        events.append(f"edit:{html}")
        await orig_edit(chat_id, message_id, rich, via=via)

    orig_run = shell.run_argv

    async def spy_run(argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> Any:
        if "restart" in argv:
            events.append("systemctl_restart")
        return await orig_run(argv, stdin=stdin, timeout=timeout)

    monkeypatch.setattr(app_mod.asyncio, "sleep", fake_sleep)
    bot.app.edit_rich = spy_edit
    shell.run_argv = spy_run

    use_icons(True)
    try:
        asyncio.run(bot.run_update(7, 42, "commit"))
    finally:
        use_icons(False)

    edits = [item["rich"].to_html() for item in bot.app.edited_rich]
    assert len(edits) == 6
    assert sleeps == [0.5, 0.5, 0.5, 0.5, 0.5]

    assert strings.RU.UPD_STAGE_FETCH_RUN in edits[0]
    assert strings.RU.UPD_STAGE_COMPARE_RUN in edits[1]
    assert strings.RU.UPD_STAGE_FETCH_DONE in edits[1]
    assert strings.RU.UPD_STAGE_APPLY_RUN in edits[2]
    assert strings.RU.UPD_STAGE_VERIFY_RUN in edits[3]
    assert strings.RU.UPD_STAGE_DEPS_RUN in edits[4]

    final_pre_restart = edits[-1]
    assert strings.RU.UPD_RESTARTING_TITLE in final_pre_restart
    assert strings.RU.UPD_DONE_TITLE not in final_pre_restart
    assert "2222bbb" in final_pre_restart

    raw_english = (
        "fetch from origin",
        "reset to ",
        "untracked files removed",
        "syntax check passed",
        "restart skipped",
    )
    for html in edits:
        for raw in raw_english:
            assert raw not in html

    handoff_index = next(idx for idx, tag in enumerate(events) if strings.RU.UPD_RESTARTING_TITLE in tag)
    restart_index = events.index("systemctl_restart")
    assert handoff_index < restart_index
    assert bot.app.sent_rich == []


def test_already_current_commit_renders_up_to_date_without_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    answers = dict(BASE)
    answers["rev-parse --short origin/main"] = (0, "1111aaa")
    answers["rev-parse origin/main"] = (0, "1111aaa0000")
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    updater, shell = build(tmp_path / "src", answers)

    bot = make_bot(tmp_path / "state")
    bot.updater = updater
    bot.state.language = "ru"
    bot.update_info = {"git": True, "repo": "https://github.com/i-execute/OBHOD", "branch": "main", "commit": "1111aaa"}

    asyncio.run(bot.run_update(7, 55, "commit"))
    assert len(bot.rendered) == 3
    final_html = bot.rendered[-1].to_html()
    assert strings.RU.UPD_ALREADY_TITLE in final_html
    assert strings.RU.UPD_RESTARTING_TITLE not in final_html
    assert not [item for item in shell.calls if "restart" in item]


def test_post_restart_verify_probes_daemons_and_sends_distinct_startup_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    monkeypatch.setattr("BOT.update.shutil.which", lambda binary: f"/usr/bin/{binary}")

    for lang, cls in (("en", strings.EN), ("ru", strings.RU), ("zh", strings.ZH)):
        sub_dir = tmp_path / lang
        updater, _shell = build(sub_dir / "src", BASE)
        asyncio.run(updater.apply("commit"))
        after_answers = dict(BASE)
        after_answers["rev-parse --short HEAD"] = (0, "2222bbb")
        updater.shell = FakeShell(after_answers)

        bot = Bot(make_config(sub_dir / "state"), control=FakeControl(), guard=FakeGuard())
        bot.app = FakeApp()
        bot.updater = updater
        bot.freeturn.control = FakeFtControl()
        bot.state.language = lang
        bot.state.freeturn.configured = True
        bot.state.xray.inbounds.append(make_inbound())
        bot.state.xray.sub_enabled = True
        bot.state.xray.sub_port = 8443
        bot.state.xray.tunnel_enabled = True
        bot.state.xray.tunnel_host = "edge.ts.net"

        use_icons(True)
        try:
            asyncio.run(bot.verify_update())
        finally:
            use_icons(False)

        assert len(bot.app.sent_rich) == 1
        card = bot.app.sent_rich[0]["rich"]
        assert isinstance(card, ScreenRich)
        html = card.to_html()
        assert cls.UPD_BOOTED_TITLE in html
        assert cls.UPD_DONE_TITLE not in html
        assert "2222bbb" in html
        assert "(6/6)" in html
        assert cls.UPD_DAEMON_BOT in html
        assert cls.UPD_DAEMON_XRAY in html
        assert cls.UPD_DAEMON_FREETURN in html
        assert cls.UPD_DAEMON_SUB in html
        assert cls.UPD_DAEMON_TAILNET in html
        assert cls.UPD_DAEMON_FAIL2BAN in html
        assert cls.SVC_STATE_ACTIVE in html
        assert "<tg-emoji" in html
        if lang != "en":
            assert ">active<" not in html


def test_post_restart_report_flags_stopped_daemon(tmp_path: Path) -> None:
    bot = Bot(make_config(tmp_path / "state"), control=FakeControl(), guard=FakeGuard())
    bot.app = FakeApp()
    bot.freeturn.control = FakeFtControl()
    bot.xray.control.core["service"] = "inactive"
    bot.state.language = "ru"
    bot.state.xray.inbounds.append(make_inbound())

    notice = {
        "healthy": True,
        "state": "active",
        "commit": "2222bbb",
        "branch": "main",
        "subject": "fix daemon report",
        "repo": "https://github.com/i-execute/OBHOD",
    }
    use_icons(True)
    try:
        asyncio.run(bot.report_update(notice))
    finally:
        use_icons(False)

    assert len(bot.app.sent_rich) == 1
    html = bot.app.sent_rich[0]["rich"].to_html()
    assert strings.RU.UPD_BOOTED_TITLE in html
    assert strings.RU.SVC_STATE_INACTIVE in html
    assert "(3/4" in html
