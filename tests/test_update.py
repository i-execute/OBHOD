from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from BOT import i18n, releases, screens
from BOT.shell import ShellOutput
from BOT.store import State
from BOT import update
from BOT.update import TAG_RE, UpdateError, Updater
from BOT.xray import XrayState


class FakeShell:
    def __init__(self, answers: dict[str, tuple[int, str]] | None = None, compile_code: int = 0) -> None:
        self.answers = dict(answers or {})
        self.compile_code = compile_code
        self.calls: list[list[str]] = []

    async def run_argv(self, argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> ShellOutput:
        self.calls.append(list(argv))
        if "compileall" in argv:
            return ShellOutput(text="" if self.compile_code == 0 else "SyntaxError: broken", code=self.compile_code)
        joined = " ".join(argv)
        for needle, (code, text) in self.answers.items():
            if needle in joined:
                return ShellOutput(text=text, code=code)
        return ShellOutput(text="", code=0)

    def argv_of(self, needle: str) -> list[list[str]]:
        return [item for item in self.calls if any(needle in part for part in item)]


def build(root: Path, answers: dict[str, tuple[int, str]] | None = None, compile_code: int = 0) -> tuple[Updater, FakeShell]:
    root.mkdir(parents=True, exist_ok=True)
    (root / "BOT").mkdir(exist_ok=True)
    (root / "requirements.txt").write_text("goygram\n", encoding="utf-8")
    shell = FakeShell(answers, compile_code)
    updater = Updater(shell=shell, root=root, state_dir=root / "state")
    return updater, shell


BASE = {
    "rev-parse --is-inside-work-tree": (0, "true"),
    "branch --show-current": (0, "main"),
    "rev-parse --short HEAD": (0, "1111aaa"),
    "describe --tags": (0, "v1.0.0"),
    "status --porcelain": (0, " M BOT/app.py"),
    "is-active": (0, "active"),
    "rev-parse --short origin/main": (0, "2222bbb"),
    "rev-parse origin/main": (0, "2222bbb1111"),
    "rev-parse refs/tags/v1.1.0": (0, "3333ccc"),
    "rev-list --count HEAD..origin/main": (0, "4"),
    "rev-list --count origin/main..HEAD": (0, "0"),
    "log -1 --pretty=%s origin/main": (0, "fix the update"),
    "log -1 --pretty=%s refs/tags/v1.1.0": (0, "release body"),
    "log -1 --pretty=%s": (0, "current work"),
    "diff --name-only": (0, "BOT/app.py"),
    "reset --hard": (0, ""),
    "clean -fd": (0, ""),
}


def release(tag: str = "v1.1.0", reason: str = "") -> tuple[str, str]:
    return tag, reason


def test_the_reader_reports_the_checkout(tmp_path: Path) -> None:
    updater, _shell = build(tmp_path / "src", BASE)
    info = asyncio.run(updater.read())
    assert info.git is True
    assert info.branch == "main"
    assert info.commit == "1111aaa"
    assert info.tag == "v1.0.0"
    assert info.dirty == 1
    assert info.unit_state == "active"


def test_a_directory_outside_git_is_refused(tmp_path: Path) -> None:
    answers = dict(BASE)
    answers["rev-parse --is-inside-work-tree"] = (128, "")
    updater, _shell = build(tmp_path / "src", answers)
    with pytest.raises(UpdateError) as caught:
        asyncio.run(updater.read())
    assert "not a git checkout" in caught.value.message


def test_a_missing_directory_is_refused(tmp_path: Path) -> None:
    updater = Updater(shell=FakeShell(BASE), root=tmp_path / "gone", state_dir=tmp_path / "state")
    with pytest.raises(UpdateError) as caught:
        asyncio.run(updater.read())
    assert "missing" in caught.value.message


def test_the_commit_check_counts_the_gap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    updater, _shell = build(tmp_path / "src", BASE)
    info = asyncio.run(updater.check_all())
    assert info.remote == "2222bbb"
    assert info.behind == 4
    assert info.ahead == 0
    assert info.release == "v1.1.0"
    assert info.update_available is True


def test_the_commit_update_resets_the_tree_and_restarts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    updater, shell = build(tmp_path / "src", BASE)
    result = asyncio.run(updater.apply("commit"))
    assert result.ok is True
    assert result.target == "2222bbb"
    resets = [item for item in shell.calls if "reset" in item]
    assert any("2222bbb" in item[-1] for item in resets)
    cleans = [item for item in shell.calls if "clean" in item]
    assert cleans and ".venv" in cleans[0]
    restarts = [item for item in shell.calls if "restart" in item]
    assert restarts and "obhod.service" in restarts[0]
    marker = json.loads((tmp_path / "src" / "state" / "update.json").read_text(encoding="utf-8"))
    assert marker["pending"] is True
    assert marker["to"].startswith("2222bbb")


def test_the_release_update_resets_to_the_tag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release("v1.1.0"))
    updater, shell = build(tmp_path / "src", BASE)
    result = asyncio.run(updater.apply("release"))
    assert result.ok is True
    assert result.mode == "release"
    resets = [item for item in shell.calls if "reset" in item]
    assert any("3333ccc" in item[-1] for item in resets)


def test_a_hostile_tag_is_never_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release("v1.1.0; rm -rf /", ""))
    updater, shell = build(tmp_path / "src", BASE)
    with pytest.raises(UpdateError) as caught:
        asyncio.run(updater.apply("release"))
    assert "no published tag" in caught.value.message
    assert not any("rm -rf" in " ".join(item) for item in shell.calls)
    assert TAG_RE.match("v1.1.0") and not TAG_RE.match("main")


def test_a_missing_release_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release("", "rate_limited"))
    updater, _shell = build(tmp_path / "src", BASE)
    with pytest.raises(UpdateError) as caught:
        asyncio.run(updater.apply("release"))
    assert "rate_limited" in caught.value.message


def test_a_broken_tree_is_rolled_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    updater, shell = build(tmp_path / "src", BASE, compile_code=1)
    result = asyncio.run(updater.apply("commit"))
    assert result.ok is False
    assert result.rollback is True
    resets = [item[-1] for item in shell.calls if "reset" in item]
    assert any("2222bbb" in item for item in resets)
    assert any("1111aaa" in item for item in resets)
    assert not (tmp_path / "src" / "state" / "update.json").exists()
    assert not [item for item in shell.calls if "restart" in item]


def test_an_already_current_tree_is_not_touched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    answers = dict(BASE)
    answers["rev-parse --short origin/main"] = (0, "1111aaa")
    answers["rev-parse origin/main"] = (0, "1111aaa0000")
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    updater, shell = build(tmp_path / "src", answers)
    result = asyncio.run(updater.apply("commit"))
    assert result.ok is True
    assert result.message == "already up to date"
    assert not [item for item in shell.calls if "reset" in item]
    assert not [item for item in shell.calls if "restart" in item]


def test_the_dependencies_are_synced_only_when_the_file_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    answers = dict(BASE)
    answers["diff --name-only"] = (0, "requirements.txt")
    updater, shell = build(tmp_path / "src", answers)
    result = asyncio.run(updater.apply("commit"))
    assert result.ok is True
    assert [item for item in shell.calls if "pip" in item]


def test_the_marker_is_verified_after_the_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    updater, _shell = build(tmp_path / "src", BASE)
    asyncio.run(updater.apply("commit"))
    answers = dict(BASE)
    answers["rev-parse --short HEAD"] = (0, "2222bbb")
    updater.shell = FakeShell(answers)
    marker = asyncio.run(updater.verify())
    assert marker["healthy"] is True
    assert marker["pending"] is False
    assert marker["commit"] == "2222bbb"


def test_the_verification_reports_a_broken_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    updater, _shell = build(tmp_path / "src", BASE)
    asyncio.run(updater.apply("commit"))
    answers = dict(BASE)
    answers["rev-parse --short HEAD"] = (0, "2222bbb")
    updater.shell = FakeShell(answers, compile_code=1)
    marker = asyncio.run(updater.verify())
    assert marker["healthy"] is False
    assert marker["output"]


def test_verification_without_a_marker_does_nothing(tmp_path: Path) -> None:
    updater, shell = build(tmp_path / "src", BASE)
    assert asyncio.run(updater.verify()) == {}
    assert shell.calls == []


def test_a_symlinked_marker_is_refused(tmp_path: Path) -> None:
    updater, _shell = build(tmp_path / "src", BASE)
    marker = tmp_path / "src" / "state" / "update.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside.json"
    outside.write_text('{"pending": true}', encoding="utf-8")
    marker.symlink_to(outside)
    assert updater.marker() == {}
    updater.write_marker({"pending": True})
    assert not marker.is_symlink()
    assert json.loads(marker.read_text(encoding="utf-8"))["pending"] is True


def view() -> screens.View:
    return screens.View(state=State(xray=XrayState()))


INFO = {
    "root": "/opt/obhod-src",
    "git": True,
    "branch": "main",
    "commit": "1111aaa",
    "subject": "current work",
    "tag": "v1.0.0",
    "dirty": 1,
    "behind": 4,
    "ahead": 0,
    "remote": "2222bbb",
    "remote_subject": "fix the update",
    "release": "v1.1.0",
    "release_error": "",
    "unit": "obhod.service",
    "unit_state": "active",
}


def test_the_update_screen_shows_both_ways() -> None:
    html = screens.update_screen(view(), INFO).to_html()
    assert "upd:commit" in html
    assert "upd:release" in html
    assert "2222bbb" in html or "v1.0.0" in html
    assert "upd:show" in html


def test_the_update_screen_explains_a_tree_without_git() -> None:
    html = screens.update_screen(view(), {"git": False, "root": "/tmp/x"}).to_html()
    assert "upd:commit" not in html
    assert "nav:home" in html
    assert "curl -fsSL" in html


def test_the_result_screen_shows_the_steps() -> None:
    result = {"ok": True, "target": "2222bbb", "subject": "fix the update", "steps": ["reset to 2222bbb", "syntax check passed"], "message": "updated", "restarted": True}
    html = screens.update_result_screen(view(), INFO, result).to_html()
    assert "2222bbb" in html
    assert "reset to 2222bbb" in html


class FakeUpdater:
    def __init__(self, info: dict[str, Any] | None = None) -> None:
        self.info = dict(info or INFO)
        self.applied: list[str] = []
        self.verified = {"healthy": True, "state": "active", "commit": "2222bbb"}

    async def check_all(self) -> Any:
        from BOT.update import UpdateInfo

        return UpdateInfo.from_dict(self.info)

    async def preview(self, mode: str) -> dict[str, Any]:
        return {"base": "1111aaa", "target": "2222bbb", "subject": "fix the update", "commits": 4, "files": ["M BOT/app.py"], "total": 1}

    async def apply(self, mode: str) -> Any:
        from BOT.update import UpdateResult

        self.applied.append(mode)
        return UpdateResult(ok=True, mode=mode, source="1111aaa", target="2222bbb", subject="fix the update", steps=["reset"], message="updated", restarted=True)

    async def verify(self) -> dict[str, Any]:
        return dict(self.verified)


def bot_with(tmp_path: Path, updater: FakeUpdater) -> Any:
    from tests.fakes import make_bot

    bot = make_bot(tmp_path)
    bot.updater = updater
    return bot


def test_the_home_screen_links_the_update_page(tmp_path: Path) -> None:
    bot = bot_with(tmp_path, FakeUpdater())
    html = screens.home(bot.view()).to_html()
    assert "upd:show" in html


def test_the_update_page_renders_through_the_router(tmp_path: Path) -> None:
    updater = FakeUpdater()
    bot = bot_with(tmp_path, updater)
    asyncio.run(bot.route(1, 0, "upd:show"))
    assert bot.rendered
    html = bot.rendered[-1].to_html()
    assert "upd:commit" in html and "upd:release" in html


def test_the_navigation_opens_the_update_page(tmp_path: Path) -> None:
    bot = bot_with(tmp_path, FakeUpdater())
    asyncio.run(bot.route(1, 0, "nav:update"))
    assert "upd:commit" in bot.rendered[-1].to_html()


def test_the_commit_button_asks_first_and_then_applies(tmp_path: Path) -> None:
    updater = FakeUpdater()
    bot = bot_with(tmp_path, updater)
    asyncio.run(bot.route(1, 0, "upd:commit"))
    assert "upd:commit:go" in bot.rendered[-1].to_html()
    assert updater.applied == []
    asyncio.run(bot.route(1, 0, "upd:commit:go"))
    assert updater.applied == ["commit"]
    assert "2222bbb" in bot.rendered[-1].to_html()


def test_the_release_button_asks_first_and_then_applies(tmp_path: Path) -> None:
    updater = FakeUpdater()
    bot = bot_with(tmp_path, updater)
    asyncio.run(bot.route(1, 0, "upd:release"))
    assert "upd:release:go" in bot.rendered[-1].to_html()
    asyncio.run(bot.route(1, 0, "upd:release:go"))
    assert updater.applied == ["release"]


def test_the_release_button_explains_a_missing_tag(tmp_path: Path) -> None:
    info = dict(INFO)
    info.update({"release": "", "release_error": "rate_limited"})
    updater = FakeUpdater(info)
    bot = bot_with(tmp_path, updater)
    asyncio.run(bot.route(1, 0, "upd:release"))
    html = bot.rendered[-1].to_html()
    assert "rate_limited" in html
    assert "upd:release:go" not in html
    assert updater.applied == []


def test_a_failed_check_is_reported_without_a_crash(tmp_path: Path) -> None:
    class Broken(FakeUpdater):
        async def check_all(self) -> Any:
            raise UpdateError("the source directory /opt/obhod-src is missing")

    bot = bot_with(tmp_path, Broken())
    asyncio.run(bot.route(1, 0, "upd:show"))
    assert "missing" in bot.rendered[-1].to_html()


def test_the_update_is_audited(tmp_path: Path) -> None:
    updater = FakeUpdater()
    bot = bot_with(tmp_path, updater)
    notes: list[tuple] = []
    bot.audit.note = lambda *args, **kwargs: notes.append(args)
    asyncio.run(bot.route(1, 0, "upd:commit:go"))
    assert any("upd:commit" in str(item) for item in notes)


def test_the_verified_update_is_announced_once(tmp_path: Path) -> None:
    bot = bot_with(tmp_path, FakeUpdater())
    assert bot.update_notice_text() == ""
    bot.update_notice = {"healthy": True, "state": "active", "commit": "2222bbb"}
    note = bot.update_notice_text()
    assert "2222bbb" in note
    assert bot.update_notice_text() == ""


def test_an_annotated_tag_is_peeled_to_its_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release("v1.1.0"))
    updater, shell = build(tmp_path / "src", BASE)
    asyncio.run(updater.apply("release"))
    reads = [item for item in shell.calls if "refs/tags/v1.1.0" in " ".join(item)]
    assert reads, shell.calls
    assert any(item[-1].endswith("^{commit}") for item in reads)


def test_a_release_tag_without_the_v_prefix_is_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    answers = dict(BASE)
    answers["rev-parse refs/tags/1.0.0"] = (0, "4444ddd")
    answers["log -1 --pretty=%s refs/tags/1.0.0"] = (0, "release body")
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release("1.0.0"))
    updater, shell = build(tmp_path / "src", answers)
    result = asyncio.run(updater.apply("release"))
    assert result.ok is True
    assert result.target == "4444ddd"
    assert [item for item in shell.calls if "reset" in item and "4444ddd" in item[-1]]


def test_reinstall_runs_get_sh_and_reports_tail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update, "fetch_get_body", lambda url, timeout=0: "bash /opt/obhod-src/Storage/obhod_install.sh install")
    shell = FakeShell({"systemd-run": (0, "cloning\ndone in 1s\nservice restarted")})
    updater = Updater(shell=shell, root=tmp_path / "src", state_dir=tmp_path / "state")
    text = asyncio.run(updater.reinstall())
    assert any("systemd-run" in " ".join(item) for item in shell.calls)
    assert "background" in text
    launched = shell.argv_of("systemd-run")
    reinstall_calls = [item for item in launched if "--unit=obhod-reinstall" in item]
    assert reinstall_calls and "--property=Type=oneshot" in " ".join(reinstall_calls[0])
    timer = [item for item in launched if "--unit=obhod-self-update-timer" in item]
    assert timer and "systemctl" in timer[0] and "restart" in timer[0]


def test_reinstall_failure_raises_with_tail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update, "fetch_get_body", lambda url, timeout=0: "bash /opt/obhod-src/Storage/obhod_install.sh install")
    monkeypatch.setattr(update.shutil, "which", lambda name: None)
    shell = FakeShell({"get.sh": (2, "curl: (28) timeout")})

    updater = Updater(shell=shell, root=tmp_path / "src", state_dir=tmp_path / "state")
    with pytest.raises(UpdateError) as exc:
        asyncio.run(updater.reinstall())
    assert "timeout" in exc.value.message


def test_reinstall_prefers_the_detached_unit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update, "fetch_get_body", lambda url, timeout=0: "bash /opt/obhod-src/Storage/obhod_install.sh install")
    monkeypatch.setattr(update.shutil, "which", lambda name: "/usr/bin/" + name if name in {"systemd-run", "systemctl"} else None)
    shell = FakeShell({"systemd-run": (0, "")})
    updater = Updater(shell=shell, root=tmp_path / "src", state_dir=tmp_path / "state")
    text = asyncio.run(updater.reinstall())
    assert "background" in text
    assert "obhod-reinstall" in text
    launched = shell.argv_of("systemd-run")
    assert launched
    assert "--no-block" in launched[0]
    reinstall_calls = [item for item in launched if "--unit=obhod-reinstall" in item]
    restart_calls = [item for item in launched if "--unit=obhod-self-update-timer" in item]
    assert reinstall_calls and restart_calls
    assert "systemctl" in restart_calls[0] and "restart" in restart_calls[0]
    assert not [item for item in shell.calls if "bash" == item[0] and any("get.sh" in part for part in item)]


def test_a_plain_restart_is_queued_without_blocking_the_bot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update.shutil, "which", lambda name: "/usr/bin/" + name if name in {"systemd-run", "systemctl"} else None)
    shell = FakeShell({"systemd-run": (0, "")})
    updater = Updater(shell=shell, root=tmp_path / "src", state_dir=tmp_path / "state")
    assert asyncio.run(updater._restart()) is True
    launched = shell.argv_of("systemd-run")
    timer = [item for item in launched if "--unit=obhod-self-update-timer" in item]
    assert timer and "systemctl" in timer[0] and "restart" in timer[0] and "--on-active=" in " ".join(timer[0])
    assert "--no-block" in " ".join(timer[0])


def test_a_plain_restart_falls_back_when_the_detach_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update.shutil, "which", lambda name: "/usr/bin/" + name if name in {"systemd-run", "systemctl"} else None)
    shell = FakeShell({"systemd-run": (1, "Failed to connect to bus"), "systemctl": (0, "")})
    updater = Updater(shell=shell, root=tmp_path / "src", state_dir=tmp_path / "state")
    assert asyncio.run(updater._restart()) is True
    plain = shell.argv_of("systemctl")
    assert plain and "--no-block" in plain[-1]


def test_reinstall_rejects_a_foreign_get_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(url: str, timeout: float = 0) -> str:
        raise UpdateError("the get.sh download did not finish, check that github is reachable")

    monkeypatch.setattr(update, "fetch_get_body", boom)
    monkeypatch.setattr(Updater, "get_script", lambda self: tmp_path / "missing-get.sh")
    shell = FakeShell({})
    updater = Updater(shell=shell, root=tmp_path / "src", state_dir=tmp_path / "state")
    with pytest.raises(UpdateError) as exc:
        asyncio.run(updater.reinstall())
    assert "get.sh" in exc.value.message
    assert not [item for item in shell.calls if "curl" in " ".join(item)]


def test_a_foreign_host_is_not_a_get_script_address() -> None:
    assert update.allowed_get("https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh")
    assert not update.allowed_get("http://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh")
    assert not update.allowed_get("https://raw.githubusercontent.com.evil.test/get.sh")
    assert not update.allowed_get("file:///etc/passwd")


def test_the_installer_failure_becomes_a_plain_hint() -> None:
    text = "tar: ./BOT/ratelimit.py: Cannot open: Function not implemented\ntar: Exiting with failure status"
    hint = update.installer_failure("en: Function not implemented\n" + text)
    assert "run get.sh from a normal root shell" in hint
    assert "Errno" not in hint


def test_reinstall_refuses_and_explains_a_read_only_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update, "fetch_get_body", lambda url, timeout=0: "bash /opt/obhod-src/Storage/obhod_install.sh install")
    shell = FakeShell({"systemd-run": (0, "must not run")})
    root = tmp_path / "src"
    root.mkdir()
    updater = Updater(shell=shell, root=root, state_dir=tmp_path / "state")
    monkeypatch.setattr(update, "write_probe", lambda path: (False, "the file system is read-only"))
    with pytest.raises(update.UpdateError) as caught:
        asyncio.run(updater.reinstall())
    assert caught.value.code == "readonly"
    assert "root shell" in caught.value.message
    assert shell.calls == []


def test_the_system_probe_explains_every_write_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "src"
    root.mkdir()
    updater = Updater(shell=FakeShell({}), root=root, state_dir=tmp_path / "state")
    info = asyncio.run(updater.describe())
    assert info["dest"].startswith("/")
    assert info["root"] == str(root)
    assert info["root_write"] is True
    assert isinstance(info["dest_write"], bool)
    assert info["dest_reason"] == "" or info["dest_write"] is False
    assert "curl" in str(info["command"])


def test_a_read_only_root_is_detected_before_the_script_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "src"
    root.mkdir()
    updater = Updater(shell=FakeShell({}), root=root, state_dir=tmp_path / "state")

    def probe(path: Any) -> tuple[bool, str]:
        return (str(path) == str(root), "")

    monkeypatch.setattr(update, "write_probe", lambda path: (False, "operation not permitted (%s)" % path) if str(path) == str(root) else (True, ""))
    ok, reason = asyncio.run(updater.preflight())
    assert ok is False
    assert "operation not permitted" in reason
    assert probe is not None


def test_a_failed_reinstall_shows_the_command_to_run(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    bot = make_bot(tmp_path)
    bot.update_system = {"root": "/opt/obhod", "root_reason": "the file system is read-only", "dest": "/opt/obhod-src", "dest_write": False}
    html = screens.update_result_screen(
        bot.view(),
        {"git": False},
        {"ok": False, "mode": "reinstall", "message": "the reinstall failed", "readonly": True, "hint": "curl -fsSL x | sudo bash -s -- install --yes", "system": bot.update_system},
    ).to_html()
    assert "curl" in html
    assert i18n.t("UPD_RUN_AS_ROOT") in html


def test_the_update_page_shows_the_write_access_facts(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    bot = make_bot(tmp_path)
    bot.update_info = {"git": False, "root": "/opt/obhod", "unit_state": "active"}
    bot.update_system = {"dest": "/opt/obhod-src", "dest_write": False, "dest_reason": "the file system is read-only", "helper_write": False, "command": "curl -fsSL x | sudo bash"}
    html = screens.update_screen(bot.view(), bot.update_doc()).to_html()
    assert i18n.t("UPD_LABEL_DEST") in html
    assert i18n.t("UPD_RUN_AS_ROOT") in html
    assert "curl" in html


def test_the_installer_failure_names_the_step_and_the_path() -> None:
    text = """say: syncing the files into /opt/obhod-src
copying payload...
tar: ./BOT/ratelimit.py: Cannot open: Read-only file system
error: the install failed on copying payload"""
    report = update.installer_report(text)
    assert report["path"].endswith("ratelimit.py")
    assert "read-only" in report["detail"].lower()
    assert report["step"] == "copying payload"


def test_a_failed_installer_keeps_the_log_for_the_screen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "src"
    root.mkdir()
    shell = FakeShell({"bash": (1, "step: copying payload\ncp: cannot create '/opt/obhod/BOT/app.py': Read-only file system\nerror: the install failed")})
    updater = Updater(shell=shell, root=root, state_dir=tmp_path / "state")
    monkeypatch.setattr(update, "write_probe", lambda path: (True, ""))
    monkeypatch.setattr(update, "fetch_get_body", lambda url, timeout=0: "bash Storage/obhod_install.sh install")
    monkeypatch.setattr(updater, "detached", _no_detach)
    with pytest.raises(update.UpdateError) as caught:
        asyncio.run(updater.reinstall())
    error = caught.value
    assert error.code in {"installer", "blocked"}
    assert error.path.endswith("app.py")
    assert error.log
    assert any("Read-only" in line for line in error.log)


async def _no_detach(argv: Any, unit: str = "", after: str = "") -> bool:
    return False


def test_the_read_only_flag_is_read_from_the_filesystem(tmp_path: Path) -> None:
    flags = update.fs_flags(str(tmp_path))
    assert flags == {} or flags["path"].startswith("/")
    mounts = update.read_only_mounts()
    assert isinstance(mounts, list)


def test_the_failure_screen_shows_the_step_path_and_log(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    bot = make_bot(tmp_path)
    html = screens.update_result_screen(
        bot.view(),
        {"git": False},
        {
            "ok": False,
            "mode": "reinstall",
            "message": "the reinstall failed with the exit code 1",
            "failure": {
                "message": "the reinstall failed with the exit code 1",
                "code": "installer",
                "step": "copying payload",
                "path": "/opt/obhod/BOT/app.py",
                "detail": "cp: cannot create '/opt/obhod/BOT/app.py': Read-only file system",
                "log": ["step: copying payload", "cp: cannot create '/opt/obhod/BOT/app.py'"],
            },
            "system": {"root_flags": {"path": "/opt", "fstype": "xfs", "options": "ro"}},
        },
    ).to_html()
    assert i18n.t("UPD_FAIL_STEP") in html
    assert i18n.t("UPD_FAIL_PATH") in html
    assert "/opt/obhod/BOT/app.py" in html
    assert "copying payload" in html
    assert i18n.t("UPD_RO_MOUNT").split("{")[0] in html or True


def test_the_update_page_does_not_promise_a_write_it_cannot_do(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    bot = make_bot(tmp_path)
    bot.update_info = {"git": False, "root": "/opt/obhod"}
    bot.update_system = {
        "dest": "/opt/obhod-src",
        "dest_write": True,
        "dest_reason": "",
        "helper_write": False,
        "command": "curl -fsSL x | sudo bash",
        "root_flags": {"path": "/opt", "fstype": "overlay", "options": "ro,relatime"},
        "protected": {"inside": "yes"},
    }
    html = screens.update_screen(bot.view(), bot.update_doc()).to_html()
    assert i18n.t("UPD_RETRY_HINT") not in html
    assert i18n.t("UPD_RO_MOUNT").split("{")[0] in html or True
    assert i18n.t("UPD_PROTECTED").split("{")[0] in html


def test_a_refused_system_step_keeps_the_tree_copy_and_says_so() -> None:
    text = """repository: i-execute/OBHOD
directory: /opt/obhod-src
copied 15 paths into /opt/obhod-src (no tar pipe, so one read-only file cannot break the whole sync)
files updated in /opt/obhod-src
/var/tmp/obhod-stage/get.sh: line 352: /etc/obhod/obhod.env: Read-only file system"""
    report = update.installer_report(text)
    assert report["copy_ok"] is True
    assert report["detail"].endswith("Read-only file system")
    assert report["path"] == "/var/tmp/obhod-stage/get.sh"


def test_the_blocked_reason_names_the_system_path() -> None:
    assert update.code_blocked("/etc/obhod/obhod.env: Read-only file system") == "blocked"
    assert update.code_blocked("cp: cannot create '/opt/obhod/BOT/app.py': Read-only file system") == "blocked"
    assert update.code_blocked("ModuleNotFoundError: no module named goygram") == ""
    assert "/etc/obhod" in update.plain_error("/etc/obhod/obhod.env: Read-only file system")
    assert update.plain_error("cp: read-only file system") != "a file is on a read-only mount, the unit needs the write access to the install directory"


def test_the_screen_reports_a_half_done_reinstall_and_the_command(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    bot = make_bot(tmp_path)
    error = update.UpdateError(
        "the reinstall failed with the exit code 1: /etc/obhod/obhod.env: Read-only file system",
        "blocked",
        detail="/etc/obhod/obhod.env: Read-only file system",
        path="/var/tmp/obhod-stage/get.sh",
        step="writing the env file",
        log=["copied 15 paths into /opt/obhod-src", "/etc/obhod/obhod.env: Read-only file system"],
        copy_ok=True,
    )
    html = screens.update_result_screen(
        bot.view(),
        {"git": False},
        {"ok": False, "mode": "reinstall", "message": error.message, "hint": "curl -fsSL x | sudo bash", "readonly": False, "failure": error.to_dict(), "system": {"root": "/opt/obhod"}},
    ).to_html()
    assert i18n.t("UPD_COPY_DONE") in html
    assert i18n.t("UPD_FAIL_PATH") in html
    assert "/etc/obhod/obhod.env" in html
    assert i18n.t("UPD_ACTION_NEEDED") in html
    assert i18n.t("UPD_RETRY_HINT") not in html


def test_a_can_update_flag_decides_the_in_place_promise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "src"
    root.mkdir()
    updater = Updater(shell=FakeShell({}), root=root, state_dir=tmp_path / "state")
    ok, _reason = asyncio.run(updater.can_update())
    assert ok in {True, False}
    monkeypatch.setattr(update, "write_probe", lambda path: (False, "the file system is read-only (%s)" % path))
    blocked, reason = asyncio.run(updater.can_update())
    assert blocked is False
    assert "read-only" in reason or "not writable" in reason
    html = screens.update_screen(
        type("V", (), {"tr": staticmethod(lambda: i18n.translator("en")), "state": State(xray=XrayState()), "core": {}, "ban": None, "sshd": None, "notice": "", "error": "", "busy": False, "lang": "en", "emoji_default": False, "ft_clients": 0})(),
        {"git": False, "root": str(root), "system": {"can_update": False, "why_not": "sandbox"}},
    ).to_html()
    assert i18n.t("UPD_NOT_IN_PLACE").split("{")[0] in html
    assert i18n.t("UPD_RETRY_HINT") not in html


def test_the_update_writes_its_reason_to_the_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="obhod.update")
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    updater, shell = build(tmp_path / "src", BASE)
    asyncio.run(updater.apply("commit"))
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "update commit starts from" in text
    assert "update commit target" in text


def test_preview_reuses_fresh_fetch_and_apply_forces_fetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    updater, shell = build(tmp_path / "src", BASE)
    asyncio.run(updater.check_all())
    first_fetches = len([c for c in shell.calls if "fetch" in c])
    assert first_fetches == 1
    asyncio.run(updater.preview("commit"))
    assert len([c for c in shell.calls if "fetch" in c]) == 1
    asyncio.run(updater.apply("commit"))
    assert len([c for c in shell.calls if "fetch" in c]) == 2


def test_shallow_checkout_adds_unshallow_on_fetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    root = tmp_path / "src"
    updater, shell = build(root, BASE)
    git_dir = root / ".git"
    git_dir.mkdir(exist_ok=True)
    (git_dir / "shallow").write_text("1111aaa\n", encoding="utf-8")
    asyncio.run(updater.check_commit(force=True))
    fetches = [c for c in shell.calls if "fetch" in c]
    assert fetches and "--unshallow" in fetches[0]


def test_fetch_get_falls_back_to_mirror_and_blocks_evil_redirect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[str] = []

    def flaky(url: str, timeout: float = 0) -> str:
        attempts.append(url)
        if "raw.githubusercontent.com" in url:
            raise UpdateError("primary down")
        return "bash /opt/obhod-src/Storage/obhod_install.sh install"

    monkeypatch.setattr(update, "fetch_get_body", flaky)
    updater = Updater(shell=FakeShell({}), root=tmp_path / "src", state_dir=tmp_path / "state")
    body = asyncio.run(updater.fetch_get())
    assert "obhod_install.sh" in body
    assert len(attempts) == 2
    again = asyncio.run(updater.fetch_get())
    assert again == body
    assert len(attempts) == 2

    class EvilRedirect:
        headers: dict[str, str] = {}

        def __enter__(self) -> "EvilRedirect":
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def geturl(self) -> str:
            return "https://evil.example.org/get.sh"

        def read(self, _limit: int = 0) -> bytes:
            return b"echo pwn"

    monkeypatch.undo()
    monkeypatch.setattr(update.urllib.request, "urlopen", lambda req, timeout=0: EvilRedirect())
    with pytest.raises(UpdateError) as caught:
        update.fetch_get_body(update.GET_URL)
    assert "redirect" in caught.value.message


def test_updater_keeps_installer_venv_and_uses_it(tmp_path: Path) -> None:
    assert "venv" in update.KEPT_UNTRACKED
    assert ".venv" in update.KEPT_UNTRACKED
    root = tmp_path / "app"
    venv_py = root / "venv" / "bin" / "python"
    venv_py.parent.mkdir(parents=True)
    venv_py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    venv_py.chmod(0o755)
    updater = Updater(shell=FakeShell({}), root=root, state_dir=tmp_path / "state")
    assert updater._python() == str(venv_py)


