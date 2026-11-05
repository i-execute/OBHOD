from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("obhod_setup", ROOT / "Storage" / "obhod_setup.py")


def load() -> Any:
    module = importlib.util.module_from_spec(SPEC)
    assert SPEC.loader is not None
    SPEC.loader.exec_module(module)
    return module


setup = load()


def test_the_glyphs_come_from_codepoints_not_from_the_source() -> None:
    source = (ROOT / "Storage" / "obhod_setup.py").read_text(encoding="utf-8")
    for name, code in (("tl", "256d"), ("br", "256f"), ("check", "2714"), ("dot_on", "25c6")):
        assert getattr(setup.g, name) == chr(int(code, 16))
        assert getattr(setup.g, name) not in source


def test_paint_respects_the_color_switch() -> None:
    setup.COLOR = True
    painted = setup.paint("x", "38;5;42")
    assert painted.startswith("\033[38;5;42m") and painted.endswith("\033[0m")
    setup.COLOR = False
    assert setup.paint("x", "38;5;42") == "x"
    setup.COLOR = False


def test_the_width_stays_inside_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(setup, "term_size", lambda: (200, 40))
    assert setup.width() == setup.MAX_WIDTH
    monkeypatch.setattr(setup, "term_size", lambda: (30, 20))
    assert setup.width() == setup.MIN_WIDTH


def test_clip_counts_visible_letters_only() -> None:
    setup.COLOR = True
    text = setup.paint("abcdef", "1")
    assert setup.vlen(setup.clip(text, 4)) == 4
    assert "\033[" in setup.clip(text, 10)
    setup.COLOR = False


def test_wrap_keeps_the_frame_aligned() -> None:
    setup.COLOR = True
    long_line = "word " * 40
    lines = setup.wrap(long_line, 30)
    assert all(setup.vlen(item) <= 30 for item in lines)
    assert len(lines) > 1
    setup.COLOR = False


def test_a_panel_draws_a_closed_frame(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(setup, "width", lambda: 40)
    setup.COLOR = False
    setup.panel("title", ["a", "b" * 80], 40)
    out = capsys.readouterr().out.splitlines()
    body = [line for line in out if line]
    assert body[0].startswith(setup.g.tl) and body[-1].startswith(setup.g.bl)
    assert all(setup.vlen(line) == 40 for line in body)
    setup.COLOR = False


def test_the_secrets_are_masked() -> None:
    assert setup.mask_secret("BOT_TOKEN", "123456:ABCDEF") == "123456:****"
    assert setup.mask_secret("API_HASH", "0123456789abcdef") == "0123****cdef"
    assert setup.mask_secret("API_HASH", "short") == "****"
    assert setup.mask_secret("API_HASH", "") == "missing"


def test_the_field_rules_match_the_bot() -> None:
    assert setup.Field("BOT_TOKEN", "t", True, "123456:ABC").check() == "must look like 123456:ABC-DEF"
    assert setup.Field("BOT_TOKEN", "t", True, "123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").check() == ""
    assert setup.Field("API_ID", "i", False, "0").check() == "must be a positive number"
    assert setup.Field("API_HASH", "h", True, "zz").check() == "must be 32 hex characters"
    assert setup.Field("OTHER", "o", False, "a=b").check() == "contains a forbidden character"
    assert setup.Field("ADMIN_ID", "a", False, "7").check() == ""


def test_a_dry_run_never_touches_the_disk(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env_file = tmp_path / "obhod.env"
    done = setup.main(
        [
            "--dry-run",
            "--yes",
            "--prefix=" + str(tmp_path / "prefix"),
            "--env-file=" + str(env_file),
            "--state-dir=" + str(tmp_path / "state"),
        ]
    )
    out = capsys.readouterr().out
    assert done == 0
    assert not env_file.exists()
    assert "dry run" in out
    assert setup.g.tl in out


def test_the_help_screen_lists_the_keys(capsys: pytest.CaptureFixture[str]) -> None:
    assert setup.main(["--help"]) == 0
    out = capsys.readouterr().out
    for key in ("--prefix", "--env-file", "--state-dir", "--python", "--skip-deps", "--yes", "--dry-run"):
        assert key in out


def test_a_broken_terminal_falls_back_to_one_line(capsys: pytest.CaptureFixture[str]) -> None:
    menu = setup.Menu("pick", ["one", "two"], "hint")
    assert menu.fallback(1) == 1


def test_the_menu_reads_arrows(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    menu = setup.Menu("pick", ["one", "two", "three"], "hint")
    keys = iter(["down", "down", "up", "enter"])
    monkeypatch.setattr(setup, "read_key", lambda stream: next(keys))
    monkeypatch.setattr(setup, "has_tty", lambda: True)
    monkeypatch.setattr(setup, "tty_stream", lambda: _FakeStream())
    monkeypatch.setattr(setup, "fd_is_tty", lambda fd: True)
    monkeypatch.setattr(setup, "COLOR", True)
    assert menu.ask(0) == 1


def test_the_menu_cancels_with_q(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    menu = setup.Menu("pick", ["one", "two"], "hint")
    monkeypatch.setattr(setup, "read_key", lambda stream: "q")
    monkeypatch.setattr(setup, "has_tty", lambda: True)
    monkeypatch.setattr(setup, "tty_stream", lambda: _FakeStream())
    monkeypatch.setattr(setup, "fd_is_tty", lambda fd: True)
    monkeypatch.setattr(setup, "COLOR", True)
    assert menu.ask(0) == -1


class _FakeStream:
    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return 0


def test_a_missing_sudo_does_not_crash_the_checks(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    screen = setup.Setup(["--yes"])
    ok, note = screen.check_root()
    assert ok is False
    assert "sudo" in note
    capsys.readouterr()


def test_the_installer_is_looked_up_next_to_the_script() -> None:
    installer = (ROOT / "Storage" / "obhod-install.sh").resolve()
    assert installer.is_file()
    assert (Path(setup.__file__).resolve().parent / "obhod-install.sh").resolve() == installer


def test_the_banner_and_summary_render(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(setup, "width", lambda: 60)
    screen = setup.Setup(["--prefix=/opt/obhod", "--env-file=/etc/obhod/obhod.env"])
    screen.banner()
    screen.summary_bar()
    out = capsys.readouterr().out
    assert "OBHOD" in out
    assert "/opt/obhod" in out
    assert setup.g.tl in out
