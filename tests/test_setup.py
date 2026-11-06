from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("obhod_setup", ROOT / "Storage" / "obhod_setup.py")


def load() -> Any:
    assert SPEC is not None and SPEC.loader is not None
    module = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(module)
    return module


setup = load()


class _FakeStream:
    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return 0


def test_the_glyphs_come_from_codepoints_not_from_the_source() -> None:
    source = (ROOT / "Storage" / "obhod_setup.py").read_text(encoding="utf-8")
    for name, code in (("tl", "256d"), ("br", "256f"), ("check", "2714"), ("radio_on", "25c9"), ("rail", "2503")):
        assert getattr(setup.g, name) == chr(int(code, 16))
        assert getattr(setup.g, name) not in source


def test_paint_respects_the_color_switch() -> None:
    setup.COLOR = True
    painted = setup.paint("x", "38;5;48")
    assert painted.startswith("\033[38;5;48m") and painted.endswith("\033[0m")
    setup.COLOR = False
    assert setup.paint("x", "38;5;48") == "x"


def test_the_width_stays_inside_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(setup, "term_size", lambda: (200, 40))
    assert setup.width() == setup.MAX_WIDTH
    monkeypatch.setattr(setup, "term_size", lambda: (30, 20))
    assert setup.width() == setup.MIN_WIDTH


def test_clip_counts_visible_letters_and_preserves_ansi() -> None:
    setup.COLOR = True
    text = setup.paint("abcdef", "1")
    clipped = setup.clip(text, 4)
    assert setup.vlen(clipped) == 4
    assert "\033[1m" in clipped and clipped.endswith("\033[0m")
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
    monkeypatch.setattr(setup, "width", lambda: 44)
    setup.COLOR = False
    setup.panel("title", ["a", "b" * 80], 44)
    out = capsys.readouterr().out.splitlines()
    body = [line for line in out if line]
    assert body[0].startswith(setup.g.tl) and body[-1].startswith(setup.g.bl)
    assert all(setup.vlen(line) == 44 for line in body)


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
    assert setup.Field("PREFIX", "p", False, "relative/path").check() == "must be an absolute path starting with /"
    assert setup.Field("OTHER", "o", False, "a=b").check() == "contains a forbidden character"
    assert setup.Field("ADMIN_ID", "a", False, "7").check() == ""


def test_all_cli_flags_are_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    for flag in ("--help", "-h", "--dry-run", "--yes", "--prefix=/opt/obhod", "--skip-deps", "install"):
        code = setup.main([flag])
        out = capsys.readouterr().out
        assert code == 2
        assert "command-line flags are not supported" in out
        assert "Storage/obhod_setup.py" in out


def test_key_reader_handles_ssh_csi_ss3_split_packets_and_crlf() -> None:
    chunks = [
        b"\x1b",
        b"[",
        b"B",
        b"\x1bOA",
        b"\x1b",
        b"[1;5",
        b"C",
        b"\x1bOD",
        b"\x1b[99;2~",
        b"\x1b[B\x1b[B \r\n",
    ]
    it = iter(chunks)
    reader = setup.KeyReader(0, read_fn=lambda _n: next(it, b""), wait_fn=lambda _t: True)
    seen = [reader.read() for _ in range(9)]
    assert seen == ["down", "up", "right", "left", "noop", "down", "down", "space", "enter"]


def test_key_reader_returns_esc_when_no_followup_bytes_arrive() -> None:
    chunks = iter([b"\x1b"])
    reader = setup.KeyReader(0, read_fn=lambda _n: next(it, b"") if (it := chunks) else b"", wait_fn=lambda _t: False)
    assert reader.read() == "esc"


def test_the_menu_supports_arrows_space_and_enter(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    menu = setup.Menu("pick", ["one", "two", "three"])
    keys = iter(["down", "down", "space", "up", "enter"])
    monkeypatch.setattr(setup, "read_key", lambda stream: next(keys))
    monkeypatch.setattr(setup, "has_tty", lambda: True)
    monkeypatch.setattr(setup, "tty_stream", lambda: _FakeStream())
    monkeypatch.setattr(setup, "fd_is_tty", lambda fd: True)
    monkeypatch.setattr(setup, "COLOR", True)
    assert menu.ask(0) == 2
    setup.COLOR = False
    capsys.readouterr()


def test_check_menu_toggles_with_space_and_confirms_with_enter(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    check = setup.CheckMenu(
        "options",
        [
            setup.CheckOption("dry_run", "Dry run", "desc", False),
            setup.CheckOption("skip_deps", "Skip deps", "desc", False),
        ],
    )
    keys = iter(["space", "down", "space", "up", "space", "enter"])
    monkeypatch.setattr(setup, "read_key", lambda stream: next(keys))
    monkeypatch.setattr(setup, "has_tty", lambda: True)
    monkeypatch.setattr(setup, "tty_stream", lambda: _FakeStream())
    monkeypatch.setattr(setup, "fd_is_tty", lambda fd: True)
    monkeypatch.setattr(setup, "COLOR", True)
    picked = check.ask()
    assert picked == {"dry_run": False, "skip_deps": True}
    setup.COLOR = False
    capsys.readouterr()


def test_field_editor_edits_with_space_and_validates_on_enter(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    fields = [
        setup.Field("PREFIX", "app prefix", False, "/opt/obhod"),
        setup.Field("ADMIN_ID", "admin id", False, ""),
    ]
    editor = setup.FieldEditor("paths", fields)
    keys = iter(["down", "space", "4", "2", "enter", "enter"])
    monkeypatch.setattr(setup, "read_key", lambda stream: next(keys))
    monkeypatch.setattr(setup, "has_tty", lambda: True)
    monkeypatch.setattr(setup, "tty_stream", lambda: _FakeStream())
    monkeypatch.setattr(setup, "fd_is_tty", lambda fd: True)
    monkeypatch.setattr(setup, "COLOR", True)
    assert editor.ask() is True
    assert fields[1].value == "42"
    setup.COLOR = False
    capsys.readouterr()


def test_the_menu_cancels_with_esc(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    menu = setup.Menu("pick", ["one", "two"])
    monkeypatch.setattr(setup, "read_key", lambda stream: "esc")
    monkeypatch.setattr(setup, "has_tty", lambda: True)
    monkeypatch.setattr(setup, "tty_stream", lambda: _FakeStream())
    monkeypatch.setattr(setup, "fd_is_tty", lambda fd: True)
    monkeypatch.setattr(setup, "COLOR", True)
    assert menu.ask(0) == -1
    setup.COLOR = False
    capsys.readouterr()


def test_interactive_wizard_dry_run_never_touches_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    env_file = tmp_path / "obhod.env"
    keys = iter(
        [
            "enter",
            "space",
            "down",
            "down",
            "space",
            "enter",
            "down",
            "space",
            "ctrl_u",
            *list(str(env_file)),
            "enter",
            "enter",
            "space",
            *list("123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "enter",
            "down",
            "space",
            *list("12345"),
            "enter",
            "down",
            "space",
            *list("0123456789abcdef0123456789abcdef"),
            "enter",
            "down",
            "space",
            *list("777000"),
            "enter",
            "enter",
            "enter",
        ]
    )
    monkeypatch.setattr(setup, "read_key", lambda stream: next(keys))
    monkeypatch.setattr(setup, "has_tty", lambda: True)
    monkeypatch.setattr(setup, "tty_stream", lambda: _FakeStream())
    monkeypatch.setattr(setup, "fd_is_tty", lambda fd: True)
    monkeypatch.setattr(setup, "COLOR", True)
    done = setup.main([])
    setup.COLOR = False
    out = capsys.readouterr().out
    assert done == 0
    assert not env_file.exists()
    assert "dry run" in out
    assert setup.g.tl in out


def test_a_missing_sudo_does_not_crash_the_checks(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    screen = setup.Setup()
    ok, note = screen.check_root()
    assert ok is False
    assert "sudo" in note


def test_setup_banner_and_preflight_feature_both_xray_and_freeturn(capsys: pytest.CaptureFixture[str]) -> None:
    setup.COLOR = False
    screen = setup.Setup()
    screen.dev = True
    screen.skip_deps = True
    screen.banner()
    assert screen.run_checks() is True
    out = capsys.readouterr().out
    assert "Xray-core & FreeTurn" in out
    assert "xray-core" in out
    assert "freeturn" in out

    capsys.readouterr()


def test_the_installer_is_looked_up_next_to_the_script() -> None:
    installer = (ROOT / "Storage" / "obhod-install.sh").resolve()
    assert installer.is_file()
    assert (Path(setup.__file__).resolve().parent / "obhod-install.sh").resolve() == installer


def test_the_banner_and_summary_render(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(setup, "width", lambda: 64)
    screen = setup.Setup()
    screen.banner()
    screen.summary_bar()
    out = capsys.readouterr().out
    assert "OBHOD" in out
    assert "/opt/obhod" in out
    assert setup.g.tl in out
