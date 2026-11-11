from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

from BOT import app as app_mod
from BOT import icons, inline, releases, strings
from BOT.app import Bot
from BOT.ui import ScreenRich, use_icons
from tests.fakes import FakeApp, FakeControl, FakeFtControl, FakeGuard, make_bot, make_config, make_inbound
from tests.test_update import BASE, FakeShell, build, release

ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_task1_installer_renamed_to_underscore_everywhere() -> None:
    assert (ROOT / "Storage" / "obhod_install.sh").is_file()
    assert not (ROOT / "Storage" / "obhod-install.sh").exists()
    bad_name = "obhod-" + "install.sh"
    for folder in ("BOT", "Storage"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                text = path.read_text(encoding="utf-8", errors="ignore")
                assert bad_name not in text, str(path)
    assert bad_name not in (ROOT / "get.sh").read_text(encoding="utf-8")


def test_task2_emoji_pack_json_merged_into_icons_all_emoji() -> None:
    assert not (ROOT / "Storage" / "emoji-pack.json").exists()
    assert isinstance(icons.ALL_EMOJI, dict)
    assert len(icons.ALL_EMOJI) >= 400
    for name, (ident, glyph) in icons.ICONS.items():
        if name in icons.BORROWED:
            continue
        assert ident in icons.ALL_EMOJI
        assert icons.ALL_EMOJI[ident] == glyph


def test_task3_inline_query_budget_is_256_including_hash() -> None:
    inline.configure("cd" * 32)
    assert inline.TOKEN_LEN == 10
    assert inline.MAX_QUERY == 256
    assert inline.MAX_VALUE == 245
    prefix = inline.prefill("xr_remark")
    assert len(prefix) == 11
    exact_query = prefix + ("a" * 245)
    assert len(exact_query) == 256
    ok_res = inline.results_for(exact_query, "bot", {}, "en")
    assert len(ok_res) == 1
    assert inline.value_for(inline.KIND_INPUT, prefix.strip(), -1, exact_query, "en") == "a" * 245
    leading_space_query = " " + exact_query
    assert inline.value_for(inline.KIND_INPUT, prefix.strip(), -1, leading_space_query, "en") == "a" * 245
    over_value_query = prefix + ("a" * 246)
    err_res = inline.results_for(over_value_query, "bot", {}, "en")
    assert "245" in err_res[0]["description"]
    with pytest.raises(inline.InlineError):
        inline.value_for(inline.KIND_INPUT, prefix.strip(), -1, over_value_query, "en")
    over_total_query = prefix.strip() + "   " + ("a" * 244)
    assert len(over_total_query) == 257
    err_total = inline.results_for(over_total_query, "bot", {}, "en")
    assert "245" in err_total[0]["description"]
    with pytest.raises(inline.InlineError):
        inline.value_for(inline.KIND_INPUT, prefix.strip(), -1, over_total_query, "en")


def test_task4_title_cycle_uses_abxy_and_unicode_arrows() -> None:
    arrows = chr(0x2191) + chr(0x2193) + chr(0x2190) + chr(0x2192)
    assert inline.TITLE_CYCLE == ("ABXY", arrows)
    inline.configure("ef" * 32)
    prefix = inline.prefill("xr_remark")
    titles = [
        inline.results_for(prefix, "bot", {}, "en")[0]["title"],
        inline.results_for(prefix + "q", "bot", {}, "en")[0]["title"],
        inline.results_for(prefix + "qw", "bot", {}, "en")[0]["title"],
        inline.results_for(prefix + "qwe", "bot", {}, "en")[0]["title"],
        inline.results_for(prefix + "qwer", "bot", {}, "en")[0]["title"],
    ]
    assert [t[-1] for t in titles] == ["A", "B", "X", "Y", "A"]
    assert [inline.title_symbol(i, 1) for i in range(4)] == list(arrows)


def test_task5_readme_is_compact_and_keeps_install_and_clients() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert len(lines) <= 45
    assert "https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh" in text
    assert "## Install" in text
    assert "## Clients" in text
    assert "INCY-DEV/incy-platforms" in text
    assert "hackdiaz-dev/turn-proxy-android" in text
    assert "anton48/vk-turn-proxy-ios" in text


def test_task6_cumulative_update_edits_and_minimal_boot_rich_with_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(releases, "latest_tag_any", lambda repo: release())
    monkeypatch.setattr("BOT.update.shutil.which", lambda binary: f"/usr/bin/{binary}")
    answers = dict(BASE)
    answers["diff --name-only"] = (0, "requirements.txt")
    updater, _shell = build(tmp_path / "src", answers)

    bot = Bot(make_config(tmp_path / "state"), control=FakeControl(), guard=FakeGuard())
    bot.app = FakeApp()
    bot.updater = updater
    bot.freeturn.control = FakeFtControl()
    bot.state.language = "ru"
    bot.state.freeturn.configured = True
    bot.state.xray.inbounds.append(make_inbound())
    bot.update_info = {"git": True, "repo": "https://github.com/i-execute/OBHOD", "branch": "main", "commit": "1111aaa"}

    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(app_mod.asyncio, "sleep", fake_sleep)

    use_icons(True)
    try:
        asyncio.run(bot.run_update(7, 99, "commit"))
    finally:
        use_icons(False)

    edits = [item["rich"].to_html() for item in bot.app.edited_rich]
    assert len(edits) == 6
    assert sleeps == [0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
    for prev, curr in zip(edits, edits[1:]):
        assert len(curr) > len(prev)
        assert "<p>\n</p>" not in curr
        assert "</p><br><p>" not in curr

    after_answers = dict(BASE)
    after_answers["rev-parse --short HEAD"] = (0, "2222bbb")
    updater.shell = FakeShell(after_answers)

    new_bot = Bot(make_config(tmp_path / "state"), control=FakeControl(), guard=FakeGuard())
    new_bot.app = FakeApp()
    new_bot.updater = updater
    new_bot.freeturn.control = FakeFtControl()
    new_bot.state.language = "ru"
    new_bot.state.freeturn.configured = True
    new_bot.state.xray.inbounds.append(make_inbound())

    use_icons(True)
    try:
        asyncio.run(new_bot.verify_update())
    finally:
        use_icons(False)

    assert len(new_bot.app.edited_rich) == 1
    post_edit = new_bot.app.edited_rich[0]
    assert post_edit["chat_id"] == 7
    assert post_edit["msg_id"] == 99
    post_edit_html = post_edit["rich"].to_html()
    assert post_edit_html.startswith(edits[-1])
    assert strings.RU.UPD_APPLIED_FINAL.split("{")[0] in post_edit_html

    assert len(new_bot.app.sent_rich) == 1
    boot_card = new_bot.app.sent_rich[0]["rich"]
    assert isinstance(boot_card, ScreenRich)
    boot_html = boot_card.to_html()
    assert strings.RU.UPD_BOOTED_TITLE in boot_html
    assert "<details><summary>" in boot_html
    assert "Xray" in boot_html
    assert "FreeTurn" in boot_html


def test_task7_tui_uninstall_and_nuke_skip_preflight_and_protect_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    setup = _load_module("obhod_setup_r23", ROOT / "Storage" / "obhod_setup.py")
    monkeypatch.setattr(setup.os, "geteuid", lambda: 0)
    wiz = setup.Setup()
    wiz.action = "nuke"
    assert wiz.run_checks() is True
    out = capsys.readouterr().out
    assert "Preflight Checks" not in out
    wiz.action = "uninstall"
    assert wiz.run_checks() is True
    assert "Preflight Checks" not in capsys.readouterr().out

    script = ROOT / "Storage" / "obhod_install.sh"
    res = subprocess.run(
        [
            "bash",
            "-c",
            f'source "{script}" && is_caller_process 424242 && echo PROTECTED',
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "OBHOD_LIB": "1", "OBHOD_CALLER_PID": "424242"},
        timeout=15,
    )
    assert res.returncode == 0
    assert "PROTECTED" in res.stdout


def test_task8_revoke_owner_and_reinstall_freeturn_and_xray_cores(tmp_path: Path) -> None:
    agent = _load_module("ft_agent_r23", ROOT / "Storage" / "remote" / "freeturn_agent.py")
    ft_root = tmp_path / "ft"
    owner_dir = ft_root / "clients" / "owner"
    auth_dir = ft_root / "auth"
    owner_dir.mkdir(parents=True)
    auth_dir.mkdir(parents=True)
    pub = "A" * 43 + "="
    (owner_dir / "publickey").write_text(pub + "\n", encoding="utf-8")
    (owner_dir / "owner.link").write_text("freeturn://eyJ2IjoxfQ\n", encoding="utf-8")
    (ft_root / "clients.list").write_text(
        f"owner|0123456789abcdef0123456789abcdef|{pub}\nphone|fedcba9876543210fedcba9876543210|BBBB\n",
        encoding="utf-8",
    )
    (auth_dir / "clients.json").write_text(
        '["0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"]',
        encoding="utf-8",
    )
    wg_conf = tmp_path / "ft-wg0.conf"
    wg_conf.write_text(
        f"[Interface]\nPrivateKey = KKKKKKKK\n\n[Peer]\n# client: owner\nPublicKey = {pub}\nAllowedIPs = 10.13.13.2/32\n\n[Peer]\n# client: phone\nPublicKey = YYYY\nAllowedIPs = 10.13.13.3/32\n",
        encoding="utf-8",
    )
    removed = agent.revoke_owner_client(str(ft_root), str(wg_conf))
    assert removed == {"removed": True, "name": "owner"}
    assert not owner_dir.exists()
    assert "owner|" not in (ft_root / "clients.list").read_text(encoding="utf-8")
    assert "0123456789abcdef0123456789abcdef" not in (auth_dir / "clients.json").read_text(encoding="utf-8")
    assert "fedcba9876543210fedcba9876543210" in (auth_dir / "clients.json").read_text(encoding="utf-8")
    assert pub not in wg_conf.read_text(encoding="utf-8")
    assert "phone" in wg_conf.read_text(encoding="utf-8")
    assert agent.owner_allowlisted(str(ft_root)) is True

    bot = make_bot(tmp_path / "bot_state")
    bot.state.language = "ru"
    bot.freeturn.control = FakeFtControl()
    asyncio.run(bot.freeturn.route(7, 10, "ft:apply"))
    assert bot.freeturn.state.installed is True
    asyncio.run(bot.freeturn.route(7, 10, "ft:share"))
    share_kbd = str(bot.rendered[-1].to_msg())
    assert "ft:rm:owner" in share_kbd
    asyncio.run(bot.freeturn.route(7, 10, "ft:rm:owner"))
    asyncio.run(bot.freeturn.route(7, 10, "ft:rm:owner:yes"))
    revoked_html = bot.rendered[-1].to_html()
    assert strings.RU.FT_OWNER_REVOKED in revoked_html
    assert "ft:owner:issue" in str(bot.rendered[-1].to_msg())
    assert "ft:un" in str(bot.rendered[-1].to_msg())
    asyncio.run(bot.freeturn.route(7, 10, "ft:un"))
    asyncio.run(bot.freeturn.route(7, 10, "ft:un:yes"))
    assert bot.freeturn.state.installed is False
    assert "ft:apply" in str(bot.rendered[-1].to_msg())
    asyncio.run(bot.freeturn.route(7, 10, "ft:apply"))
    assert bot.freeturn.state.installed is True

    bot.state.xray.inbounds.append(make_inbound())
    asyncio.run(bot.xray.core_action(7, 11, "install", ""))
    assert bot.xray.core.get("installed") is True
    asyncio.run(bot.xray.core_action(7, 11, "purge", ""))
    asyncio.run(bot.xray.core_action(7, 11, "purge2", ""))
    assert bool(bot.xray.core.get("installed")) is False
    assert len(bot.state.xray.inbounds) == 1
    asyncio.run(bot.xray.route(7, 11, "xr:home"))
    assert "xr:core:install" in str(bot.rendered[-1].to_msg())
    asyncio.run(bot.xray.core_action(7, 11, "install", ""))
    assert bot.xray.core.get("installed") is True
