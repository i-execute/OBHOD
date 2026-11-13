from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest

from BOT import i18n, xscreens
from BOT.app import Bot
from BOT.panel import XrayPanel
from BOT.ui import ScreenRich, use_icons
from BOT.xray import parse_tailnet_input, tailnet_expiry_label
from tests.fakes import FakeApp, FakeControl, FakeEvent, FakeGuard, make_bot, make_config

ROOT = Path(__file__).resolve().parents[1]
XRAY_AGENT_PATH = ROOT / "Storage" / "remote" / "xray_agent.py"

SAMPLE_KEY = "".join(("ts", "key-auth-", "0" * 16, "-", "1" * 32))
SAMPLE_INSTALL_CMD = (
    "curl -fsSL https://tailscale.com/install.sh | sh && "
    "sudo tailscale up --auth-key=" + SAMPLE_KEY + " --advertise-exit-node"
)


def run(coro):
    return asyncio.run(coro)


def load_agent():
    spec = importlib.util.spec_from_file_location("xray_agent_r19", XRAY_AGENT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_post_update_notification_is_rich_and_localized_in_all_languages(tmp_path: Path) -> None:
    for idx, (lang, expected_state) in enumerate(
        (
            ("en", "active"),
            ("ru", "\u0430\u043a\u0442\u0438\u0432\u043d\u0430"),
            ("zh", "\u8fd0\u884c\u4e2d"),
        )
    ):
        sub_dir = tmp_path / f"case_{idx}"
        sub_dir.mkdir(parents=True, exist_ok=True)
        bot = Bot(make_config(sub_dir), control=FakeControl(), guard=FakeGuard())
        bot.app = FakeApp()
        bot.state.language = lang
        notice = {
            "healthy": True,
            "commit": "829752d",
            "state": "active",
            "branch": "main",
            "subject": "round19 fix",
            "repo": "https://github.com/i-execute/OBHOD",
        }
        bot.update_notice = dict(notice)
        text = bot.update_notice_text()
        assert expected_state in text
        if lang != "en":
            assert "active" not in text

        bot.update_notice = dict(notice)
        html_inline = bot.update_notice_html()
        assert expected_state in html_inline
        if lang != "en":
            assert "active" not in html_inline

        bot.update_notice = dict(notice)
        use_icons(True)
        try:
            run(bot.report_update(notice))
        finally:
            use_icons(False)
        assert bot.update_notice == {}
        assert bot.app.messages == []
        assert len(bot.app.sent_rich) == 1
        card = bot.app.sent_rich[0]["rich"]
        assert isinstance(card, ScreenRich)
        rendered = card.to_html()
        assert "https://github.com/i-execute/OBHOD/commit/829752d" in rendered
        assert expected_state in rendered
        assert 'align="center"' in rendered
        assert "<tg-emoji" in rendered
        if lang != "en":
            assert ">active<" not in rendered


def test_strings_never_call_tailnet_permanent_domain() -> None:
    from BOT import strings

    forbidden = (
        "permanent domain",
        "\u043f\u043e\u0441\u0442\u043e\u044f\u043d\u043d\u044b\u0439 \u0434\u043e\u043c\u0435\u043d",
        "\u043f\u043e\u0441\u0442\u043e\u044f\u043d\u043d\u043e\u0435 https",
        "\u6c38\u4e45\u57df\u540d",
    )
    for cls in (strings.EN, strings.RU, strings.ZH):
        assert cls.DOM_TITLE == "Tailscale"
        assert "443" not in cls.DOM_NOTE2
        for name, val in vars(cls).items():
            if isinstance(val, str):
                low = val.lower()
                for bad in forbidden:
                    assert bad not in low, f"{cls.__name__}.{name} still contains {bad!r}"


def test_parse_tailnet_input_accepts_full_install_command_and_bare_key(tmp_path: Path) -> None:
    key, exit_node = parse_tailnet_input(SAMPLE_INSTALL_CMD)
    assert key == SAMPLE_KEY
    assert exit_node is True

    key2, exit_node2 = parse_tailnet_input(SAMPLE_KEY)
    assert key2 == SAMPLE_KEY
    assert exit_node2 is False

    bad_key, bad_exit = parse_tailnet_input("curl -fsSL https://example.com | sh")
    assert bad_key == ""
    assert bad_exit is False

    bot = make_bot(tmp_path)
    panel = XrayPanel(bot, bot.control)
    run(panel.apply_input(1, "xr_tunnel_key", "subs", SAMPLE_INSTALL_CMD))
    assert panel.tunnel_key == SAMPLE_KEY
    assert panel.tunnel_exit_node is True
    assert panel.key_path().read_text(encoding="utf-8") == SAMPLE_KEY
    assert SAMPLE_KEY not in json.dumps(bot.state.to_dict())
    assert bot.state.xray.tunnel_enabled is True
    assert bot.state.xray.sub_enabled is True
    assert bot.state.xray.sub_port != 443
    assert bot.state.xray.tunnel_key_expiry == "2027-05-03T00:00:00Z"


def test_admin_pasting_tailnet_command_directly_in_chat_deletes_message_and_configures(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    evt = FakeEvent(text=SAMPLE_INSTALL_CMD, from_id=7, chat_id=7, msg_id=555)
    run(bot.on_message(evt))
    assert (7, 555) in bot.app.deleted
    assert bot.xray.tunnel_key == SAMPLE_KEY
    assert bot.state.xray.tunnel_enabled is True
    assert bot.state.xray.sub_enabled is True


def test_agent_installs_via_official_script_and_tracks_key_expiry(monkeypatch) -> None:
    agent = load_agent()
    calls: list[list[str]] = []
    installed = {"ok": False}

    def fake_which(name: str):
        if name == "tailscale":
            return "/usr/bin/tailscale" if installed["ok"] else None
        if name == "curl":
            return "/usr/bin/curl"
        return "/usr/bin/" + name

    def fake_run(argv, timeout=180, check=False):
        calls.append(list(argv))
        if argv[0] == "sh":
            installed["ok"] = True
            return 0, "installed"
        if len(argv) > 1 and argv[1] == "version":
            return 0, "1.82.0\n"
        if len(argv) > 1 and argv[1] == "status":
            payload = {
                "BackendState": "Running",
                "HaveNodeKey": True,
                "Self": {
                    "DNSName": "node-1.tail9999.ts.net.",
                    "KeyExpiry": "2027-05-03T12:00:00Z",
                    "Expired": False,
                },
            }
            return 0, json.dumps(payload)
        if len(argv) > 1 and argv[1] == "funnel" and "status" in argv:
            return 0, "https://node-1.tail9999.ts.net:8443"
        return 0, ""

    monkeypatch.setattr(agent.shutil, "which", fake_which)
    monkeypatch.setattr(agent, "has_systemd", lambda: True)
    monkeypatch.setattr(agent, "fetch_tailscale_installer", lambda: b"#!/bin/sh\n" + b"echo ok\n" * 40)
    monkeypatch.setattr(agent, "run", fake_run)

    state, err = agent.cmd_tunnel_up(
        {"key": SAMPLE_INSTALL_CMD, "hostname": "", "port": "24567", "https_port": "8443", "auto_install": "1"},
        [],
    )
    assert err is None
    assert installed["ok"] is True
    assert any(cmd[0] == "sh" for cmd in calls)
    assert any(cmd[:3] == ["systemctl", "enable", "--now"] for cmd in calls)
    up_calls = [cmd for cmd in calls if len(cmd) > 1 and cmd[1] == "up"]
    assert len(up_calls) == 1
    assert "--authkey=" + SAMPLE_KEY in up_calls[0]
    assert "--advertise-exit-node" in up_calls[0]
    assert state["hostname"] == "node-1.tail9999.ts.net"
    assert state["key_expiry"] == "2027-05-03T12:00:00Z"
    assert state["expired"] is False


def test_agent_reuses_node_key_without_repassing_authkey_and_detects_expiry(monkeypatch) -> None:
    agent = load_agent()
    calls: list[list[str]] = []
    node_state = {
        "BackendState": "Running",
        "HaveNodeKey": True,
        "Self": {"DNSName": "node-1.tail9999.ts.net.", "Expired": False},
    }

    def fake_run(argv, timeout=180, check=False):
        calls.append(list(argv))
        if len(argv) > 1 and argv[1] == "status":
            return 0, json.dumps(node_state)
        if len(argv) > 1 and argv[1] == "funnel" and "status" in argv:
            return 0, "https://node-1.tail9999.ts.net:10000"
        if len(argv) > 1 and argv[1] == "version":
            return 0, "1.82.0"
        return 0, ""

    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/tailscale")
    monkeypatch.setattr(agent, "run", fake_run)

    state, err = agent.cmd_tunnel_up({"key": "", "hostname": "", "port": "24567", "https_port": "10000"}, [])
    assert err is None
    assert state["key_expiry"] == "never"
    assert [cmd for cmd in calls if len(cmd) > 1 and cmd[1] == "up"] == []

    node_state["Self"]["Expired"] = True
    with pytest.raises(agent.ScriptError) as exc_info:
        agent.cmd_tunnel_up({"key": "", "hostname": "", "port": "24567", "https_port": "10000"}, [])
    assert exc_info.value.code == "key_expired"


def test_tailnet_expiry_rendering_in_subs_and_domain_screens(tmp_path: Path) -> None:
    assert tailnet_expiry_label("never", False, "ru") == i18n.t("TAILNET_EXPIRY_NEVER", "ru")
    assert tailnet_expiry_label("2099-01-01T00:00:00Z", True, "ru") == i18n.t("TAILNET_EXPIRED", "ru")
    future = tailnet_expiry_label("2099-01-01T00:00:00Z", False, "en")
    assert "2099-01-01" in future

    bot = make_bot(tmp_path)
    panel = XrayPanel(bot, bot.control)
    bot.state.language = "ru"
    run(panel.apply_input(1, "xr_tunnel_key", "subs", SAMPLE_KEY))
    active_html = xscreens.subs_screen(panel.view(), panel.sub_rows()).to_html()
    assert "Tailscale" in active_html
    assert i18n.t("TAILNET_EXPIRY", "ru") in active_html
    assert "2027-05-03" in active_html

    bot.state.xray.tunnel_expired = True
    bot.state.xray.tunnel_enabled = False
    expired_html = xscreens.subs_screen(panel.view(), panel.sub_rows()).to_html()
    assert i18n.t("TAILNET_EXPIRED_NOTE", "ru") in expired_html
    assert i18n.t("TAILNET_EXPIRED", "ru") in expired_html
