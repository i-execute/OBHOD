from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import os
import sys
import tarfile
import time
from pathlib import Path

import pytest

from BOT import i18n, inline, strings, xscreens
from BOT.panel import PanelError, XrayPanel
from BOT.xray import compact_tailscale_input, parse_tailnet_input, parse_tailscale_input
from BOT.xrayrpc import XrayError as RpcError
from tests.fakes import FakeEvent, make_bot

ROOT = Path(__file__).resolve().parents[1]
XRAY_AGENT_PATH = ROOT / "Storage" / "remote" / "xray_agent.py"

USER_LINUX_SERVER_CMD = (
    "curl -fsSL https://tailscale.com/install.sh | sh && "
    "sudo tailscale up --auth-key=tskey-auth-k4QrgziQ1o11CNTRL-cC5HZT7BXLUitSqMgodtLUtfJpmyDFzVj "
    "--advertise-exit-node"
)
USER_AUTH_KEY = "tskey-auth-k4QrgziQ1o11CNTRL-cC5HZT7BXLUitSqMgodtLUtfJpmyDFzVj"

REQUIRED_TAILSCALE_URLS = (
    "https://console.tailscale.com/admin/machines/new-linux",
    "https://console.tailscale.com/admin/settings/keys",
    "https://console.tailscale.com/admin/settings/oauth",
    "https://console.tailscale.com/admin/acls/visual/tags",
    "https://console.tailscale.com/admin/dns",
    "https://console.tailscale.com/admin/acls",
    "https://tailscale.com/docs/features/tags",
    "https://tailscale.com/docs/features/ephemeral-nodes",
    "https://tailscale.com/docs/features/exit-nodes",
    "https://tailscale.com/docs/features/access-control/auth-keys#types-of-auth-keys",
    "https://tailscale.com/docs/features/access-control/auth-keys#key-expiry",
    "https://tailscale.com/docs/features/tailscale-funnel",
)


def run(coro):
    return asyncio.run(coro)


def load_agent():
    spec = importlib.util.spec_from_file_location("xray_agent_r24", XRAY_AGENT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_user_linux_server_command_parses_and_activates_subscription(tmp_path: Path) -> None:
    parsed = parse_tailscale_input(USER_LINUX_SERVER_CMD)
    assert parsed.key == USER_AUTH_KEY
    assert parsed.exit_node is True
    assert parsed.kind == "auth"
    legacy_key, legacy_exit = parse_tailnet_input(USER_LINUX_SERVER_CMD)
    assert legacy_key == USER_AUTH_KEY
    assert legacy_exit is True

    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    evt = FakeEvent(text=USER_LINUX_SERVER_CMD, from_id=7, chat_id=7, msg_id=901)
    run(bot.on_message(evt))
    assert (7, 901) in bot.app.deleted
    assert bot.xray.tunnel_key == USER_AUTH_KEY
    assert bot.state.xray.tunnel_exit_node is True
    assert bot.state.xray.tunnel_enabled is True
    assert bot.state.xray.sub_enabled is True
    html = bot.sent[-1].to_html()
    assert "https://obhod.tail1234.ts.net:" in html
    assert USER_AUTH_KEY not in html


def test_tags_oauth_hostname_and_long_inline_compaction(tmp_path: Path) -> None:
    long_cmd = (
        "curl -fsSL https://tailscale.com/install.sh | sh && "
        "sudo tailscale up --auth-key=tskey-client-k4QrgziQ1o11CNTRL-cC5HZT7BXLUitSqMgodtLUtfJpmyDFzVj"
        "?ephemeral=false&preauthorized=true "
        "--advertise-tags=tag:obhod,tag:vps-node --advertise-exit-node --hostname=obhod-eu"
    )
    assert len(long_cmd) > inline.MAX_VALUE
    cleaned = inline.clean_value("xr_tunnel_key", long_cmd, "ru")
    assert len(cleaned) <= inline.MAX_VALUE
    parsed = parse_tailscale_input(cleaned)
    assert parsed.kind == "oauth"
    assert parsed.key.endswith("?ephemeral=false&preauthorized=true")
    assert parsed.tags == "tag:obhod,tag:vps-node"
    assert parsed.exit_node is True
    assert parsed.hostname == "obhod-eu"
    assert compact_tailscale_input(long_cmd) == cleaned

    bot = make_bot(tmp_path)
    panel = XrayPanel(bot, bot.control)
    run(panel.apply_input(1, "xr_tunnel_key", "subs", cleaned))
    assert bot.state.xray.tunnel_tags == "tag:obhod,tag:vps-node"
    assert bot.state.xray.tunnel_key_expiry == "never"
    reloaded = XrayPanel(bot, bot.control)
    assert reloaded.tunnel_tags == "tag:obhod,tag:vps-node"
    assert reloaded.tunnel_exit_node is True


def test_api_access_token_is_deleted_from_chat_and_explained_clearly(tmp_path: Path) -> None:
    api_token = "tskey-api-k4QrgziQ1o11CNTRL-abcdef1234567890abcdef"
    parsed = parse_tailscale_input(api_token)
    assert parsed.key == ""
    assert parsed.kind == "api_token"

    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    with pytest.raises(PanelError) as exc_info:
        bot.xray.set_field("xr_tunnel_key", "subs", api_token)
    assert str(exc_info.value) == i18n.t("DOM_KEY_API_WRONG", "ru")

    evt = FakeEvent(text=api_token, from_id=7, chat_id=7, msg_id=777)
    run(bot.on_message(evt))
    assert (7, 777) in bot.app.deleted
    rendered = bot.sent[-1].to_html()
    assert i18n.t("DOM_KEY_API_WRONG", "ru") in rendered
    assert api_token not in rendered


def test_run_funnel_captures_interactive_approval_link_without_hanging(tmp_path: Path, monkeypatch) -> None:
    agent = load_agent()
    approval_link = "https://login.tailscale.com/f/funnel?node=nAbCdEf12345"
    fake_cli = tmp_path / "fake_ts.py"
    fake_cli.write_text(
        "import sys, time\n"
        f"sys.stdout.write('Funnel is not enabled on your tailnet.\\nTo enable, visit:\\n  {approval_link}\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    started = time.monotonic()
    rc, output = agent.run_funnel([sys.executable, str(fake_cli)], timeout=25)
    elapsed = time.monotonic() - started
    assert rc != 0
    assert approval_link in output
    assert elapsed < 4.0

    def fake_state(prefer_port=0):
        return {
            "installed": True,
            "version": "1.82.0",
            "backend": "Running",
            "hostname": "vps-1.tail9999.ts.net",
            "url": "",
            "funnel": False,
            "key_expiry": "2027-05-03T00:00:00Z",
            "expired": False,
            "have_node_key": True,
            "tags": [],
            "public_ip": "198.51.100.44",
        }

    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/tailscale")
    monkeypatch.setattr(agent, "tunnel_state", fake_state)
    monkeypatch.setattr(agent, "run", lambda argv, timeout=180, check=False: (0, ""))
    monkeypatch.setattr(agent, "run_funnel", lambda argv, timeout=30: (1, f"To enable, visit: {approval_link}"))

    with pytest.raises(agent.ScriptError) as err_info:
        agent.cmd_tunnel_up({"key": USER_AUTH_KEY, "hostname": "", "port": "24567", "https_port": "8443"}, [])
    assert err_info.value.code == "funnel_disabled"
    assert err_info.value.data["approval_url"] == approval_link
    assert err_info.value.data["public_ip"] == "198.51.100.44"

    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    panel = XrayPanel(bot, bot.control)

    async def failing_up(*args, **kwargs):
        raise RpcError("funnel disabled", "funnel_disabled", err_info.value.data)

    monkeypatch.setattr(bot.control, "tunnel_up", failing_up)
    run(panel.apply_input(1, "xr_tunnel_key", "subs", USER_LINUX_SERVER_CMD))
    assert bot.state.xray.tunnel_approval_url == approval_link
    screen_html = xscreens.subs_screen(panel.view(), panel.sub_rows()).to_html()
    assert approval_link in screen_html
    assert i18n.t("TAILSCALE_APPROVE_BTN", "ru") in screen_html


def test_single_use_key_recovery_and_dom_up_restarts_sub_server(tmp_path: Path, monkeypatch) -> None:
    agent = load_agent()
    seen: list[list[str]] = []

    def fake_run(argv, timeout=180, check=False):
        seen.append(list(argv))
        if len(argv) > 1 and argv[1] == "up" and any(x.startswith("--authkey=") for x in argv):
            return 1, "backend error: authkey already used"
        if len(argv) > 1 and argv[1] == "status":
            return 0, json.dumps(
                {
                    "BackendState": "Running",
                    "HaveNodeKey": True,
                    "Self": {
                        "DNSName": "vps-1.tail9999.ts.net.",
                        "Expired": False,
                        "Tags": ["tag:server"],
                    },
                }
            )
        if len(argv) > 1 and argv[1] == "funnel" and "status" in argv:
            return 0, "https://vps-1.tail9999.ts.net:8443 (Funnel on)"
        if len(argv) > 1 and argv[1] == "version":
            return 0, "1.82.0"
        return 0, ""

    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/tailscale")
    monkeypatch.setattr(agent, "run", fake_run)
    state, err = agent.cmd_tunnel_up(
        {"key": USER_AUTH_KEY, "hostname": "", "port": "24567", "https_port": "8443", "tags": "tag:server"},
        [],
    )
    assert err is None
    assert state["funnel"] is True
    assert state["key_expiry"] == "never"
    reconf_calls = [cmd for cmd in seen if len(cmd) > 1 and cmd[1] == "up" and not any(x.startswith("--authkey=") for x in cmd)]
    assert len(reconf_calls) == 1
    assert "--advertise-tags=tag:server" in reconf_calls[0]

    bot = make_bot(tmp_path)
    panel = XrayPanel(bot, bot.control)
    run(panel.apply_input(1, "xr_tunnel_key", "subs", USER_LINUX_SERVER_CMD))
    run(panel.tunnel_action(1, 0, "off"))
    assert bot.state.xray.sub_enabled is False
    bot.control.calls.clear()
    run(panel.tunnel_action(1, 0, "up"))
    assert bot.state.xray.tunnel_enabled is True
    assert bot.state.xray.sub_enabled is True
    call_names = [item[0] for item in bot.control.calls]
    assert "sub-install" in call_names
    assert "sub-sync" in call_names


def test_all_languages_expose_tailscale_branding_and_actual_docs_links(tmp_path: Path) -> None:
    for lang, catalog in (("en", strings.EN), ("ru", strings.RU), ("zh", strings.ZH)):
        assert catalog.DOM_TITLE == "Tailscale"
        assert "Tailnet" not in catalog.UPD_DAEMON_TAILNET
        assert "tailnet" not in catalog.DOM_KEY_INPUT.lower()
        bot = make_bot(tmp_path / lang)
        bot.state.language = lang
        panel = XrayPanel(bot, bot.control)
        initial_html = xscreens.subs_screen(panel.view(), panel.sub_rows()).to_html()
        for url in REQUIRED_TAILSCALE_URLS:
            assert url in initial_html, f"missing {url} in {lang} subs_screen"


def test_protect_system_strict_escapes_via_systemd_run_with_stdin(monkeypatch) -> None:
    agent = load_agent()
    recorded: list[tuple[list[str], bytes | None]] = []
    installed = {"done": False}

    class FakeCompleted:
        def __init__(self, returncode: int, stdout: bytes) -> None:
            self.returncode = returncode
            self.stdout = stdout

    def fake_subproc_run(argv, input=None, stdout=None, stderr=None, timeout=None, env=None, cwd=None, check=False):
        cmd = [str(item) for item in argv]
        recorded.append((cmd, input))
        if "systemd-run" in cmd[0] and "/bin/sh" in cmd and "-s" in cmd:
            assert input is not None and input.startswith(b"#!/bin/sh")
            installed["done"] = True
            return FakeCompleted(0, b"installed via systemd-run")
        if "status" in cmd and "--json" in cmd:
            body = {
                "BackendState": "Running",
                "HaveNodeKey": True,
                "Self": {"DNSName": "resolute.tail1234.ts.net.", "Expired": False},
            }
            return FakeCompleted(0, json.dumps(body).encode("utf-8"))
        if "funnel" in cmd and "status" in cmd:
            return FakeCompleted(0, b"https://resolute.tail1234.ts.net:8443")
        if "version" in cmd:
            return FakeCompleted(0, b"1.104.6")
        return FakeCompleted(0, b"")

    def fake_which(name: str):
        if name == "tailscale":
            return "/usr/bin/tailscale" if installed["done"] else None
        if name == "systemd-run":
            return "/usr/bin/systemd-run"
        if name == "systemctl":
            return "/usr/bin/systemctl"
        if name == "curl":
            return "/usr/bin/curl"
        return "/usr/bin/" + name

    monkeypatch.setattr(agent, "has_systemd", lambda: True)
    monkeypatch.setattr(agent, "sandboxed_host", lambda: True)
    monkeypatch.setattr(agent.shutil, "which", fake_which)
    monkeypatch.setattr(agent, "fetch_tailscale_installer", lambda: b"#!/bin/sh\n" + b"echo ok\n" * 40)
    monkeypatch.setattr(agent.subprocess, "run", fake_subproc_run)

    state, err = agent.cmd_tunnel_install({}, [])
    assert err is None
    assert installed["done"] is True
    assert state["installed"] is True
    assert any("systemd-run" in call[0][0] and "/bin/sh" in call[0] for call in recorded)


def test_static_tarball_fallback_installs_into_usr_local_bin_when_apt_fails(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XRAY_ROOT", str(tmp_path))
    agent = load_agent()
    agent.ROOT = str(tmp_path)
    agent.UNIT_DIR = str(tmp_path / "etc" / "systemd" / "system")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in (
            ("tailscale_1.104.6_amd64/tailscale", b"#!/bin/sh\necho 1.104.6\n"),
            ("tailscale_1.104.6_amd64/tailscaled", b"#!/bin/sh\nexit 0\n"),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(content))
    tgz_bytes = buf.getvalue()

    def fake_fetch(url: str, timeout: int = 120) -> bytes:
        if url == agent.TAILSCALE_INSTALL_URL:
            return b"#!/bin/sh\n" + b"exit 1\n" * 40
        if url == agent.TAILSCALE_STABLE_JSON_URL:
            return json.dumps(
                {
                    "Tarballs": {
                        "amd64": "tailscale_1.104.6_amd64.tgz",
                        "arm64": "tailscale_1.104.6_arm64.tgz",
                    }
                }
            ).encode("utf-8")
        if url.endswith(".tgz"):
            return tgz_bytes
        raise AssertionError("unexpected url: " + url)

    ts_bin = tmp_path / "usr" / "local" / "bin" / "tailscale"
    tsd_bin = tmp_path / "usr" / "local" / "bin" / "tailscaled"

    def fake_which(name: str):
        if name == "tailscale":
            return str(ts_bin) if ts_bin.is_file() else None
        return "/usr/bin/" + name

    def fake_run_host(argv, timeout=180, stdin_bytes=None):
        if argv[0] in ("/bin/sh", "sh"):
            return 1, "/usr/share/keyrings/tailscale-archive-keyring.gpg: Read-only file system"
        if len(argv) > 1 and argv[1] == "version":
            return 0, "1.104.6"
        if len(argv) > 1 and argv[1] == "status":
            return 0, json.dumps({"BackendState": "NeedsLogin", "HaveNodeKey": False, "Self": {}})
        return 0, ""

    monkeypatch.setattr(agent, "has_systemd", lambda: True)
    monkeypatch.setattr(agent, "sandboxed_host", lambda: True)
    monkeypatch.setattr(agent, "fetch_url_bytes", fake_fetch)
    monkeypatch.setattr(agent.shutil, "which", fake_which)
    monkeypatch.setattr(agent, "run_host", fake_run_host)

    state, err = agent.cmd_tunnel_install({}, [])
    assert err is None
    assert ts_bin.is_file() and os.access(ts_bin, os.X_OK)
    assert tsd_bin.is_file() and os.access(tsd_bin, os.X_OK)
    unit_path = tmp_path / "etc" / "systemd" / "system" / "tailscaled.service"
    assert unit_path.is_file()
    assert str(tsd_bin) in unit_path.read_text(encoding="utf-8")
    assert state["installed"] is True
    assert state["version"] == "1.104.6"

