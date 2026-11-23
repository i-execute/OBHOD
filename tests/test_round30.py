from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path

from BOT import i18n, xscreens
from BOT.scan import ScanResult
from BOT.ui import MAX_BUTTONS, count_buttons
from BOT.xray import (
    XrayState,
    client_config,
    inbound_api_port,
    inbound_daemon_config,
    inbound_link,
    new_inbound,
)
from tests.fakes import make_bot


def load_agent_with_root(name: str, root: Path):
    prev = os.environ.get("XRAY_ROOT")
    os.environ["XRAY_ROOT"] = str(root)
    try:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / "Storage/remote/xray_agent.py")
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if prev is None:
            os.environ.pop("XRAY_ROOT", None)
        else:
            os.environ["XRAY_ROOT"] = prev


def sample_target(host: str = "dl.google.com", chain_bytes: int = 4200) -> ScanResult:
    return ScanResult(
        target=f"{host}:443",
        host=host,
        port=443,
        feasible=True,
        tls13=True,
        h2=True,
        x25519=True,
        pq_hybrid=True,
        pq_group="x25519mlkem768",
        cert_valid=True,
        days_left=60,
        latency_ms=11,
        server_names=[host],
        cert_chain_bytes=chain_bytes,
    )


def test_subscription_menu_singular_no_apply_no_direct_vless_links_and_always_shows_url(tmp_path: Path) -> None:
    assert i18n.t("NAV_SUBS", "ru") == "\u041f\u043e\u0434\u043f\u0438\u0441\u043a\u0430"
    assert i18n.t("XR_SUBS_TITLE", "ru") == "\u041f\u043e\u0434\u043f\u0438\u0441\u043a\u0430"
    assert i18n.t("NAV_SUBS", "en") == "Subscription"
    assert i18n.t("XR_SUBS_TITLE", "en") == "Subscription"

    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    state = XrayState()
    state.sub_address = "203.0.113.10"
    state.tunnel_host = "hotaru-club.tail2ecfd5.ts.net:8443"
    state.tunnel_enabled = True
    state.sub_enabled = True
    for idx, port in enumerate((443, 8443, 2053, 2083), start=1):
        inb = new_inbound("vless", port, "xhttp" if idx % 2 == 0 else "raw", "reality")
        inb.remark = f"node-{idx}"
        inb.enable = True
        state.add(inb)
    bot.state.xray = state

    html = xscreens.subs_screen(bot.xray.view(), bot.xray.sub_rows()).build()
    assert "\u041f\u043e\u0434\u043f\u0438\u0441\u043a\u0430" in html
    assert "\u041f\u043e\u0434\u043f\u0438\u0441\u043a\u0438" not in html
    assert "xr:subs:apply" not in html
    assert "vless://" not in html
    assert "https://hotaru-club.tail2ecfd5.ts.net:8443/" in html
    assert count_buttons(html) <= MAX_BUTTONS

    state_no_ip = XrayState()
    state_no_ip.tunnel_host = "hotaru-club.tail2ecfd5.ts.net:8443"
    state_no_ip.tunnel_enabled = True
    state_no_ip.sub_enabled = True
    inb_single = new_inbound("vless", 443, "raw", "reality")
    inb_single.enable = True
    state_no_ip.add(inb_single)
    view_no_ip = xscreens.XrayView(state=state_no_ip, lang="ru", bundle=None, address="")
    html_no_ip = xscreens.subs_screen(view_no_ip, []).build()
    assert "https://hotaru-club.tail2ecfd5.ts.net:8443/" in html_no_ip
    assert "xr:subs:apply" not in html_no_ip
    assert "vless://" not in html_no_ip


def test_xray_home_inbounds_list_and_wizard_single_start_button(tmp_path: Path, monkeypatch) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    bot.state.ssh.host = "203.0.113.50"
    bot.state.xray.sub_address = "203.0.113.50"
    bot.state.xray.tunnel_host = "hotaru-club.tail2ecfd5.ts.net:8443"
    bot.state.xray.tunnel_enabled = True

    async def fake_scan(targets, sni="", xver=0, candidates=None, concurrency=16):
        return [sample_target("dl.google.com", 4500)]

    monkeypatch.setattr("BOT.panel.scan_targets", fake_scan)

    asyncio.run(bot.xray.route(7, 10, "xr:home"))
    home_empty = bot.rendered[-1].build()
    assert "xr:new" in home_empty
    assert "xr:list" in home_empty
    assert "xr:subs" in home_empty

    asyncio.run(bot.xray.route(7, 10, "xr:new"))
    asyncio.run(bot.xray.route(7, 10, "xr:wiz:net:xhttp"))
    asyncio.run(bot.xray.route(7, 10, "xr:subscan:cand:wiz"))
    asyncio.run(bot.xray.route(7, 10, "xr:wiz:pick:0"))
    asyncio.run(bot.xray.route(7, 10, "xr:wiz:make:reality-x25519mlkem768"))

    assert len(bot.state.xray.inbounds) == 1
    inb = bot.state.xray.inbounds[0]
    assert inb.enable is False
    assert inb.dirty is False

    created_html = bot.rendered[-1].build()
    assert f"xr:instart:{inb.id}" in created_html
    assert f"xr:inapply:{inb.id}" not in created_html
    assert "xr:core:apply" not in created_html
    assert "xr:subs:apply" not in created_html
    assert "vless://" in created_html

    asyncio.run(bot.xray.route(7, 10, f"xr:instart:{inb.id}"))
    assert inb.enable is True
    assert inb.dirty is False
    assert any(call[0] == "inbound-apply" and call[1] == str(inb.id) for call in bot.xray.control.calls)
    assert any(call[0] in {"sub-install", "sub-sync"} for call in bot.xray.control.calls)

    started_html = bot.rendered[-1].build()
    assert f"xr:instop:{inb.id}" in started_html
    assert f"xr:instart:{inb.id}" not in started_html
    assert f"xr:inapply:{inb.id}" not in started_html

    asyncio.run(bot.xray.route(7, 10, "xr:home"))
    home_filled = bot.rendered[-1].build()
    assert str(inb.port) in home_filled
    assert "XHTTP" in home_filled
    assert "xr:list" in home_filled

    asyncio.run(bot.xray.route(7, 10, "xr:list"))
    list_html = bot.rendered[-1].build()
    assert f'data="xr:in:{inb.id}">{inb.remark}</tg-button>' in list_html
    assert count_buttons(list_html) <= MAX_BUTTONS


def test_running_inbound_edit_shows_apply_changes_edits_busy_restarts_and_updates_sub(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    bot.state.ssh.host = "203.0.113.50"
    bot.state.xray.sub_address = "203.0.113.50"
    bot.state.xray.tunnel_host = "hotaru-club.tail2ecfd5.ts.net:8443"
    bot.state.xray.tunnel_enabled = True
    bot.state.xray.sub_enabled = True

    inb = new_inbound("vless", 443, "raw", "reality")
    inb.remark = "main-raw"
    inb.enable = True
    inb.dirty = False
    bot.state.xray.add(inb)
    bot.state.xray.ensure_sub_all()

    asyncio.run(bot.xray.route(7, 20, f"xr:in:{inb.id}"))
    clean_card = bot.rendered[-1].build()
    assert f"xr:inapply:{inb.id}" not in clean_card
    assert f"xr:instop:{inb.id}" in clean_card
    assert "switch_inline_query_current_chat" in clean_card

    asyncio.run(bot.xray.apply_input(7, "xr_port", str(inb.id), "24443"))
    assert inb.port == 24443
    assert inb.dirty is True

    asyncio.run(bot.xray.route(7, 20, f"xr:in:{inb.id}"))
    dirty_card = bot.rendered[-1].build()
    assert f"xr:inapply:{inb.id}" in dirty_card
    assert i18n.t("XR_BTN_APPLY_CHANGES", "ru") in dirty_card

    before_renders = len(bot.rendered)
    bot.xray.control.calls.clear()
    asyncio.run(bot.xray.route(7, 20, f"xr:inapply:{inb.id}"))
    new_renders = bot.rendered[before_renders:]
    assert len(new_renders) >= 2
    busy_html = new_renders[0].build()
    final_html = new_renders[-1].build()
    assert i18n.t("BUSY_INBOUND_RESTART", "ru") in busy_html
    assert inb.dirty is False
    assert f"xr:inapply:{inb.id}" not in final_html
    assert ":24443?" in final_html

    apply_calls = [c for c in bot.xray.control.calls if c[0] == "inbound-apply"]
    sub_calls = [c for c in bot.xray.control.calls if c[0] == "sub-sync"]
    assert len(apply_calls) == 1
    assert '"port": 24443' in apply_calls[0][2]
    assert len(sub_calls) >= 1
    live_reg = bot.state.xray.sub_registry("203.0.113.50", [])
    sub_entries = live_reg.get("entries") or {}
    sub_links = []
    for entry in sub_entries.values():
        sub_links.extend(entry.get("links") or [])
    assert any(":24443?" in link for link in sub_links)


def test_xhttp_and_grpc_disable_tcp_mux_and_daemon_configs_have_unique_api_ports() -> None:
    inb_xhttp = new_inbound("vless", 443, "xhttp", "reality")
    inb_grpc = new_inbound("vless", 8443, "grpc", "reality")
    inb_raw = new_inbound("vless", 2053, "raw", "reality")
    inb_xhttp.id = 1
    inb_grpc.id = 2
    inb_raw.id = 3

    cc_xhttp = client_config(inb_xhttp, inb_xhttp.ensure_credential(), "203.0.113.10")
    cc_grpc = client_config(inb_grpc, inb_grpc.ensure_credential(), "203.0.113.10")
    cc_raw = client_config(inb_raw, inb_raw.ensure_credential(), "203.0.113.10")

    assert "mux" not in cc_xhttp["outbounds"][0]
    assert "mux" not in cc_grpc["outbounds"][0]
    assert "mux" not in cc_raw["outbounds"][0]

    cfg1 = json.loads(inbound_daemon_config(inb_xhttp))
    cfg2 = json.loads(inbound_daemon_config(inb_grpc))
    assert inbound_api_port(1) != inbound_api_port(2)
    assert cfg1["inbounds"][0]["port"] == inbound_api_port(1)
    assert cfg2["inbounds"][0]["port"] == inbound_api_port(2)
    assert cfg1["inbounds"][1]["port"] == 443
    assert cfg2["inbounds"][1]["port"] == 8443
    assert inbound_link(inb_xhttp, "203.0.113.10").startswith("vless://")


def test_agent_per_inbound_daemons_isolated_directories_and_independent_lifecycle(tmp_path: Path) -> None:
    root = tmp_path / "xroot"
    agent = load_agent_with_root("xr_agent_r30_iso", root)
    fake_core = Path(agent.CORE)
    fake_core.parent.mkdir(parents=True, exist_ok=True)
    fake_core.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
    fake_core.chmod(0o755)

    agent.has_systemd = lambda: False
    agent.test_config = lambda payload: (True, "Configuration OK")
    agent.open_ufw_ports = lambda ports: None
    agent.port_open = lambda port: True
    agent.core_version = lambda: "26.11.9"

    inb1 = new_inbound("vless", 31443, "raw", "reality")
    inb1.id = 1
    inb2 = new_inbound("vless", 32443, "xhttp", "reality")
    inb2.id = 2

    cfg1_b64 = agent.base64.b64encode(inbound_daemon_config(inb1).encode("utf-8")).decode("ascii")
    cfg2_b64 = agent.base64.b64encode(inbound_daemon_config(inb2).encode("utf-8")).decode("ascii")

    try:
        res1, _ = agent.cmd_inbound_apply({"id": "1", "remark": "raw-1", "config_b64": cfg1_b64}, [])
        res2, _ = agent.cmd_inbound_apply({"id": "2", "remark": "xhttp-2", "config_b64": cfg2_b64}, [])

        conf1 = Path(agent.inb_conf_path(1))
        conf2 = Path(agent.inb_conf_path(2))
        log1 = Path(agent.inb_log_dir(1))
        log2 = Path(agent.inb_log_dir(2))
        pid1 = int(Path(agent.inb_pid_path(1)).read_text(encoding="utf-8").strip())
        pid2 = int(Path(agent.inb_pid_path(2)).read_text(encoding="utf-8").strip())

        assert conf1.is_file() and conf2.is_file()
        assert conf1.parent != conf2.parent
        assert log1.is_dir() and log2.is_dir()
        assert log1 != log2
        assert pid1 != pid2
        assert res2["daemons"] == {"1": "active", "2": "active"}

        saved1 = json.loads(conf1.read_text(encoding="utf-8"))
        assert saved1["log"]["access"] == str(log1 / "access.log")
        assert saved1["log"]["error"] == str(log1 / "error.log")

        stopped1, _ = agent.cmd_inbound_stop({"id": "1"}, [])
        assert stopped1["daemons"]["1"] == "inactive"
        assert stopped1["daemons"]["2"] == "active"

        removed1, _ = agent.cmd_inbound_remove({"id": "1"}, [])
        assert not conf1.exists()
        assert "1" not in removed1["daemons"]
        assert removed1["daemons"]["2"] == "active"
    finally:
        for ident in (1, 2):
            try:
                agent.stop_inbound_daemon(ident)
            except Exception:
                pass
