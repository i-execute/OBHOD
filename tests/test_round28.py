from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
from pathlib import Path
import threading
from typing import Any
import urllib.request

import pytest

from BOT import i18n, screens, xscreens
from BOT.app import Bot
from BOT.panel import PanelError
from BOT.scan import ScanResult, vps_subnet_cidr
from BOT.xrayrpc import CoreState, SubState, TunnelState
from tests.fakes import FakeApp, FakeGuard, make_config


def load_module(name: str, rel_path: str) -> Any:
    full = Path(__file__).resolve().parent.parent / rel_path
    spec = importlib.util.spec_from_file_location(name, full)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeXrayControl:
    def __init__(self) -> None:
        self.applied_configs: list[dict[str, Any]] = []
        self.synced_registries: list[tuple[dict[str, Any], int, str]] = []
        self.tunnel_calls: list[dict[str, Any]] = []
        self.sub_installs: list[tuple[int, str]] = []

    async def probe(self, _ssh: Any) -> CoreState:
        return CoreState(installed=True, running=True, service="active", version="26.3.27", inbounds=len(self.applied_configs[-1]["inbounds"]) if self.applied_configs else 1)

    async def apply(self, _ssh: Any, config: dict[str, Any], version: str = "") -> CoreState:
        self.applied_configs.append(config)
        return CoreState(installed=True, running=True, service="active", version=version or "26.3.27", inbounds=len(config.get("inbounds") or []))

    async def sub_install(self, _ssh: Any, port: int, domain: str) -> SubState:
        self.sub_installs.append((int(port), str(domain)))
        return SubState(installed=True, listening=True, port=int(port), service="active", entries=1)

    async def sub_sync(self, _ssh: Any, registry: dict[str, Any], port: int, domain: str = "") -> SubState:
        self.synced_registries.append((registry, int(port), str(domain)))
        return SubState(installed=True, listening=True, port=int(port), service="active", entries=len(registry.get("entries") or {}))

    async def sub_status(self, _ssh: Any, port: int) -> SubState:
        return SubState(installed=True, listening=True, port=int(port), service="active", entries=1)

    async def tunnel_up(self, _ssh: Any, key: str, hostname: str, port: int, **kwargs: Any) -> TunnelState:
        https_port = int(kwargs.get("https_port", 443) or 443)
        self.tunnel_calls.append({"key": key, "hostname": hostname, "port": int(port), "https_port": https_port})
        base = hostname.split(":", 1)[0] if hostname else "obhod-node.tail9999.ts.net"
        if not base.endswith(".ts.net"):
            base = f"{base}.tail9999.ts.net"
        url = f"https://{base}" if https_port == 443 else f"https://{base}:{https_port}"
        return TunnelState(
            installed=True,
            running=True,
            funnel=True,
            backend="Running",
            hostname=base,
            url=url,
            port=int(port),
            key_expiry="2027-01-01T00:00:00Z",
            expired=False,
            have_node_key=True,
            public_ip="185.199.108.25",
        )

    async def tunnel_status(self, _ssh: Any) -> TunnelState:
        return TunnelState(
            installed=True,
            running=True,
            funnel=True,
            backend="Running",
            hostname="obhod-node.tail9999.ts.net",
            url="https://obhod-node.tail9999.ts.net:8443",
            port=29123,
            key_expiry="2027-01-01T00:00:00Z",
            expired=False,
            have_node_key=True,
            public_ip="185.199.108.25",
        )


def make_bot(tmp_path: Path, control: FakeXrayControl | None = None) -> tuple[Bot, FakeXrayControl]:
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    ctl = control or FakeXrayControl()
    bot = Bot(make_config(tmp_path), control=ctl, guard=FakeGuard())
    bot.rendered = []
    bot.sent = []
    bot.app = FakeApp()

    async def fake_render(_chat_id: int, _msg_id: int, rich: Any) -> None:
        bot.rendered.append(rich)

    async def fake_send(_chat_id: int, rich: Any) -> int:
        bot.sent.append(rich)
        return len(bot.sent)

    async def fake_guard_port(port: int) -> tuple[int, str]:
        return port, ""

    async def fake_free_of_strangers() -> tuple[set[int], dict[int, str]]:
        return set(), {}

    bot.render = fake_render
    bot.send = fake_send
    bot.xray.guard_port = fake_guard_port
    bot.xray.free_of_strangers = fake_free_of_strangers
    bot.state.language = "ru"
    bot.state.xray.sub_address = "185.199.108.25"
    bot.xray.core = {"installed": True, "running": True, "service": "active", "version": "26.3.27", "inbounds": 0}
    return bot, ctl


def test_no_clients_anywhere_and_all_inbounds_hosted_on_single_sub(tmp_path: Path, monkeypatch: Any) -> None:
    bot, ctl = make_bot(tmp_path)
    bot.state.xray.tunnel_host = "obhod-node.tail9999.ts.net:8443"
    bot.state.xray.tunnel_enabled = True
    bot.state.xray.sub_enabled = True
    bot.state.xray.sub_port = 29123

    asyncio.run(bot.xray.create_quick(1, 0, "reality", "raw", "443"))
    asyncio.run(bot.xray.create_quick(1, 0, "reality", "xhttp", "8443"))
    asyncio.run(bot.xray.create_quick(1, 0, "reality", "grpc", "2053"))

    assert len(bot.state.xray.inbounds) == 3
    for inb in bot.state.xray.inbounds:
        assert len(inb.clients) == 1
        assert inb.clients[0].email == ""
        link = inb.inbound_link("185.199.108.25")
        assert link.startswith("vless://")
        assert link.endswith(f"#{inb.remark}")
        assert "-owner" not in link

    cfg = json.loads(bot.state.xray.to_config())
    vless_inbounds = [item for item in cfg["inbounds"] if item.get("protocol") == "vless"]
    assert len(vless_inbounds) == 3
    for raw_inb in vless_inbounds:
        clients = raw_inb["settings"]["clients"]
        assert len(clients) == 1
        assert "email" not in clients[0]

    bot.xray.core["inbounds"] = 3
    home_html = screens.home(bot.view()).to_html()
    xhome_html = xscreens.home(bot.xray.view()).to_html()
    inb_html = xscreens.inbound_screen(bot.xray.view(), bot.state.xray.inbounds[0]).to_html()
    subs_html = xscreens.subs_screen(bot.xray.view(), bot.xray.sub_rows()).to_html()

    for html in (home_html, xhome_html, inb_html, subs_html):
        for forbidden in ("xr:cladd", "xr:cl:", "xr:cldel", "xr:clflow", "xr:cllimit", "xr:subrot", i18n.t("HOME_LABEL_CLIENTS", "ru")):
            assert forbidden not in html
    assert "vless://" in inb_html

    rows = bot.xray.sub_rows()
    assert len(rows) == 1
    _label, sub_path, sub_url = rows[0]
    assert sub_url == f"https://obhod-node.tail9999.ts.net:8443{sub_path}"

    registry = bot.state.xray.sub_registry("185.199.108.25", [])
    assert len(registry["entries"]) == 1
    reg_file = tmp_path / "subscriptions.json"
    reg_file.write_text(json.dumps(registry), encoding="utf-8")

    sub_srv = load_module("sub_srv_r28", "Storage/remote/sub_server.py")
    monkeypatch.setattr(sub_srv, "REGISTRY", str(reg_file))
    sub_srv.CACHE["key"] = None
    sub_srv.CACHE["body"] = None

    srv = sub_srv.Server(("127.0.0.1", 0), sub_srv.Handler)
    port_num = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        assert not sub_path.endswith("/json")
        with urllib.request.urlopen(f"http://127.0.0.1:{port_num}{sub_path}", timeout=5) as resp_b64:
            assert resp_b64.status == 200
            decoded_lines = base64.b64decode(resp_b64.read()).decode("utf-8").strip().splitlines()
            assert len(decoded_lines) == 3
            assert all(line.startswith("vless://") for line in decoded_lines)

        with urllib.request.urlopen(f"http://127.0.0.1:{port_num}{sub_path}/json", timeout=5) as resp_json:
            assert resp_json.status == 200
            parsed_json = json.loads(resp_json.read().decode("utf-8"))
            assert isinstance(parsed_json, list)
            assert len(parsed_json) == 3
    finally:
        srv.shutdown()
        srv.server_close()
    assert len(ctl.synced_registries) >= 3


def test_subscription_url_never_changes_across_deletes_rotations_and_vps_reboot(tmp_path: Path) -> None:
    ctl = FakeXrayControl()
    bot, _ = make_bot(tmp_path, ctl)
    bot.state.xray.tunnel_host = "obhod-node.tail9999.ts.net:8443"
    bot.state.xray.tunnel_enabled = True
    bot.state.xray.sub_enabled = True
    bot.state.xray.sub_port = 29123

    asyncio.run(bot.xray.create_quick(1, 0, "reality", "raw", "443"))
    first_rows = bot.xray.sub_rows()
    assert len(first_rows) == 1
    _, first_path, first_url = first_rows[0]

    inb_id = str(bot.state.xray.inbounds[0].id)
    asyncio.run(bot.xray.delete_inbound(1, 0, inb_id))
    assert bot.state.xray.inbounds == []
    assert bot.xray.sub_rows()[0][2] == first_url

    asyncio.run(bot.xray.subs_action(1, 0, "rotate"))
    assert bot.xray.sub_rows()[0][2] == first_url

    asyncio.run(bot.xray.create_quick(1, 0, "reality", "xhttp", "8443"))
    assert bot.xray.sub_rows()[0][2] == first_url
    bot.save()

    ctl_after_reboot = FakeXrayControl()
    rebooted_bot, _ = make_bot(tmp_path, ctl_after_reboot)
    asyncio.run(rebooted_bot.ensure_cores_warm())

    assert rebooted_bot.xray.sub_rows()[0][1] == first_path
    assert rebooted_bot.xray.sub_rows()[0][2] == first_url
    assert rebooted_bot.state.xray.sub_port == 29123
    assert rebooted_bot.state.xray.tunnel_host == "obhod-node.tail9999.ts.net:8443"
    assert len(ctl_after_reboot.tunnel_calls) == 1
    assert ctl_after_reboot.tunnel_calls[0]["port"] == 29123
    assert ctl_after_reboot.tunnel_calls[0]["https_port"] == 8443
    assert len(ctl_after_reboot.synced_registries) == 1
    assert ctl_after_reboot.synced_registries[0][1] == 29123

    xr_agent = load_module("xr_agent_r28", "Storage/remote/xray_agent.py")
    unit_dir = tmp_path / "systemd"
    xr_agent.UNIT_DIR = str(unit_dir)
    xr_agent.STATE = str(tmp_path / "state")
    Path(xr_agent.STATE).mkdir(parents=True, exist_ok=True)
    unit_path = xr_agent.write_sub_unit("/opt/obhod/sub_server.py", str(tmp_path / "subscriptions.json"), 29123)
    unit_body = Path(unit_path).read_text(encoding="utf-8")
    assert "After=network.target network-online.target" in unit_body
    assert "Wants=network-online.target" in unit_body
    assert "WantedBy=multi-user.target" in unit_body
    assert "OBHOD_SUB_PORT=29123" in unit_body


def test_only_reality_inbounds_allowed_in_ui_and_panel(tmp_path: Path) -> None:
    bot, _ = make_bot(tmp_path)

    new_html = xscreens.new_menu(bot.xray.view()).to_html()
    assert "xr:wiz:net:raw" in new_html
    assert "xr:wiz:net:xhttp" in new_html
    assert "xr:wiz:net:grpc" in new_html
    assert ":none" not in new_html
    assert ":tls" not in new_html

    custom_html = xscreens.custom_menu(bot.xray.view()).to_html()
    assert "xr:cyc:network" in custom_html
    assert "xr:cyc:security" not in custom_html

    for bad_sec in ("none", "tls", "xtls"):
        for net in ("raw", "xhttp", "grpc"):
            with pytest.raises(PanelError):
                asyncio.run(bot.xray.create_quick(1, 0, bad_sec, net))
            bot.xray.draft = {"network": net, "security": bad_sec, "port": "9443"}
            with pytest.raises(PanelError):
                asyncio.run(bot.xray.create_custom(1, 0))


def test_reality_subnet_scanner_in_creation_and_inbound_menus(tmp_path: Path, monkeypatch: Any) -> None:
    bot, _ = make_bot(tmp_path)
    assert vps_subnet_cidr("185.199.108.25") == "185.199.108.0/24"
    assert vps_subnet_cidr("10.0.0.5") == ""

    fake_hits = [
        ScanResult(
            target="185.199.108.77:443",
            host="185.199.108.77",
            ip="185.199.108.77",
            port=443,
            feasible=True,
            tls13=True,
            h2=True,
            alpn="h2",
            x25519=True,
            cert_valid=True,
            cert_chain_valid=True,
            server_names=["edge-cdn.example.org"],
            latency_ms=4,
        ),
        ScanResult(
            target="185.199.108.88:443",
            host="185.199.108.88",
            ip="185.199.108.88",
            port=443,
            feasible=False,
            tls13=False,
            reason="tls 1.2 only",
        ),
    ]
    scanned_batches: list[tuple[list[str], int]] = []

    async def fake_scan_targets(targets: list[str], **kwargs: Any) -> list[ScanResult]:
        scanned_batches.append((list(targets), int(kwargs.get("concurrency", 0))))
        return list(fake_hits)

    monkeypatch.setattr("BOT.panel.scan_targets", fake_scan_targets)

    asyncio.run(bot.xray.route(1, 0, "xr:subscan:new"))
    open_html = bot.rendered[-1].to_html()
    assert "xr:subscan:vps:new" in open_html
    assert "185.199.108.0/24" in open_html

    asyncio.run(bot.xray.route(1, 0, "xr:subscan:vps:new"))
    assert scanned_batches[-1] == (["185.199.108.0/24"], 48)
    scan_html = bot.rendered[-1].to_html()
    assert "xr:subscan:pick:new:0" in scan_html
    assert "xr:subscan:pick:new:1" not in scan_html

    asyncio.run(bot.xray.route(1, 0, "xr:subscan:pick:new:0"))
    picked_menu_html = bot.rendered[-1].to_html()
    assert "185.199.108.77:443" in picked_menu_html
    assert "edge-cdn.example.org" in picked_menu_html

    asyncio.run(bot.xray.create_quick(1, 0, "reality", "xhttp", "443"))
    created = bot.state.xray.inbounds[0]
    assert created.dest == "185.199.108.77:443"
    assert created.sni == "edge-cdn.example.org"

    second_hit = ScanResult(
        target="151.101.1.55:443",
        host="151.101.1.55",
        ip="151.101.1.55",
        port=443,
        feasible=True,
        tls13=True,
        h2=True,
        alpn="h2",
        x25519=True,
        cert_valid=True,
        cert_chain_valid=True,
        server_names=["mirror.example.net"],
        latency_ms=7,
    )
    fake_hits[:] = [second_hit]
    asyncio.run(bot.xray.apply_input(1, "xr_subnet_cidr", str(created.id), "151.101.1.0/24"))
    assert scanned_batches[-1] == (["151.101.1.0/24"], 48)
    cidr_html = bot.sent[-1].to_html()
    assert f"xr:subscan:pick:{created.id}:0" in cidr_html

    asyncio.run(bot.xray.route(1, 0, f"xr:subscan:pick:{created.id}:0"))
    assert created.dest == "151.101.1.55:443"
    assert created.sni == "mirror.example.net"
