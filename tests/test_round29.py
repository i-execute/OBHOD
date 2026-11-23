from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
from pathlib import Path
from typing import Any

from BOT import antiddos, app as appmod, i18n, scan, ui, xscreens
from BOT.xray import DEFAULT_DEST, DEFAULT_SNI, VlessEncryption, XrayState, new_inbound
from tests.fakes import FakeApp, FakeControl, FakeGuard, make_config

_ORIG_PUBLIC_ADDRESS = appmod.public_address


def load_module(name: str, rel_path: str):
    path = Path(__file__).resolve().parents[1] / rel_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_bot(tmp_path: Path, control: FakeControl | None = None):
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    ctl = control or FakeControl()
    bot = appmod.Bot(make_config(tmp_path), control=ctl, guard=FakeGuard())
    bot.app = FakeApp()
    bot.state.xray.sub_address = "203.0.113.10"
    sent: list[Any] = []

    async def fake_send(chat_id: int, rich: Any) -> int:
        sent.append(rich)
        return len(sent)

    async def fake_edit(chat_id: int, msg_id: int, rich: Any) -> int:
        sent.append(rich)
        return msg_id or len(sent)

    bot.send = fake_send
    bot.edit = fake_edit
    bot.xray.send = fake_send
    bot.xray.render = lambda chat_id, msg_id, rich: fake_edit(chat_id, msg_id, rich)
    return bot, sent, ctl


def make_scan_result(host: str, latency_ms: int, cert_chain_bytes: int) -> scan.ScanResult:
    return scan.ScanResult(
        target=f"{host}:443",
        host=host,
        port=443,
        feasible=True,
        tls13=True,
        h2=True,
        x25519=True,
        pq_hybrid=True,
        alpn="h2",
        cert_valid=True,
        days_left=90,
        server_names=[host],
        latency_ms=latency_ms,
        cert_chain_bytes=cert_chain_bytes,
        ml_dsa_ready=cert_chain_bytes >= scan.ML_DSA65_CHAIN_MIN,
        groups={"x25519": scan.GROUP_YES, "x25519mlkem768": scan.GROUP_YES},
    )


def test_xray_vless_settings_omit_fallbacks_and_parse_real_mlkem768_output(tmp_path: Path) -> None:
    assert DEFAULT_DEST == "dl.google.com:443"
    assert DEFAULT_SNI == "dl.google.com"

    inb = new_inbound("vless", 443, "raw", "reality")
    cfg = json.loads(XrayState(inbounds=[inb]).to_config())
    vless_inbounds = [item for item in cfg["inbounds"] if item.get("protocol") == "vless"]
    assert len(vless_inbounds) == 1
    settings = vless_inbounds[0]["settings"]
    assert settings["decryption"] != "none"
    assert "fallbacks" not in settings

    mlkem_seed_86 = "A" * 86
    mlkem_client_1024 = "B" * 1024
    x25519_priv_43 = "C" * 43
    x25519_pub_43 = "D" * 43

    ve = VlessEncryption()
    ve.set_pair(
        {
            "decryption": f"mlkem768x25519plus.native.600s.{mlkem_seed_86}",
            "encryption": f"mlkem768x25519plus.native.0rtt.{mlkem_client_1024}",
        }
    )
    assert ve.auth_kind() == "mlkem768"

    xr_agent = load_module("xr_agent_r29_vless", "Storage/remote/xray_agent.py")
    sample_stdout = (
        "Authentication: X25519, not Post-Quantum\n"
        f'"decryption": "mlkem768x25519plus.native.600s.{x25519_priv_43}",\n'
        f'"encryption": "mlkem768x25519plus.native.0rtt.{x25519_pub_43}"\n\n'
        "Authentication: ML-KEM-768, Post-Quantum\n"
        f'"decryption": "mlkem768x25519plus.native.600s.{mlkem_seed_86}",\n'
        f'"encryption": "mlkem768x25519plus.native.0rtt.{mlkem_client_1024}"\n'
    )
    fake_core = tmp_path / "xray"
    xr_agent.CORE = str(fake_core)
    xr_agent.pinned_with_fallback = lambda flags, force=False: fake_core.write_text("bin", encoding="utf-8")
    xr_agent.run = lambda argv, timeout=180, check=False: (0, sample_stdout)

    out_pq, _ = xr_agent.cmd_vlessenc({"auth": "mlkem768", "auto-install": "true"}, [])
    assert fake_core.is_file()
    assert out_pq["decryption"] == f"mlkem768x25519plus.native.600s.{mlkem_seed_86}"
    assert out_pq["encryption"] == f"mlkem768x25519plus.native.0rtt.{mlkem_client_1024}"
    assert '"' not in out_pq["decryption"]
    assert "," not in out_pq["decryption"]

    out_x, _ = xr_agent.cmd_vlessenc({"auth": "x25519"}, [])
    assert out_x["decryption"] == f"mlkem768x25519plus.native.600s.{x25519_priv_43}"
    assert out_x["encryption"] == f"mlkem768x25519plus.native.0rtt.{x25519_pub_43}"


def test_antiddos_port_scan_excludes_vpn_ports_and_ufw_opens_inbound_ports(monkeypatch) -> None:
    policy = antiddos.Policy(enabled=True, ports=[443, 8443, 24443])
    rules = antiddos.nft_table(policy)
    assert "tcp dport != { 443, 8443, 24443 } tcp flags & (fin|syn|rst|ack) == syn update @port_scan" in rules
    assert "tcp dport { 443, 8443, 24443 } tcp flags & (fin|syn|rst|ack) == syn update @port_scan" not in rules
    assert antiddos.SYN_RATE >= 150
    assert antiddos.SCAN_RATE >= 50

    xr_agent = load_module("xr_agent_r29_ufw", "Storage/remote/xray_agent.py")
    seen_cmds: list[list[str]] = []

    def fake_run(argv: list[str], timeout: int = 30, check: bool = False):
        seen_cmds.append(list(argv))
        if argv[:2] == ["/usr/sbin/ufw", "status"]:
            return 0, "Status: active\n"
        return 0, "Rule added\n"

    orig_which = xr_agent.shutil.which
    monkeypatch.setattr(xr_agent.shutil, "which", lambda name: "/usr/sbin/ufw" if name == "ufw" else orig_which(name))
    xr_agent.run = fake_run
    xr_agent.open_ufw_ports([443, 28443])
    assert ["/usr/sbin/ufw", "allow", "443/tcp"] in seen_cmds
    assert ["/usr/sbin/ufw", "allow", "28443/tcp"] in seen_cmds


def test_public_address_detects_nat_private_ip_and_probes_external_ipv4(monkeypatch) -> None:
    class DummySock:
        def settimeout(self, val: float) -> None:
            pass

        def connect(self, addr: tuple[str, int]) -> None:
            pass

        def getsockname(self) -> tuple[str, int]:
            return ("10.128.0.15", 51234)

        def close(self) -> None:
            pass

    monkeypatch.setattr(appmod, "_CACHED_PUBLIC_IP", "")
    monkeypatch.setattr(appmod.socket, "socket", lambda *a, **kw: DummySock())
    monkeypatch.setattr(appmod, "_probe_external_ipv4", lambda: "185.199.108.42")
    assert _ORIG_PUBLIC_ADDRESS() == "185.199.108.42"


def test_single_subscription_url_has_no_json_suffix_and_serves_incy_base64(tmp_path: Path, monkeypatch) -> None:
    bot, _, _ = make_bot(tmp_path)
    bot.state.xray.tunnel_host = "obhod-incy.tail1234.ts.net:8443"
    bot.state.xray.tunnel_enabled = True
    bot.state.xray.sub_enabled = True
    bot.xray.core = {"installed": True, "running": True, "inbounds": 1}

    asyncio.run(bot.xray.create_quick(1, 0, "reality", "raw", "443"))
    rows = bot.xray.sub_rows()
    assert len(rows) == 1
    _, sub_path, sub_url = rows[0]
    assert not sub_path.endswith("/json")
    assert not sub_url.endswith("/json")
    assert sub_url.startswith("https://obhod-incy.tail1234.ts.net:8443/")

    html = xscreens.subs_screen(bot.xray.view(), rows).to_html()
    assert sub_url in html
    assert "/json" not in html

    for lang in ("en", "ru", "zh"):
        title = i18n.t("XR_SUBS_JSON_TITLE", lang)
        assert "JSON" not in title
        assert "json" not in title

    import threading
    import urllib.request

    reg = bot.state.xray.sub_registry("203.0.113.10", [])
    reg_path = tmp_path / "subs.json"
    reg_path.write_text(json.dumps(reg), encoding="utf-8")
    sub_srv = load_module("sub_srv_r29", "Storage/remote/sub_server.py")
    monkeypatch.setattr(sub_srv, "REGISTRY", str(reg_path))
    sub_srv.CACHE["key"] = None
    sub_srv.CACHE["body"] = None
    srv = sub_srv.Server(("127.0.0.1", 0), sub_srv.Handler)
    port_num = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port_num}{sub_path}", timeout=5) as resp:
            assert resp.status == 200
            decoded = base64.b64decode(resp.read()).decode("utf-8").strip().splitlines()
            assert len(decoded) == 1
            assert decoded[0].startswith("vless://")
            assert "sni=dl.google.com" in decoded[0]
    finally:
        srv.shutdown()
        srv.server_close()


def test_three_step_wizard_grid_2x5_and_cert_chain_mldsa_filter(tmp_path: Path, monkeypatch) -> None:
    bot, sent, ctl = make_bot(tmp_path)
    bot.xray.auto_scan_on_open = True

    scanned_batch = [
        make_scan_result(
            host=f"edge-{idx}.example.com",
            latency_ms=12 + idx * 5,
            cert_chain_bytes=3400 if idx == 0 else 4300,
        )
        for idx in range(12)
    ]

    async def fake_scan_targets(targets, **kwargs):
        if len(targets) == 1 and targets[0] == "cdn.cloudflare.com:443":
            return [make_scan_result("cdn.cloudflare.com", 9, 3427)]
        return list(scanned_batch)

    monkeypatch.setattr("BOT.panel.scan_targets", fake_scan_targets)

    asyncio.run(bot.xray.route(1, 10, "xr:new"))
    step1_html = sent[-1].to_html()
    assert "xr:wiz:net:raw" in step1_html
    assert "xr:wiz:net:xhttp" in step1_html
    assert "xr:wiz:net:grpc" in step1_html
    assert step1_html.count("<tg-button ") <= ui.MAX_BUTTONS

    asyncio.run(bot.xray.route(1, 10, "xr:wiz:net:xhttp"))
    step2_html = sent[-1].to_html()
    for idx in range(10):
        assert f'data="xr:wiz:pick:{idx}"' in step2_html
    assert 'data="xr:wiz:pick:10"' not in step2_html
    assert step2_html.count("<tg-button-row") >= 5
    assert step2_html.count("<tg-button ") <= ui.MAX_BUTTONS

    asyncio.run(bot.xray.route(1, 10, "xr:wiz:pick:0"))
    step3_short_cert_html = sent[-1].to_html()
    assert 'data="xr:wiz:make:reality"' in step3_short_cert_html
    assert 'data="xr:wiz:make:reality-x25519mlkem768"' in step3_short_cert_html
    assert 'data="xr:wiz:make:reality-mldsa65"' not in step3_short_cert_html
    assert 'data="xr:wiz:make:reality-mldsa65-x25519mlkem768"' not in step3_short_cert_html

    asyncio.run(bot.xray.route(1, 10, "xr:wiz:back"))
    asyncio.run(bot.xray.route(1, 10, "xr:wiz:pick:1"))
    step3_full_cert_html = sent[-1].to_html()
    assert 'data="xr:wiz:make:reality"' in step3_full_cert_html
    assert 'data="xr:wiz:make:reality-x25519mlkem768"' in step3_full_cert_html
    assert 'data="xr:wiz:make:reality-mldsa65"' in step3_full_cert_html
    assert 'data="xr:wiz:make:reality-mldsa65-x25519mlkem768"' in step3_full_cert_html

    asyncio.run(bot.xray.route(1, 10, "xr:wiz:make:reality-mldsa65-x25519mlkem768"))
    assert len(bot.state.xray.inbounds) == 1
    created = bot.state.xray.inbounds[0]
    assert created.network == "xhttp"
    assert created.dest == "edge-1.example.com:443"
    assert created.sni == "edge-1.example.com"
    assert created.security_kind() == "reality-mldsa65-x25519mlkem768"
    assert created.mldsa65_seed and created.mldsa65_verify
    assert created.port in bot.state.ddos.get("ports", [])
    assert ["mldsa65"] in ctl.calls

    bot.xray.wiz_network = "grpc"
    asyncio.run(bot.xray.apply_input(1, "xr_subnet_cidr", "wiz", "cdn.cloudflare.com:443"))
    manual_single_html = sent[-1].to_html()
    assert "cdn.cloudflare.com:443" in manual_single_html
    assert 'data="xr:wiz:make:reality"' in manual_single_html
    assert 'data="xr:wiz:make:reality-mldsa65"' not in manual_single_html

    asyncio.run(bot.xray.apply_input(1, "xr_subnet_cidr", "wiz", "185.199.108.0/24"))
    manual_cidr_html = sent[-1].to_html()
    assert 'data="xr:wiz:pick:0"' in manual_cidr_html
