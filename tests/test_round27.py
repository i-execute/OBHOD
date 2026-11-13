from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import threading
import urllib.request

from BOT import ftscreens, screens, subs, xscreens
from BOT.scan import ScanResult
from BOT.xray import XrayState, new_inbound, tailnet_expiry_stage
from tests.fakes import make_bot


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_agent(name: str, rel: str):
    path = REPO_ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_legacy_auto_raw_owner_inbound_migrated_once() -> None:
    auto_inb = new_inbound("vless", 38443, "raw", "reality")
    auto_inb.remark = "sub-38443"
    auto_inb.sni = "dl.google.com"
    auto_inb.dest = "dl.google.com:443"
    auto_inb.make_client("owner")
    auto_inb2 = new_inbound("vless", 49443, "raw", "reality")
    auto_inb2.make_client("owner")
    custom_inb = new_inbound("vless", 443, "xhttp", "reality")
    custom_inb.sni = "www.microsoft.com"
    custom_inb.dest = "www.microsoft.com:443"
    custom_inb.make_client("alice")

    legacy_payload = {
        "inbounds": [auto_inb.to_dict(), auto_inb2.to_dict(), custom_inb.to_dict()],
        "sub_port": 31234,
    }
    migrated = XrayState.from_dict(legacy_payload)
    assert bool(migrated.manual_schema) is True
    assert migrated.purged_auto_raw is True
    assert len(migrated.inbounds) == 1
    assert migrated.inbounds[0].network == "xhttp"
    assert migrated.inbounds[0].clients[0].email == "alice"

    manual_raw = new_inbound("vless", 41234, "raw", "reality")
    manual_raw.sni = "dl.google.com"
    manual_raw.dest = "dl.google.com:443"
    manual_raw.make_client("owner")
    migrated.add(manual_raw)
    reloaded = XrayState.from_dict(migrated.to_dict())
    assert len(reloaded.inbounds) == 2


def test_xray_creates_inbounds_without_auto_owner_or_auto_raw(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    asyncio.run(bot.xray.create_quick(1, 0, "reality", "xhttp"))
    assert len(bot.state.xray.inbounds) == 1
    assert [c.email for c in bot.state.xray.inbounds[0].clients] == [""]

    bot.xray.draft = {"network": "grpc", "security": "reality", "port": "24443"}
    asyncio.run(bot.xray.create_custom(1, 0))
    assert len(bot.state.xray.inbounds) == 2
    assert [c.email for c in bot.state.xray.inbounds[1].clients] == [""]

    pick = ScanResult(
        target="dl.google.com",
        host="dl.google.com",
        ip="142.250.74.142",
        port=443,
        feasible=True,
        tls13=True,
        h2=True,
        alpn="h2",
        x25519=True,
        cert_valid=True,
        cert_chain_valid=True,
        cert_issuer="GTS",
        cert_subject="dl.google.com",
        server_names=["dl.google.com"],
        latency_ms=12,
    )
    bot.xray.results = [pick]
    asyncio.run(bot.xray.scan_action(1, 0, "create", "0"))
    assert all(c.email == "" for c in bot.state.xray.inbounds[-1].clients)


def test_freeturn_never_auto_creates_owner_but_keeps_existing_owner(tmp_path: Path, monkeypatch, capsys) -> None:
    ft = load_agent("ft_agent_r27", "Storage/remote/freeturn_agent.py")
    root = tmp_path / "ft_root"
    wg_conf = tmp_path / "ft-wg0.conf"
    root.mkdir(parents=True, exist_ok=True)
    peer_header = chr(35) + " BEGIN PEER owner"
    peer_footer = chr(35) + " END PEER owner"
    wg_conf.write_text(f"[Interface]\nPrivateKey = PRIV\n\n{peer_header}\n[Peer]\nPublicKey = PUB1\n{peer_footer}\n", encoding="utf-8")

    monkeypatch.setattr(ft, "INSTALL_ROOT", str(root))
    monkeypatch.setattr(ft, "script_source", lambda flags: str(tmp_path / "fake.sh"))

    def fake_run_script(_script, _plan, _timeout):
        owner_dir = root / "clients" / "owner"
        owner_dir.mkdir(parents=True, exist_ok=True)
        (owner_dir / "wg.conf").write_text("[Interface]\nAddress = 10.66.0.2/32\n", encoding="utf-8")
        (root / "clients.list").write_text("owner|PUB1|10.66.0.2\n", encoding="utf-8")
        payload = {
            "proto": ft.PROTO,
            "result": "ok",
            "data": {
                "name": "owner",
                "link": "freeturn://auto-owner",
                "conf": "[Interface]\nAddress = 10.66.0.2/32\n",
                "links": {"owner": "freeturn://auto-owner"},
                "clients": [{"name": "owner", "ip": "10.66.0.2"}],
            },
        }
        return json.dumps(payload), 0

    monkeypatch.setattr(ft, "run_script", fake_run_script)
    orig_strip = ft.strip_auto_owner
    monkeypatch.setattr(ft, "strip_auto_owner", lambda data, r=str(root): orig_strip(data, root=r, wg_conf=str(wg_conf)))

    assert ft.has_owner_client(str(root)) is False
    rc = ft.main(["apply", "--connect=https://vk.com/call/join/test123"])
    assert rc == 0
    out_clean = json.loads(capsys.readouterr().out.strip())
    assert out_clean["result"] == "ok"
    assert "link" not in out_clean["data"]
    assert out_clean["data"]["clients"] == []
    assert not (root / "clients" / "owner").exists()

    owner_dir = root / "clients" / "owner"
    owner_dir.mkdir(parents=True, exist_ok=True)
    (owner_dir / "wg.conf").write_text("[Interface]\nAddress = 10.66.0.2/32\n", encoding="utf-8")
    (root / "clients.list").write_text("owner|PUB1|10.66.0.2\n", encoding="utf-8")
    assert ft.has_owner_client(str(root)) is True

    rc2 = ft.main(["apply", "--connect=https://vk.com/call/join/test123"])
    assert rc2 == 0
    out_keep = json.loads(capsys.readouterr().out.strip())
    assert out_keep["result"] == "ok"
    assert out_keep["data"]["links"].get("owner") == "freeturn://auto-owner"
    assert (root / "clients" / "owner").is_dir()

    bot = make_bot(tmp_path / "bot")
    bot.freeturn.state.installed = True
    html = ftscreens.share_screen(bot.freeturn.view()).to_html()
    assert "ft:clients" in html


def test_subs_screen_blocks_dummy_links_and_uses_json_endpoint(tmp_path: Path, monkeypatch) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    bot.state.xray.sub_address = "203.0.113.10"
    bot.state.xray.tunnel_host = "node-a.tail1234.ts.net:8443"
    bot.state.xray.tunnel_enabled = True
    bot.state.xray.sub_enabled = True

    bot.xray.core = {"installed": False, "running": False, "inbounds": 0}
    html_no_xray = xscreens.subs_screen(bot.xray.view(), bot.xray.sub_rows()).to_html()
    assert "xr:core:install" in html_no_xray
    assert "/json</pre>" not in html_no_xray

    bot.xray.core = {"installed": True, "running": True, "inbounds": 0}
    html_no_inb = xscreens.subs_screen(bot.xray.view(), bot.xray.sub_rows()).to_html()
    assert "xr:new" in html_no_inb
    assert "/json</pre>" not in html_no_inb

    inb = new_inbound("vless", 443, "xhttp", "reality")
    inb.sni = "dl.google.com"
    inb.dest = "dl.google.com:443"
    inb.enable = False
    bot.state.xray.add(inb)
    html_unstarted = xscreens.subs_screen(bot.xray.view(), bot.xray.sub_rows()).to_html()
    assert "xr:list" in html_unstarted
    assert "/json</pre>" not in html_unstarted

    inb.enable = True
    bot.xray.core = {"installed": True, "running": True, "inbounds": 1}
    html_ready = xscreens.subs_screen(bot.xray.view(), bot.xray.sub_rows()).to_html()
    assert "https://node-a.tail1234.ts.net:8443/" in html_ready
    assert "/json</pre>" not in html_ready
    assert f"127.0.0.1:{bot.state.xray.sub_port}" in html_ready
    assert "xr:dom:port" not in html_ready
    assert "xr:subs:rotate" not in html_ready

    registry = bot.state.xray.sub_registry("203.0.113.10", [])
    reg_file = tmp_path / "registry.json"
    reg_file.write_text(json.dumps(registry), encoding="utf-8")

    sub_mod = load_agent("sub_srv_r27", "Storage/remote/sub_server.py")
    monkeypatch.setattr(sub_mod, "REGISTRY", str(reg_file))
    sub_mod.CACHE["key"] = None
    sub_mod.CACHE["body"] = None
    bundle = subs.aggregate(bot.state.xray, [], "203.0.113.10", bot.state.xray.sub_port)

    srv = sub_mod.Server(("127.0.0.1", 0), sub_mod.Handler)
    port_num = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port_num}{bundle.json_path()}", timeout=5) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type", "").startswith("application/json")
            assert resp.headers.get("Content-Disposition") is None
            parsed = json.loads(resp.read().decode("utf-8"))
            assert isinstance(parsed, list) and len(parsed) == 1
            assert parsed[0]["outbounds"][0]["protocol"] == "vless"
            assert parsed[0]["outbounds"][0]["streamSettings"]["network"] == "xhttp"
    finally:
        srv.shutdown()
        srv.server_close()


def test_update_messages_have_no_empty_paragraphs_and_clean_newlines(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    view = bot.view()
    info = {"git": True, "repo": "i-execute/OBHOD", "branch": "main"}
    blocks = list(screens.banner(view, bot.tr())) + screens.update_live_blocks(
        view,
        info,
        ["fetch", "compare", "apply", "verify", "restarting"],
        {"target": "abcdef123456", "subject": "round 27"},
    )
    rich = screens.update_cumulative_screen(view, blocks)
    html = rich.to_html()
    assert "</p><br><p>" not in html
    assert "</blockquote><br><p>" not in html
    assert "<p>\n</p>" not in html
    assert "<p><br></p>" not in html
    assert "\n\n" not in html
    assert "<br>" in html
    assert bot.tr()("LOADING_BODY") not in html


def test_funnel_port_preserved_on_key_rotation_and_switchable_manually(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inb = new_inbound("vless", 443, "xhttp", "reality")
    inb.sni = "dl.google.com"
    inb.dest = "dl.google.com:443"
    inb.make_client("alice")
    bot.state.xray.add(inb)
    bot.state.xray.sub_address = "203.0.113.10"
    bot.state.xray.tunnel_host = "my-srv.tail1234.ts.net:10000"
    bot.state.xray.tunnel_enabled = True
    bot.state.xray.tunnel_key_expiry = "2026-11-10T00:00:00Z"

    seen_https_ports: list[int] = []
    orig_up = bot.xray.control.tunnel_up

    async def spy_up(cfg, key, hostname, port, https_port=8443, **kw):
        seen_https_ports.append(int(https_port))
        res = await orig_up(cfg, key, hostname, port, https_port=https_port, **kw)
        res.url = f"https://my-srv.tail1234.ts.net:{https_port}"
        res.hostname = f"my-srv.tail1234.ts.net:{https_port}"
        res.key_expiry = "2027-05-04T00:00:00Z"
        return res

    bot.xray.control.tunnel_up = spy_up

    new_key = "curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up --auth-key=" + "".join(("ts", "key-auth-", "0" * 24))
    asyncio.run(bot.xray.apply_input(1, "xr_tunnel_key", "subs", new_key))
    assert seen_https_ports[-1] == 10000
    assert bot.state.xray.tunnel_host == "my-srv.tail1234.ts.net:10000"

    asyncio.run(bot.xray.tunnel_action(1, 10, "port"))
    assert seen_https_ports[-1] == 8443
    assert bot.state.xray.tunnel_host == "my-srv.tail1234.ts.net:8443"


def test_xray_agent_force_reauth_and_turns_off_old_funnel_port(monkeypatch) -> None:
    agent = load_agent("xr_agent_r27", "Storage/remote/xray_agent.py")
    cmds: list[list[str]] = []
    switched = {"done": False}

    def fake_run(argv, timeout=180, check=False):
        cmds.append(list(argv))
        if len(argv) > 1 and argv[1] == "funnel" and "--bg" in argv:
            switched["done"] = True
            return 0, ""
        if argv[1] == "status" and "--json" in argv:
            doc = {
                "BackendState": "Running",
                "HaveNodeKey": True,
                "Self": {
                    "DNSName": "obhod-keep.tail1234.ts.net.",
                    "KeyExpiry": "2027-05-01T00:00:00Z",
                },
            }
            return 0, json.dumps(doc)
        if argv[1] == "funnel" and "status" in argv:
            if switched["done"]:
                return 0, "https://obhod-keep.tail1234.ts.net:10000"
            return 0, "https://obhod-keep.tail1234.ts.net:8443"
        if argv[1] == "version":
            return 0, "1.104.6"
        return 0, ""

    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/tailscale")
    monkeypatch.setattr(agent, "run", fake_run)

    state, err = agent.cmd_tunnel_up(
        {"key": "".join(("ts", "key-auth-", "0" * 24)), "hostname": "", "port": 34567, "https_port": 10000},
        [],
    )
    assert err is None
    assert state["url"] == "https://obhod-keep.tail1234.ts.net:10000"
    up_calls = [c for c in cmds if len(c) > 1 and c[1] == "up"]
    assert up_calls
    assert "--force-reauth" in up_calls[0]
    assert "--hostname=obhod-keep" in up_calls[0]
    off_calls = [c for c in cmds if "--https=8443" in c and "off" in c]
    assert len(off_calls) >= 2


def test_tailscale_expiry_notifications_at_30d_7d_and_expired(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.admin_id = 777
    bot.state.language = "ru"
    now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)

    bot.state.xray.tunnel_enabled = True
    bot.state.xray.tunnel_host = "srv.tail1234.ts.net:8443"
    bot.state.xray.tunnel_key_expiry = (now + timedelta(days=90)).isoformat()

    stage_90 = asyncio.run(bot.check_tailscale_expiry_notify(now=now, refresh=False))
    assert stage_90 == ""
    assert len(bot.sent) == 0

    bot.state.xray.tunnel_key_expiry = (now + timedelta(days=25, hours=4)).isoformat()
    stage_30 = asyncio.run(bot.check_tailscale_expiry_notify(now=now, refresh=False))
    assert stage_30 == "30d"
    assert len(bot.sent) == 1
    html_30 = bot.sent[-1].to_html()
    assert "25" in html_30
    assert "Disable key expiry" in html_30
    assert "https://login.tailscale.com/admin/machines" in html_30

    dup_30 = asyncio.run(bot.check_tailscale_expiry_notify(now=now, refresh=False))
    assert dup_30 == ""
    assert len(bot.sent) == 1

    later_7d = now + timedelta(days=20)
    stage_7 = asyncio.run(bot.check_tailscale_expiry_notify(now=later_7d, refresh=False))
    assert stage_7 == "7d"
    assert len(bot.sent) == 2
    assert "5" in bot.sent[-1].to_html()

    later_exp = now + timedelta(days=27)
    stage_exp = asyncio.run(bot.check_tailscale_expiry_notify(now=later_exp, refresh=False))
    assert stage_exp == "expired"
    assert len(bot.sent) == 3

    bot.state.xray.tunnel_key_expiry = "never"
    bot.state.xray.tunnel_expired = False
    stage_never, _ = tailnet_expiry_stage("never", False, now=later_exp)
    assert stage_never == ""
    cleared = asyncio.run(bot.check_tailscale_expiry_notify(now=later_exp, refresh=False))
    assert cleared == ""
    assert bot.state.xray.tunnel_expiry_notified == ""
