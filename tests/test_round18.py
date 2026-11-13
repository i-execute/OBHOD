from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import re
from pathlib import Path

import pytest

from BOT import dscreens, ftscreens, i18n, ui, xscreens
from BOT.xray import SUB_SEGMENT_LEN, TUNNEL_HOST_RE, new_inbound
from tests.fakes import make_bot
from tests.test_screens import render_all

ROOT = Path(__file__).resolve().parents[1]
SUB_SERVER_PATH = ROOT / "Storage" / "remote" / "sub_server.py"
XRAY_AGENT_PATH = ROOT / "Storage" / "remote" / "xray_agent.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_subscription_endpoint_and_bundle_never_expose_freeturn(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.xray.sub_address = "203.0.113.10"
    inbound = new_inbound("vless", 34567, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    bot.freeturn.state.remember("owner", "freeturn://secret-ft-peer")
    bot.freeturn.state.remember("phone", "freeturn://second-ft-peer")

    bundle = bot.xray.sub_bundle("203.0.113.10")
    assert bundle is not None
    assert len(bundle.links) == 1
    assert bundle.links[0].startswith("vless://")
    assert all("freeturn://" not in link for link in bundle.links)

    payload = bot.subs_payload()
    dumped = json.dumps(payload)
    assert "freeturn://" not in dumped
    assert "vless://" in dumped

    sub_mod = load_module("round18_sub_server", SUB_SERVER_PATH)
    mixed_entry = {
        "links": [
            "vless://uuid@203.0.113.10:34567?security=reality#sub",
            "freeturn://should-never-appear",
            "wg://should-never-appear",
        ]
    }
    raw_b64 = sub_mod.payload_of(mixed_entry)
    decoded = base64.b64decode(raw_b64).decode("utf-8")
    assert decoded == "vless://uuid@203.0.113.10:34567?security=reality#sub\n"
    assert "freeturn://" not in decoded
    assert len(sub_mod.xray_only(mixed_entry["links"])) == 1


@pytest.mark.parametrize("lang", ("en", "ru", "zh"))
def test_every_table_in_all_screens_is_centered(lang: str) -> None:
    sample = ui.table([("info", "param", ui.code("val"))], ("left", "right"))
    assert '<th align="center">' in sample
    assert '<td align="center">' in sample
    assert "<th>" not in sample
    assert "<td>" not in sample

    extra = [
        ("ft_home", ftscreens.home(ftscreens.FtView(lang=lang))),
        ("ft_fw", ftscreens.fw_screen(ftscreens.FtView(guard={"port": 51820, "proto": "udp", "mode": "vk"}, lang=lang))),
        ("dbg_home", dscreens.home(dscreens.DbgView(lang=lang))),
    ]
    for name, rich in list(render_all(lang)) + extra:
        html = rich.to_html() if hasattr(rich, "to_html") else rich.build()
        bare_th = re.findall(r"<th(?![^>]*\balign=\"center\")[^>]*>", html)
        bare_td = re.findall(r"<td(?![^>]*\balign=\"center\")[^>]*>", html)
        assert not bare_th, f"{name} ({lang}) has uncentered <th>: {bare_th}"
        assert not bare_td, f"{name} ({lang}) has uncentered <td>: {bare_td}"


def test_no_tunnel_ui_shown_until_tailnet_key_is_inserted(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)

    home_html = xscreens.home(bot.xray.view()).to_html()
    assert 'data="xr:dom"' not in home_html

    subs_html = xscreens.subs_screen(bot.xray.view(), bot.xray.sub_rows()).to_html()
    assert "<table" not in subs_html
    assert 'data="xr:dom"' not in subs_html
    assert subs_html.count("switch_inline_query_current_chat") == 1
    assert i18n.t("DOM_KEY_INPUT", bot.state.language) in subs_html
    for junk in ("xr:subs:traffic", "xr:subs:apply", "xr:subs:status", "xr:subs:stop"):
        assert junk not in subs_html

    dom_html = xscreens.domain_screen(bot.xray.view(), None, "").to_html()
    assert "<table" not in dom_html
    assert dom_html.count("switch_inline_query_current_chat") == 1


def test_pasting_tailnet_key_raises_random_port_inbound_and_permanent_domain_without_443(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.xray.sub_address = "203.0.113.10"
    existing_443 = new_inbound("vless", 443, "raw", "reality")
    existing_443.make_client("owner")
    bot.state.xray.add(existing_443)
    bot.freeturn.state.remember("owner", "freeturn://never-in-sub")

    key = "".join(("ts", "key-auth-", "0" * 32))
    asyncio.run(bot.xray.apply_input(1, "xr_tunnel_key", "-", key))

    state = bot.state.xray
    assert state.sub_port != 443
    assert 20000 <= state.sub_port <= 59999

    non_443_inbounds = [item for item in state.inbounds if item.port != 443]
    assert len(non_443_inbounds) == 0
    assert len(state.inbounds) == 1

    assert state.tunnel_enabled is True
    assert state.sub_enabled is True
    assert state.tunnel_host.endswith((":8443", ":10000"))
    assert ":443" not in state.tunnel_host
    assert not TUNNEL_HOST_RE.match("obhod.tail1234.ts.net:443")

    html = bot.sent[-1].to_html()
    pattern = re.compile(
        r"https://[a-z0-9.-]+\.ts\.net:(?:8443|10000)/([A-Za-z0-9_-]{%d})/([A-Za-z0-9_-]{%d})(?=</pre>)"
        % (SUB_SEGMENT_LEN, SUB_SEGMENT_LEN)
    )
    match = pattern.search(html)
    assert match is not None, html
    assert "/json" not in html
    assert "freeturn://" not in html


def test_xray_agent_never_touches_port_443_for_tunnel(monkeypatch) -> None:
    agent = load_module("round18_xray_agent", XRAY_AGENT_PATH)
    seen = []

    def fake_run(argv, timeout=180, check=False):
        seen.append(argv)
        if argv[1] == "funnel" and "status" in argv:
            return 0, "https://obhod-ab12.tail1234.ts.net:8443"
        if argv[1] == "status":
            return 0, '{"BackendState": "Running", "Self": {"DNSName": "obhod-ab12.tail1234.ts.net."}}'
        if argv[1] == "version":
            return 0, "1.80.2"
        return 0, ""

    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/tailscale")
    monkeypatch.setattr(agent, "run", fake_run)

    with pytest.raises(agent.ScriptError):
        agent.cmd_tunnel_up({"key": "tskey-auth-" + "a" * 20, "hostname": "obhod", "port": "443"}, [])

    state, err = agent.cmd_tunnel_up({"key": "tskey-auth-" + "a" * 20, "hostname": "", "port": "34567"}, [])
    assert err is None
    assert state["url"] == "https://obhod-ab12.tail1234.ts.net:8443"
    funnel_cmd = [cmd for cmd in seen if len(cmd) > 2 and cmd[1] == "funnel" and "--bg" in cmd][0]
    assert "--https=443" not in funnel_cmd
    assert any(arg in ("--https=8443", "--https=10000") for arg in funnel_cmd)
    assert "http://127.0.0.1:34567" in funnel_cmd
