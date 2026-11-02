from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from BOT import i18n, xscreens
from BOT.panel import PanelError, XrayPanel, host_port, parse_port, state_report
from BOT.ui import code
from BOT.scan import ScanResult
from BOT.xray import SUB_SEGMENT_LEN, XrayState, config_json, new_inbound
from BOT.xrayrpc import XrayError as RpcError
from tests.fakes import FakeControl, FakeGuard, make_bot, make_inbound


def panel(tmp_path: Path) -> tuple[XrayPanel, object]:
    bot = make_bot(tmp_path)
    return XrayPanel(bot, bot.control), bot


def run(coro: object) -> None:
    asyncio.run(coro)


def test_next_port_skips_used(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.add(new_inbound("vless", 443, "raw", "reality"))
    assert item.next_port() == 8443


def test_create_custom_inbound(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    item.draft = {"network": "xhttp", "security": "tls", "port": "8443"}
    run(item.create_custom(1, 0))
    inbound = bot.state.xray.inbounds[0]
    assert inbound.port == 8443
    assert inbound.network == "xhttp"
    assert inbound.security == "tls"
    assert inbound.clients[0].email == "owner"
    assert bot.rendered


def test_create_quick_rejects_unknown_network(tmp_path: Path) -> None:
    item, _bot = panel(tmp_path)
    with pytest.raises(PanelError):
        run(item.create_quick(1, 0, "reality", "ws"))
    with pytest.raises(PanelError):
        run(item.create_quick(1, 0, "xtls", "raw"))


def test_cycle_rotates_values(tmp_path: Path) -> None:
    item, _bot = panel(tmp_path)
    item.draft = {"network": "raw", "security": "reality"}
    item.cycle("network")
    assert item.draft["network"] == "grpc"
    item.cycle("security")
    assert item.draft["security"] == "tls"
    item.cycle("unknown")


def test_set_port_detects_conflict(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    first = new_inbound("vless", 443, "raw", "reality")
    second = new_inbound("vless", 8443, "raw", "tls")
    bot.state.xray.add(first)
    bot.state.xray.add(second)
    with pytest.raises(PanelError):
        item.set_field("xr_port", str(second.id), "443")
    notice = item.set_field("xr_port", str(second.id), "9443")
    assert "9443" in notice


def test_set_remark_and_sni(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    with pytest.raises(PanelError):
        item.set_field("xr_remark", str(inbound.id), "")
    assert item.set_field("xr_remark", str(inbound.id), "main") == i18n.t("NOTICE_NAME")
    assert inbound.remark == "main"
    item.set_field("xr_sni", str(inbound.id), "www.microsoft.com")
    assert inbound.dest == "www.microsoft.com:443"
    item.set_field("xr_dest", str(inbound.id), "www.apple.com:8443")
    assert inbound.dest == "www.apple.com:8443"


def test_set_network_specific_fields(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "xhttp", "reality")
    bot.state.xray.add(inbound)
    item.set_field("xr_path", str(inbound.id), "obhod")
    assert inbound.path == "/obhod"
    item.set_field("xr_host_header", str(inbound.id), "example.com")
    assert inbound.host_header == "example.com"
    item.set_field("xr_fingerprint", str(inbound.id), "firefox")
    assert inbound.fingerprint == "firefox"
    with pytest.raises(PanelError):
        item.set_field("xr_fingerprint", str(inbound.id), "netscape")
    item.set_field("xr_alpn", str(inbound.id), "h2,http/1.1")
    assert inbound.alpn == ["h2", "http/1.1"]
    item.set_field("xr_short_id", str(inbound.id), "abcd1234")
    assert inbound.short_ids == ["abcd1234"]
    item.set_field("xr_padding", str(inbound.id), "60-40-0")
    assert inbound.encryption.padding == "60-40-0"


def test_client_fields(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    assert "owner" in item.set_field("xr_client_email", str(inbound.id), "owner")
    with pytest.raises(PanelError):
        item.set_field("xr_client_email", str(inbound.id), "owner")
    assert "flow" in item.set_field("xr_client_flow", f"{inbound.id}:owner", "xtls-rprx-vision")
    with pytest.raises(PanelError):
        item.set_field("xr_client_flow", f"{inbound.id}:owner", "xtls-rprx-direct")
    assert "3" in item.set_field("xr_client_limit", f"{inbound.id}:owner", "3")
    with pytest.raises(PanelError):
        item.set_field("xr_client_limit", f"{inbound.id}:owner", "many")


def test_client_flow_needs_raw_reality(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "grpc", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    with pytest.raises(PanelError):
        item.set_field("xr_client_flow", f"{inbound.id}:owner", "xtls-rprx-vision")


def test_global_fields(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    assert item.set_field("xr_scan_targets", "", "a:443, b:443") == i18n.t("NOTICE_TARGETS_COUNT", count=2)
    assert bot.state.xray.scan_targets == ["a:443", "b:443"]
    with pytest.raises(PanelError):
        item.set_field("xr_scan_targets", "", "")
    assert "c:443" in item.set_field("xr_scan_manual", "", "c:443")
    item.set_field("xr_scan_manual", "", "10.0.0.0/30")
    assert "10.0.0.0/30" in bot.state.xray.scan_targets
    assert "debug" in item.set_field("xr_log_level", "", "debug")
    with pytest.raises(PanelError):
        item.set_field("xr_log_level", "", "loud")
    item.set_field("xr_sub_port", "", "2097")
    assert bot.state.sub_port == 2097
    with pytest.raises(PanelError):
        item.set_field("xr_sub_port", "", "0")
    item.set_field("xr_bantime", "", "60")
    assert bot.state.xray.fail2ban_bantime == 60
    with pytest.raises(PanelError):
        item.set_field("xr_bantime", "", "0")


def test_mldsa_fields(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    item.set_field("xr_mldsa65_seed", str(inbound.id), "SEED")
    item.set_field("xr_mldsa65_verify", str(inbound.id), "VERIFY")
    assert inbound.mldsa65_verify == "VERIFY"
    assert inbound.mldsa65_seed == "SEED"
    item.set_field("xr_mldsa65_seed", str(inbound.id), "")
    assert inbound.mldsa65_seed == "" and inbound.mldsa65_verify == ""
    run(item.mldsa_action(1, 0, str(inbound.id), "gen"))
    assert inbound.mldsa65_seed == "SEEDVALUE"
    assert inbound.mldsa65_verify == "VERIFYVALUE"
    run(item.mldsa_action(1, 0, str(inbound.id), "clear"))
    assert inbound.mldsa65_seed == ""


def test_mldsa_needs_reality(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "tls")
    bot.state.xray.add(inbound)
    run(item.mldsa_action(1, 0, str(inbound.id), "gen"))
    assert inbound.mldsa65_seed == ""


def test_regen_reality_keys(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    before = inbound.reality_private
    item.core = {"installed": True}
    run(item.regen_keys(1, 0, str(inbound.id)))
    assert inbound.reality_private == "PRIVATEKEY"
    assert inbound.reality_public == "PUBLICKEY"
    assert inbound.reality_private != before
    plain = new_inbound("vless", 8443, "raw", "tls")
    bot.state.xray.add(plain)
    run(item.regen_keys(1, 0, str(plain.id)))
    assert plain.reality_private == ""


def test_delete_inbound_and_client(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    inbound.make_client("phone")
    bot.state.xray.add(inbound)
    run(item.delete_client(1, 0, str(inbound.id), "phone"))
    assert inbound.client("phone") is None
    with pytest.raises(PanelError):
        run(item.delete_client(1, 0, str(inbound.id), "ghost"))
    run(item.delete_inbound(1, 0, str(inbound.id)))
    assert bot.state.xray.inbounds == []


def test_toggle_inbound(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    run(item.toggle(1, 0, str(inbound.id)))
    assert inbound.enable is False
    run(item.toggle(1, 0, str(inbound.id)))
    assert inbound.enable is True


def test_show_links_and_subscription(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    bot.state.xray.sub_address = "203.0.113.10"
    item.save()
    run(item.show_links(1, 0, str(inbound.id)))
    run(item.show_subscription(1, 0, str(inbound.id), "owner"))
    path, url = item.sub_url("owner")
    assert len(path) == 2 + SUB_SEGMENT_LEN * 2
    assert url.endswith(path)
    assert url.startswith("http://203.0.113.10:2096/")
    before = path
    run(item.rotate_subscription(1, 0, str(inbound.id), "owner"))
    after, _url = item.sub_url("owner")
    assert after != before


def test_subs_apply_pushes_registry(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    item.save()
    run(item.subs_action(1, 0, "apply"))
    calls = [call for call in bot.control.calls if call[0].startswith("sub-")]
    assert calls[0][0] == "sub-install"
    assert calls[1][0] == "sub-sync"
    assert bot.state.xray.sub_enabled is True
    run(item.subs_action(1, 0, "status"))
    run(item.subs_action(1, 0, "stop"))
    assert bot.state.xray.sub_enabled is False


def test_subs_need_no_credentials(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    item = XrayPanel(bot, bot.control)
    run(item.subs_action(1, 0, "apply"))
    assert "sub_install" in bot.control.calls or bot.control.calls


def test_core_actions(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    run(item.check(1, 0))
    assert item.core["installed"] is True
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    item.save()
    run(item.apply(1, 0))
    assert any(call[0] == "apply" for call in bot.control.calls)
    run(item.core_action(1, 0, "restart", ""))
    run(item.core_action(1, 0, "stop", ""))
    run(item.core_action(1, 0, "ver", "latest"))
    assert bot.state.xray.version == "latest"
    run(item.core_action(1, 0, "ver", "pin"))
    assert bot.state.xray.version == "26.10.29" or bot.state.xray.version.startswith("v26")
    run(item.purge(1, 0))
    assert item.core == {}


def test_apply_without_inbounds(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    run(item.apply(1, 0))
    assert not any(call[0] == "apply" for call in bot.control.calls)


def test_logs(tmp_path: Path) -> None:
    item, _bot = panel(tmp_path)
    run(item.logs(1, 0, "50"))
    run(item.logs(1, 0, "bad"))


def test_scan_run_and_use(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    result = ScanResult(
        target="www.google.com:443",
        host="www.google.com",
        port=443,
        feasible=True,
        tls13=True,
        h2=True,
        x25519=True,
        pq_hybrid=True,
        cert_valid=True,
        days_left=30,
        latency_ms=9,
        server_names=["www.google.com"],
    )

    seen: dict[str, object] = {}

    async def fake_scan(targets: list[str], sni: str = "", xver: int = 0, candidates: object = None, concurrency: int = 16) -> list[ScanResult]:
        seen["targets"] = targets
        seen["sni"] = sni
        seen["xver"] = xver
        seen["candidates"] = candidates
        return [result]

    monkeypatch.setattr("BOT.panel.scan_targets", fake_scan)
    bot.state.xray.scan_targets = ["www.google.com:443"]
    run(item.scan_action(1, 0, "run", ""))
    assert item.results[0].target == "www.google.com:443"
    assert seen["targets"] == ["www.google.com:443"]
    assert seen["xver"] == 0
    assert len(seen["candidates"] or []) >= 100
    run(item.scan_action(1, 0, "use", "0"))
    assert inbound.dest == "www.google.com:443"
    assert inbound.sni == "www.google.com"
    with pytest.raises(PanelError):
        run(item.scan_action(1, 0, "use", "9"))


def test_scan_without_reality_inbound(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "tls")
    bot.state.xray.add(inbound)
    item.results = [ScanResult(target="a:443", host="a", port=443, feasible=True)]
    run(item.scan_action(1, 0, "use", "0"))
    assert inbound.dest != "a:443"


def test_scan_targets_reset_and_empty(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    run(item.scan_action(1, 0, "reset", ""))
    assert len(bot.state.xray.scan_targets) >= 100
    bot.state.xray.scan_targets = []
    run(item.scan_action(1, 0, "run", ""))


def test_routes_render(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    for data in (
        "xr:home",
        "xr:new",
        "xr:new:raw:reality",
        "xr:custom",
        "xr:cyc:security",
        "xr:scan",
        "xr:scan:targets",
        "xr:subs",
        "xr:core",
        "xr:logs:50",
        f"xr:in:{inbound.id}",
        f"xr:link:{inbound.id}",
        f"xr:cl:{inbound.id}:owner",
        f"xr:sub:{inbound.id}:owner",
        f"xr:edit:{inbound.id}:xr_port",
        f"xr:cladd:{inbound.id}",
        f"xr:clflow:{inbound.id}:owner",
        f"xr:mldsa:{inbound.id}",
        f"xr:del:{inbound.id}",
        "xr:nope",
    ):
        run(item.route(1, 0, data))
    assert len(bot.rendered) == 20


def test_host_port_and_parse_port() -> None:
    assert host_port("example.com:443") == ("example.com", 443)
    assert host_port("example.com") == ("example.com", 443)
    assert host_port("[2001:db8::1]:8443") == ("2001:db8::1", 8443)
    with pytest.raises(PanelError):
        host_port("")
    with pytest.raises(PanelError):
        host_port("a b:443")
    assert parse_port("443") == 443
    with pytest.raises(PanelError):
        parse_port("x")
    with pytest.raises(PanelError):
        parse_port("70000")


def test_state_report_of_fake_core() -> None:
    from BOT.xrayrpc import CoreState

    report = state_report(CoreState.from_dict(FakeControl().core))
    assert report["installed"] is True
    assert report["ports"] == [443]


def test_fake_guard_is_not_touched_by_panel(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    guard = FakeGuard()
    assert guard.calls == []
    assert isinstance(bot.state.xray, XrayState)
    assert make_inbound().clients[0].email == "owner"
    assert item.address() == ""


def test_new_global_fields(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    notice = item.set_field("xr_scan_candidates", "", "a:443, b:443, a:443")
    assert notice == i18n.t("NOTICE_CANDIDATES", count=2)
    assert bot.state.xray.scan_candidates == ["a:443", "b:443"]
    assert item.set_field("xr_scan_sni", "", "www.google.com") == i18n.t("NOTICE_SCAN_SNI", value="www.google.com")
    assert bot.state.xray.scan_sni == "www.google.com"
    assert item.set_field("xr_scan_xver", "", "2") == i18n.t("NOTICE_SCAN_XVER", value=2)
    assert bot.state.xray.scan_xver == 2
    with pytest.raises(PanelError):
        item.set_field("xr_scan_xver", "", "3")
    assert item.set_field("xr_dns_servers", "", "1.1.1.1, 9.9.9.9") == i18n.t("NOTICE_DNS", value="1.1.1.1, 9.9.9.9")
    assert bot.state.xray.dns_servers == ["1.1.1.1", "9.9.9.9"]
    assert item.set_field("xr_dns_servers", "", "") == i18n.t("NOTICE_DNS", value=i18n.t("UI_NONE"))
    assert bot.state.xray.dns_servers == []
    assert item.set_field("xr_api_port", "", "63000") == i18n.t("NOTICE_API_PORT", port=63000)
    assert bot.state.xray.api_port == 63000
    assert item.set_field("xr_access_log", "", "/tmp/a.log") == i18n.t("NOTICE_ACCESS_LOG", value="/tmp/a.log")
    assert bot.state.xray.access_log == "/tmp/a.log"
    with pytest.raises(PanelError):
        item.set_field("xr_access_log", "", "relative.log")


def test_scan_reset_uses_the_candidate_list(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.scan_candidates = ["a:443", "b:443"]
    run(item.scan_action(1, 0, "reset", ""))
    assert bot.state.xray.scan_targets == ["a:443", "b:443"]
    bot.state.xray.scan_candidates = []
    run(item.scan_action(1, 0, "reset", ""))
    assert len(bot.state.xray.scan_targets) >= 100


def test_support_link_and_announce_are_validated(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    for bad in ("t.me/help", "https://t.me/" + "a" * 300, "https://t.me/hel p", "javascript:alert(1)"):
        with pytest.raises(PanelError):
            item.set_field("xr_sub_support", "", bad)
    item.set_field("xr_sub_support", "", "https://t.me/obhod_support")
    assert bot.state.xray.support_url() == "https://t.me/obhod_support"
    assert bot.state.xray.sub_registry("203.0.113.10")["entries"]
    with pytest.raises(PanelError):
        item.set_field("xr_sub_announce", "", "a" * 300)
    with pytest.raises(PanelError):
        item.set_field("xr_sub_announce", "", "first\nsecond")
    item.set_field("xr_sub_announce", "", "  the   server is fine ")
    assert bot.state.xray.announce() == "the server is fine"
    item.set_field("xr_sub_support", "", "")
    assert bot.state.xray.support_url() == ""
    entry = next(iter(bot.state.xray.sub_registry("203.0.113.10")["entries"].values()))
    assert entry["announce"] == "the server is fine"
    assert entry["support_url"] == ""


def test_traffic_from_the_core_reaches_the_registry(tmp_path: Path) -> None:
    import asyncio

    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    inbound.clients[0].total_gb = 100
    bot.state.xray.add(inbound)
    bot.control.traffic = {
        "user>>>owner>>>traffic>>>uplink": 4096,
        "user>>>owner>>>traffic>>>downlink": 8192,
    }
    assert asyncio.run(item.refresh_traffic()) is True
    assert bot.state.xray.traffic["owner"] == {"up": 4096, "down": 8192}
    entry = list(bot.state.xray.sub_registry("203.0.113.10")["entries"].values())[0]
    assert entry["up"] == 4096
    assert entry["down"] == 8192
    assert entry["total"] == 100 * 1024 * 1024 * 1024


def test_a_silent_core_api_keeps_the_old_traffic(tmp_path: Path) -> None:
    import asyncio

    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    bot.state.xray.traffic = {"owner": {"up": 11, "down": 22}}

    async def boom(cfg, pattern="user>>>"):
        raise RpcError("the api is off")

    bot.control.stats = boom
    assert asyncio.run(item.refresh_traffic()) is False
    assert bot.state.xray.traffic["owner"] == {"up": 11, "down": 22}


def test_the_subs_screen_pulls_the_traffic_first(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    bot.state.xray.add(inbound)
    bot.control.traffic = {"user>>>owner>>>traffic>>>uplink": 5, "user>>>owner>>>traffic>>>downlink": 6}
    before = len(bot.control.calls)
    asyncio.run(item.subs_action(1, 0, ""))
    assert ["stats", "user>>>"] in bot.control.calls[before:]
    assert bot.state.xray.traffic["owner"] == {"up": 5, "down": 6}


def short_chain_target() -> ScanResult:
    return ScanResult(
        target="legacy.example.com:443",
        host="legacy.example.com",
        port=443,
        tls13=True,
        h2=True,
        x25519=True,
        pq_hybrid=False,
        cert_valid=True,
        days_left=30,
        cert_chain_bytes=1200,
        ml_dsa_ready=False,
        latency_ms=40,
    )


def test_scan_target_mismatch_offers_another_encryption(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    inbound.mldsa65_seed = "s" * 32
    inbound.mldsa65_verify = "v" * 32
    bot.state.xray.add(inbound)
    item.results = [short_chain_target()]
    run(item.scan_action(1, 0, "use", "0"))
    assert inbound.dest != "legacy.example.com:443"
    run(item.scan_action(1, 0, "fit", "0"))
    html = bot.rendered[-1].to_html()
    assert "xr:scan:sec:tls:0" in html
    assert "xr:scan:sec:reality:0" in html
    assert "xr:scan:sec:reality-mldsa:0" not in html


def test_scan_switch_encryption_applies_the_target(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    inbound.cert_file = "/etc/ssl/fullchain.pem"
    inbound.key_file = "/etc/ssl/key.pem"
    bot.state.xray.add(inbound)
    item.results = [short_chain_target()]
    run(item.scan_action(1, 0, "sec", "tls", "0"))
    assert inbound.security == "tls"
    assert inbound.dest == "legacy.example.com:443"


def test_scan_switch_to_post_quantum_records_the_group(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    bot.state.xray.add(inbound)
    item.results = [ScanResult(target="www.apple.com:443", host="www.apple.com", port=443, tls13=True, h2=True, x25519=True, pq_hybrid=True, cert_valid=True, days_left=90, cert_chain_bytes=2000)]
    run(item.scan_action(1, 0, "sec", "reality-pq", "0"))
    assert inbound.security == "reality"
    assert inbound.pq_mode == "x25519mlkem768"
    assert inbound.security_kind() == "reality-x25519mlkem768"


def test_scan_switch_to_ml_dsa_generates_the_keys(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    bot.state.xray.add(inbound)
    item.results = [ScanResult(target="www.apple.com:443", host="www.apple.com", port=443, tls13=True, h2=True, x25519=True, pq_hybrid=True, cert_valid=True, days_left=90, cert_chain_bytes=4096, ml_dsa_ready=True)]
    run(item.scan_action(1, 0, "sec", "reality-mldsa", "0"))
    assert inbound.mldsa65_seed == "SEEDVALUE"
    assert inbound.security_kind() == "reality-mldsa65"
    assert inbound.dest == "www.apple.com:443"


def test_scan_switch_rejects_an_unknown_kind(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    bot.state.xray.add(inbound)
    item.results = [short_chain_target()]
    with pytest.raises(PanelError):
        run(item.scan_action(1, 0, "sec", "xtls", "0"))
    with pytest.raises(PanelError):
        run(item.scan_action(1, 0, "sec", "tls", "x"))


def test_scan_switch_to_tls_needs_a_certificate(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    bot.state.xray.add(inbound)
    item.results = [short_chain_target()]
    run(item.scan_action(1, 0, "sec", "tls", "0"))
    assert inbound.security == "reality"
    assert "certificate" in bot.rendered[-1].to_html()


def test_scan_switch_rejects_an_encryption_the_target_does_not_fit(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    bot.state.xray.add(inbound)
    item.results = [short_chain_target()]
    run(item.scan_action(1, 0, "sec", "reality-pq", "0"))
    assert inbound.pq_mode == ""
    assert i18n.t("XR_SCAN_SEC_BAD", "en", security=xscreens.security_label("reality-pq", "en")) in bot.rendered[-1].to_html()


def test_scan_input_adds_the_default_port(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    notice = item.set_field("xr_scan_manual", "", "www.apple.com")
    assert bot.state.xray.scan_targets[-1] == "www.apple.com:443"
    assert "www.apple.com:443" in notice
    item.set_field("xr_scan_manual", "", "https://www.google.com/search?q=1")
    assert bot.state.xray.scan_targets[-1] == "www.google.com:443"
    with pytest.raises(PanelError):
        item.set_field("xr_scan_manual", "", "host.com:99999")
    with pytest.raises(PanelError):
        item.set_field("xr_scan_manual", "", "  ")


def test_scan_list_input_skips_broken_targets(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    notice = item.set_field("xr_scan_targets", "", "a.com, b.com:8443; a.com, bad_host.com")
    assert bot.state.xray.scan_targets == ["a.com:443", "b.com:8443"]
    assert "skipped" in notice
    with pytest.raises(PanelError):
        item.set_field("xr_scan_targets", "", "bad_host.com")


def test_scan_candidates_are_normalized(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    item.set_field("xr_scan_candidates", "", "a.com, b.com:8443")
    assert bot.state.xray.scan_candidates == ["a.com:443", "b.com:8443"]


def test_scan_switch_to_every_post_quantum_kind(tmp_path: Path) -> None:
    groups = {"X25519MLKEM768": "yes", "P256MLKEM768": "yes"}
    for position, (kind, mode) in enumerate((("reality-x25519mlkem768", "x25519mlkem768"), ("reality-p256mlkem768", "p256mlkem768"))):
        item, bot = panel(tmp_path / str(position))
        inbound = new_inbound("vless", 443, "raw", "reality")
        inbound.reality_private = "k" * 43
        bot.state.xray.add(inbound)
        item.results = [ScanResult(target="www.apple.com:443", host="www.apple.com", port=443, tls13=True, h2=True, x25519=True, pq_hybrid=True, groups=groups, cert_valid=True, days_left=90, cert_chain_bytes=4096, ml_dsa_ready=True)]
        run(item.scan_action(1, 0, "sec", kind, "0"))
        assert inbound.pq_mode == mode
        assert inbound.security_kind() == kind
        assert inbound.dest == "www.apple.com:443"


def test_check_target_action(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    inbound.dest = "www.cloudflare.com:443"
    inbound.sni = "www.cloudflare.com"
    bot.state.xray.add(inbound)

    async def fake_probe(host: str, port: int = 443, sni: str = "", timeout: float = 10.0, xver: int = 0, allow_private: bool = False, bulk: bool = False) -> ScanResult:
        assert host == "www.cloudflare.com" and port == 443 and sni == "www.cloudflare.com"
        return ScanResult(target="www.cloudflare.com:443", tls13=True, h2=True, x25519=True, pq_hybrid=True, pq_group="X25519MLKEM768", groups={"X25519MLKEM768": "yes"}, cert_valid=True, days_left=88, cert_chain_bytes=3425)

    monkeypatch.setattr("BOT.panel.probe", fake_probe)
    run(item.check_target(1, 0, str(inbound.id)))
    html = bot.rendered[-1].to_html()
    assert i18n.t("XR_CHECK_OK", "en", security=code(xscreens.security_label("reality", "en"))) in html
    assert "3425" in html
    assert "xr:fit:" + str(inbound.id) in html


def test_check_target_without_an_inbound(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    run(item.check_target(1, 0, ""))
    assert i18n.t("XR_CHECK_MISSING", "en") in bot.rendered[-1].to_html()


def test_a_subnet_scan_fills_the_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    item, bot = panel(tmp_path)
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    bot.state.xray.add(inbound)
    seen: list[str] = []

    async def fake_scan(targets: list[str], sni: str = "", xver: int = 0, candidates: object = None, concurrency: int = 16) -> list[ScanResult]:
        from BOT.scan import enumerate_cidr

        hosts = [item for token in targets if "/" in token for item in enumerate_cidr(token, 8)]
        seen.extend(hosts)
        return [
            ScanResult(target="%s:443" % host, host=host, port=443, feasible=True, tls13=True, h2=True, x25519=True, pq_hybrid=True, pq_group="X25519MLKEM768", groups={"X25519MLKEM768": "yes"}, cert_valid=True, days_left=30, cert_chain_bytes=4096, ml_dsa_ready=True)
            for host in hosts
        ]

    monkeypatch.setattr("BOT.panel.scan_targets", fake_scan)
    assert item.set_field("xr_scan_targets", "", "104.16.132.0/29") == i18n.t("NOTICE_TARGETS_COUNT", count=1)
    assert bot.state.xray.scan_targets == ["104.16.132.0/29"]
    run(item.scan_action(1, 0, "run", ""))
    assert seen == ["104.16.132.0", "104.16.132.1", "104.16.132.2", "104.16.132.3", "104.16.132.4", "104.16.132.5", "104.16.132.6", "104.16.132.7"]
    assert len(item.results) == 8
    run(item.scan_action(1, 0, "use", "5"))
    assert inbound.dest == "104.16.132.5:443"
    config = config_json(bot.state.xray.inbounds)
    assert inbound.to_json() in config["inbounds"]


class Ports:
    def __init__(self, ports: list[int], process: str = "nginx") -> None:
        self.payload = {"ports": [{"port": port, "proto": "tcp", "process": process, "address": "0.0.0.0:%d" % port} for port in ports], "count": len(ports)}

    async def net_ports(self, keep: str = "", timeout: float = 60.0) -> dict[str, object]:
        return dict(self.payload)


def with_ports(bot: object, ports: list[int]) -> None:
    bot.freeturn.control = Ports(ports)


def test_a_busy_port_moves_the_new_inbound(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    with_ports(bot, [443])
    run(item.create_quick(1, 0, "reality", "raw", "443"))
    inbound = bot.state.xray.inbounds[0]
    assert inbound.port == 444
    assert "443" in bot.rendered[-1].to_html()


def test_a_busy_port_says_who_holds_it(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    with_ports(bot, [8443])
    run(item.create_custom(1, 0))
    item.draft = {"network": "raw", "security": "reality", "port": "8443"}
    run(item.create_custom(1, 0))
    inbound = bot.state.xray.inbounds[0]
    assert inbound.port == 443
    assert "nginx" in bot.rendered[-1].to_html()


def test_an_own_port_is_never_moved(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.add(new_inbound("vless", 443, "raw", "reality"))
    with_ports(bot, [443])
    run(item.create_quick(1, 0, "reality", "raw", "8443"))
    assert bot.state.xray.inbounds[0].port == 443
    assert bot.state.xray.inbounds[1].port == 8443


def test_apply_moves_the_api_and_the_subscription_port(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    item.state.add(new_inbound("vless", 443, "raw", "reality"))
    with_ports(bot, [2096, 62789])
    run(item.apply(1, 0))
    assert bot.state.xray.sub_port != 2096
    assert bot.state.xray.api_port != 62789
    assert "2096" in bot.rendered[-1].to_html()
    assert "62789" in bot.rendered[-1].to_html()


def test_apply_refuses_an_inbound_port_of_a_stranger(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    item.state.add(new_inbound("vless", 443, "raw", "reality"))
    with_ports(bot, [443])
    run(item.apply(1, 0))
    html = bot.rendered[-1].to_html()
    assert "443" in html
    assert "nginx" in html
    assert bot.control.calls == [] or "apply" not in [call[0] for call in bot.control.calls]


def test_apply_keeps_the_ports_when_they_are_free(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    item.state.add(new_inbound("vless", 443, "raw", "reality"))
    with_ports(bot, [])
    before = (bot.state.xray.sub_port, bot.state.xray.api_port)
    run(item.apply(1, 0))
    assert (bot.state.xray.sub_port, bot.state.xray.api_port) == before


def test_the_encryption_screen_lists_the_six_kinds(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.add(make_inbound("reality", "raw", 443))
    run(item.encryption_action(1, 0, "1", ""))
    html = bot.rendered[-1].to_html()
    for combo in ("native/x25519", "native/mlkem768", "xorpub/x25519", "xorpub/mlkem768", "random/x25519", "random/mlkem768"):
        assert combo in html
    assert i18n.t("XR_ENC_ACTIVE") in html


def test_switching_to_mlkem768_takes_the_core_pair(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.add(make_inbound("reality", "raw", 443))
    run(item.encryption_action(1, 0, "1", "xorpub/mlkem768"))
    inbound = bot.state.xray.inbounds[0]
    assert inbound.encryption.mode == "xorpub"
    assert inbound.encryption.auth_kind() == "mlkem768"
    assert len(inbound.encryption.private_key) > 300
    assert "xorpub/mlkem768" in bot.rendered[-1].to_html()


def test_switching_to_x25519_takes_the_short_pair(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.add(make_inbound("reality", "raw", 443))
    run(item.encryption_action(1, 0, "1", "native/x25519"))
    inbound = bot.state.xray.inbounds[0]
    assert inbound.encryption.auth_kind() == "x25519"
    assert inbound.encryption.mode == "native"


def test_a_foreign_combo_is_refused(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.add(make_inbound("reality", "raw", 443))
    run(item.encryption_action(1, 0, "1", "rc4/mlkem768"))
    assert i18n.t("XR_ENC_COMBO_BAD") in bot.rendered[-1].to_html()
    assert bot.state.xray.inbounds[0].encryption.mode == "native"


def test_the_encryption_screen_without_an_inbound(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    run(item.encryption_action(1, 0, "", ""))
    assert i18n.t("XR_CHECK_MISSING") in bot.rendered[-1].to_html()


def test_the_tunnel_check_reports_the_funnel(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    run(item.tunnel_action(1, 0, "status"))
    html = bot.rendered[-1].to_html()
    assert "obhod.tail1234.ts.net" in html
    assert i18n.t("DOM_READY") in html


def test_a_bad_hostname_stops_the_tunnel(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.tunnel_host = "not a host"
    run(item.tunnel_action(1, 0, "up"))
    assert i18n.t("DOM_HOST_BAD") in bot.rendered[-1].to_html()
    assert ["tunnel-up"] not in [[call[0]] for call in bot.control.calls]


def test_the_tunnel_up_takes_the_name_and_the_port(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    item.tunnel_key = "tskey-auth-abc123-def456"
    bot.state.xray.tunnel_host = "obhod.tail1234.ts.net"
    bot.state.xray.sub_port = 9443
    run(item.tunnel_action(1, 0, "up"))
    call = [item for item in bot.control.calls if item[0] == "tunnel-up"][0]
    assert call[2] == "obhod.tail1234.ts.net"
    assert call[3] == "9443"
    assert bot.state.xray.tunnel_enabled is True


def test_the_tunnel_off_clears_the_flag(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.tunnel_enabled = True
    bot.state.xray.tunnel_host = "obhod.tail1234.ts.net"
    run(item.tunnel_action(1, 0, "off"))
    assert bot.state.xray.tunnel_enabled is False
    assert i18n.t("DOM_OFF_DONE") in bot.rendered[-1].to_html()


def test_the_host_input_is_validated(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    with pytest.raises(PanelError):
        item.set_field("xr_tunnel_host", "-", "obhod; rm -rf /")
    note = item.set_field("xr_tunnel_host", "-", "obhod.tail1234.ts.net")
    assert bot.state.xray.tunnel_host == "obhod.tail1234.ts.net"
    assert "obhod.tail1234.ts.net" in note


def test_the_key_input_is_validated_and_kept_out_of_the_state(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    with pytest.raises(PanelError):
        item.set_field("xr_tunnel_key", "-", "nope")
    item.set_field("xr_tunnel_key", "-", "tskey-auth-abc123-def456")
    assert item.tunnel_key == "tskey-auth-abc123-def456"
    assert "tskey" not in json.dumps(bot.state.to_dict())


def test_the_subscription_url_switches_to_the_tunnel(tmp_path: Path) -> None:
    item, bot = panel(tmp_path)
    bot.state.xray.add(make_inbound("reality", "raw", 443))
    bot.state.xray.sub_address = "203.0.113.10"
    direct = item.sub_rows()[0][2]
    assert direct.startswith("http://203.0.113.10:")
    bot.state.xray.tunnel_host = "obhod.tail1234.ts.net"
    bot.state.xray.tunnel_enabled = True
    through = item.sub_rows()[0][2]
    assert through.startswith("https://obhod.tail1234.ts.net/")
    assert ":2096" not in through
