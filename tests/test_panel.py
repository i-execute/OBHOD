from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from BOT import i18n
from BOT.panel import PanelError, XrayPanel, host_port, parse_port, state_report
from BOT.scan import ScanResult
from BOT.xray import SUB_SEGMENT_LEN, XrayState, new_inbound
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
    assert item.address() == "127.0.0.1"


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
