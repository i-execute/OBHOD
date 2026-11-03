from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from BOT import chebur, dpi, i18n, screens, ui, xray
from BOT.store import State
from tests.fakes import make_bot


def inbound(**kwargs: Any) -> Any:
    options = {"network": "raw", "security": "reality", "port": 443}
    options.update(kwargs)
    item = xray.new_inbound(**options)
    item.make_client("one")
    return item


def test_the_fingerprint_list_is_split_by_wave() -> None:
    assert dpi.fingerprint_state("chrome") == "suspicious"
    assert dpi.fingerprint_state("Safari") == "suspicious"
    assert dpi.fingerprint_state("ios") == "suspicious"
    assert dpi.fingerprint_state("firefox") == "loyal"
    assert dpi.fingerprint_state("edge") == "loyal"
    assert dpi.fingerprint_state("random") == "unstable"
    assert dpi.fingerprint_state("randomized") == "unstable"
    assert dpi.fingerprint_state("") == "unknown"
    assert dpi.fingerprint_state("opera") == "unknown"


def test_a_new_inbound_no_longer_defaults_to_the_watched_fingerprint() -> None:
    fresh = inbound()
    assert fresh.fingerprint == "firefox"
    assert xray.FINGERPRINTS[0] == "firefox"
    stored = xray.XrayInbound.from_dict({})
    assert stored.fingerprint == "firefox"


def test_the_link_carries_the_chosen_fingerprint() -> None:
    item = inbound()
    client = item.clients[0]
    link = xray.link_for(item, client, "203.0.113.9")
    assert "fp=firefox" in link
    item.fingerprint = "chrome"
    assert "fp=chrome" in xray.link_for(item, client, "203.0.113.9")


def test_the_hosting_list_matches_owners_not_single_letters() -> None:
    assert dpi.hosting_state("AS49505 Selectel") == "selectel"
    assert dpi.hosting_state("Yandex.Cloud") == "yandex"
    assert dpi.hosting_state("VK Cloud, mcs.mail.ru") == "vk"
    assert dpi.hosting_state("Timeweb Ltd") == "timeweb"
    assert dpi.hosting_state("Hetzner Online GmbH") == ""
    assert dpi.hosting_state("") == ""


def test_the_3xui_trap_keys_are_found_anywhere_in_a_config() -> None:
    settings = {"network": "xhttp", "xhttpSettings": {"path": "/x", "extra": {"scMinPostsIntervalMs": "30", "scMaxEachPostBytes": "1000000"}}}
    assert dpi.trap_keys(settings) == ["scMaxEachPostBytes", "scMinPostsIntervalMs"]
    assert dpi.trap_keys({"xhttpSettings": {"path": "/only"}}) == []
    assert dpi.trap_keys(None) == []
    assert dpi.risky_interval("30") is True
    assert dpi.risky_interval(600) is False
    assert dpi.risky_interval("fast") is True


def test_one_inbound_with_chrome_and_one_name_is_the_whole_chain() -> None:
    item = inbound()
    item.fingerprint = "chrome"
    report = dpi.audit([item])
    assert report.chain() is True
    assert report.level() == "high"
    assert report.risks == ["fingerprint", "single_sni", "vision_mux"]


def test_a_second_server_name_breaks_the_chain() -> None:
    item = inbound()
    item.fingerprint = "chrome"
    item.host_header = "cdn.example.net"
    report = dpi.audit([item])
    assert "single_sni" not in report.risks
    assert report.chain() is False


def test_a_missing_tls_is_the_worst_case() -> None:
    report = dpi.audit([inbound(security="none")])
    assert report.level() == "high"
    assert "no_tls" in report.risks


def test_xhttp_and_a_crowd_are_reported() -> None:
    item = inbound(network="xhttp", security="tls")
    item.fingerprint = "firefox"
    for index in range(dpi.PARALLEL_LIMIT):
        item.make_client("user%d" % index)
    report = dpi.audit([item])
    assert "xhttp_posts" in report.risks
    assert "many_clients" in report.risks
    assert report.level() == "medium"


def test_a_disabled_inbound_is_not_audited() -> None:
    item = inbound()
    item.enable = False
    report = dpi.audit([item])
    assert report.inbounds == []
    assert report.level() == "low"


def test_the_hosting_answer_adds_the_first_link() -> None:
    report = dpi.audit([inbound()])
    dpi.apply_hosting(report, "Selectel", "AS49505", "Moscow", "203.0.113.9")
    assert report.hosting == "selectel"
    assert "hosting" in report.risks
    assert report.level() == "high"
    assert report.address == "203.0.113.9"
    assert "AS49505, Selectel" == report.hosting_label


def test_the_screen_renders_in_every_language() -> None:
    item = inbound()
    item.fingerprint = "chrome"
    report = dpi.audit([item])
    for language in i18n.LANGUAGES:
        view = screens.View(state=State(), lang=language)
        html = screens.dpi_screen(view, report).to_html()
        assert i18n.t("DPI_QUOTE", language) in html
        assert i18n.t("DPI_RISK_FINGERPRINT", language) in html
        assert i18n.t("DPI_ADV_TRAP", language) in html
        assert i18n.t("DPI_QUOTE_TWITCH", language) in html
        assert "{" not in html
        ui.validate_buttons(html)
        assert "xr:dpi:host" in html


def test_the_screen_survives_an_empty_state() -> None:
    report = dpi.audit([])
    html = screens.dpi_screen(screens.View(state=State(), lang="en"), report).to_html()
    assert i18n.t("DPI_NO_INBOUNDS", "en") in html
    assert i18n.t("DPI_LEVEL_LOW", "en") in html
    ui.validate_buttons(html)


def test_the_xray_home_offers_the_audit() -> None:
    html = screens.home(screens.View(state=State(), lang="en")).to_html()
    assert "xr:dpi" in html
    assert i18n.t("NAV_DPI", "en") in html


def test_the_route_renders_and_checks_the_hosting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    bot.state.xray.inbounds = [inbound()]
    monkeypatch.setattr(bot, "address", lambda: "203.0.113.9")
    panel = bot.xray
    asyncio.run(panel.route(1, 0, "xr:dpi"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("DPI_TITLE", "en") in html

    def fake_check(host: str, timeout: float = chebur.CHECK_TIMEOUT) -> chebur.Registry:
        return chebur.Registry(target=host, kind="ip", geo=chebur.Geo(asn="AS49505", organisation="Selectel", location="Moscow"))

    monkeypatch.setattr(chebur, "check", fake_check)
    asyncio.run(panel.route(1, 0, "xr:dpi:host"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("DPI_HOST_MATCH", "en") in html
    assert panel.dpi_host is not None


def test_a_failed_hosting_check_is_reported_not_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    bot.state.xray.inbounds = [inbound()]
    monkeypatch.setattr(bot, "address", lambda: "203.0.113.9")

    def refuse(host: str, timeout: float = chebur.CHECK_TIMEOUT) -> chebur.Registry:
        raise chebur.CheburError("cheburcheck is unreachable: timed out", "network")

    monkeypatch.setattr(chebur, "check", refuse)
    asyncio.run(bot.xray.route(1, 0, "xr:dpi:host"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("DPI_HOST_UNKNOWN", "en") in html
    assert bot.xray.dpi_host is None


def test_an_unknown_address_does_not_call_the_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = make_bot(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(chebur, "check", lambda host, timeout=0: calls.append(host))
    monkeypatch.setattr(bot, "address", lambda: "")
    asyncio.run(bot.xray.route(1, 0, "xr:dpi:host"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("DPI_HOST_NONE", "en") in html
    assert calls == []


def test_the_trap_button_reads_the_server_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.xray.inbounds = [inbound(network="xhttp")]
    from BOT.xrayrpc import TrapState

    async def scan(cfg: Any) -> TrapState:
        return TrapState.from_dict({"config_path": "/usr/local/etc/xray/config.json", "found": [{"tag": "in-443", "port": 443, "keys": {"scMinPostsIntervalMs": "30"}}], "count": 1, "inbounds": 1})

    monkeypatch.setattr(bot.xray.control, "dpi_scan", scan)
    asyncio.run(bot.xray.route(1, 0, "xr:dpi:trap"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    ui.validate_buttons(html)
    assert i18n.t("DPI_TRAP_COUNT", "en", count=1) in html
    assert "scMinPostsIntervalMs" in html
    assert "xr:dpi:trapfix" in html


def test_a_failed_trap_scan_is_reported_not_raised(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    from BOT.xrayrpc import XrayError as RpcError

    async def refuse(cfg: Any) -> Any:
        raise RpcError("the transport to the server failed", "transport")

    monkeypatch.setattr(bot.xray.control, "dpi_scan", refuse)
    asyncio.run(bot.xray.route(1, 0, "xr:dpi:trap"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("DPI_TRAP_UNKNOWN", "en") in html
    assert bot.xray.dpi_trap is None
    assert "xr:dpi:trapfix" not in html


def test_the_fix_asks_first_and_then_strips(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    from BOT.xrayrpc import TrapState

    asyncio.run(bot.xray.route(1, 0, "xr:dpi:trapfix"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("DPI_TRAP_CONFIRM_TITLE", "en") in html
    assert "xr:dpi:trapfix2" in html

    async def fix(cfg: Any) -> TrapState:
        return TrapState.from_dict({"config_path": "/etc/xray.json", "found": [], "count": 0, "stripped": 2, "restarted": True})

    monkeypatch.setattr(bot.xray.control, "dpi_fix", fix)
    asyncio.run(bot.xray.route(1, 0, "xr:dpi:trapfix2"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("DPI_TRAP_FIXED", "en", count=2) in html
    assert "xr:dpi:trapfix" not in html
