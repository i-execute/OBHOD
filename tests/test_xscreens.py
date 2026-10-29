from __future__ import annotations

import pytest

from BOT import i18n, xscreens
from BOT.scan import ScanResult
from BOT.ui import MAX_BUTTONS, count_buttons
from BOT.xray import NETWORKS, SECURITIES, SUB_SEGMENT_LEN, new_inbound


def view(security: str = "reality", network: str = "raw") -> xscreens.XrayView:
    from BOT.xray import XrayState

    state = XrayState()
    state.inbounds.append(new_inbound("vless", 443, network, security))
    return xscreens.XrayView(state=state, core={"installed": True, "service": "active", "version": "26.10.29"})


def test_home_and_core_line() -> None:
    item = view()
    html = xscreens.home(item).to_html()
    assert "Xray" in html
    assert "26.10.29" in html
    assert count_buttons(html) <= MAX_BUTTONS
    assert i18n.t("HOME_CORE_MISSING") in xscreens.core_line(xscreens.XrayView(state=item.state, core={"installed": False}), i18n.translator())
    assert i18n.t("HOME_CORE_MISSING", "zh") in xscreens.core_line(xscreens.XrayView(state=item.state, core={"installed": False}, lang="zh"), i18n.translator("zh"))


def test_new_menu_lists_only_supported_values() -> None:
    html = xscreens.new_menu(view()).to_html()
    for network in NETWORKS:
        assert network in html
    for security in SECURITIES:
        assert security in html
    for name in ("vmess", "trojan", "shadowsocks", "ws", "httpupgrade"):
        assert name not in html


def test_custom_menu_shows_relevant_fields() -> None:
    item = view()
    item.draft = {"network": "xhttp", "security": "reality", "port": "443"}
    html = xscreens.custom_menu(item).to_html()
    assert "443" in html
    assert "xr:cyc:network" in html


@pytest.mark.parametrize("security", SECURITIES)
@pytest.mark.parametrize("network", NETWORKS)
def test_inbound_screen_matches_security(security: str, network: str) -> None:
    state_inbound = new_inbound("vless", 8443, network, security)
    state_inbound.make_client("owner")
    item = view(security, network)
    html = xscreens.inbound_screen(item, state_inbound).to_html()
    assert "id" in html
    assert count_buttons(html) <= MAX_BUTTONS
    relevant = xscreens.relevant_fields(security, network)
    if "mldsa65" in relevant:
        assert "ml-dsa-65" in html
    if "service" in relevant:
        assert "grpc" in html or i18n.t("FIELD_SERVICE") in html


def test_inbound_screen_marks_rest_fields_collapsed() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    html = xscreens.inbound_screen(view(), inbound).to_html()
    assert "<details" in html
    assert i18n.t("XR_INBOUND_REST") in html


def test_links_screen_renders_links() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    links = [("owner", "vless://uuid@host:443?security=reality")]
    html = xscreens.links_screen(view(), inbound, "host", links).to_html()
    assert "vless://uuid" in html
    assert "copy_text" in html


def test_links_screen_moves_a_long_link_into_the_summary() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    long_link = "vless://" + "a" * 500
    html = xscreens.links_screen(view(), inbound, "host", [("owner", long_link)]).to_html()
    assert "<details>" in html
    assert long_link in html
    assert "copy_text" not in html


def test_inbound_screen_offers_a_list_for_fixed_choices() -> None:
    from BOT import inline

    inline.configure("ab" * 32)
    inbound = new_inbound("vless", 443, "raw", "reality")
    html = xscreens.inbound_screen(view(), inbound).to_html()
    assert i18n.t("BTN_LIST") in html
    assert inline.list_query("xr_fingerprint", str(inbound.id)) in html


def test_client_screen_fields() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    html = xscreens.client_screen(view(), inbound, "owner", "vless://x", "http://h:2096/a/b", "/a/b").to_html()
    assert "owner" in html
    assert "/a/b" in html
    assert "xtls-rprx-vision" in html


def test_client_screen_missing_client() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    html = xscreens.client_screen(view(), inbound, "ghost", "", "", "").to_html()
    assert i18n.t("XR_CLIENT_MISSING") in html


def test_mldsa_screen() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    html = xscreens.mldsa_screen(view(), inbound).to_html()
    assert "3500" in html
    assert "xr:mldsa" in html


def test_subs_screen_shows_path_format() -> None:
    item = view()
    html = xscreens.subs_screen(item, []).to_html()
    assert "&lt;64&gt;/&lt;64&gt;" in html
    assert "3x-ui" in i18n.t("SET_NOTE_SUB_PATH")
    assert i18n.t("XR_SUBS_NOTE", length=SUB_SEGMENT_LEN) in html
    assert "xr:subs:apply" in html


def test_core_screen_with_and_without_state() -> None:
    item = view()
    html = xscreens.core_screen(item).to_html()
    assert "26.10.29" in html
    empty = xscreens.XrayView(state=item.state)
    assert i18n.t("XR_CORE_UNKNOWN") in xscreens.core_screen(empty).to_html()


def test_scan_screen_with_results() -> None:
    result = ScanResult(
        target="www.google.com:443",
        host="www.google.com",
        port=443,
        feasible=True,
        tls13=True,
        h2=True,
        x25519=True,
        pq_hybrid=True,
        pq_group="x25519mlkem768",
        cert_valid=True,
        days_left=40,
        latency_ms=12,
        server_names=["www.google.com"],
    )
    item = view()
    item.state.scan_targets = ["www.google.com:443"]
    html = xscreens.scan_screen(item, [result]).to_html()
    assert "www.google.com:443" in html
    assert "x25519mlkem768" in html
    assert "xr:scan:use:0" in html


def test_scan_screen_without_results() -> None:
    html = xscreens.scan_screen(view()).to_html()
    assert i18n.t("XR_SCAN_EMPTY") in html
    assert "<code>none</code>" in html
    assert "<code>0</code>" in html
    assert "&lt;code&gt;" not in html


def test_scan_targets_and_input_screens() -> None:
    item = view()
    item.state.scan_targets = ["a:443", "b:443"]
    assert "a:443" in xscreens.scan_targets_screen(item).to_html()
    html = xscreens.input_screen(item, "xr_port", "1", "xr:in:1").to_html()
    assert "switch_inline_query_current_chat" in html
    with pytest.raises(Exception):
        xscreens.input_screen(item, "nope")


def test_confirm_logs_busy() -> None:
    assert "xr:del2:1" in xscreens.confirm_screen(view(), "t", "b", "xr:del2:1").to_html()
    assert "line" in xscreens.logs_screen(view(), ["line"], 200).to_html()
    assert "work" in xscreens.busy_screen("work").to_html()


def test_version_row_and_defaults() -> None:
    assert "xr:core:ver:latest" in xscreens.version_row("v26.10.29")
    assert len(xscreens.default_targets()) >= 100
    assert xscreens.stat_line(new_inbound("vless", 443, "raw", "reality")) == "vless 443 raw reality"
