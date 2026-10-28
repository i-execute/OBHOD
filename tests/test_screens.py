from __future__ import annotations

import re
from pathlib import Path

import pytest

from BOT import i18n, screens
from BOT.guard import BanState, SshState
from BOT.scan import ScanResult
from BOT.store import State, Store
from BOT.ui import MAX_BUTTONS, count_buttons
from BOT.xray import XrayState, new_inbound


def make_view(tmp_path: Path, **kwargs: object) -> screens.View:
    state = State(xray=XrayState())
    state.xray.inbounds.append(new_inbound("vless", 443, "raw", "reality"))
    return screens.View(state=state, **kwargs)


def test_home_renders_without_server_state(tmp_path: Path) -> None:
    view = make_view(tmp_path)
    html = screens.home(view).to_html()
    assert "OBHOD" in html
    assert "vless" in html
    assert count_buttons(html) <= MAX_BUTTONS


def test_home_reports_core_and_ban_state(tmp_path: Path) -> None:
    view = make_view(tmp_path, core={"installed": True, "service": "active", "version": "26.10.21", "listening": [443]})
    html = screens.home(view).to_html()
    assert "26.10.21" in html
    assert "443" in html


def test_ssh_settings_shows_a_local_shell(tmp_path: Path) -> None:
    view = make_view(tmp_path)
    html = screens.ssh_settings(view).to_html()
    assert i18n.t("SSH_LOCAL_MODE") in html
    assert i18n.t("SSH_NO_PASSWORD") in html
    assert "ssh_host" not in html
    assert "switch_inline_query_current_chat" in html
    assert count_buttons(html) <= MAX_BUTTONS


def test_settings_screen_shows_subscription_path_format(tmp_path: Path) -> None:
    html = screens.settings(make_view(tmp_path)).to_html()
    assert "&lt;64&gt;/&lt;64&gt;" in html


def test_ban_screen_reports_jail_and_rules(tmp_path: Path) -> None:
    ban = BanState(installed=True, jails=["obhod-ipl", "obhod-sshd"], banned=["1.2.3.4"], chain_rules=["DROP all -- 1.2.3.4"])
    view = make_view(tmp_path, ban=ban)
    view.state.xray.fail2ban_enabled = True
    html = screens.ban_screen(view).to_html()
    assert "obhod-ipl" in html
    assert "1.2.3.4" in html
    assert "OBHOD-IPL" in html


def test_ban_screen_shows_limits(tmp_path: Path) -> None:
    html = screens.ban_screen(make_view(tmp_path)).to_html()
    assert "maxretry 1" in html
    assert "findtime 32" in html
    assert "LIMIT_IP" in html


def test_sshd_screen_reports_options(tmp_path: Path) -> None:
    item = SshState(ports=[2222], permit_root_login="no", password_authentication="no", service="active", keys=2, key_user="root")
    html = screens.sshd_screen(make_view(tmp_path, sshd=item)).to_html()
    assert "2222" in html
    assert "no" in html
    assert "2" in html


def test_sshd_screen_without_state(tmp_path: Path) -> None:
    html = screens.sshd_screen(make_view(tmp_path)).to_html()
    assert i18n.t("SSHD_NOT_READ") in html


def test_help_mentions_only_supported_surface(tmp_path: Path) -> None:
    html = screens.help_screen(make_view(tmp_path)).to_html()
    for word in ("vless", "raw", "grpc", "xhttp", "reality", "mlkem768x25519plus", "ml-dsa-65"):
        assert word in html
    for word in ("vmess", "trojan", "shadowsocks", "ws", "kcp"):
        assert word not in html


def test_error_and_busy_screens(tmp_path: Path) -> None:
    view = make_view(tmp_path)
    assert "boom" in screens.error_screen(view, i18n.t("ERR_TITLE"), "boom").to_html()
    assert "work" in screens.busy_screen("work").to_html()
    assert i18n.t("DENIED_BODY") in screens.denied().to_html()
    assert i18n.t("DENIED_BODY", "ru") in screens.denied("ru").to_html()
    assert i18n.t("DENIED_BODY", "zh") in screens.denied("zh").to_html()


def test_prompt_screen_uses_inline_input(tmp_path: Path) -> None:
    html = screens.prompt("ssh_new_port").to_html()
    assert "switch_inline_query_current_chat" in html
    html_error = screens.prompt("ssh_new_port", error="bad").to_html()
    assert "bad" in html_error


def test_confirm_and_logs_screens(tmp_path: Path) -> None:
    assert "fb:install" in screens.confirm("t", "b", "fb:install").to_html()
    html = screens.logs_screen(make_view(tmp_path), ["line"], 50).to_html()
    assert "line" in html
    assert "xr:logs:200" in html


def test_subscription_hint_contains_path(tmp_path: Path) -> None:
    html = screens.subscription_hint("/a/b", "http://host:2096/a/b").to_html()
    assert "/a/b" in html
    assert "secrets" in html


def test_subscription_hint_puts_a_long_url_into_the_summary() -> None:
    url = "http://host:2096/" + "a" * 400
    html = screens.subscription_hint("/a/b", url).to_html()
    assert "<details>" in html
    assert i18n.t("UI_LONG_TITLE") in html
    assert "copy_text" not in html


def test_subscription_hint_keeps_a_short_url_on_a_button() -> None:
    html = screens.subscription_hint("/a/b", "http://host:2096/a/b").to_html()
    assert "copy_text" in html
    assert "<details>" not in html


def render_all(lang: str = i18n.DEFAULT_LANGUAGE) -> list[tuple[str, object]]:
    from BOT import xscreens
    from BOT.xray import XrayState as _State

    state = State(xray=_State())
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    state.xray.add(inbound)
    state.xray.scan_targets = ["www.google.com:443"]
    core = {"installed": True, "service": "active", "version": "26.10.21", "listening": [443], "ports": [443]}
    view = screens.View(state=state, core=core, ban=BanState(installed=True, jails=["obhod-ipl"], banned=["1.2.3.4"]), sshd=SshState(ports=[22]), lang=lang)
    xview = xscreens.XrayView(state=state.xray, core=core, lang=lang)
    xview.draft = {"network": "xhttp", "security": "reality", "port": "443"}
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
        days_left=30,
        latency_ms=8,
        server_names=["www.google.com"],
    )
    items: list[tuple[str, object]] = [
        ("home", screens.home(view)),
        ("settings", screens.settings(view)),
        ("ssh_settings", screens.ssh_settings(view)),
        ("ban", screens.ban_screen(view)),
        ("sshd", screens.sshd_screen(view)),
        ("help", screens.help_screen(view)),
        ("prompt", screens.prompt("ssh_new_port", lang)),
        ("confirm", screens.confirm("t", "b", "fb:install", lang)),
        ("logs", screens.logs_screen(view, ["line"], 50)),
        ("busy", screens.busy_screen("busy", lang, ["step"])),
        ("xray_home", xscreens.home(xview)),
        ("xray_new", xscreens.new_menu(xview)),
        ("xray_custom", xscreens.custom_menu(xview)),
        ("xray_inbound", xscreens.inbound_screen(xview, inbound)),
        ("xray_links", xscreens.links_screen(xview, inbound, "203.0.113.10", [("owner", "vless://uuid@host:443")])),
        ("xray_client", xscreens.client_screen(xview, inbound, "owner", "vless://x", "http://h:2096/a/b", "/a/b")),
        ("xray_mldsa", xscreens.mldsa_screen(xview, inbound)),
        ("xray_subs", xscreens.subs_screen(xview, [("owner", "/a/b", "http://h:2096/a/b")])),
        ("xray_core", xscreens.core_screen(xview)),
        ("xray_scan", xscreens.scan_screen(xview, [result])),
        ("xray_targets", xscreens.scan_targets_screen(xview)),
        ("xray_input", xscreens.input_screen(xview, "xr_port", "1", "xr:in:1")),
        ("xray_logs", xscreens.logs_screen(xview, ["line"], 200)),
        ("language", screens.language_screen(view)),
    ]
    return items


def test_store_roundtrip(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    state = State(xray=XrayState())
    state.sub_port = 2096
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    state.xray.add(inbound)
    state.xray.sub_address = "203.0.113.10"
    store.save(state)
    again = store.load()
    assert again.sub_port == 2096
    assert again.xray.inbounds[0].clients[0].email == "owner"
    assert again.xray.inbounds[0].clients[0].sub_key
    assert again.xray.sub_address == "203.0.113.10"


def test_store_ignores_broken_file(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{", encoding="utf-8")
    assert Store(path).load().xray.inbounds == []


def test_store_permissions(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    store.save(State())
    assert oct(store.path.stat().st_mode)[-3:] == "600"


def test_invalid_field_raises(tmp_path: Path) -> None:
    with pytest.raises(Exception):
        screens.prompt("nope")


@pytest.mark.parametrize("lang", i18n.LANGUAGES)
def test_every_screen_renders_in_every_language(lang: str) -> None:
    items = render_all(lang)
    assert len(items) >= 24
    for name, rich in items:
        html = rich.build()
        assert html, name
        assert count_buttons(html) <= MAX_BUTTONS, name


@pytest.mark.parametrize("lang,pattern", [("ru", r"[\u0400-\u04ff]"), ("zh", r"[\u4e00-\u9fff]")])
def test_screens_use_the_selected_alphabet(lang: str, pattern: str) -> None:
    check = re.compile(pattern)
    for name, rich in render_all(lang):
        assert check.search(rich.build()), name


def test_language_screen_lists_every_catalog() -> None:
    view = screens.View(state=State(xray=XrayState()))
    html = screens.language_screen(view).to_html()
    for item in i18n.LANGUAGES:
        assert f"lang:set:{item}" in html
        assert i18n.t("LANG_NAME", item) in html
