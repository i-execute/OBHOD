from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest

from tests.test_screens import render_all as _render_all

VOID = {"br", "hr", "img", "video", "audio", "input", "source"}
ALLOWED = {
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "b", "i", "u", "s", "code", "pre",
    "a", "blockquote", "cite", "aside", "details", "summary", "ul", "ol", "li",
    "table", "caption", "tr", "th", "td", "footer", "mark", "span", "tg-button", "hr",
    "tg-button-row", "tg-spoiler", "figure", "figcaption", "div", "hr", "tg-emoji",
}
ATTRS = {
    "data", "type", "text", "url", "style", "align", "open", "href", "class",
    "bordered", "striped", "query", "emoji-id",
}


class Checker(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.tags: list[str] = []
        self.attrs: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, _ in attrs:
            self.attrs.add(name)
            if name not in ATTRS:
                self.errors.append(f"unknown attribute {name} on {tag}")
        if tag not in ALLOWED:
            self.errors.append(f"unknown tag {tag}")
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            return
        if not self.stack:
            self.errors.append(f"closing {tag} without opening")
            return
        if self.stack[-1] != tag:
            self.errors.append(f"closing {tag} while {self.stack[-1]} is open")
            return
        self.stack.pop()


def render_all() -> list[tuple[str, str]]:
    return [(name, rich.build()) for name, rich in _render_all()]


def render_all_with_icons() -> list[tuple[str, str]]:
    from BOT import ui

    ui.use_icons(True)
    try:
        return [(name, rich.build()) for name, rich in _render_all()]
    finally:
        ui.use_icons(False)


@pytest.mark.parametrize("name,html", render_all(), ids=[item[0] for item in render_all()])
def test_markup_is_balanced(name: str, html: str) -> None:
    checker = Checker()
    checker.feed(html)
    checker.close()
    assert checker.errors == []
    assert checker.stack == []


@pytest.mark.parametrize("name,html", render_all(), ids=[item[0] for item in render_all()])
def test_no_raw_markup_leaks(name: str, html: str) -> None:
    for leaked in ("&amp;lt;", "&lt;code", "&lt;/code", "&lt;b&gt;", "&lt;/b&gt;", "&lt;a ", "&lt;/a&gt;", "&lt;span", "&lt;mark", "&lt;tg-"):
        assert leaked not in html, (name, leaked)
    for block in re.findall(r"<blockquote>(.*?)</blockquote>", html, re.S):
        assert "<code>" not in block, name
    assert "<script" not in html
    assert "\\n" not in html


@pytest.mark.parametrize("name,html", render_all(), ids=[item[0] for item in render_all()])
def test_buttons_have_type_and_payload(name: str, html: str) -> None:
    for tag in re.findall(r"<tg-button [^>]*>", html):
        assert (
            'type="callback_data"' in tag
            or 'type="copy_text"' in tag
            or 'type="switch_inline_query_current_chat"' in tag
            or 'type="url"' in tag
        )
        if 'type="callback_data"' in tag:
            assert "data=" in tag
        elif 'type="copy_text"' in tag:
            assert "text=" in tag
        elif 'type="url"' in tag:
            assert "url=" in tag
        else:
            assert "query=" in tag


def test_screen_is_not_empty() -> None:
    for name, html in render_all():
        if name in {"denied"}:
            continue
        assert len(html) > 60, name


@pytest.mark.parametrize(
    "name,html",
    render_all_with_icons(),
    ids=[item[0] for item in render_all_with_icons()],
)
def test_markup_with_icons_is_balanced(name: str, html: str) -> None:
    checker = Checker()
    checker.feed(html)
    assert checker.errors == [], name
    assert checker.stack == [], name
    assert "tg-emoji" in html, name
    assert "&lt;tg-emoji" not in html, name


def test_extended_screens_and_commit_links_have_valid_html() -> None:
    from BOT import dscreens, ftscreens, screens, tools, ui, xscreens
    from BOT.freeturn import FtClient, FtConfig, FtShare, FtState
    from BOT.scan import ScanResult
    from BOT.store import State
    from BOT.xray import XrayState, new_inbound

    ui.use_icons(True)
    try:
        for flag in (False, True):
            assert "&lt;tg-emoji" not in ui.status_line(flag, flag, flag, "ru")
    finally:
        ui.use_icons(False)

    v = screens.View(state=State(), lang="ru")
    upd_res = screens.update_result_screen(
        v,
        {"git": True, "repo": "i-execute/OBHOD", "commit": "769f155"},
        {"ok": True, "target": "769f155", "subject": "fix <tag> & update", "message": "already up to date", "rollback": True, "source": "5e78240", "steps": ["fetch from origin"]},
    ).build()
    upd_ro = screens.update_screen(
        v,
        {"git": False, "root": "/opt/obhod", "system": {"protected": {"inside": "yes"}, "dest": "/opt/obhod-src", "dest_write": False}},
    ).build()
    ft_view = ftscreens.FtView(
        state=FtState(installed=True, running=True, config=FtConfig()),
        draft=FtConfig(backend="external", connect="127.0.0.1:51820"),
        clients=[FtClient(name="owner", owner=True)],
        share=FtShare(host="89.125.48.221", port=56000, mode="udp", obf_profile="rtpopus3", key_present=True),
        totals={"online": 1, "clients": 1, "rx": 1024, "tx": 2048},
        lang="ru",
    )
    xr_state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    inbound.mldsa65_seed = "s" * 32
    inbound.mldsa65_verify = "v" * 32
    xr_state.add(inbound)
    scan_res = ScanResult(target="a.example:443", host="a.example", port=443, tls13=True, h2=True, x25519=True, pq_hybrid=False, cert_valid=True, days_left=30, cert_chain_bytes=1800, ml_dsa_ready=False)
    samples = [
        ("upd_res", upd_res),
        ("upd_ro", upd_ro),
        ("ft_plan", ftscreens.plan_screen(ft_view).build()),
        ("ft_clients", ftscreens.clients_screen(ft_view).build()),
        ("dbg_stub", dscreens.stub_screen(dscreens.DbgView(lang="ru"), "probe", "timeout", "example.com", "dbg:home").build()),
        ("tools_fortress", tools.fortress_screen(dscreens.DbgView(lang="ru")).build()),
        ("xr_mismatch", xscreens.scan_mismatch_screen(xscreens.XrayView(state=xr_state, lang="ru"), scan_res, inbound, 0).build()),
        ("xr_check", xscreens.target_check_screen(xscreens.XrayView(state=xr_state, lang="ru"), inbound, scan_res).build()),
    ]
    assert 'href="https://github.com/i-execute/OBHOD/commit/769f155"' in upd_res
    assert 'href="https://github.com/i-execute/OBHOD/commit/5e78240"' in upd_res
    for name, html in samples:
        checker = Checker()
        checker.feed(html)
        checker.close()
        assert checker.errors == [], (name, checker.errors)
        assert checker.stack == [], (name, checker.stack)
        for leaked in ("&amp;lt;", "&lt;code", "&lt;b&gt;", "&lt;a ", "&lt;span", "&lt;tg-"):
            assert leaked not in html, (name, leaked)
        for block in re.findall(r"<blockquote>(.*?)</blockquote>", html, re.S):
            assert "<code>" not in block, name


@pytest.mark.parametrize("name,html", render_all(), ids=[item[0] for item in render_all()])
def test_button_rows_carry_only_buttons(name: str, html: str) -> None:
    for inner in re.findall(r"<tg-button-row[^>]*>(.*?)</tg-button-row>", html, re.S):
        stripped = re.sub(r"<tg-button [^>]*>[^<]*</tg-button>", "", inner).strip()
        assert stripped == "" or stripped.startswith("<tg-button"), (name, stripped[:80])


def test_table_headers_come_from_the_catalog() -> None:
    from BOT import i18n

    known = set()
    for catalog in i18n.CATALOGS.values():
        known |= {value for key, value in vars(catalog).items() if key.isupper()}
    for name, html in render_all():
        for header in re.findall(r"<th>([^<]*)</th>", html):
            assert header in known, (name, header)


def test_to_html_preserves_newlines_inside_pre_and_wg_details() -> None:
    from BOT import ftscreens
    from BOT.freeturn import FtClient, FtShare, FtState, normalize_conf

    raw_conf = "[Interface]\\nPrivateKey = abcdef123456=\\nAddress = 10.13.13.2/32\\n[Peer]\\nPublicKey = xyz987=\\nEndpoint = 127.0.0.1:18080"
    conf = normalize_conf(raw_conf)
    assert "\n" in conf and "\\n" not in conf

    view = ftscreens.FtView(
        state=FtState(installed=True, running=True),
        clients=[FtClient(name="owner", owner=True, ip="10.13.13.2/32")],
        share=FtShare(host="198.51.100.5", port=56120, mode="udp", obf_profile="rtpopus3", key_present=True),
        link="freeturn://short",
        conf=conf,
        lang="ru",
    )
    for page in (ftscreens.share_screen(view), ftscreens.client_screen(view, "owner"), ftscreens.logs_screen(ftscreens.FtView(logs=["line1", "line2"]))):
        wire = page.to_html()
        pre_blocks = re.findall(r"<pre(?:\s[^>]*)?>(.*?)</pre>", wire, re.S)
        assert pre_blocks
        for inner in pre_blocks:
            assert "<br>" not in inner
    assert "[Interface]\nPrivateKey = abcdef123456=\nAddress = 10.13.13.2/32\n[Peer]\nPublicKey = xyz987=" in ftscreens.share_screen(view).to_html()

