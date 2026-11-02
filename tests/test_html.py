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
    assert "&amp;lt;" not in html
    assert "<script" not in html
    assert "\\n" not in html


@pytest.mark.parametrize("name,html", render_all(), ids=[item[0] for item in render_all()])
def test_buttons_have_type_and_payload(name: str, html: str) -> None:
    for tag in re.findall(r"<tg-button [^>]*>", html):
        assert (
            'type="callback_data"' in tag
            or 'type="copy_text"' in tag
            or 'type="switch_inline_query_current_chat"' in tag
        )
        if 'type="callback_data"' in tag:
            assert "data=" in tag
        elif 'type="copy_text"' in tag:
            assert "text=" in tag
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
