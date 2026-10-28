from __future__ import annotations

import random
import string
from pathlib import Path

import pytest

from BOT import inline, ui
from BOT.xray import new_inbound

ROOT = Path(__file__).resolve().parent.parent
ALPHABET = string.printable + "".join(chr(code) for code in range(1, 32)) + "\u0439\u4e2d\U0001F4DD"


def samples(count: int = 400) -> list[str]:
    rng = random.Random(20261028)
    out = ["", " ", "-", "\x00", "\n\n", "a" * 5000, inline.MARKER, inline.MARKER + inline.SEPARATOR]
    for _ in range(count):
        length = rng.randint(0, 80)
        out.append("".join(rng.choice(ALPHABET) for _ in range(length)))
    return out


@pytest.mark.parametrize("text", samples())
def test_the_inline_parser_never_crashes(text: str) -> None:
    inline.configure("ab" * 32)
    assert isinstance(inline.parse_payload(text), tuple)
    assert isinstance(inline.parse_query(text), tuple)
    assert isinstance(inline.parse_result_id(text), tuple)
    assert isinstance(inline.parse_option_id(text), tuple)
    try:
        inline.clean_value("xr_remark", text)
    except inline.InlineError:
        pass


@pytest.mark.parametrize("text", samples(120))
def test_the_inline_results_never_crash(text: str) -> None:
    inline.configure("cd" * 32)
    results = inline.results_for(text, "bot", {}, "en")
    assert isinstance(results, list)
    for item in results:
        assert item["id"]
        assert len(item["id"]) <= 64
        assert item["title"]


@pytest.mark.parametrize("text", samples(120))
def test_a_rendered_value_never_breaks_the_html(text: str) -> None:
    html = ui.screen("title", "subtitle", [ui.quote(ui.bold(text)), ui.pre(text)], [ui.row(ui.button("b", "nav:home"))])
    rendered = html.to_html()
    assert "<script" not in rendered.lower()
    assert "\x00" not in rendered


@pytest.mark.parametrize("text", samples(80))
def test_a_hostile_remark_stays_inside_one_line(text: str) -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.remark = text[:40]
    inbound.make_client("owner")
    link = inbound.clients[0].ident
    assert link and "\n" not in link


def test_a_hostile_registry_entry_cannot_escape_the_headers(tmp_path: Path) -> None:
    import importlib.util
    import sys

    path = ROOT / "Storage" / "remote" / "sub_server.py"
    spec = importlib.util.spec_from_file_location("fuzz_sub_server", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["fuzz_sub_server"] = module
    spec.loader.exec_module(module)
    hostile = {
        "title": "a\r\nX-Bad: 1",
        "path": "/x\r\nX-Bad: 2",
        "filename": "../../etc/passwd",
        "refresh": "999999",
        "links": ["vless://ok"],
    }
    for key, value in module.header_lines(hostile, "obhod"):
        assert "\r" not in str(value)
        assert "\n" not in str(value)
    assert module.header_safe(None) == ""
    assert module.header_safe("x" * 5000) == "x" * 200
    assert module.refresh_hours({"refresh": "not a number"}) == "12"
    assert module.refresh_hours({"refresh": -5}) == "1"


def test_a_hostile_value_never_reaches_a_callback() -> None:
    html = ui.screen("t", "s", [ui.quote("body")], [ui.row(ui.button("b", "nav:home"))]).to_html()
    assert "callback_data" in html
    with pytest.raises(ValueError):
        ui.button("long", "x" * 65).html()
    assert "nav:home" in ui.button("b", "nav:home").html()
