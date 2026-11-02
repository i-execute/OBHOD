from __future__ import annotations

import re

import pytest
from goygram.rich import Rich

from BOT import i18n
from BOT.ui import (
    MAX_BUTTONS,
    big,
    bold,
    button,
    bullet_list,
    chip,
    code,
    copy_button,
    copy_row,
    count_buttons,
    details,
    fitted,
    divider,
    esc,
    heading,
    muted,
    input_row,
    long_block,
    numbered,
    pre,
    quote,
    row,
    screen,
    status_line,
    table,
    validate_buttons,
)

BUTTON_RE = re.compile(r"<tg-button [^>]*>")
ROW_RE = re.compile(r"<tg-button-row[^>]*>(.*?)</tg-button-row>", re.S)


def test_esc_and_helpers() -> None:
    assert esc("<b>&\"") == "&lt;b&gt;&amp;&quot;"
    assert code("x") == "<code>x</code>"
    assert bold("x") == "<b>x</b>"
    assert muted("x").startswith("<span")
    assert chip("x") == "<mark>x</mark>"


def test_button_html_shape() -> None:
    html = button("Menu", "nav:home").html()
    assert html.startswith('<tg-button type="callback_data"')
    assert 'data="nav:home"' in html
    assert html.endswith(">Menu</tg-button>")


def test_button_rejects_long_callback() -> None:
    with pytest.raises(ValueError):
        button("x", "a" * 65).html()


def test_copy_button_is_text_type() -> None:
    html = copy_button("Copy", "freeturn://abc")
    assert 'type="copy_text"' in html
    assert 'text="freeturn://abc"' in html


def test_row_wraps_buttons() -> None:
    html = row(button("a", "x"), button("b", "y"))
    assert html.startswith("<tg-button-row align=\"left\">")
    assert html.endswith("</tg-button-row>")
    assert count_buttons(html) == 2


def test_big_is_single_button_row() -> None:
    html = big("Apply", "srv:apply", "success")
    assert count_buttons(html) == 1
    assert 'style="success"' in html
    assert html.count("<tg-button-row") == 1


def test_table_escapes_keys_not_values() -> None:
    html = table([("<k>", code("v"))])
    assert "<td>&lt;k&gt;</td>" in html
    assert "<td><code>v</code></td>" in html


def test_lists_details_quote_pre() -> None:
    assert bullet_list(["a", "b"]) == "<ul><li>a</li><li>b</li></ul>"
    assert numbered(["a"]).startswith("<ol>")
    assert details("t", "b").startswith("<details><summary>t</summary>")
    assert quote("x") == "<blockquote>x</blockquote>"
    assert heading("t", 2) == "<h2>t</h2>"
    assert divider() == "<hr/>"
    assert pre("a<b") == "<pre>a&lt;b</pre>"
    assert pre("{}", "json").startswith('<pre><code class="language-json">')


def test_screen_returns_rich_with_buttons() -> None:
    rich = screen("Title", "subtitle", ["<p>x</p>"], [big("a", "nav:home")], footer=muted("f"))
    assert isinstance(rich, Rich)
    html = rich.build()
    assert html.startswith("<h2>Title</h2>")
    assert "subtitle" in html
    assert "<hr/>" in html
    assert count_buttons(html) == 1
    assert html.rstrip().endswith("</footer>")


def test_screen_without_buttons_has_no_divider() -> None:
    html = screen("t", "", [], []).build()
    assert "<hr/>" not in html


def test_screen_every_button_is_inside_a_row() -> None:
    html = screen("t", "", [], [big("a", "x"), row(button("b", "y"), button("c", "z"))]).build()
    inside = sum(count_buttons(body) for body in ROW_RE.findall(html))
    assert inside == count_buttons(html)


def test_validate_buttons_limit() -> None:
    html = "".join(row(button(str(i), f"d{i}")) for i in range(MAX_BUTTONS))
    validate_buttons(html)
    html = "".join(row(button(str(i), f"d{i}")) for i in range(MAX_BUTTONS + 1))
    with pytest.raises(ValueError):
        validate_buttons(html)


def test_status_line_states() -> None:
    assert "not connected" in status_line(False, False, False)
    assert "not installed" in status_line(True, False, False)
    assert "running" in status_line(True, True, True)
    assert "stopped" in status_line(True, False, True)


def test_copy_row_respects_the_platform_limit() -> None:
    from BOT.ui import COPY_TEXT_LIMIT, long_payload

    assert "copy_text" in copy_row("copy", "x" * COPY_TEXT_LIMIT)
    assert copy_row("copy", "x" * (COPY_TEXT_LIMIT + 1)) == ""
    assert copy_row("copy", "") == ""
    assert "freeturn://" in long_payload("freeturn://" + "a" * 900)
    assert long_payload("") == ""


def test_long_block_is_a_collapsed_summary() -> None:
    html = long_block("whole config", "A" * 400)
    assert html.startswith("<details>")
    assert "<summary>whole config</summary>" in html
    assert "A" * 400 in html
    assert long_block("t", "") == ""


def test_fitted_keeps_short_text_on_a_button() -> None:
    button_html, block_html = fitted("copy", "https://example.com/sub", "en")
    assert "copy_text" in button_html
    assert block_html == ""


def test_fitted_moves_long_text_into_the_summary() -> None:
    long_url = "vless://" + "a" * 900
    button_html, block_html = fitted("copy", long_url, "en")
    assert button_html == ""
    assert "<details>" in block_html
    assert long_url in block_html
    assert i18n.t("UI_LONG_HINT", "en") in block_html


def test_input_row_prefills_only_a_token() -> None:
    from BOT import inline

    inline.configure("ab" * 32)
    html = input_row("dest", "xr_sni", "1", "en")
    assert html.count("switch_inline_query_current_chat") == 1
    assert "xr_sni" not in html
    assert inline.token_for("xr_sni", "1") in html


def test_input_row_adds_the_list_button_for_fixed_choices() -> None:
    from BOT import inline

    inline.configure("ab" * 32)
    manual = input_row("fingerprint", "xr_fingerprint", "1", "en")
    assert manual.count("switch_inline_query_current_chat") == 2
    assert i18n.t("BTN_LIST", "en") in manual


def test_the_loading_screen_never_repeats_itself() -> None:
    from BOT import screens, ui

    for lang in i18n.LANGUAGES:
        body = i18n.t("LOADING_BODY", lang)
        step = i18n.t("LOADING_STEP", lang)
        html = ui.loading(i18n.t("LOADING_TITLE", lang), body, [step]).to_html()
        assert html.count(body) == 1
        assert html.count(step) == 1
        busy = screens.busy_screen(body, lang, [step]).to_html()
        assert busy.count(body) == 1
        assert busy.count(step) == 1
