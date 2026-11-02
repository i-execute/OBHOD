from __future__ import annotations

import pytest

from BOT import i18n, inline
from BOT.inline import (
    FIELDS,
    KIND_INPUT,
    KIND_OPTION,
    MARKER,
    MODE_INPUT,
    MODE_LIST,
    clean_value,
    field,
    list_query,
    options,
    parse_option_id,
    parse_payload,
    parse_query,
    parse_result_id,
    payload_text,
    prefill,
    results_for,
    resolve,
    token_for,
    value_for,
    value_from_payload,
)


@pytest.fixture(autouse=True)
def fixed_secret() -> None:
    inline.configure("ab" * 32)


def text_of(result: dict) -> str:
    return str(result["input_message_content"]["message_text"])


def test_token_is_short_and_stable() -> None:
    first = token_for("xr_fingerprint", "3")
    second = token_for("xr_fingerprint", "3")
    assert first == second
    assert len(first) == inline.TOKEN_LEN
    assert first.isalpha() or first.isalnum()
    assert token_for("xr_fingerprint", "4") != first
    assert token_for("xr_sni", "3") != first


def test_the_value_never_rides_in_the_button() -> None:
    query = prefill("xr_fingerprint", "3")
    assert "fingerprint" not in query
    assert "chrome" not in query
    assert query.endswith(" ")
    assert resolve(query.strip())[0] == "xr_fingerprint"


def test_input_and_list_tokens_differ() -> None:
    manual = token_for("xr_fingerprint", "3", MODE_INPUT)
    listing = token_for("xr_fingerprint", "3", MODE_LIST)
    assert manual != listing
    assert resolve(manual)[2] == MODE_INPUT
    assert resolve(listing)[2] == MODE_LIST
    assert prefill("xr_fingerprint", "3").strip() == manual
    assert list_query("xr_fingerprint", "3") == listing


def test_unknown_token_is_reported() -> None:
    results = results_for("zzzzzzzzzz", "bot", lang="en")
    assert len(results) == 1
    assert results[0]["title"] == i18n.t("INL_STALE", "en")


def test_idle_query_lists_fields() -> None:
    results = results_for("", "bot", lang="en")
    assert len(results) == min(len(FIELDS), inline.MAX_RESULTS)
    assert all(text_of(item) == MARKER or text_of(item).startswith(MARKER) for item in results)
    assert results_for("nonsense", "bot", lang="en") == []


def test_input_token_gives_one_card() -> None:
    query = prefill("xr_port")
    results = results_for(query, "bot", {"xr_port": "443"}, "en")
    assert len(results) == 1
    assert "current value" in results[0]["description"]
    assert parse_result_id(results[0]["id"]) == (KIND_INPUT, query.strip(), -1)


def test_typed_value_is_previewed_with_a_rotating_symbol() -> None:
    query = prefill("xr_remark")
    empty = results_for(query, "bot", {}, "en")[0]["title"]
    short = results_for(query + "ab ", "bot", {}, "en")[0]["title"]
    long_value = results_for(query + "abcdef ", "bot", {}, "en")[0]["title"]
    assert empty.endswith(inline.title_symbol(0))
    assert short.endswith(inline.title_symbol(2))
    assert long_value.endswith(inline.title_symbol(6))
    assert empty != short


def test_list_token_returns_the_whole_catalogue() -> None:
    query = list_query("xr_fingerprint")
    results = results_for(query, "bot", {}, "en")
    titles = [item["title"] for item in results[1:]]
    assert titles == list(options("xr_fingerprint"))
    assert results[0]["title"].startswith(field("xr_fingerprint").label("en"))
    assert results[0]["description"] == i18n.t("INL_LIST_DESC", "en", label=field("xr_fingerprint").label("en"))


def test_fields_without_options_have_no_list() -> None:
    assert inline.has_options("xr_sni") is False
    results = results_for(list_query("xr_sni"), "bot", {}, "en")
    assert len(results) == 1
    assert results[0]["description"] == i18n.t("INL_LIST_EMPTY", "en")


def test_option_id_and_value() -> None:
    query = list_query("xr_fingerprint")
    results = results_for(query, "bot", {}, "en")
    option = results[2]
    kind, token, index = parse_option_id(option["id"])
    assert (kind, token, index) == (KIND_OPTION, query, 1)
    assert value_for(kind, token, index, "", "en") == options("xr_fingerprint")[1]
    assert parse_option_id("i:" + query) == ("", "", -1)
    assert parse_option_id("o:short:0") == ("", "", -1)
    assert parse_option_id("x:" + query + ":0") == ("", "", -1)


def test_value_for_the_manual_card() -> None:
    query = prefill("xr_sni") + "  www.example.com  "
    token = parse_query(query)[0]
    assert value_for(KIND_INPUT, token, -1, query, "en") == "www.example.com"


def test_payload_round_trip() -> None:
    token = token_for("xr_sni")
    text = payload_text(token, KIND_INPUT, -1, "www.example.com")
    assert text.startswith(MARKER)
    assert parse_payload(text) == (token, KIND_INPUT, -1, "www.example.com")


def test_payload_round_trip_with_unicode() -> None:
    token = token_for("xr_remark")
    value = "\u0443\u0437\u0435\u043b-1.example"
    assert parse_payload(payload_text(token, KIND_INPUT, -1, value))[3] == value


def test_payload_of_an_option() -> None:
    token = token_for("xr_fingerprint", "", MODE_LIST)
    text = payload_text(token, KIND_OPTION, 3, "")
    assert parse_payload(text) == (token, KIND_OPTION, 3, "")
    assert value_from_payload(*parse_payload(text)) == options("xr_fingerprint")[3]


def test_payload_rejects_foreign_text() -> None:
    assert parse_payload("hello") == ("", "", -1, "")
    assert parse_payload(MARKER) == ("", "", -1, "")
    assert parse_payload(MARKER + inline.SEPARATOR + "zzz") == ("", "", -1, "")
    assert parse_payload(MARKER + inline.SEPARATOR + "o0") == ("", "", -1, "")


def test_payload_value_is_checked_by_the_field_rules() -> None:
    token = token_for("xr_port")
    assert value_from_payload(token, KIND_INPUT, -1, "70000") == "70000"
    with pytest.raises(inline.InlineError):
        value_from_payload(token, KIND_INPUT, -1, "x" * (inline.MAX_VALUE + 1))


def test_resolve_of_a_foreign_token() -> None:
    assert resolve("aaaaaaaaaa") == ("", "", "")


def test_clean_value_shapes() -> None:
    assert clean_value("xr_remark", "  my   node ") == "my node"
    assert clean_value("xr_dns_servers", "1.1.1.1;8.8.8.8") == "1.1.1.1, 8.8.8.8"
    assert clean_value("ssh_pubkey", "  ssh-ed25519 AAA  ") == "ssh-ed25519 AAA"
    with pytest.raises(inline.InlineError):
        clean_value("xr_remark", "x" * (inline.MAX_VALUE + 1))


def test_results_sources() -> None:
    query = prefill("xr_remark") + "main "
    bot_view = results_for(query, "bot", {}, "en")[0]
    mt_view = results_for(query, "mt", {}, "en")[0]
    assert "input_message_content" in bot_view
    assert mt_view["_"] == "inputBotInlineResult"
    assert mt_view["send_message"]["message"].startswith(MARKER)


def test_every_language_renders() -> None:
    query = list_query("xr_log_level")
    for code in i18n.LANGUAGES:
        results = results_for(query, "bot", {}, code)
        assert results
        assert all(item["title"] for item in results)


def test_every_option_field_has_a_known_label() -> None:
    for ident in inline.OPTIONS:
        assert ident in FIELDS
        assert inline.OPTIONS[ident]


def test_fixed_choice_fields_follow_the_core_allowlists() -> None:
    from BOT.xray import FINGERPRINTS, LOG_LEVELS

    assert options("xr_fingerprint") == tuple(FINGERPRINTS)
    assert options("xr_log_level") == tuple(LOG_LEVELS)
    assert options("xr_client_flow") == ("xtls-rprx-vision",)
    assert "http/1.1" in options("xr_alpn")


def test_every_field_has_a_handler() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "BOT"
    xray_src = (root / "panel.py").read_text(encoding="utf-8")
    ft_src = (root / "ftpanel.py").read_text(encoding="utf-8")
    app_src = (root / "app.py").read_text(encoding="utf-8")
    debug_src = (root / "dbg.py").read_text(encoding="utf-8")
    for ident in FIELDS:
        if ident.startswith("ssh_"):
            pool = app_src
        elif ident.startswith("ft_"):
            pool = ft_src
        elif ident.startswith("dbg_"):
            pool = debug_src
        else:
            pool = xray_src
        assert '"%s"' % ident in pool, ident


def test_every_option_field_is_a_real_field() -> None:
    assert set(inline.OPTIONS) <= set(FIELDS)


def test_no_field_carries_a_credential() -> None:
    for ident in FIELDS:
        for word in ("password", "passwd", "secret", "token", "private"):
            assert word not in ident
