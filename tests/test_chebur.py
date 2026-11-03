from __future__ import annotations

import json

import pytest

from BOT import chebur, dscreens, i18n, inline, ui


REGISTRY = {
    "id": "ctx-token-123",
    "target": "31.77.12.187",
    "target_type": "IPv4",
    "blocked": False,
    "ips": ["31.77.12.187"],
    "blocked_subnets": [],
    "cdn_providers": {},
    "geo": {"asn": "AS219337", "country_code": "DE", "organisation": "Fzco", "location": "Frankfurt, DE"},
    "reverse_lookup": [],
    "complaints": [{"date": "2026-11-01", "count": 0}, {"date": "2026-11-02", "count": 3}],
}

EVENTS = [
    ("started", {"id": "job-1", "online_probes": 3, "target": "31.77.12.187"}),
    ("result", {"asn": "AS12389", "provider": "Rostelecom", "region": "Krasnodar", "verdicts": ["tspu_block"], "dpi_hop": 1}),
    ("result", {"asn": "AS8359", "provider": "MTS", "region": "Moscow", "verdicts": ["tspu_block"]}),
    ("result", {"asn": "AS3216", "provider": "Beeline", "region": "Tver", "verdicts": ["uncertain"]}),
    ("done", {}),
]


class FakeHandle:
    def __init__(self, body: bytes, lines: list[bytes] | None = None) -> None:
        self.body = body
        self.lines = list(lines or [])
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self.body[:size] if size and size > 0 else self.body

    def readline(self) -> bytes:
        return self.lines.pop(0) if self.lines else b""

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> "FakeHandle":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def sse(events: list[tuple[str, dict]]) -> list[bytes]:
    out: list[bytes] = []
    for name, payload in events:
        out.append(("event:%s\n" % name).encode())
        out.append(("data:%s\n" % json.dumps(payload)).encode())
        out.append(b"\n")
    return out


def install(monkeypatch: pytest.MonkeyPatch, registry: dict | None = None, events: list[tuple[str, dict]] | None = None) -> list[str]:
    seen: list[str] = []

    def fake(url, accept, timeout, stream=False):
        seen.append(url)
        if "probe" in url:
            return FakeHandle(b"", sse(events or EVENTS))
        return FakeHandle(json.dumps(registry if registry is not None else REGISTRY).encode())

    monkeypatch.setattr(chebur, "_request", fake)
    return seen


def test_the_target_needs_to_be_an_address_or_a_domain() -> None:
    assert chebur.clean_target("31.77.12.187") == ("31.77.12.187", "ip")
    assert chebur.clean_target(" Example.COM ") == ("example.com", "domain")
    assert chebur.clean_target("https://cheburcheck.ru/api/v1/check?target=1.1.1.1") == ("cheburcheck.ru", "domain")
    for bad in ("", " ", "1.2.3", "1.2.3.4.5", "256.1.1.1", "0.1.2.3", "224.0.0.1", "[::1]", "a/b", "a b", "-bad.com", "example.c", "x" * 300):
        with pytest.raises(chebur.CheburError):
            chebur.clean_target(bad)


def test_the_registry_answer_is_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = install(monkeypatch)
    registry = chebur.check("31.77.12.187")
    assert seen[0].startswith("https://cheburcheck.ru/api/v1/check?target=31.77.12.187")
    assert registry.blocked is False
    assert registry.geo.asn == "AS219337"
    assert registry.geo.label() == "AS219337, Fzco, Frankfurt, DE"
    assert registry.complaint_total() == 3
    assert registry.complaint_peak() == 3
    assert registry.context == "ctx-token-123"
    assert len(registry.complaint_spark()) == 2


def test_a_broken_registry_answer_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chebur, "_request", lambda *a, **k: FakeHandle(b"not json"))
    with pytest.raises(chebur.CheburError) as error:
        chebur.check("1.1.1.1")
    assert error.value.code == "bad_json"
    monkeypatch.setattr(chebur, "_request", lambda *a, **k: FakeHandle(b"[]"))
    with pytest.raises(chebur.CheburError):
        chebur.check("1.1.1.1")


def test_the_probe_stream_is_aggregated(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch)
    live = chebur.probe("ctx-token-123")
    assert live.online == 3
    assert len(live.results) == 3
    assert live.counts() == {"tspu_block": 2, "uncertain": 1}
    assert live.blocking() == 2
    assert live.share() > 0.6
    assert live.blocked() is True
    assert live.verdict() == "tspu_block"
    assert live.providers_for("tspu_block") == ["Rostelecom", "MTS"]
    assert live.finished is True


def test_the_probe_refuses_an_empty_context() -> None:
    for token in ("", "  ", "a b", "x" * 2000, "line\nbreak"):
        with pytest.raises(chebur.CheburError):
            chebur.probe(token)


def test_a_clean_address_is_not_reported_as_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    clean = [("started", {"online_probes": 2}), ("result", {"provider": "MTS", "verdicts": ["ok"]}), ("result", {"provider": "TTK", "verdicts": ["uncertain"]}), ("done", {})]
    install(monkeypatch, events=clean)
    answer = chebur.lookup("89.125.48.221", live=True)
    assert answer.registry is not None and answer.registry.blocked is False
    assert answer.blocked() is False
    assert answer.verdict() == "clean"
    assert answer.live is not None and answer.live.counts() == {"ok": 1, "uncertain": 1}


def test_the_registry_alone_decides_when_the_probe_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    listed = dict(REGISTRY, blocked=True, blocked_subnets=["31.77.12.0/24"])
    install(monkeypatch, registry=listed)
    answer = chebur.lookup("31.77.12.187", live=False)
    assert answer.registry is not None and answer.registry.subnets == ["31.77.12.0/24"]
    assert answer.blocked() is True
    assert answer.verdict() == "registry"
    assert answer.live is None


def test_a_short_block_share_is_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    mixed = [("started", {"online_probes": 10})]
    for index in range(8):
        mixed.append(("result", {"provider": "MTS", "verdicts": ["ok"]}))
    mixed.append(("result", {"provider": "TTK", "verdicts": ["sni_block"]}))
    mixed.append(("done", {}))
    install(monkeypatch, events=mixed)
    answer = chebur.lookup("1.1.1.1", live=True)
    assert answer.live is not None
    assert answer.live.blocked() is False
    assert answer.verdict() == "partial"


def test_a_failed_probe_keeps_the_registry_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def fake(url, accept, timeout, stream=False):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeHandle(json.dumps(REGISTRY).encode())
        raise chebur.CheburError("cheburcheck is unreachable: timeout", "network")

    monkeypatch.setattr(chebur, "_request", fake)
    answer = chebur.lookup("31.77.12.187", live=True)
    assert answer.registry is not None
    assert answer.live is None
    assert answer.error.startswith("cheburcheck is unreachable")
    assert answer.verdict() == "clean"


def test_the_screen_renders_in_every_language(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch)
    answer = chebur.lookup("31.77.12.187", live=True)
    for language in i18n.LANGUAGES:
        view = dscreens.DbgView(chebur=answer, chebur_target="31.77.12.187", target="31.77.12.187", emoji=False, lang=language)
        html = dscreens.chebur_screen(view).to_html()
        assert "31.77.12.187" in html
        assert "dbg:chk:probe" in html
        assert "dbg:chk:both" in html
        assert i18n.t("CHK_NOTE", language) in html
        assert "{" not in html
        ui.validate_buttons(html)


def test_the_empty_screen_offers_the_input() -> None:
    view = dscreens.DbgView(emoji=False, lang="en")
    html = dscreens.chebur_screen(view).to_html()
    assert i18n.t("CHK_NO_ANSWER", "en") in html
    assert i18n.t("CHK_ST_UNKNOWN", "en") in html
    assert "switch_inline_query_current_chat" in html


def test_the_screen_never_leaks_a_traceback() -> None:
    answer = chebur.Answer(target="1.1.1.1", error="cheburcheck answered 502", code="http_502")
    view = dscreens.DbgView(chebur=answer, emoji=False, lang="en")
    html = dscreens.chebur_screen(view).to_html()
    assert "cheburcheck answered 502" in html
    assert "Traceback" not in html


def test_the_debug_home_offers_the_checker() -> None:
    html = dscreens.home(dscreens.DbgView(emoji=False, lang="en")).to_html()
    assert "dbg:chk" in html
    assert i18n.t("CHK_BTN_OPEN", "en") in html


def test_the_field_is_registered_for_the_inline_input() -> None:
    item = inline.field("dbg_chk_target")
    assert item.ident == "dbg_chk_target"
    assert item.label("ru")
    assert item.hint("zh")
    assert not item.secret
    inline.configure("test-secret")
    token = inline.token_for("dbg_chk_target", "-")
    results = inline.results_for("%s 89.125.48.221" % token, lang="en")
    assert results
    body = results[0]["input_message_content"]["message_text"]
    token_out, kind, index, payload = inline.parse_payload(body)
    assert inline.value_from_payload(token_out, kind, index, payload, "en") == "89.125.48.221"


def test_the_api_base_is_https_only() -> None:
    assert chebur.BASE.startswith("https://")
    assert chebur.CHECK_PATH.startswith("/api/v1/check")
    assert chebur.PROBE_PATH.startswith("/api/v1/probe/")
    assert chebur.PROBE_DEADLINE <= 300


def test_the_sparkline_never_exceeds_its_marks() -> None:
    registry = chebur.Registry(complaints=[chebur.Complaint("2026-11-01", value) for value in (0, 1, 5, 12, 0)])
    spark = registry.complaint_spark()
    assert len(spark) == 5
    assert spark[3] == "#"
    assert spark[0] == " "
    assert chebur.Registry().complaint_spark() == ""
