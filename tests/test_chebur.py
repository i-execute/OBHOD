from __future__ import annotations

import json
import threading
from pathlib import Path

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
        self.offset = 0
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        start = self.offset
        end = len(self.body) if not size or size < 0 else min(len(self.body), start + size)
        self.offset = end
        return self.body[start:end]

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


class FakeSocket:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.closed = False

    def close(self) -> None:
        self.closed = True


def fake_dns(monkeypatch: pytest.MonkeyPatch, addresses: list[str] | None = None) -> None:
    rows = list(addresses) if addresses is not None else ["188.120.251.237"]
    infos = [(2, 1, 6, "", (address, 443)) for address in rows]

    def answer(*args, **kwargs):
        if not rows:
            raise chebur.socket.gaierror("no name")
        return infos

    monkeypatch.setattr(chebur.socket, "getaddrinfo", answer)


def test_reach_reports_a_live_port(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_dns(monkeypatch)
    monkeypatch.setattr(chebur.socket, "create_connection", lambda *a, **k: FakeSocket())
    probe = chebur.reach()
    assert probe.state() == "ok"
    assert probe.reachable() is True
    assert probe.addresses == ["188.120.251.237"]
    assert probe.error == ""


def test_reach_reports_a_dead_port(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_dns(monkeypatch)

    def refuse(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(chebur.socket, "create_connection", refuse)
    probe = chebur.reach()
    assert probe.state() == "tcp"
    assert probe.reachable() is False
    assert "timed out" in probe.error


def test_reach_reports_a_dead_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_dns(monkeypatch, [])

    def no_connect(*args, **kwargs):
        raise AssertionError("the port must not be touched when the name does not resolve")

    monkeypatch.setattr(chebur.socket, "create_connection", no_connect)
    probe = chebur.reach()
    assert probe.state() == "dns"
    assert probe.dns_ok is False
    assert probe.addresses == []


def test_a_dead_api_says_the_host_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(url, accept, timeout, stream=False):
        raise chebur.CheburError("cheburcheck is unreachable: timed out", "network")

    monkeypatch.setattr(chebur, "_request", refuse)
    fake_dns(monkeypatch)

    def refuse_port(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(chebur.socket, "create_connection", refuse_port)
    answer = chebur.lookup("31.77.12.187", live=True)
    assert answer.registry is None
    assert answer.reach is not None and answer.reach.reachable() is False
    for language in i18n.LANGUAGES:
        t = lambda key, **values: i18n.t(key, language, **values)
        phrase = dscreens.chebur_quote(t, answer, "31.77.12.187")
        assert phrase == t("CHK_QUOTE_API_DOWN", value=answer.reach.error[:90])
        html = dscreens.chebur_screen(dscreens.DbgView(chebur=answer, chebur_target="31.77.12.187", emoji=False, lang=language)).to_html()
        assert i18n.t("CHK_NET_TITLE", language) in html
        assert "{" not in html
        ui.validate_buttons(html)


def test_a_blocked_address_is_named_as_banned(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch)
    answer = chebur.lookup("31.77.12.187", live=True)
    t = lambda key, **values: i18n.t(key, "en", **values)
    phrase = dscreens.chebur_quote(t, answer, "31.77.12.187")
    assert phrase == t("CHK_QUOTE_BANNED", blocked=2, total=3, target="31.77.12.187")
    assert "will not work from russia" in phrase
    html = dscreens.chebur_screen(dscreens.DbgView(chebur=answer, emoji=False, lang="en")).to_html()
    assert phrase in html


def test_a_clean_address_is_named_as_working(monkeypatch: pytest.MonkeyPatch) -> None:
    clean = [("started", {"online_probes": 2}), ("result", {"provider": "MTS", "verdicts": ["ok"]}), ("result", {"provider": "TTK", "verdicts": ["uncertain"]}), ("done", {})]
    install(monkeypatch, events=clean)
    answer = chebur.lookup("89.125.48.221", live=True)
    t = lambda key, **values: i18n.t(key, "en", **values)
    assert dscreens.chebur_quote(t, answer, "89.125.48.221") == t("CHK_QUOTE_CLEAN", ok=1, total=2, target="89.125.48.221")


def test_the_registry_listing_is_named_as_banned(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, registry=dict(REGISTRY, blocked=True))
    answer = chebur.lookup("31.77.12.187", live=False)
    t = lambda key, **values: i18n.t(key, "en", **values)
    assert dscreens.chebur_quote(t, answer, "31.77.12.187") == t("CHK_QUOTE_REGISTRY")


def test_the_completed_event_ends_the_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    events = [("started", {"online_probes": 1}), ("result", {"provider": "MTS", "verdicts": ["ok"]}), ("completed", {})]
    install(monkeypatch, events=events)
    live = chebur.probe("ctx-token-123")
    assert live.finished is True
    assert live.error == ""
    assert len(live.results) == 1


def test_a_failed_stream_keeps_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    events = [("started", {"online_probes": 1}), ("error", {"message": "the job expired"})]
    install(monkeypatch, events=events)
    live = chebur.probe("ctx-token-123")
    assert live.finished is False
    assert live.error == "the job expired"


def test_the_verdict_is_the_worst_blocking_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    events = [("started", {"online_probes": 3})]
    for _index in range(2):
        events.append(("result", {"provider": "MTS", "verdicts": ["sni_block"]}))
    events.append(("result", {"provider": "TTK", "verdicts": ["tspu_block"]}))
    events.append(("done", {}))
    install(monkeypatch, events=events)
    live = chebur.probe("ctx-token-123")
    assert live.verdict() == "sni_block"
    assert live.blocking_kinds() == ["sni_block", "tspu_block"]
    assert dscreens.chebur_status_key(live.verdict()) == "CHK_ST_SNI"
    assert i18n.t("CHK_ST_SNI", "en") in dscreens.chebur_screen(dscreens.DbgView(chebur=chebur.Answer(target="1.1.1.1", live=live), emoji=False, lang="en")).to_html()


def test_every_error_code_has_a_translated_sentence() -> None:
    for code in ("network", "timeout", "bad_json", "bad_arg", "http_401", "http_429", "http_502", "http_999"):
        key = chebur.error_key(code)
        assert i18n.has_key(key, "en") and i18n.has_key(key, "ru") and i18n.has_key(key, "zh")
    assert chebur.error_key("http_401") == "CHK_ERR_TOKEN"
    assert chebur.error_key("http_429") == "CHK_ERR_RATE"
    answer = chebur.Answer(target="1.1.1.1", error="cheburcheck answered 502", code="http_502")
    html = dscreens.chebur_screen(dscreens.DbgView(chebur=answer, emoji=False, lang="ru")).to_html()
    assert i18n.t("CHK_ERR_HTTP", "ru", value="cheburcheck answered 502") in html


def test_the_panel_runs_the_registry_on_a_worker_thread(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from BOT import chebur as chk
    from tests.fakes import make_bot

    seen: list[str] = []

    def fake_check(host, timeout=chk.CHECK_TIMEOUT):
        seen.append("thread:" + threading.current_thread().name)
        return chk.Registry(target=host, kind="ip", blocked=False, ips=[host], context="ctx-token-123")

    def fake_probe(context, deadline=chk.PROBE_DEADLINE, on_result=None):
        return chk.Live(target="31.77.12.187", online=2, results=[chk.Probe("MTS", "Moscow", "AS1", ["ok"])], finished=True, elapsed=1.0)

    monkeypatch.setattr(chk, "check", fake_check)
    monkeypatch.setattr(chk, "probe", fake_probe)
    bot = make_bot(tmp_path)
    debug = bot.debug
    reply = lambda coro: asyncio.run(coro)
    reply(debug.apply_input(1, "dbg_chk_target", "-", "31.77.12.187"))
    reply(debug.chebur_action(1, 0, "both"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("CHK_QUOTE_CLEAN", "en", ok=1, total=1, target="31.77.12.187") in html
    assert debug.chebur is not None and debug.chebur.verdict() == "clean"
    assert seen and not seen[0].endswith("MainThread")


def test_the_panel_reports_a_dead_api_in_the_quote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from BOT import chebur as chk
    from tests.fakes import make_bot

    def refuse(host, timeout=chk.CHECK_TIMEOUT):
        raise chk.CheburError("cheburcheck is unreachable: timed out", "network")

    monkeypatch.setattr(chk, "check", refuse)
    monkeypatch.setattr(chk, "reach", lambda timeout=chk.REACH_TIMEOUT: chk.Reach(dns_ok=True, tcp_ok=False, latency=8.0, error="timed out"))
    bot = make_bot(tmp_path)
    asyncio.run(bot.debug.chebur_action(1, 0, "check"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("CHK_QUOTE_API_DOWN", "en", value="timed out") in html
    assert i18n.t("CHK_NET_TITLE", "en") in html
    assert i18n.t("CHK_NET_NO", "en") in html
    assert "cheburcheck is unreachable: timed out" not in html


def test_the_reachability_button_measures_the_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from BOT import chebur as chk
    from tests.fakes import make_bot

    monkeypatch.setattr(chk, "reach", lambda timeout=chk.REACH_TIMEOUT: chk.Reach(addresses=["188.120.251.237"], dns_ok=True, tcp_ok=True, latency=0.05))
    bot = make_bot(tmp_path)
    asyncio.run(bot.debug.chebur_action(1, 0, "net"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert "188.120.251.237" in html
    assert i18n.t("CHK_BTN_NET", "en") in html
    assert i18n.t("CHK_NET_YES", "en") in html


def test_a_probe_with_two_blocking_kinds_counts_once() -> None:
    live = chebur.Live(results=[chebur.Probe("MTS", "Moscow", "AS1", ["tspu_block", "sni_block"]), chebur.Probe("TTK", "Tver", "AS2", ["ok"])])
    assert live.counts() == {"tspu_block": 1, "sni_block": 1, "ok": 1}
    assert live.blocking() == 1
    assert live.share() == 0.5


def test_the_api_flags_are_read_strictly() -> None:
    assert chebur.truth(True) is True
    assert chebur.truth("false") is False
    assert chebur.truth("0") is False
    assert chebur.truth(1) is True
    assert chebur.verdict_list("ok") == ["ok"]
    assert chebur.verdict_list(["ok", "", "sni_block"]) == ["ok", "sni_block"]
    assert chebur.verdict_list(None) == []


def test_a_string_verdict_is_not_split_into_letters(monkeypatch: pytest.MonkeyPatch) -> None:
    events = [("started", {"online_probes": "3"}), ("result", {"provider": "MTS", "verdicts": "ok"}), ("done", {})]
    install(monkeypatch, events=events)
    live = chebur.probe("ctx-token-123")
    assert live.online == 3
    assert live.results[0].verdicts == ["ok"]


def test_a_bad_online_counter_does_not_break_the_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    events = [("started", {"online_probes": "many"}), ("result", {"provider": "MTS", "verdicts": ["ok"]}), ("done", {})]
    install(monkeypatch, events=events)
    live = chebur.probe("ctx-token-123")
    assert live.online == 0
    assert len(live.results) == 1


def test_a_trailing_dot_in_a_domain_is_dropped() -> None:
    assert chebur.clean_target("example.com.") == ("example.com", "domain")


def test_a_subnet_and_an_as_number_are_accepted() -> None:
    assert chebur.clean_target("31.77.12.0/24") == ("31.77.12.0/24", "subnet")
    assert chebur.clean_target("AS219337") == ("AS219337", "asn")
    assert chebur.clean_target("as219337") == ("AS219337", "asn")
    assert chebur.clean_target("219337") == ("AS219337", "asn")
    for bad in ("31.77.12.0/33", "AS0", "AS99999999999", "example.com/path", "9", "123"):
        with pytest.raises(chebur.CheburError):
            chebur.clean_target(bad)


def test_a_big_registry_answer_is_read_completely(monkeypatch: pytest.MonkeyPatch) -> None:
    huge = dict(REGISTRY, ips=["10.0.%d.%d" % (index // 250, index % 250) for index in range(20000)])
    body = json.dumps(huge).encode()
    assert len(body) > chebur.CHUNK * 2
    monkeypatch.setattr(chebur, "_request", lambda *a, **k: FakeHandle(body))
    registry = chebur.check("AS219337")
    assert registry.ip_count == 20000
    assert len(registry.ips) == chebur.IP_LIST_CAP
    assert registry.blocked is False


def test_an_endless_answer_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    class Endless:
        def read(self, size: int = -1) -> bytes:
            return b"x" * (size if size and size > 0 else 1024)

        def close(self) -> None:
            return None

    monkeypatch.setattr(chebur, "_request", lambda *a, **k: Endless())
    with pytest.raises(chebur.CheburError) as error:
        chebur.check("1.1.1.1")
    assert error.value.code == "bad_json"


def test_the_registry_kind_comes_from_the_validator() -> None:
    assert chebur.Registry(kind="asn").kind == "asn"
    for name in ("CHK_KIND_IP", "CHK_KIND_DOMAIN", "CHK_KIND_SUBNET", "CHK_KIND_ASN", "CHK_IPS_MORE"):
        for language in i18n.LANGUAGES:
            assert i18n.has_key(name, language)


def test_a_subnet_target_skips_the_live_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, registry=dict(REGISTRY, target="31.77.12.0/24", ips=["31.77.12.1"] * 10))
    seen: list[str] = []
    original = chebur.probe

    def spy(context, deadline=chebur.PROBE_DEADLINE, on_result=None):
        seen.append(context)
        return original(context, deadline, on_result)

    monkeypatch.setattr(chebur, "probe", spy)
    answer = chebur.lookup("31.77.12.0/24", live=True)
    assert answer.registry is not None and answer.registry.kind == "subnet"
    assert answer.live is None
    assert seen == []
    t = lambda key, **values: i18n.t(key, "en", **values)
    assert dscreens.chebur_quote(t, answer, "31.77.12.0/24") == t("CHK_QUOTE_WIDE", target="31.77.12.0/24")


def test_a_clean_registry_without_a_probe_asks_for_one(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch)
    answer = chebur.lookup("31.77.12.187", live=False)
    t = lambda key, **values: i18n.t(key, "en", **values)
    assert dscreens.chebur_quote(t, answer, "31.77.12.187") == t("CHK_QUOTE_REGISTRY_CLEAN", target="31.77.12.187")
    assert chebur.probe_supported("ip") and chebur.probe_supported("domain")
    assert not chebur.probe_supported("asn") and not chebur.probe_supported("subnet")


def test_a_bad_typed_target_is_answered_not_raised(tmp_path: Path) -> None:
    import asyncio

    from tests.fakes import make_bot

    bot = make_bot(tmp_path)
    asyncio.run(bot.debug.apply_input(1, "dbg_chk_target", "-", "1.2.3"))
    html = (bot.rendered or bot.sent)[-1].to_html()
    assert i18n.t("CHK_BAD_TARGET", "en") in html
    assert bot.debug.chebur_target == ""


def test_a_broken_stream_is_reported_in_the_catalog_language() -> None:
    live = chebur.Live(target="1.1.1.1", online=0, results=[], finished=False, error="the probe stream broke off: reset", elapsed=2.0)
    answer = chebur.Answer(target="1.1.1.1", live=live)
    for language in i18n.LANGUAGES:
        html = dscreens.chebur_screen(dscreens.DbgView(chebur=answer, emoji=False, lang=language)).to_html()
        assert i18n.t("CHK_ERR_PROBE", language, value="the probe stream broke off: reset") in html
        assert i18n.t("CHK_STREAM_CUT", language) in html
