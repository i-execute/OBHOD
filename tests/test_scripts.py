from __future__ import annotations

from pathlib import Path

from BOT import i18n, net, scripts


def test_every_target_names_its_url() -> None:
    for item in scripts.targets():
        url = item.url("v4.1.2")
        assert url.startswith("https://github.com/")
        assert url.endswith(item.asset.rsplit("/", 1)[-1])
        assert "v4.1.2" in url


def test_the_digest_must_be_hexadecimal() -> None:
    assert scripts.valid_digest("a" * 64) == "a" * 64
    assert scripts.valid_digest("A" * 64) == "a" * 64
    assert scripts.valid_digest("z" * 64) == ""
    assert scripts.valid_digest("a" * 63) == ""
    assert scripts.valid_digest(None) == ""


def test_the_cache_is_parsed_and_cleaned() -> None:
    rows = scripts.parse_cache(
        [
            {"name": "install.sh", "digest": "a" * 64, "size": 100, "at": 5},
            {"name": "../../evil", "digest": "b" * 64},
            {"name": "install.sh", "digest": "nonsense"},
        ]
    )
    assert len(rows) == 2
    assert rows[1].digest == ""


def test_the_cache_has_a_ceiling() -> None:
    rows = scripts.parse_cache([{"name": "install.sh", "digest": "a" * 64}] * 500)
    assert len(rows) <= scripts.MAX_SCRIPTS


def test_a_missing_cache_is_pending() -> None:
    report = scripts.merge([], {})
    assert report.records
    assert report.pending()
    assert not report.has_news


def test_a_changed_digest_is_news() -> None:
    cached = [scripts.Record(name="install.sh", digest="a" * 64, size=10, at=1.0)]
    probes = {"freeturn": {"url": "u", "digest": "b" * 64, "size": 11}}
    report = scripts.merge(cached, probes)
    assert report.has_news
    install = [item for item in report.records if item.name == "install.sh"][0]
    assert install.changed
    assert install.state_key() == "SCR_CHANGED"


def test_the_same_digest_is_not_news() -> None:
    cached = [scripts.Record(name="install.sh", digest="a" * 64, size=10, at=1.0)]
    probes = {"freeturn": {"url": "u", "digest": "a" * 64, "size": 10}}
    report = scripts.merge(cached, probes)
    assert not report.has_news
    assert not report.pending()


def test_an_optional_script_never_blocks() -> None:
    cached = [scripts.Record(name="install.sh", digest="a" * 64, size=10, at=1.0)]
    report = scripts.merge(cached, {})
    assert not report.pending()


def test_a_dead_probe_does_not_look_like_news() -> None:
    cached = [scripts.Record(name="install.sh", digest="a" * 64, size=10, at=1.0)]
    report = scripts.merge(cached, {"freeturn": {"error": "download_failed"}})
    assert not report.has_news
    assert report.records[0].error == "download_failed"


def test_the_report_round_trips() -> None:
    report = scripts.merge([], {})
    payload = report.to_dict()
    assert payload["checked_at"] == report.checked_at
    assert len(payload["records"]) == len(report.records)


def test_a_silly_host_is_refused() -> None:
    for bad in ("", " ", "a" * 300, "http://x", "1.2.3.4;rm", "1.2.3.4 && ls", "$(reboot)", "exam ple.com"):
        try:
            net.parse(bad)
        except net.NetError:
            continue
        raise AssertionError(bad)


def test_a_subnet_must_be_small() -> None:
    try:
        net.parse("10.0.0.0/8")
    except net.NetError as exc:
        assert exc.code == "too_big"
    else:
        raise AssertionError("a wide subnet passed")


def test_a_subnet_is_counted_without_the_edges() -> None:
    target = net.parse("203.0.113.0/24")
    assert target.kind == "subnet"
    assert target.count == 254
    assert target.hosts()[0] == "203.0.113.1"


def test_a_host_with_a_port_is_accepted() -> None:
    target = net.parse("example.com:443")
    assert target.host == "example.com"
    assert target.port == 443


def test_a_silly_port_is_refused() -> None:
    for bad in ("example.com:0", "example.com:70000", "example.com:abc"):
        try:
            net.parse(bad)
        except net.NetError:
            continue
        raise AssertionError(bad)


def test_the_port_list_is_validated() -> None:
    assert net.parse_ports("22,80") == [22, 80]
    assert net.parse_ports("22,80,80") == [22, 80]
    assert net.parse_ports("8000-8002") == [8000, 8001, 8002]
    for bad in ("0", "70000", "a", "10-5", "1-99999"):
        try:
            net.parse_ports(bad)
        except net.NetError:
            continue
        raise AssertionError(bad)


def test_the_hop_count_is_bounded() -> None:
    assert net.parse_hops("5") == 5
    assert net.parse_hops("") == net.DEFAULT_HOPS
    for bad in ("0", "21", "abc", "-1"):
        try:
            net.parse_hops(bad)
        except net.NetError:
            continue
        raise AssertionError(bad)


def test_the_scan_answer_is_read() -> None:
    answer = net.scan_raw({"hosts": 2, "results": [{"host": "10.0.0.1", "open": [80]}, {"host": "10.0.0.2", "open": []}]}, "t", 1.5)
    assert answer.hosts == 2
    assert answer.alive == 1
    assert answer.open_ports == ["10.0.0.1:80"]


def test_a_broken_scan_answer_is_reported() -> None:
    answer = net.scan_raw({"message": "no such thing"}, "t", 0.0)
    assert answer.error
    assert net.scan_raw(None, "t", 0.0).error


def test_the_trace_answer_is_read() -> None:
    answer = net.trace_raw({"hops": [{"index": 1, "address": "10.0.0.1", "rtt": 1.25}, {"index": 2, "address": "", "rtt": 0}]}, "t", 2.0)
    assert len(answer.hops) == 2
    assert answer.hops[0].line().startswith("1  10.0.0.1")
    assert answer.hops[1].line() == "2  *"


def test_the_traceback_is_kept_readable() -> None:
    try:
        raise ValueError("boom")
    except ValueError as exc:
        text = net.trace_text(exc)
    assert "Traceback" in text
    assert "ValueError: boom" in text
    assert len(text) <= 3600


def test_the_script_labels_exist_in_every_language() -> None:
    for language in i18n.LANGUAGES:
        for key in ("SCR_TITLE", "SCR_NOTE", "SCR_WARN", "SCR_LIST", "SCR_FETCH", "SCR_KEEP", "SCR_EMPTY"):
            assert i18n.raw(key, language), key


def test_the_debug_labels_exist_in_every_language() -> None:
    from BOT import strings

    for name in dir(strings.EN):
        if not name.startswith("DBG_"):
            continue
        for language in i18n.LANGUAGES:
            assert i18n.raw(name, language), name


def test_the_local_storage_has_no_secrets() -> None:
    root = Path(__file__).resolve().parent.parent
    for path in (root / "Storage").rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert "PRIVATE KEY-----" not in text, path
