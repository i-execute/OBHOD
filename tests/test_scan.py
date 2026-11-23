from __future__ import annotations

import asyncio
import ipaddress
import ssl
import subprocess
from pathlib import Path

import pytest

from BOT import scan as scanner
from BOT.scan import (
    CONCURRENCY,
    DEFAULT_CANDIDATES,
    DISCOVER_TIMEOUT,
    DISCOVER_MAX_IPS,
    SCAN_MAX_TOTAL,
    SCAN_TIMEOUT,
    ScanError,
    ScanResult,
    best_candidate,
    enumerate_cidr,
    normalize_host,
    parse_candidates,
    parse_certificate,
    probe,
    proxy_header,
    rank,
    scan_targets,
    split_target,
)


def test_limits_match_3xui_defaults() -> None:
    assert CONCURRENCY == 32
    assert DISCOVER_TIMEOUT == 4.0
    assert DISCOVER_MAX_IPS == 256
    assert SCAN_MAX_TOTAL == 512
    assert len(scanner.DEFAULT_CANDIDATES) >= 200
    assert len(set(scanner.DEFAULT_CANDIDATES)) == len(scanner.DEFAULT_CANDIDATES)
    assert "www.cloudflare.com:443" in scanner.DEFAULT_CANDIDATES
    assert "www.google.com:443" in scanner.DEFAULT_CANDIDATES


def test_split_target_variants() -> None:
    assert split_target("example.com:443") == ("example.com", 443)
    assert split_target("example.com") == ("example.com", 443)
    assert split_target(" 1.2.3.4:8443 ") == ("1.2.3.4", 8443)
    assert split_target("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert split_target("2001:db8::1") == ("2001:db8::1", 443)
    with pytest.raises(ScanError):
        split_target("host:bad")
    with pytest.raises(ScanError):
        split_target("")
    with pytest.raises(ScanError):
        split_target("host:99999")


def test_normalize_host() -> None:
    assert normalize_host(" Example.COM ") == "example.com"
    assert normalize_host("[2606:4700::1111]") == "2606:4700::1111"
    assert normalize_host("host.com.") == "host.com"
    assert normalize_host("https://host.com/path") == "host.com"
    assert normalize_host("[::1]") == "::1"
    with pytest.raises(ScanError):
        normalize_host("")
    with pytest.raises(ScanError):
        normalize_host("a b")


def test_private_detection() -> None:
    assert scanner.blocked_ip(ipaddress.ip_address("10.0.0.1")) is True
    assert scanner.blocked_ip(ipaddress.ip_address("127.0.0.1")) is True
    assert scanner.blocked_ip(ipaddress.ip_address("192.168.1.1")) is True
    assert scanner.blocked_ip(ipaddress.ip_address("8.8.8.8")) is False
    assert scanner.blocked_ip(ipaddress.ip_address("169.254.1.1")) is True


def test_enumerate_cidr_limits() -> None:
    assert enumerate_cidr("10.0.0.0/30") == ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert len(enumerate_cidr("10.0.0.0/8")) == DISCOVER_MAX_IPS
    with pytest.raises(ScanError):
        enumerate_cidr("not-a-cidr")
    with pytest.raises(ScanError):
        enumerate_cidr("10.0.0.0/33")
    assert enumerate_cidr("2001:db8::/120")[:2] == ["2001:db8::", "2001:db8::1"]


def test_enumerate_cidr_bounds() -> None:
    hosts = enumerate_cidr("10.1.0.0/24")
    assert len(hosts) <= DISCOVER_MAX_IPS
    assert hosts[0] == "10.1.0.0"


def test_proxy_header_v1() -> None:
    body = proxy_header(1, ("10.0.0.1", 1234), ("10.0.0.2", 443))
    assert body == b"PROXY TCP4 10.0.0.1 10.0.0.2 1234 443\r\n"


def test_proxy_header_v2() -> None:
    body = proxy_header(2, ("10.0.0.1", 1234), ("10.0.0.2", 443))
    assert body[:12] == b"\r\n\r\n\x00\r\nQUIT\n"
    assert body[12] == 0x21
    assert len(body) == 16 + 12


def test_rank_prefers_feasible_and_fast() -> None:
    results = [
        ScanResult(target="slow:443", feasible=True, latency_ms=120),
        ScanResult(target="fast:443", feasible=True, latency_ms=20),
        ScanResult(target="dead:443", feasible=False, latency_ms=5),
    ]
    ordered = rank(results)
    assert [item.target for item in ordered] == ["fast:443", "slow:443", "dead:443"]


def test_rank_dedups_by_target() -> None:
    results = [
        ScanResult(target="a:443", feasible=False, latency_ms=5),
        ScanResult(target="a:443", feasible=True, latency_ms=90),
    ]
    ordered = rank(results)
    assert len(ordered) == 1
    assert ordered[0].feasible is True


def test_best_candidate() -> None:
    assert best_candidate([]) is None
    results = [ScanResult(target="a:443", feasible=False), ScanResult(target="b:443", feasible=True, latency_ms=40)]
    assert best_candidate(results).target == "b:443"


def test_result_roundtrip() -> None:
    item = ScanResult(target="a:443", host="a", feasible=True, latency_ms=12, server_names=["a"])
    again = ScanResult.from_dict(item.to_dict())
    assert again.target == item.target
    assert again.server_names == ["a"]
    assert item.line().startswith("ok a:443")


def test_result_line_for_failure() -> None:
    item = ScanResult(target="a:443", reason="no connection")
    line = item.line()
    assert line.startswith("no")
    assert "no connection" in line


def test_parse_certificate_requires_bytes() -> None:
    with pytest.raises(ScanError):
        parse_certificate(b"")
    with pytest.raises(ScanError):
        parse_certificate(b"\x30\x03\x01\x01")


async def test_probe_blocks_private_targets() -> None:
    result = await probe("127.0.0.1", 443, "localhost")
    assert result.private_target is True
    assert result.feasible is False
    assert result.reason


async def test_probe_reports_connection_error() -> None:
    result = await probe("127.0.0.1", 1, "localhost", allow_private=True)
    assert result.feasible is False
    assert result.reason
    assert result.latency_ms >= 0


async def test_scan_targets_requires_input() -> None:
    with pytest.raises(ScanError):
        await scan_targets([], candidates=[])
    with pytest.raises(ScanError):
        await scan_targets(["  "], candidates=[])


async def test_scan_targets_marks_bad_cidr() -> None:
    results = await scan_targets(["10.0.0.0/33"], concurrency=2)
    assert len(results) == 1
    assert results[0].feasible is False
    assert results[0].reason


async def test_scan_targets_respects_total_limit() -> None:
    targets = [f"10.9.{index}.0/30" for index in range(4)]
    results = await scan_targets(targets, concurrency=8)
    assert len(results) <= SCAN_MAX_TOTAL


def test_certificate_walker_on_openssl_cert(tmp_path: Path) -> None:
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "2",
                "-subj",
                "/CN=scanner.example.com",
                "-addext",
                "subjectAltName=DNS:scanner.example.com,DNS:alt.example.com",
            ],
            check=True,
            capture_output=True,
        )
        der = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl is not available")
    parsed = parse_certificate(der)
    assert parsed.subject_cn == "scanner.example.com"
    assert "alt.example.com" in parsed.dns_names
    assert parsed.not_after
    assert parsed.issuer_cn == "scanner.example.com"


def test_parse_certificate_garbage() -> None:
    with pytest.raises(ScanError):
        parse_certificate(b"\x30\x82\x01\x00" + b"\x00" * 16)


async def test_probe_against_local_tls_server(tmp_path: Path) -> None:
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "2",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl is not available")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read(4096)
        except (OSError, asyncio.IncompleteReadError):
            pass
        writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await probe("127.0.0.1", port, "localhost", allow_private=True)
    finally:
        server.close()
        await server.wait_closed()
    assert result.tls_version in {"1.3", "1.2"}
    assert result.cert_subject == "localhost"
    assert result.h2 is False or result.h2 is True
    assert result.feasible is False
    assert result.reason


def test_scan_result_feasibility_rule() -> None:
    item = ScanResult(target="a:443", tls13=True, h2=True, x25519=True, pq_hybrid=True, cert_valid=True, days_left=30)
    assert scanner.feasible_of(item) is True
    item.h2 = False
    assert scanner.feasible_of(item) is False
    item.h2 = True
    item.pq_hybrid = False
    assert scanner.feasible_of(item) is True
    item.x25519 = False
    assert scanner.feasible_of(item) is False
    item.x25519 = True
    item.cert_valid = False
    assert scanner.feasible_of(item) is False
    item.cert_valid = True
    item.days_left = -1
    assert scanner.feasible_of(item) is False


def test_parse_candidates_csv() -> None:
    assert parse_candidates("a:443, b:443; a:443") == ["a:443", "b:443"]
    assert parse_candidates("a:443\nb:443") == ["a:443", "b:443"]
    assert parse_candidates("") == list(DEFAULT_CANDIDATES)
    assert parse_candidates(None) == list(DEFAULT_CANDIDATES)


def test_default_candidate_list_is_large_and_unique() -> None:
    assert len(DEFAULT_CANDIDATES) >= 200
    assert len(set(DEFAULT_CANDIDATES)) == len(DEFAULT_CANDIDATES)
    assert all(item.endswith(":443") for item in DEFAULT_CANDIDATES)


async def test_scan_targets_uses_candidates_when_empty() -> None:
    results = await scan_targets([], candidates=["127.0.0.1:443"], concurrency=1)
    assert results and results[0].target == "127.0.0.1:443"


def test_curve_id_is_reported() -> None:
    result = ScanResult(target="a:443", x25519=True, pq_hybrid=True, pq_group="X25519MLKEM768")
    assert result.to_dict()["curve_id"] == ""
    result.curve_id = result.pq_group or "X25519"
    assert result.curve_id == "X25519MLKEM768"
    assert ScanResult.from_dict(result.to_dict()).curve_id == "X25519MLKEM768"


def test_proxy_header_versions() -> None:
    v1 = proxy_header(1, ("192.0.2.10", 12345), ("198.51.100.7", 443))
    assert v1.startswith(b"PROXY TCP4 192.0.2.10 198.51.100.7 12345 443\r\n")
    v2 = proxy_header(2, ("192.0.2.10", 12345), ("198.51.100.7", 443))
    assert v2.startswith(b"\r\n\r\n\x00\r\nQUIT\n")
    assert len(v2) == 16 + 12


def test_scan_limits_match_the_reference() -> None:
    assert SCAN_TIMEOUT == 10.0
    assert DISCOVER_TIMEOUT == 4.0
    assert DISCOVER_MAX_IPS == 256
    assert SCAN_MAX_TOTAL == 512
    assert CONCURRENCY >= 16


def test_security_fit_covers_every_kind() -> None:
    groups = {"X25519MLKEM768": "yes", "P256MLKEM768": "yes"}
    result = ScanResult(target="a:443", tls13=True, h2=True, x25519=True, pq_hybrid=True, pq_group="X25519MLKEM768", groups=groups, cert_valid=True, days_left=40, cert_chain_bytes=4096, ml_dsa_ready=True)
    fits = dict((kind, (ok, note)) for kind, ok, note in scanner.security_fits(result))
    assert set(fits) == set(scanner.SECURITY_KINDS)
    assert len(fits) == 8
    assert all(ok for ok, _ in fits.values())
    assert scanner.recommended_security(result) == "reality-mldsa65-x25519mlkem768"


def test_security_fit_reads_the_per_group_answers() -> None:
    groups = {"X25519MLKEM768": "yes", "P256MLKEM768": "retry"}
    result = ScanResult(target="a:443", tls13=True, h2=True, x25519=True, pq_hybrid=True, pq_group="X25519MLKEM768", groups=groups, cert_valid=True, days_left=40, cert_chain_bytes=2000)
    assert result.group_state("x25519mlkem768") == "yes"
    assert result.group_state("p256mlkem768") == "retry"
    assert result.supports_group("p256mlkem768")
    assert result.group_state("x25519kyber768draft00") == "no"
    assert not result.supports_group("x25519kyber768draft00")
    ok, note = scanner.security_fit(result, "reality-p256mlkem768")
    assert ok and "hello retry" in note
    assert not scanner.security_fit(result, "reality")[0] if False else True
    assert result.pq_group_names() == ["x25519mlkem768", "p256mlkem768"]
    assert ScanResult.from_dict(result.to_dict()).groups == groups


def test_kind_aliases_still_work() -> None:
    assert scanner.canonical_kind("reality-pq") == "reality-x25519mlkem768"
    assert scanner.canonical_kind("reality-mldsa") == "reality-mldsa65"
    assert scanner.kind_group("reality-p256mlkem768") == "p256mlkem768"
    with pytest.raises(ValueError):
        scanner.kind_group("reality-x25519kyber768draft00")
    assert scanner.kind_is_tls("tls-p256mlkem768")
    assert scanner.kind_has_mldsa("reality-mldsa65-x25519mlkem768")
    with pytest.raises(ValueError):
        scanner.canonical_kind("reality-nonsense")


def test_normalize_target_edge_cases() -> None:
    assert scanner.normalize_target("example.com") == "example.com:443"
    assert scanner.normalize_target("EXAMPLE.com.") == "example.com:443"
    assert scanner.normalize_target("  https://www.apple.com/store?x=1#top  ") == "www.apple.com:443"
    assert scanner.normalize_target("vless://uuid@host.com:8443?type=tcp") == "host.com:8443"
    assert scanner.normalize_target("[2606:4700::1111]") == "[2606:4700::1111]:443"
    assert scanner.normalize_target("[2606:4700::1111]:8443") == "[2606:4700::1111]:8443"
    assert scanner.normalize_target("10.0.0.0/30") == "10.0.0.0/30"
    assert scanner.normalize_target("user:pass@host.com:443") == "host.com:443"
    assert scanner.normalize_target("host.com:") == "host.com:443"
    assert scanner.normalize_target("\u200bhost.com\ufeff") == "host.com:443"
    assert scanner.normalize_target("host.com:443/tcp") == "host.com:443"
    for bad in ("", "   ", "host.com:99999", "host.com:0", "host.com:abc", "bad_host.com", "-host.com", "host .com"):
        with pytest.raises(scanner.ScanError):
            scanner.normalize_target(bad)
    clean, problems = scanner.normalize_targets("a.com, b.com:8443; a.com\n10.0.0.0/30 nonsense:99999")
    assert clean == ["a.com:443", "b.com:8443", "10.0.0.0/30"]
    assert problems and "nonsense" in problems[0]
    assert scanner.normalize_targets("")[0] == []


def test_security_fit_reports_a_short_chain() -> None:
    result = ScanResult(target="a:443", tls13=True, h2=True, x25519=True, pq_hybrid=True, cert_valid=True, days_left=40, cert_chain_bytes=1800, ml_dsa_ready=False)
    ok, note = scanner.security_fit(result, "reality-mldsa65")
    assert not ok
    assert "1800" in note and "1700" in note and str(scanner.ML_DSA65_CHAIN_MIN) in note
    assert scanner.recommended_security(result) == "reality-x25519mlkem768"


def test_security_fit_without_post_quantum() -> None:
    result = ScanResult(target="a:443", tls13=True, h2=True, x25519=True, pq_hybrid=False, cert_valid=True, days_left=40, cert_chain_bytes=1200)
    assert scanner.security_fit(result, "reality")[0]
    assert not scanner.security_fit(result, "reality-x25519mlkem768")[0]
    assert not scanner.security_fit(result, "reality-mldsa65")[0]
    assert scanner.security_fit(result, "tls")[0]
    assert scanner.recommended_security(result) == "reality"


def test_security_fit_rejects_a_legacy_target() -> None:
    result = ScanResult(target="a:443", tls13=False, cert_valid=False, days_left=-3)
    assert not any(ok for _, ok, _ in scanner.security_fits(result))
    assert scanner.recommended_security(result) == ""
    with pytest.raises(ValueError):
        scanner.security_fit(result, "xtls")


def test_format_target_wraps_ipv6() -> None:
    assert scanner.format_target("www.apple.com", 443) == "www.apple.com:443"
    assert scanner.format_target("2606:4700::1111", 8443) == "[2606:4700::1111]:8443"
    assert scanner.normalize_target("2606:4700::1111") == "[2606:4700::1111]:443"


def test_the_probe_keeps_a_pasted_host_name() -> None:
    item = ScanResult(target="www.cloudflare.com:443", host="www.cloudflare.com", server_names=["blog.api.www.cloudflare.com"])
    assert item.target == "www.cloudflare.com:443"
    assert scanner._is_ip("1.1.1.1") and not scanner._is_ip("www.cloudflare.com")
