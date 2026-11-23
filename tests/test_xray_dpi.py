from __future__ import annotations

import json

import pytest

from BOT import xray
from BOT.xray import (
    DEFAULT_FINGERPRINT,
    FINGERPRINTS,
    MASS_FINGERPRINTS,
    MUX_CONCURRENCY,
    SYNTHETIC_FINGERPRINTS,
    VISION_FLOW,
    XrayError,
    XrayInbound,
    client_config,
    client_stream,
    config_json,
    mux_block,
    mux_ignored,
    sockopt_block,
)


def inbound(**kwargs) -> XrayInbound:
    body = dict(
        id=1,
        port=443,
        network="raw",
        security="reality",
        sni="www.example.com",
        dest="www.example.com:443",
        short_ids=["a1b2c3d4"],
        reality_private="priv",
        reality_public="pub",
    )
    body.update(kwargs)
    item = XrayInbound(**body)
    item.encryption = xray.VlessEncryption(private_key="a" * 32, public_key="b" * 32)
    item.clients = [xray.XrayClient(ident="11111111-1111-1111-1111-111111111111", email="phone", flow="", enable=True)]
    return item


def test_the_default_fingerprint_is_not_the_mass_one() -> None:
    assert DEFAULT_FINGERPRINT == "firefox"
    assert DEFAULT_FINGERPRINT not in MASS_FINGERPRINTS
    assert MASS_FINGERPRINTS == ("chrome",)
    assert SYNTHETIC_FINGERPRINTS == ("randomized",)
    assert XrayInbound().fingerprint == DEFAULT_FINGERPRINT
    assert XrayInbound.from_dict({}).fingerprint == DEFAULT_FINGERPRINT


def test_the_catalog_carries_every_documented_fingerprint() -> None:
    for name in ("chrome", "firefox", "edge", "safari", "ios", "android", "360", "qq", "random", "randomized"):
        assert name in FINGERPRINTS
    assert len(set(FINGERPRINTS)) == len(FINGERPRINTS)
    assert FINGERPRINTS[0] == "firefox"


def test_a_link_without_a_fingerprint_falls_back_to_the_safe_one() -> None:
    item = inbound(fingerprint="")
    link = xray.vless_link(item, item.clients[0], "203.0.113.9")
    assert "fp=firefox" in link
    item.fingerprint = "qq"
    assert "fp=qq" in xray.vless_link(item, item.clients[0], "203.0.113.9")


def test_every_inbound_closes_the_mptcp_listener() -> None:
    for network in ("raw", "grpc", "xhttp"):
        for security in ("reality", "tls", "none"):
            stream = inbound(network=network, security=security).stream()
            assert stream["sockopt"]["tcpMptcp"] is False
            assert stream["sockopt"]["acceptProxyProtocol"] is False
    assert sockopt_block()["tcpMptcp"] is False


def test_the_generated_config_keeps_the_sockopt_block() -> None:
    config = config_json([inbound()])
    body = json.loads(json.dumps(config))
    for item in body["inbounds"]:
        if "streamSettings" in item:
            assert item["streamSettings"]["sockopt"]["tcpMptcp"] is False


def test_mux_is_off_under_vision_and_on_otherwise() -> None:
    assert mux_ignored(VISION_FLOW) is True
    assert mux_block(VISION_FLOW) == {}
    assert mux_block("") == {"enabled": True, "concurrency": MUX_CONCURRENCY}
    assert MUX_CONCURRENCY == 8


def test_the_client_config_carries_mux_only_where_it_works() -> None:
    plain = inbound()
    client = plain.clients[0]
    body = client_config(plain, client, "203.0.113.9")
    assert body["outbounds"][0]["mux"] == {"enabled": True, "concurrency": 8}
    assert body["outbounds"][0]["streamSettings"]["sockopt"]["tcpMptcp"] is False
    assert body["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] == "firefox"

    vision = inbound()
    vision.clients = [xray.XrayClient(ident="22222222-2222-2222-2222-222222222222", email="tv", flow=VISION_FLOW, enable=True)]
    body = client_config(vision, vision.clients[0], "203.0.113.9")
    assert "mux" not in body["outbounds"][0]
    assert body["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] == VISION_FLOW


def test_the_client_config_refuses_an_inbound_without_keys() -> None:
    item = inbound()
    item.encryption = xray.VlessEncryption()
    with pytest.raises(XrayError):
        client_config(item, item.clients[0], "203.0.113.9")


def test_the_client_stream_mirrors_the_server_security() -> None:
    assert client_stream(inbound()).get("realitySettings") is not None
    tls = client_stream(inbound(security="tls", sni="example.com", alpn=["h2"]))
    assert tls["tlsSettings"]["serverName"] == "example.com"
    assert tls["tlsSettings"]["alpn"] == ["h2"]
    plain = client_stream(inbound(security="none"))
    assert "realitySettings" not in plain and "tlsSettings" not in plain
