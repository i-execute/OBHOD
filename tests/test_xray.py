from __future__ import annotations

import json
import re
import string

import pytest

from BOT.xray import (
    API_PORT,
    API_LISTEN,
    API_SERVICES,
    API_TAG,
    DEFAULT_ACCESS_LOG,
    DEFAULT_ERROR_LOG,
    DEFAULT_METRICS,
    DNS_TAG,
    FINGERPRINTS,
    NETWORKS,
    PROTOCOLS,
    SECURITIES,
    SUB_ALPHABET,
    SUB_SEGMENT_LEN,
    VLESS_CLIENT_MODES,
    VLESS_HANDSHAKE,
    VLESS_MODES,
    VlessEncryption,
    XrayError,
    XrayState,
    config_json,
    config_text,
    gen_sub_segment,
    link_for,
    links_for,
    new_inbound,
    parse_link,
    relevant_fields,
    subscription_payload,
    summary,
    valid_email,
    valid_padding,
    valid_short_id,
    valid_sub_segment,
    vless_link,
    x25519,
    x25519_keypair,
)


def test_protocol_surface_is_post_quantum_only() -> None:
    assert PROTOCOLS == ("vless",)
    assert NETWORKS == ("raw", "grpc", "xhttp")
    assert SECURITIES == ("reality", "tls", "none")
    assert VLESS_HANDSHAKE == "mlkem768x25519plus"
    assert VLESS_MODES == ("native", "xorpub", "random")
    assert VLESS_CLIENT_MODES == ("0rtt", "1rtt")
    assert "chrome" in FINGERPRINTS


def test_sub_segment_is_64_url_safe_chars() -> None:
    seen = set()
    for _ in range(200):
        value = gen_sub_segment()
        assert len(value) == SUB_SEGMENT_LEN == 64
        assert set(value) <= set(SUB_ALPHABET)
        assert "/" not in value and "+" not in value and "=" not in value
        seen.add(value)
    assert len(seen) == 200
    assert set(SUB_ALPHABET) == set(string.ascii_letters + string.digits + "-_")
    assert valid_sub_segment("a" * 64) == "a" * 64
    with pytest.raises(XrayError):
        valid_sub_segment("a" * 63)
    with pytest.raises(XrayError):
        valid_sub_segment("/" * 64)
    with pytest.raises(XrayError):
        valid_sub_segment("a" * 63 + "=")


def test_sub_path_has_two_64_char_segments() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    client = inbound.make_client("owner")
    sub_id, sub_key = client.ensure_subscription()
    assert len(sub_id) == len(sub_key) == 64
    assert client.sub_path() == "/" + sub_id + "/" + sub_key
    assert len(client.sub_path()) == 130


def test_x25519_exchanges_the_same_secret() -> None:
    private_one, public_one = x25519_keypair()
    private_two, public_two = x25519_keypair()
    from BOT.xray import _b64url, _unb64url

    first = x25519(_unb64url(private_one), _unb64url(public_two))
    second = x25519(_unb64url(private_two), _unb64url(public_one))
    assert first == second
    assert len(_b64url(first)) == 43
    scalar = bytes([1] + [0] * 31)
    point = bytes([9] + [0] * 31)
    assert len(x25519(scalar, point)) == 32
    with pytest.raises(XrayError):
        x25519(b"short", point)


def test_encryption_strings_use_the_post_quantum_handshake() -> None:
    lock = VlessEncryption(mode="native", ticket="600s").generate()
    assert lock.decryption().startswith(VLESS_HANDSHAKE + ".native.600s.")
    assert lock.encryption("0rtt").startswith(VLESS_HANDSHAKE + ".native.0rtt.")
    assert lock.private_key and lock.public_key
    with pytest.raises(XrayError):
        VlessEncryption(mode="rc4").generate()
    with pytest.raises(XrayError):
        lock.encryption("2rtt")


def test_inbound_without_keys_refuses_to_render_settings() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.encryption.private_key = ""
    with pytest.raises(XrayError):
        inbound.settings()


def test_new_inbound_networks_and_securities() -> None:
    for network in NETWORKS:
        for security in SECURITIES:
            inbound = new_inbound("vless", 8443, network, security)
            data = inbound.to_json()
            assert data["protocol"] == "vless"
            assert data["streamSettings"]["network"] in {"tcp", "grpc", "xhttp"}
            assert data["streamSettings"]["security"] in {"reality", "tls", "none"}
            assert data["settings"]["decryption"].startswith(VLESS_HANDSHAKE)
    with pytest.raises(XrayError):
        new_inbound("vmess", 443, "raw", "reality")
    with pytest.raises(XrayError):
        new_inbound("vless", 443, "ws", "reality")
    with pytest.raises(XrayError):
        new_inbound("vless", 443, "raw", "xtls")


def test_config_json_is_valid_and_post_quantum_only() -> None:
    inbound = new_inbound("vless", 443, "grpc", "reality")
    inbound.make_client("owner")
    config = config_json([inbound])
    entries = [item for item in config["inbounds"] if item.get("protocol") == "vless"]
    assert entries[0]["settings"]["clients"][0]["id"]
    text = config_text([inbound])
    assert json.loads(text) == config
    assert "mlkem768x25519plus" in text
    for name in ("vmess", "trojan", "shadowsocks", "kcp", "httpupgrade"):
        assert f'"{name}"' not in text


def test_reality_stream_carries_server_names_and_keys() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    stream = inbound.stream()
    assert stream["security"] == "reality"
    assert stream["realitySettings"]["serverNames"] == [inbound.sni]
    assert stream["realitySettings"]["privateKey"]
    assert stream["realitySettings"]["shortIds"]


def test_mldsa65_seed_is_optional_and_gated() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    assert "mldsa65Seed" not in inbound.stream()["realitySettings"]
    inbound.mldsa65_seed = "SEED"
    assert inbound.stream()["realitySettings"]["mldsa65Seed"] == "SEED"
    plain = new_inbound("vless", 443, "raw", "tls")
    plain.mldsa65_seed = "SEED"
    assert "mldsa65Seed" not in json.dumps(plain.stream())


def test_relevant_fields_follow_security_and_network() -> None:
    assert "mldsa65" in relevant_fields("reality", "raw")
    assert "service" in relevant_fields("reality", "grpc")
    assert "path" in relevant_fields("reality", "xhttp")
    assert "cert_file" in relevant_fields("tls", "raw")
    assert relevant_fields("none", "raw") == ()
    assert "service" in relevant_fields("none", "grpc")
    assert "mldsa65" not in relevant_fields("tls", "raw")


def test_vless_link_carries_pq_parameters() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    client = inbound.make_client("owner")
    link = vless_link(inbound, client, "example.com", 443)
    assert link.startswith("vless://")
    assert "security=reality" in link
    assert "pbk=" in link
    assert "encryption=mlkem768x25519plus" in link
    assert "type=tcp" in link
    assert "flow=xtls-rprx-vision" in link
    parsed = parse_link(link)
    assert parsed["protocol"] == "vless"
    assert parsed["params"]["security"] == "reality"
    assert parsed["encryption"].startswith(VLESS_HANDSHAKE)
    assert parsed["post_quantum"] is True


def test_parse_link_rejects_other_protocols_and_empty_encryption() -> None:
    with pytest.raises(XrayError):
        parse_link("vmess://abcdef")
    with pytest.raises(XrayError):
        parse_link("vless://uuid@host:443?security=tls&type=tcp&encryption=none")
    with pytest.raises(XrayError):
        parse_link("")
    inbound = new_inbound("vless", 443, "xhttp", "tls")
    client = inbound.make_client("owner")
    link = link_for(inbound, client, "example.com", 443)
    assert "path=" in link
    assert "type=xhttp" in link


def test_subscription_payload_is_base64_of_links() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    inbound.make_client("phone")
    links = [link for _name, link in links_for(inbound, "example.com", 443)]
    payload = subscription_payload(links)
    import base64

    body = base64.b64decode(payload.encode("ascii")).decode("utf-8")
    assert body.count("vless://") == 2


def test_state_registry_uses_sub_id_as_key() -> None:
    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    state.add(inbound)
    client = inbound.client("owner")
    registry = state.sub_registry("203.0.113.10")
    assert registry["port"] == 2096
    entry = registry["entries"][client.sub_id]
    assert entry["key"] == client.sub_key
    assert entry["path"] == "/" + client.sub_id + "/" + client.sub_key
    assert len(entry["key"]) == 64
    assert entry["links"] and entry["links"][0].startswith("vless://")


def test_state_crud_and_helpers() -> None:
    state = XrayState()
    first = new_inbound("vless", 443, "raw", "reality")
    second = new_inbound("vless", 8443, "xhttp", "tls")
    state.add(first)
    state.add(second)
    assert state.ports() == [443, 8443]
    assert len(state.enabled()) == 2
    second.enable = False
    assert len(state.enabled()) == 1
    assert state.inbound(first.id).port == 443
    assert state.by_remark(first.remark) is first
    assert state.remove(first.id) is True
    assert state.inbound(first.id) is None


def test_adopt_scan_sets_target() -> None:
    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    state.add(inbound)
    state.adopt_scan(inbound.id, "www.microsoft.com", "www.microsoft.com", 443)
    assert inbound.dest == "www.microsoft.com:443"
    assert inbound.sni == "www.microsoft.com"
    with pytest.raises(XrayError):
        state.adopt_scan(9999, "a", "a", 443)


def test_ml_dsa_helpers_gate_security() -> None:
    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    state.add(inbound)
    with pytest.raises(XrayError):
        state.set_mldsa65(inbound.id, "", "VERIFY")
    state.set_mldsa65(inbound.id, "SEED", "VERIFY")
    assert inbound.mldsa65_seed == "SEED"
    state.clear_mldsa65(inbound.id)
    assert inbound.mldsa65_seed == ""
    plain = new_inbound("vless", 8443, "raw", "none")
    state.add(plain)
    with pytest.raises(XrayError):
        state.set_reality_keys(plain.id, "a", "b")


def test_summary_rows_are_readable() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    rows = summary(inbound)
    keys = [row[1] for row in rows]
    assert all(row[0] for row in rows)
    assert all(len(row) == 3 for row in rows)
    assert "protocol" in keys
    assert "network" in keys
    assert "security" in keys


def test_validators() -> None:
    assert valid_email("phone-1") == "phone-1"
    with pytest.raises(XrayError):
        valid_email("bad name")
    assert valid_short_id("") == ""
    with pytest.raises(XrayError):
        valid_short_id("zzzz")
    assert valid_padding("") == ""
    assert valid_padding("60-40-0") == "60-40-0"
    with pytest.raises(XrayError):
        valid_padding("60")
    assert re.fullmatch(r"[0-9a-f]{8}", valid_short_id("abcdef12"))


def test_config_matches_the_reference_sections() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    config = config_json([inbound])
    assert config["log"]["access"] == DEFAULT_ACCESS_LOG
    assert config["log"]["error"] == DEFAULT_ERROR_LOG
    assert config["log"]["dnsLog"] is False
    assert config["log"]["maskAddress"] == ""
    assert config["stats"] == {}
    assert config["api"]["tag"] == API_TAG
    assert config["api"]["services"] == list(API_SERVICES)
    assert config["policy"]["levels"]["0"]["statsUserUplink"] is True
    assert config["policy"]["levels"]["0"]["statsUserDownlink"] is True
    assert config["policy"]["levels"]["0"]["statsUserOnline"] is True
    assert config["policy"]["system"]["statsInboundUplink"] is True
    assert config["policy"]["system"]["statsOutboundUplink"] is False
    assert config["routing"]["domainStrategy"] == "AsIs"
    assert config["routing"]["rules"][0] == {"type": "field", "inboundTag": [API_TAG], "outboundTag": API_TAG}
    assert {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"} in config["routing"]["rules"]
    assert {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"} in config["routing"]["rules"]
    assert config["outbounds"][0]["tag"] == "direct"
    assert config["outbounds"][0]["settings"]["finalRules"][0] == {"action": "block", "ip": ["geoip:private"]}
    assert config["outbounds"][1] == {"protocol": "blackhole", "settings": {}, "tag": "blocked"}
    assert config["metrics"]["listen"] == DEFAULT_METRICS


def test_config_api_inbound_is_local() -> None:
    inbound = new_inbound("vless", 8443, "grpc", "reality")
    inbound.make_client("owner")
    config = config_json([inbound], api_port=62790)
    api = config["inbounds"][0]
    assert api["tag"] == API_TAG
    assert api["listen"] == API_LISTEN
    assert api["port"] == 62790
    assert api["protocol"] == "tunnel"
    assert api["settings"]["rewriteAddress"] == API_LISTEN
    assert config["inbounds"][1]["port"] == 8443


def test_config_can_disable_api_and_metrics() -> None:
    inbound = new_inbound("vless", 443, "raw", "tls")
    inbound.make_client("owner")
    config = config_json([inbound], api_enabled=False, metrics="")
    assert "api" not in config
    assert "metrics" not in config
    assert len(config["inbounds"]) == 1


def test_config_dns_block_is_optional() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    plain = config_json([inbound])
    assert "dns" not in plain
    with_dns = config_json([inbound], dns_servers=["1.1.1.1", "8.8.8.8"])
    assert with_dns["dns"]["servers"] == ["1.1.1.1", "8.8.8.8"]
    assert with_dns["dns"]["queryStrategy"] == "UseIPv4v6"
    assert with_dns["outbounds"][-1]["tag"] == DNS_TAG
    assert with_dns["routing"]["rules"][1]["inboundTag"] == [DNS_TAG]


def test_state_config_uses_its_own_settings() -> None:
    state = XrayState()
    state.inbounds.append(new_inbound("vless", 443, "raw", "reality"))
    state.inbounds[0].make_client("owner")
    state.api_port = 63000
    state.metrics = ""
    state.dns_servers = ["9.9.9.9"]
    state.access_log = "/tmp/access.log"
    config = json.loads(state.to_config())
    assert config["log"]["access"] == "/tmp/access.log"
    assert config["inbounds"][0]["port"] == 63000
    assert "metrics" not in config
    assert config["dns"]["servers"] == ["9.9.9.9"]


def test_state_candidates_helpers() -> None:
    state = XrayState()
    assert len(state.candidates()) >= 100
    assert state.candidates_csv() == ",".join(state.candidates())
    state.scan_candidates = ["a:443"]
    assert state.candidates() == ["a:443"]
    state.dns_servers = ["1.1.1.1", "9.9.9.9"]
    assert state.dns_csv() == "1.1.1.1, 9.9.9.9"


def test_the_system_config_has_every_3xui_section() -> None:
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    config = config_json([inbound])
    assert set(config) == {"log", "inbounds", "outbounds", "routing", "policy", "stats", "api", "metrics"}
    assert set(config["log"]) == {"loglevel", "access", "error", "dnsLog", "maskAddress"}
    assert set(config["policy"]) == {"levels", "system"}
    assert config["inbounds"][0] == {
        "listen": API_LISTEN,
        "port": API_PORT,
        "protocol": "tunnel",
        "settings": {"rewriteAddress": API_LISTEN},
        "tag": API_TAG,
    }
    assert [item["tag"] for item in config["outbounds"]] == ["direct", "blocked"]


def test_every_created_inbound_lands_in_the_config() -> None:
    raw = new_inbound("vless", 443, "raw", "reality")
    raw.remark = "reality-443"
    raw.make_client("owner")
    raw.make_client("phone")
    grpc = new_inbound("vless", 8443, "grpc", "tls")
    grpc.remark = "grpc-8443"
    grpc.make_client("laptop")
    xhttp = new_inbound("vless", 2053, "xhttp", "reality")
    xhttp.remark = "xhttp-2053"
    xhttp.make_client("tablet")
    config = config_json([raw, grpc, xhttp], dns_servers=["1.1.1.1", "8.8.8.8"])
    inbounds = config["inbounds"]
    assert len(inbounds) == 4
    assert [item["port"] for item in inbounds] == [API_PORT, 443, 8443, 2053]
    ports = {item["port"]: item for item in inbounds[1:]}
    assert [client["email"] for client in ports[443]["settings"]["clients"]] == ["owner", "phone"]
    assert ports[8443]["settings"]["clients"][0]["email"] == "laptop"
    assert ports[2053]["settings"]["clients"][0]["email"] == "tablet"
    assert ports[443]["streamSettings"]["security"] == "reality"
    assert ports[8443]["streamSettings"]["security"] == "tls"
    assert ports[2053]["streamSettings"]["network"] == "xhttp"
    assert set(config) == {"log", "inbounds", "outbounds", "routing", "policy", "stats", "api", "metrics", "dns"}
    assert config["dns"]["servers"] == ["1.1.1.1", "8.8.8.8"]
    assert json.loads(config_text([raw, grpc, xhttp]))["inbounds"] == inbounds[:1] + [item for item in inbounds[1:4]]
