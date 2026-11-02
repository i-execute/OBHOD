from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from BOT import portguard
from BOT.freeturn import FtConfig
from BOT.guard import SshState
from BOT.store import State
from BOT.xray import XrayState, new_inbound


def state() -> State:
    st = State(xray=XrayState(), ssh=SshState(ports=[22]))
    st.xray.add(new_inbound("vless", 443, "raw", "reality"))
    st.xray.add(new_inbound("vless", 8443, "grpc", "tls"))
    return st


def test_parse_ports_keeps_only_the_numbers() -> None:
    assert portguard.parse_ports("22, 443,abc,,70000,0,443") == [22, 443]


def test_parse_ports_returns_nothing_for_garbage() -> None:
    assert portguard.parse_ports(None) == []
    assert portguard.parse_ports("hello") == []


def test_parse_ports_is_capped() -> None:
    raw = ",".join(str(item) for item in range(1, 400))
    assert len(portguard.parse_ports(raw)) == portguard.MAX_TRACKED


def test_join_sorts_and_dedupes() -> None:
    assert portguard.join([443, 22, 443]) == "22,443"


def test_keep_list_covers_ssh_xray_and_the_sub_port() -> None:
    keep = portguard.protected_ports(state())
    assert 22 in keep
    assert 443 in keep
    assert 8443 in keep
    assert 2096 in keep


def test_keep_list_honours_a_custom_ssh_port() -> None:
    st = State(xray=XrayState(), ssh=SshState(ports=[2222]))
    assert 2222 in portguard.protected_ports(st)
    assert 22 not in portguard.protected_ports(st)


def test_keep_list_accepts_extra_ports() -> None:
    assert 9000 in portguard.protected_ports(state(), [9000])


def test_check_rejects_a_port_out_of_range() -> None:
    with pytest.raises(portguard.PortError):
        portguard.check(0, [], "closed")
    with pytest.raises(portguard.PortError):
        portguard.check(70000, [], "closed")


def test_check_refuses_to_close_ssh() -> None:
    with pytest.raises(portguard.PortError):
        portguard.check(22, [22, 443], "closed")


def test_check_refuses_a_module_port() -> None:
    with pytest.raises(portguard.PortError):
        portguard.check(443, [22, 443], "vk")


def test_check_allows_a_fresh_engine_port() -> None:
    portguard.check(56000, [22, 443, 2096], "closed")
    portguard.check(56000, [22, 443, 2096], "vk")


def test_is_protected_handles_empty_lists() -> None:
    assert portguard.is_protected(22, []) is False
    assert portguard.is_protected(22, [22]) is True


def test_parse_ss_reads_the_listeners() -> None:
    text = "Netid State Local\nudp UNCONN 0.0.0.0:56000 0.0.0.0:* users:((\"freeturn\",pid=1,fd=3))"
    owners = portguard.parse_ss(text, [56000])
    assert owners[0].port == 56000
    assert owners[0].proto == "udp"
    assert owners[0].process == "freeturn"


def test_parse_ss_marks_ssh() -> None:
    text = "Netid State Local\n" 'tcp LISTEN 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=2,fd=3))'
    owners = portguard.parse_ss(text, [])
    assert owners[0].protected is True
    assert owners[0].reason == "ssh"


def test_parse_ss_marks_a_module_port() -> None:
    text = "Netid State Local\ntcp LISTEN [::]:443 [::]:* users:((\"xray\",pid=3,fd=3))"
    owners = portguard.parse_ss(text, [443])
    assert owners[0].protected is True
    assert owners[0].reason == "module"


def test_parse_ss_skips_the_header_and_noise() -> None:
    assert portguard.parse_ss("Netid State\n\njunk\n", []) == []
    assert portguard.parse_ss("", []) == []


def test_owner_roundtrip() -> None:
    owner = portguard.Owner(port=443, proto="tcp", process="xray", address="0.0.0.0:443", protected=True, reason="module")
    again = portguard.Owner.from_dict(owner.to_dict())
    assert again.to_dict() == owner.to_dict()


def test_owner_survives_broken_data() -> None:
    owner = portguard.Owner.from_dict({"port": "abc", "proto": None})
    assert owner.port == 0
    assert owner.proto == ""


def test_owner_from_dict_tolerates_none() -> None:
    assert portguard.Owner.from_dict(None).port == 0


def test_owner_clamps_a_huge_port() -> None:
    assert portguard.Owner.from_dict({"port": 999999}).port == 65535


def test_describe_prints_the_owners() -> None:
    owner = portguard.Owner(port=22, proto="tcp", process="sshd")
    assert "22/tcp sshd" in portguard.describe([owner])


def test_untouched_returns_the_protected_ones() -> None:
    owners = [portguard.Owner(port=22, protected=True), portguard.Owner(port=56000)]
    assert [item.port for item in portguard.untouched(owners)] == [22]


def test_the_engine_port_is_never_in_the_keep_list() -> None:
    st = state()
    st.freeturn = type("Ft", (), {"config": FtConfig(listen_port=56000)})()
    keep = portguard.protected_ports(st)
    assert 56000 not in keep


def test_free_port_keeps_the_preferred_one() -> None:
    assert portguard.free_port(444, set()) == 444


def test_free_port_skips_a_busy_one() -> None:
    assert portguard.free_port(2096, {2096}) == 2097
    assert portguard.free_port(2096, {2096, 2097, 2098}) == 2099


def test_free_port_never_hands_out_the_ssh_ports() -> None:
    assert portguard.free_port(22, set()) == 23
    assert portguard.free_port(2222, set()) == 2223


def test_free_port_handles_a_zero_preference() -> None:
    assert portguard.free_port(0, set()) == 1025


def test_free_port_skips_the_protected_list() -> None:
    assert portguard.free_port(8080, {"8080", "8081"}) == 8082


def test_foreign_ports_leave_our_own_alone() -> None:
    owners = [portguard.Owner(port=443), portguard.Owner(port=8443)]
    assert portguard.foreign_ports(owners, [443]) == [8443]


def test_owner_label_names_the_process() -> None:
    owners = [portguard.Owner(port=2096, proto="tcp", process="nginx")]
    assert portguard.owner_label(2096, owners) == "nginx"
    assert portguard.owner_label(1, owners) == "unknown"
