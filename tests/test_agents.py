from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FREETURN = ROOT / "Storage" / "remote" / "freeturn_agent.py"
XRAY = ROOT / "Storage" / "remote" / "xray_agent.py"


def load(path: Path, name: str, root: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def freeturn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OBHOD_ROOT", str(tmp_path))
    return load(FREETURN, "obhod_freeturn_agent", tmp_path)


@pytest.fixture()
def xray(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XRAY_ROOT", str(tmp_path))
    return load(XRAY, "obhod_xray_agent", tmp_path)


def test_the_freeturn_target_stops_every_abuse(freeturn) -> None:
    for bad in ("", " ", "a;rm -rf /", "$(id)", "`id`", "203.0.113.1 && id", "x" * 300, "1.2.3.4/8", "ff02::1"):
        with pytest.raises(freeturn.AgentError):
            freeturn.net_target({"target": bad})
    kind, host, hosts = freeturn.net_target({"target": "203.0.113.0/30"})
    assert kind == "subnet"
    assert host == "203.0.113.0/30"
    assert hosts == ["203.0.113.1", "203.0.113.2"]
    assert freeturn.net_target({"target": "example.com:443"})[1] == "example.com"
    assert freeturn.net_target({"target": "203.0.113.7:443"}) == ("host", "203.0.113.7", ["203.0.113.7"])


def test_the_freeturn_port_list_is_bounded(freeturn) -> None:
    assert freeturn.scan_ports({}) == [22, 80, 443]
    assert freeturn.scan_ports({"ports": "443, 22-24 ,443"}) == [22, 23, 24, 443]
    assert freeturn.scan_ports({"ports": "1,,"}) == [1]
    for bad in ("0", "70000", "22-20", "1-2000", "a", "-", "65536"):
        with pytest.raises(freeturn.AgentError):
            freeturn.scan_ports({"ports": bad})
    with pytest.raises(freeturn.AgentError):
        freeturn.scan_ports({"ports": ",".join(str(port) for port in range(1, 200))})


def test_the_freeturn_version_never_leaves_the_pins(freeturn) -> None:
    assert freeturn.resolve_version("local") == (freeturn.FALLBACK_VERSION, "local")
    assert freeturn.resolve_version("") == (freeturn.FALLBACK_VERSION, "default")
    with pytest.raises(freeturn.AgentError):
        freeturn.resolve_version("1.2.3; rm -rf /")
    with pytest.raises(freeturn.AgentError):
        freeturn.resolve_version("v9.9.9")
    assert freeturn.resolve_version("latest", lambda repo: ("", "unreachable")) == (freeturn.FALLBACK_VERSION, "fallback")


def test_the_freeturn_download_only_leaves_over_https(freeturn) -> None:
    assert freeturn.allowed_url("https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.2/install.sh")
    for bad in ("http://github.com/x", "https://evil.example/x", "file:///etc/passwd", "https://github.com.evil.example/x", ""):
        assert freeturn.allowed_url(bad) is False


def test_the_freeturn_checksum_parser_ignores_noise(freeturn) -> None:
    body = b"deadbeef  other.sh\n" + b"a" * 64 + b"  install.sh\n"
    assert freeturn.digest_of_checksums(body) == "a" * 64
    assert freeturn.digest_of_checksums(b"") == ""
    assert freeturn.digest_of_checksums(b"zzz install.sh") == ""
    assert freeturn.digest_of_checksums(None) == ""


def test_the_freeturn_cache_is_rejected_when_tampered(freeturn, tmp_path: Path) -> None:
    import hashlib

    body = b"#!/bin/sh\necho hi\n"
    digest = hashlib.sha256(body).hexdigest()
    freeturn.CACHE_DIR = str(tmp_path / "cache")
    path = freeturn.write_cache(digest, body)
    assert Path(path).read_text().endswith("echo hi\n")
    assert freeturn.read_cache(digest) == path
    Path(path).write_text("tampered")
    assert freeturn.read_cache(digest) == ""
    assert not Path(path).exists()


def test_the_xray_release_url_is_guarded(xray) -> None:
    assert xray.safe_url("https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip")
    for bad in ("http://github.com/XTLS/Xray-core/releases/download/v1/Xray-linux-64.zip", "https://evil.example/x.zip",
                "https://github.com@evil.example/x.zip", "https://user:pass@github.com/x.zip", "file:///etc/passwd"):
        with pytest.raises(xray.ScriptError):
            xray.safe_url(bad)
    local = "/tmp/" + "release.zip"
    assert xray.safe_url("file://" + local) == "file://" + local
    with pytest.raises(xray.ScriptError):
        xray.safe_url("file:///etc/shadow")
    with pytest.raises(xray.ScriptError):
        xray.safe_url("https://github.com/XTLS/Xray-core/releases/download/v1/page.html")


def test_the_xray_flags_are_parsed_strictly(xray) -> None:
    flags, rest = xray.parse_flags(["--port=2096", "--force", "extra"])
    assert flags["port"] == "2096"
    assert flags["force"] is True
    assert rest == ["extra"]
    flags, rest = xray.parse_flags(["--server-b64=-"])
    assert flags["server_b64"] == "-"
    assert rest == []


def test_the_xray_agent_refuses_a_missing_registry_on_sync(xray, tmp_path: Path) -> None:
    with pytest.raises(xray.ScriptError):
        xray.cmd_sub_sync({"registry_b64": ""}, [])
    with pytest.raises(xray.ScriptError):
        xray.cmd_sub_sync({"registry_b64": "e30="}, [])


def test_the_xray_state_report_survives_a_bare_host(xray, tmp_path: Path) -> None:
    report = xray.state_report()
    assert report["installed"] is False
    assert report["version"] == ""
    assert report["ports"] == []


def test_the_xray_stats_need_an_api_inbound(xray, tmp_path: Path) -> None:
    core = tmp_path / "xray"
    core.write_text("#!/bin/sh\n")
    xray.CORE = str(core)
    xray.read_config = lambda: {"inbounds": [{"port": 443, "protocol": "vless", "tag": "in-1"}]}
    with pytest.raises(xray.ScriptError):
        xray.cmd_stats({"pattern": "user>>>"}, [])


def test_the_xray_api_endpoint_is_found_and_bounded(xray) -> None:
    xray.read_config = lambda: {"inbounds": [{"port": 443, "tag": "in"}, {"port": 62789, "protocol": "tunnel", "tag": "api"}]}
    assert xray.api_endpoint() == "127.0.0.1:62789"
    xray.read_config = lambda: {"inbounds": [{"port": "bad", "tag": "api"}]}
    assert xray.api_endpoint() == ""
    xray.read_config = lambda: {"inbounds": []}
    assert xray.api_endpoint() == ""


def test_the_xray_emit_is_json(xray, capsys) -> None:
    xray.emit({"proto": xray.PROTO, "result": "ok", "data": {"a": 1}})
    line = capsys.readouterr().out.strip()
    assert json.loads(line)["result"] == "ok"


def test_the_xray_unknown_command_exits(xray, capsys) -> None:
    assert xray.main([]) == 2
    assert json.loads(capsys.readouterr().out.strip())["code"] == "bad_arg"
    assert xray.main(["nope"]) == 2
    assert json.loads(capsys.readouterr().out.strip())["code"] == "bad_arg"


def test_the_freeturn_argv_is_parsed(freeturn) -> None:
    command, flags = freeturn.parse_argv(["net-scan", "--target=203.0.113.1", "--ports=22", "--deep"])
    assert command == "net-scan"
    assert flags["target"] == "203.0.113.1"
    assert flags["deep"] == "1"
    with pytest.raises(freeturn.AgentError):
        freeturn.parse_argv([])
    with pytest.raises(freeturn.AgentError):
        freeturn.parse_argv(["nope"])
    with pytest.raises(freeturn.AgentError):
        freeturn.parse_argv(["net-scan", "positional"])
    with pytest.raises(freeturn.AgentError):
        freeturn.parse_argv(["net-scan", "--="])


def test_the_freeturn_peers_survive_broken_dump_output(freeturn, monkeypatch) -> None:
    monkeypatch.setattr(freeturn.shutil, "which", lambda name: "/usr/bin/" + name)
    dump = [
        "wg0\t" + "p" * 43 + "=\tprivate\t51820\toff",
        "wg0\t" + "k" * 43 + "=\t(none)\t203.0.113.9:51820\t10.0.0.2/32\t0\t1024\t2048\t25",
        "broken line with tabs\tand more",
        "wg0\tshort",
        "",
    ]
    monkeypatch.setattr(freeturn, "wg_command", lambda argv: dump)
    peers, interfaces = freeturn.wg_peers({"iface": "all"})
    assert len(peers) == 1
    assert peers[0]["rx"] == 1024
    assert peers[0]["psk"] == 0
    assert interfaces == ["wg0"]


def fake_core(tmp_path: Path, body: str = "#!/bin/sh\necho 'Configuration OK'\nexit 0\n") -> Path:
    core = tmp_path / "usr" / "local" / "bin" / "xray"
    core.parent.mkdir(parents=True, exist_ok=True)
    core.write_text(body)
    core.chmod(0o755)
    return core


def test_the_xray_agent_writes_tests_and_rolls_back_a_config(xray, tmp_path: Path) -> None:
    fake_core(tmp_path)
    xray.has_systemd = lambda: False
    config = json.dumps({"inbounds": [{"port": 8443, "protocol": "vless", "tag": "in-1"}]})
    state, _ = xray.cmd_apply({"config_b64": __import__("base64").b64encode(config.encode()).decode(), "no_restart": True}, [])
    assert Path(xray.CONF).read_text() == config
    assert state["inbounds"] == 1

    broken = "{this is not json"
    with pytest.raises(xray.ScriptError):
        xray.cmd_apply({"config_b64": __import__("base64").b64encode(broken.encode()).decode(), "no_restart": True}, [])
    assert Path(xray.CONF).read_text() == config

    backup = xray.backup_config()
    assert backup and Path(backup).exists()
    Path(xray.CONF).write_text("{}")
    xray.restore_config(backup)
    assert Path(xray.CONF).read_text() == config


def test_the_xray_agent_reports_the_core_it_finds(xray, tmp_path: Path) -> None:
    fake_core(tmp_path, "#!/bin/sh\necho 'Xray 26.10.31'\n")
    report = xray.state_report()
    assert report["installed"] is True
    assert report["config_exists"] is False
    assert report["systemd"] in {True, False}


def test_the_xray_agent_rejects_a_config_that_is_not_json(xray, tmp_path: Path) -> None:
    fake_core(tmp_path)
    with pytest.raises(xray.ScriptError):
        xray.cmd_apply({"config_b64": "Zm9v"}, [])
    with pytest.raises(xray.ScriptError):
        xray.cmd_apply({}, [])


def test_the_xray_agent_runs_the_core_tests(xray, tmp_path: Path) -> None:
    fake_core(tmp_path, "#!/bin/sh\necho 'Configuration OK'\nexit 0\n")
    result, _ = xray.cmd_test({"config_b64": __import__("base64").b64encode(b"{}").decode()}, [])
    assert result["valid"] is True
    assert "OK" in result["output"]
    fake_core(tmp_path, "#!/bin/sh\necho 'failed to parse'\nexit 1\n")
    result, _ = xray.cmd_test({"config_b64": __import__("base64").b64encode(b"{}").decode()}, [])
    assert result["valid"] is False
    assert "parse" in result["output"]


def test_the_xray_agent_uninstalls_what_it_wrote(xray, tmp_path: Path) -> None:
    fake_core(tmp_path)
    xray.has_systemd = lambda: False
    Path(xray.CONF).parent.mkdir(parents=True, exist_ok=True)
    Path(xray.CONF).write_text("{}")
    Path(xray.UNIT).parent.mkdir(parents=True, exist_ok=True)
    Path(xray.UNIT).write_text("[Unit]\n")
    state, _ = xray.cmd_uninstall({"purge": True}, [])
    assert not Path(xray.CORE).exists()
    assert not Path(xray.UNIT).exists()
    assert state["removed"]


def test_the_xray_subscription_server_is_written_privately(xray, tmp_path: Path) -> None:
    import base64 as b64

    body = b"#!/usr/bin/env python3\nprint('sub')\n"
    state, _ = xray.cmd_sub_install({"server_b64": b64.b64encode(body).decode(), "port": "2096"}, [])
    server, registry, _unit = xray.sub_paths()
    assert Path(server).read_bytes() == body
    assert oct(Path(server).stat().st_mode)[-3:] == "755"
    assert state["installed"] is True
    with pytest.raises(xray.ScriptError):
        xray.cmd_sub_install({}, [])


def test_the_xray_registry_is_written_0600(xray, tmp_path: Path) -> None:
    import base64 as b64

    server, registry, _unit = xray.sub_paths()
    Path(server).parent.mkdir(parents=True, exist_ok=True)
    Path(server).write_text("#!/usr/bin/env python3\n")
    xray.port_open = lambda port: False
    xray.has_systemd = lambda: False
    xray.start_sub = lambda port, path: None
    payload = json.dumps({"port": 2096, "entries": {"a": {"links": ["vless://x"]}}})
    xray.cmd_sub_sync({"registry_b64": b64.b64encode(payload.encode()).decode()}, [])
    assert oct(Path(registry).stat().st_mode)[-3:] == "600"
    assert json.loads(Path(registry).read_text())["entries"]["a"]["links"] == ["vless://x"]
    with pytest.raises(xray.ScriptError):
        xray.cmd_sub_sync({"registry_b64": b64.b64encode(b"not json").decode()}, [])


def test_the_freeturn_guard_refuses_a_wildcard_port(freeturn) -> None:
    with pytest.raises(freeturn.AgentError):
        freeturn.guard_port({"port": "0"})
    with pytest.raises(freeturn.AgentError):
        freeturn.guard_port({"port": "70000"})
    assert freeturn.guard_port({"port": "51820"}) == 51820
    with pytest.raises(freeturn.AgentError):
        freeturn.guard_proto({"proto": "sctp"})
    assert freeturn.guard_proto({"proto": "udp"}) == ("udp",)
    assert freeturn.guard_proto({"proto": "both"}) == ("udp", "tcp")
    assert freeturn.guard_proto({}) == ("udp",)


def test_the_freeturn_cidr_list_is_bounded(freeturn) -> None:
    with pytest.raises(freeturn.AgentError):
        freeturn.guard_cidrs({"cidrs": ""})
    assert freeturn.guard_cidrs({"cidrs": "203.0.113.0/24, 198.51.100.0/24"}) == ["203.0.113.0/24", "198.51.100.0/24"]
    for bad in ("0.0.0.0/0", "not-an-ip", "203.0.113.0/33", "::/0", "203.0.113.0/24; rm -rf /"):
        with pytest.raises(freeturn.AgentError):
            freeturn.guard_cidrs({"cidrs": bad})


def test_the_vless_encryption_lists_every_pair(xray, monkeypatch) -> None:
    monkeypatch.setattr(xray.os.path, "isfile", lambda path: True)
    text = "\n".join(
        [
            "Authentication: X25519",
            "Decryption: mlkem768x25519plus.native.600s." + "a" * 43,
            "Encryption: mlkem768x25519plus.native.0rtt." + "b" * 43,
            "",
            "Authentication: ML-KEM-768",
            "Decryption: mlkem768x25519plus.random.600s." + "c" * 400,
            "Encryption: mlkem768x25519plus.random.0rtt." + "d" * 400,
        ]
    )
    monkeypatch.setattr(xray, "run", lambda argv, timeout=60: (0, text))
    out, error = xray.cmd_vlessenc({}, [])
    assert error is None
    assert len(out["items"]) == 2
    assert out["items"][1]["auth"] == "ML-KEM-768"
    assert out["decryption"] == out["items"][0]["decryption"]


def test_the_vless_encryption_refuses_empty_output(xray, monkeypatch) -> None:
    monkeypatch.setattr(xray.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(xray, "run", lambda argv, timeout=60: (0, ""))
    with pytest.raises(xray.ScriptError):
        xray.cmd_vlessenc({}, [])
