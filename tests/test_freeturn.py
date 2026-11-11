from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from BOT import freeturn
from BOT.freeturn import (
    FtClient,
    FtConfig,
    FtControl,
    FtError,
    FtShare,
    FtState,
    asset_of_arch,
    complete_link,
    core_url,
    decode_link,
    encode_link,
    normalize_conf,
    parse_response,
    script_digest,
    script_url,
    valid_cidr,
    valid_hex64,
    valid_host,
    valid_hostport,
    valid_name,
)
from BOT.shell import ShellOutput

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "Storage" / "remote" / "freeturn_agent.py"


def load_agent() -> Any:
    spec = importlib.util.spec_from_file_location("freeturn_agent_under_test", AGENT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeShell:
    def __init__(self, text: str = "") -> None:
        self.text = text
        self.calls: list[tuple[list[str], float | None]] = []

    async def run_argv(self, argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> ShellOutput:
        self.calls.append((list(argv), timeout))
        return ShellOutput(text=self.text, code=0)


def ok_envelope(data: dict[str, Any], logs: list[str] | None = None) -> str:
    return json.dumps({"proto": 3, "result": "ok", "data": data, "logs": logs or []})


def err_envelope(code: str, msg: str, stage: str = "apply") -> str:
    return json.dumps({"proto": 3, "result": "err", "code": code, "msg": msg, "stage": stage, "logs": []})


def test_config_defaults_pass_validation() -> None:
    config = FtConfig().check()
    assert config.method == "systemd"
    assert config.listen_port == freeturn.DEFAULT_LISTEN_PORT


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "snap"),
        ("backend", "own"),
        ("mode", "icmp"),
        ("obf_profile", "xor"),
        ("listen_port", 0),
        ("listen_port", 70000),
        ("wg_net", "10.13.13.5/24"),
        ("wg_net", "10.0.0.0/8"),
        ("host", "-bad host"),
        ("connect", "1.2.3.4"),
        ("version", "nightly"),
    ],
)
def test_config_rejects_bad_values(field: str, value: Any) -> None:
    config = FtConfig()
    setattr(config, field, value)
    with pytest.raises(FtError):
        config.check()


def test_tcp_needs_an_external_backend() -> None:
    with pytest.raises(FtError):
        FtConfig(mode="tcp").check()
    config = FtConfig(mode="tcp", backend="external", connect="198.51.100.9:443")
    assert config.check().mode == "tcp"


def test_server_argv_shape() -> None:
    config = FtConfig(listen_port=56123, host="203.0.113.10").check()
    argv = config.server_argv()
    assert "--method=systemd" in argv
    assert "--wg-port=51820" in argv
    assert "--wg-net=10.13.13.0/24" in argv
    assert "--host=203.0.113.10" in argv
    external = FtConfig(backend="external", mode="tcp", connect="198.51.100.9:443").check()
    out = external.server_argv()
    assert not any(item.startswith("--wg-") for item in out)
    assert "--mode=tcp" in out
    assert "--connect=198.51.100.9:443" in out


def test_validators() -> None:
    assert valid_cidr("10.13.13.0/24")
    assert valid_cidr("10.13.0.0/16")
    assert valid_cidr("10.13.13.0/29")
    assert not valid_cidr("10.13.13.0/30")
    assert not valid_cidr("10.13.13.7/24")
    assert not valid_cidr("example/24")
    assert valid_name("phone-1")
    assert not valid_name("-phone")
    assert not valid_name("\u0442\u0435\u043b\u0435\u0444\u043e\u043d")
    assert not valid_name("a" * 40)
    assert valid_hex64("a" * 64)
    assert not valid_hex64("a" * 63)
    assert not valid_hex64("z" * 64)
    assert valid_host("203.0.113.10")
    assert valid_host("node.example.com")
    assert not valid_host("bad host")
    assert valid_hostport("203.0.113.10:56000")
    assert valid_hostport("[2001:db8::1]:56000")
    assert not valid_hostport("203.0.113.10")
    assert not valid_hostport("203.0.113.10:99999")


def test_release_urls() -> None:
    assert script_url("v4.1.2").endswith("/v4.1.2/install.sh")
    assert script_url("4.1.2").endswith("/v4.1.2/install.sh")
    assert len(script_digest("v4.1.2")) == 64
    assert script_digest("v0.0.1", digest_lookup=lambda tag: "") == ""
    assert script_digest("v4.1.0", digest_lookup=lambda tag: "") == ""
    assert script_digest("v4.2.0", digest_lookup=lambda tag: "c" * 64) == "c" * 64
    assert asset_of_arch("x86_64") == "server-linux-amd64"
    assert asset_of_arch("aarch64") == "server-linux-arm64"
    assert asset_of_arch("mips") == ""
    assert core_url("v4.1.2", "aarch64").endswith("/v4.1.2/server-linux-arm64")
    assert core_url("v4.1.2", "mips") == ""


def test_parse_response_reads_the_last_json_line() -> None:
    text = "\n".join(["welcome to the server", "last login", ok_envelope({"installed": True}, ["done"])])
    response = parse_response(text)
    assert response.ok
    assert response.data["installed"] is True
    assert response.logs == ["done"]


def test_parse_response_error_carries_the_code() -> None:
    response = parse_response(err_envelope("port_busy", "the port is busy"))
    assert not response.ok
    with pytest.raises(FtError) as info:
        response.raise_for_status()
    assert info.value.code == "port_busy"
    assert "busy" in info.value.message


def test_parse_response_failure_modes() -> None:
    with pytest.raises(FtError) as info:
        parse_response("")
    assert info.value.code == "transport"
    with pytest.raises(FtError) as info:
        parse_response("{not json}")
    assert info.value.code == "transport"
    payload = json.dumps({"proto": 9, "result": "ok", "data": {}})
    with pytest.raises(FtError) as info:
        parse_response(payload)
    assert info.value.code == "proto_mismatch"


def test_unknown_error_code_still_reads() -> None:
    response = parse_response(err_envelope("weird_code", "", "init"))
    with pytest.raises(FtError) as info:
        response.raise_for_status()
    assert info.value.code == "weird_code"


def test_state_never_keeps_the_obfuscation_key() -> None:
    key = "d" * 64
    probe = {
        "installed": True,
        "running": True,
        "euid": 0,
        "arch": "x86_64",
        "method": "systemd",
        "version": "v4.1.2",
        "config": {"method": "systemd", "listen_port": 56123, "obf_key": key, "version": "latest"},
    }
    state = FtState.from_dict(probe)
    assert state.key_present
    stored = json.dumps(state.to_dict())
    assert key not in stored
    assert "obf_key" not in stored
    restored = FtState.from_dict(state.to_dict())
    assert restored.key_present
    assert restored.config.listen_port == 56123


def test_client_and_share_models_sanitize_values() -> None:
    client = FtClient.from_dict({"name": "phone" * 20, "client_id": "XYZ", "self": True, "ip": "10.13.13.2", "hs": "17"})
    assert len(client.name) <= 32
    assert client.client_id == ""
    assert client.owner is True
    assert client.handshake == 17
    share = FtShare.from_dict({"backend": "new", "host": "203.0.113.10", "port": 56123, "mode": "udp", "obf_profile": "rtpopus3", "obf_key": "e" * 64})
    assert share.peer() == "203.0.113.10:56123"
    assert share.key_present
    assert FtShare.from_dict({}).peer() == ""


def test_link_roundtrip() -> None:
    payload = {
        "v": 1,
        "provider": "vk",
        "peer": "203.0.113.10:56123",
        "obf": "rtpopus3",
        "key": "f" * 64,
        "cid": "0123456789abcdef0123456789abcdef",
        "name": "owner",
    }
    link = encode_link(payload)
    assert link.startswith("freeturn://")
    assert decode_link(link)["peer"] == "203.0.113.10:56123"
    assert "=" not in link


@pytest.mark.parametrize(
    "body",
    [
        {"v": 2, "provider": "vk", "peer": "1.2.3.4:1"},
        {"v": 1, "peer": "1.2.3.4:1"},
        {"v": 1, "provider": "vk", "peer": "1.2.3.4"},
        {"v": 1, "provider": "vk", "peer": "1.2.3.4:1", "key": "zz"},
        {"v": 1, "provider": "vk", "peer": "1.2.3.4:1", "cid": "nope"},
    ],
)
def test_decode_link_rejects_bad_payloads(body: dict[str, Any]) -> None:
    link = "freeturn://" + base64.urlsafe_b64encode(json.dumps(body).encode("utf-8")).decode("ascii").rstrip("=")
    with pytest.raises(FtError):
        decode_link(link)


def test_decode_link_rejects_bad_prefix_and_payload() -> None:
    with pytest.raises(FtError):
        decode_link("https://example.com")
    with pytest.raises(FtError):
        decode_link("freeturn://not-base64!!")


def test_complete_link_adds_transport_and_arq_profile() -> None:
    base = encode_link({"v": 1, "provider": "vk", "peer": "203.0.113.10:56123", "cid": "0123456789abcdef0123456789abcdef"})
    filled = decode_link(complete_link(base, FtConfig(backend="external", mode="tcp")))
    assert "transport" not in filled
    assert filled["mode"] == "tcp"
    assert filled["kcp"]["mtu"] == 1200
    assert filled["n"] == 12
    assert filled["spc"] == 12
    tcp_filled = decode_link(complete_link(base, FtConfig(backend="external", mode="tcp", transport="tcp")))
    assert tcp_filled["transport"] == "tcp"
    udp_filled = decode_link(complete_link(base, FtConfig(transport="udp")))
    assert udp_filled["transport"] == "udp"
    assert udp_filled["n"] == 12
    assert udp_filled["spc"] == 12
    assert "obf" not in udp_filled
    keyed = encode_link(
        {
            "v": 1,
            "provider": "vk",
            "peer": "203.0.113.10:56123",
            "key": "a" * 64,
            "cid": "0123456789abcdef0123456789abcdef",
            "wg": "# note\n[Interface]\nMTU = 1280\nPrivateKey = abc\n",
        }
    )
    keyed_filled = decode_link(complete_link(keyed, FtConfig(obf_profile="rtpopus3")))
    assert keyed_filled["obf"] == "rtpopus3"
    assert "MTU" not in keyed_filled["wg"]
    assert keyed_filled["wg"] == "[Interface]\nPrivateKey = abc"


@pytest.mark.asyncio
async def test_control_apply_raw_response_probes_and_keeps_fresh_owner_link() -> None:
    fresh_key = "b" * 64
    owner_uri = encode_link(
        {
            "v": 1,
            "provider": "vk",
            "peer": "89.125.48.221:56696",
            "obf": "rtpopus3",
            "key": fresh_key,
            "cid": "02597c3861867329181e3f01898c44eb",
            "name": "owner",
        }
    )

    class SequenceShell:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []
            self.replies = [
                ok_envelope({"owner": {"client_id": "02597c3861867329181e3f01898c44eb", "link": owner_uri}, "obf_key": fresh_key, "needs_restart": True}),
                ok_envelope(
                    {
                        "installed": True,
                        "running": True,
                        "euid": 0,
                        "arch": "x86_64",
                        "method": "docker",
                        "version": "v4.1.2",
                        "config": {"method": "docker", "backend": "new", "listen_port": 56696, "mode": "udp", "obf_profile": "rtpopus3", "obf_key": fresh_key},
                    }
                ),
            ]

        async def run_argv(self, argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> ShellOutput:
            self.calls.append(list(argv))
            return ShellOutput(text=self.replies.pop(0), code=0)

    shell = SequenceShell()
    control = FtControl(shell=shell)
    state = await control.apply(FtConfig(method="docker", backend="new", listen_port=56696))
    assert state.installed is True
    assert state.running is True
    assert state.key_present is True
    assert len(shell.calls) == 2
    decoded = decode_link(state.links["owner"])
    assert decoded["key"] == fresh_key
    assert decoded["n"] == 12
    assert decoded["spc"] == 12


def test_agent_ensure_apply_port_open_handles_normalized_flags_and_nft(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    agent = load_agent()
    conf_dir = tmp_path / "ft"
    conf_dir.mkdir()
    (conf_dir / "install.conf").write_text('LISTEN_PORT="56000"\nPROXY_MODE="udp"\n', encoding="utf-8")
    monkeypatch.setattr(agent, "INSTALL_ROOT", str(conf_dir))
    executed: list[list[str]] = []

    def fake_run_tool(argv: list[str], timeout: int = 30) -> tuple[int, str]:
        executed.append(list(argv))
        if argv[:4] == ["nft", "list", "table", "inet"]:
            return 0, "table inet obhod_ddos {\n chain input {\n }\n}"
        if argv[:3] == ["nft", "list", "ruleset"]:
            return 0, "table inet filter {\n chain input {\n type filter hook input priority filter; policy drop;\n }\n}"
        if argv[:2] == ["ufw", "status"]:
            return 0, "Status: active\n[ 1] 56000/udp DENY IN Anywhere\n"
        return 0, ""

    monkeypatch.setattr(agent, "run_tool", fake_run_tool)
    monkeypatch.setattr(agent, "guard_backend", lambda: "ufw")
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/sbin/" + name)
    agent.ensure_apply_port_open({"listen_port": "56000", "mode": "udp"}, {"data": {}})
    assert ["nft", "flush", "set", "inet", "obhod_ddos", "conn_flood"] in executed
    assert ["nft", "insert", "rule", "inet", "obhod_ddos", "input", "udp", "dport", "56000", "accept"] in executed
    assert ["nft", "insert", "rule", "inet", "filter", "input", "udp", "dport", "56000", "accept"] in executed
    assert ["ufw", "--force", "delete", "1"] in executed
    assert ["ufw", "allow", "56000/udp"] in executed


def test_ft_state_migrates_legacy_udp_links_to_tcp() -> None:
    from BOT.freeturn import FtState

    legacy_uri = encode_link({"v": 1, "provider": "vk", "peer": "89.125.48.221:56000", "transport": "tcp", "obf": "rtpopus3"})
    migrated = FtState.from_dict({"installed": True, "transport_schema": 2, "config": {"transport": "tcp"}, "links": {"owner": legacy_uri}})
    assert migrated.config.transport == "auto"
    assert "transport" not in decode_link(migrated.links["owner"])
    saved = migrated.to_dict()
    assert saved["transport_schema"] == 3
    explicit_udp = encode_link({"v": 1, "provider": "vk", "peer": "89.125.48.221:56000", "transport": "udp"})
    kept = FtState.from_dict({"installed": True, "transport_schema": 3, "config": {"transport": "udp"}, "links": {"owner": explicit_udp}})
    assert kept.config.transport == "udp"
    assert decode_link(kept.links["owner"])["transport"] == "udp"


def test_normalize_conf_drops_comments_and_mtu() -> None:
    body = "# note\n[Interface]\nMTU = 1420\nPrivateKey = abc\n\n; other\n[Peer]\nPublicKey = def\n"
    assert normalize_conf(body) == "[Interface]\nPrivateKey = abc\n[Peer]\nPublicKey = def"


@pytest.mark.asyncio
async def test_control_sends_the_pinned_script_flags() -> None:
    shell = FakeShell(ok_envelope({"installed": False, "euid": 0, "arch": "x86_64"}))
    control = FtControl(shell=shell)
    state = await control.probe()
    assert state.installed is False
    argv, timeout = shell.calls[0]
    assert argv[0].endswith("python3") or "python" in argv[0]
    joined = " ".join(argv)
    assert "--script-url=https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.2/install.sh" in joined
    assert "--script-sha256=91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100" in joined
    assert timeout == 120


@pytest.mark.asyncio
async def test_control_apply_passes_the_key_only_when_given() -> None:
    shell = FakeShell(ok_envelope({"installed": True}))
    control = FtControl(shell=shell)
    await control.apply(FtConfig(listen_port=56123))
    assert not any("--obf-key" in item for item in shell.calls[-1][0])
    await control.apply(FtConfig(listen_port=56123), obf_key="a" * 64)
    assert any("--obf-key=" + "a" * 64 in item for item in shell.calls[-1][0])
    with pytest.raises(FtError):
        await control.apply(FtConfig(listen_port=56123), obf_key="short")


@pytest.mark.asyncio
async def test_control_allows_the_owner_revocation_call() -> None:
    shell = FakeShell(ok_envelope({"removed": True, "name": "owner"}))
    control = FtControl(shell=shell)
    res = await control.client_remove("owner")
    assert res.result == "ok"
    assert any("--name=owner" in item for item in shell.calls[-1][0])


@pytest.mark.asyncio
async def test_control_validates_names_before_touching_the_server() -> None:
    shell = FakeShell(ok_envelope({"client": {}}))
    control = FtControl(shell=shell)
    with pytest.raises(FtError):
        await control.client_add("bad name")
    assert shell.calls == []
    await control.client_add("phone")
    assert any("--name=phone" in item for item in shell.calls[-1][0])


@pytest.mark.asyncio
async def test_control_logs_and_clients_parse() -> None:
    payload = ok_envelope(
        {
            "lines": ["a", "b"],
            "clients": [{"name": "owner", "client_id": "0123456789abcdef0123456789abcdef", "self": True}],
            "share": {"backend": "new", "host": "203.0.113.10", "port": 56123, "mode": "udp", "obf_profile": "rtpopus3", "obf_key": "a" * 64},
        }
    )
    shell = FakeShell(payload)
    control = FtControl(shell=shell)
    assert await control.logs(50) == ["a", "b"]
    clients, share = await control.client_list()
    assert clients[0].owner
    assert share.peer() == "203.0.113.10:56123"


@pytest.mark.asyncio
async def test_control_uninstall_target_is_checked() -> None:
    shell = FakeShell(ok_envelope({}))
    control = FtControl(shell=shell)
    with pytest.raises(FtError):
        await control.uninstall("everything")
    await control.uninstall("all", True)
    argv = shell.calls[-1][0]
    assert "--target=all" in argv
    assert "--purge" in argv


def test_agent_parses_arguments() -> None:
    module = load_agent()
    command, flags = module.parse_argv(["client-add", "--name=phone", "--purge"])
    assert command == "client-add"
    assert flags["name"] == "phone"
    assert flags["purge"] == "1"
    with pytest.raises(module.AgentError):
        module.parse_argv([])
    with pytest.raises(module.AgentError):
        module.parse_argv(["rm-rf"])
    with pytest.raises(module.AgentError):
        module.parse_argv(["probe", "name=phone"])


def test_agent_builds_the_script_command_line() -> None:
    module = load_agent()
    argv = module.command_argv("apply", {"method": "systemd", "listen_port": "56123", "obf_profile": "rtpopus3", "wg_net": "10.13.13.0/24"})
    assert argv == ["apply", "--method=systemd", "--listen_port=56123".replace("_", "-"), "--wg-net=10.13.13.0/24", "--obf-profile=rtpopus3"]
    with pytest.raises(module.AgentError):
        module.command_argv("apply", {"unknown": "1"})
    with pytest.raises(module.AgentError):
        module.command_argv("apply", {"host": "1.2.3.4\nrm -rf /"})
    logs = module.command_argv("logs", {"tail": "50"})
    assert logs == ["logs", "--tail=50"]
    with pytest.raises(module.AgentError):
        module.command_argv("logs", {"tail": "abc"})
    assert module.command_argv("uninstall", {"target": "all", "purge": "1"}) == ["uninstall", "--target=all", "--purge"]


def test_agent_refuses_a_non_github_address() -> None:
    module = load_agent()
    assert module.allowed_url("https://github.com/x/y/install.sh")
    assert not module.allowed_url("http://github.com/x/y/install.sh")
    assert not module.allowed_url("https://evil.example/install.sh")
    assert not module.allowed_url("file:///etc/passwd")
    with pytest.raises(module.AgentError) as info:
        module.download("http://github.com/x/y/install.sh", "")
    assert info.value.code == "bad_arg"


def test_agent_rejects_a_wrong_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()
    body = b"#!/bin/bash\nRPC_COMMANDS=probe\n"

    class FakeResponse:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload

        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self, size: int) -> bytes:
            return self.payload[:size]

        def geturl(self) -> str:
            return "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.2/install.sh"

    monkeypatch.setattr(module, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda request, timeout=0: FakeResponse(body))
    with pytest.raises(module.AgentError) as info:
        module.download(module.DEFAULT_URL, "0" * 64)
    assert info.value.code == "digest_mismatch"
    good = module.sha256_of(body)
    path = module.download(module.DEFAULT_URL, good)
    assert Path(path).read_text(encoding="utf-8").startswith("#!/bin/bash")
    assert oct(Path(path).stat().st_mode)[-3:] == "600"
    assert module.script_source({"script_sha256": good}) == path


def test_agent_rejects_a_file_that_is_not_the_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self, size: int) -> bytes:
            return b"<html>nope</html>"

        def geturl(self) -> str:
            return module.DEFAULT_URL

    monkeypatch.setattr(module, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda request, timeout=0: FakeResponse())
    with pytest.raises(module.AgentError) as info:
        module.download(module.DEFAULT_URL, "")
    assert info.value.code == "download_failed"


def test_agent_runs_a_script_and_passes_the_envelope(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = load_agent()
    script = tmp_path / "install.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "echo 'motd noise'\n"
        "printf '{\"proto\":3,\"result\":\"ok\",\"data\":{\"echo\":\"%s\"},\"logs\":[]}\\n' \"$1\"\n",
        encoding="utf-8",
    )
    module.script_source = lambda flags: str(script)
    code = module.main(["probe"])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert code == 0
    assert out["result"] == "ok"
    assert out["data"]["echo"] == "probe"


def test_agent_reports_a_missing_answer(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = load_agent()
    script = tmp_path / "install.sh"
    script.write_text("#!/usr/bin/env bash\necho only noise\n", encoding="utf-8")
    module.script_source = lambda flags: str(script)
    code = module.main(["probe"])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert code == 1
    assert out["result"] == "err"
    assert out["code"] == "internal"


def test_agent_reports_a_protocol_mismatch(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = load_agent()
    script = tmp_path / "install.sh"
    script.write_text("#!/usr/bin/env bash\necho '{\"proto\":1,\"result\":\"ok\",\"data\":{},\"logs\":[]}'\n", encoding="utf-8")
    module.script_source = lambda flags: str(script)
    code = module.main(["probe"])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert code == 1
    assert out["code"] == "proto_mismatch"


def test_agent_reports_the_script_error_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = load_agent()
    script = tmp_path / "install.sh"
    script.write_text(
        "#!/usr/bin/env bash\necho '{\"proto\":3,\"result\":\"err\",\"code\":\"port_busy\",\"msg\":\"busy\",\"stage\":\"apply\",\"logs\":[]}'\n",
        encoding="utf-8",
    )
    module.script_source = lambda flags: str(script)
    code = module.main(["apply", "--listen_port=56123"])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert code == 1
    assert out["code"] == "port_busy"
    assert out["stage"] == "apply"


def test_agent_timeout_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = load_agent()
    script = tmp_path / "install.sh"
    script.write_text("#!/usr/bin/env bash\nsleep 5\n", encoding="utf-8")
    module.script_source = lambda flags: str(script)
    module.TIMEOUTS = dict(module.TIMEOUTS)
    module.TIMEOUTS["probe"] = 1
    code = module.main(["probe"])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert code == 1
    assert out["code"] == "start_failed"


def test_agent_refuses_an_oversized_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self, size: int) -> bytes:
            return b"RPC_COMMANDS" + b"x" * (module.MAX_SCRIPT_BYTES + 10)

        def geturl(self) -> str:
            return module.DEFAULT_URL

    monkeypatch.setattr(module, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda request, timeout=0: FakeResponse())
    with pytest.raises(module.AgentError) as info:
        module.download(module.DEFAULT_URL, "")
    assert info.value.code == "download_failed"


def test_agent_refuses_a_redirect_outside_github(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self, size: int) -> bytes:
            return b"RPC_COMMANDS=probe\n"

        def geturl(self) -> str:
            return "https://evil.example/install.sh"

    monkeypatch.setattr(module, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda request, timeout=0: FakeResponse())
    with pytest.raises(module.AgentError) as info:
        module.download(module.DEFAULT_URL, "")
    assert info.value.code == "bad_arg"


def test_agent_cache_is_reused_and_checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()
    body = b"#!/usr/bin/env bash\nRPC_COMMANDS=probe\n"
    digest = module.sha256_of(body)
    monkeypatch.setattr(module, "CACHE_DIR", str(tmp_path / "cache"))
    path = module.write_cache(digest, body)
    assert module.read_cache(digest) == path
    Path(path).write_text("tampered", encoding="utf-8")
    assert module.read_cache(digest) == ""
    assert not Path(path).exists()


def test_agent_never_shells_out_for_flags(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = load_agent()
    script = tmp_path / "install.sh"
    script.write_text("#!/usr/bin/env bash\nprintf '{\"proto\":3,\"result\":\"ok\",\"data\":{\"argc\":%d},\"logs\":[]}\\n' $#\n", encoding="utf-8")
    module.script_source = lambda flags: str(script)
    module.main(["probe", "--host=1.2.3.4;touch /tmp/pwned", "--script-sha256=" + "a" * 64])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["result"] == "ok"
    assert out["data"]["argc"] == 2
    assert not Path("/tmp/pwned").exists()


def test_the_bot_resolves_latest_and_falls_back_to_the_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(freeturn.releases, "latest_tag", lambda repo: ("v4.1.2", ""))
    assert freeturn.resolve_version("latest") == ("v4.1.2", "api")
    monkeypatch.setattr(freeturn.releases, "latest_tag", lambda repo: ("v4.2.0", ""))
    assert freeturn.resolve_version("latest") == (freeturn.FALLBACK_VERSION, "not_pinned")
    monkeypatch.setattr(freeturn.releases, "latest_tag", lambda repo: ("", "rate_limited"))
    assert freeturn.resolve_version("latest") == (freeturn.FALLBACK_VERSION, "fallback")


def test_the_bot_resolves_a_requested_version_without_the_api(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(repo: str) -> tuple[str, str]:
        raise AssertionError("the api must not be called for a pinned version")

    monkeypatch.setattr(freeturn.releases, "latest_tag", explode)
    assert freeturn.resolve_version("") == (freeturn.FALLBACK_VERSION, "pinned")
    assert freeturn.resolve_version("4.1.2") == ("v4.1.2", "pinned")
    assert freeturn.resolve_version("local") == (freeturn.FALLBACK_VERSION, "local")
    for gone in ("v4.1.0", "v4.2.0"):
        with pytest.raises(FtError) as caught:
            freeturn.resolve_version(gone)
        assert caught.value.code == "not_pinned", gone


def test_a_plan_version_must_be_pinned() -> None:
    FtConfig(version="latest").check()
    FtConfig(version="local").check()
    FtConfig(version="4.1.2").check()
    FtConfig(version="v4.1.2").check()
    for gone in ("v4.1.0", "v4.2.0"):
        with pytest.raises(FtError) as caught:
            FtConfig(version=gone).check()
        assert caught.value.code == "not_pinned", gone
    with pytest.raises(FtError) as wrong:
        FtConfig(version="banana").check()
    assert wrong.value.code == "bad_arg"


def test_the_plan_rewrites_latest_to_the_resolved_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    control = FtControl(shell=FakeShell())
    monkeypatch.setattr(freeturn.releases, "latest_tag", lambda repo: ("", "rate_limited"))
    items = control.plan_argv(["apply", "--version=latest"])
    joined = " ".join(items)
    assert "--version=latest" not in items
    assert "--version=" + freeturn.FALLBACK_VERSION in items
    assert "releases/download/%s/install.sh" % freeturn.FALLBACK_VERSION in joined
    assert "--script-sha256=" + freeturn.PINNED_SCRIPT_SHA256[freeturn.FALLBACK_VERSION] in joined


def test_the_plan_follows_the_api_when_it_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    control = FtControl(shell=FakeShell())
    monkeypatch.setitem(freeturn.PINNED_SCRIPT_SHA256, "v4.2.0", "b" * 64)
    monkeypatch.setattr(freeturn.releases, "latest_tag", lambda repo: ("v4.2.0", ""))
    items = control.plan_argv(["apply", "--version=latest"])
    assert "--version=v4.2.0" in items
    assert " ".join(items).count("releases/download/v4.2.0/install.sh") == 1
    assert "--script-sha256=" + "b" * 64 in items


def test_the_local_version_keeps_its_flag_and_a_pinned_script(monkeypatch: pytest.MonkeyPatch) -> None:
    control = FtControl(shell=FakeShell())
    monkeypatch.setattr(freeturn.releases, "latest_tag", lambda repo: ("v4.1.2", ""))
    items = control.plan_argv(["apply", "--version=local"])
    assert "--version=local" in items
    assert "releases/download/%s/install.sh" % freeturn.FALLBACK_VERSION in " ".join(items)


def test_the_version_choices_are_all_pinned() -> None:
    assert freeturn.VERSION_CHOICES == ("latest", "v4.1.2")
    assert freeturn.FALLBACK_VERSION in freeturn.VERSION_CHOICES
    assert freeturn.PINNED_SCRIPT_SHA256 == {freeturn.FALLBACK_VERSION: freeturn.PINNED_SCRIPT_SHA256[freeturn.FALLBACK_VERSION]}
    for item in freeturn.VERSION_CHOICES:
        if item == "latest":
            continue
        assert item in freeturn.PINNED_SCRIPT_SHA256


def test_the_agent_resolves_the_version_the_same_way() -> None:
    module = load_agent()
    assert module.FALLBACK_VERSION == freeturn.FALLBACK_VERSION
    assert module.SCRIPT_SHA256 == freeturn.PINNED_SCRIPT_SHA256
    assert module.DEFAULT_URL.endswith("/%s/install.sh" % module.FALLBACK_VERSION)
    assert module.DEFAULT_SHA256 == module.SCRIPT_SHA256[module.FALLBACK_VERSION]
    assert module.resolve_version("")[0] == module.FALLBACK_VERSION
    assert module.resolve_version("v4.1.2") == ("v4.1.2", "pinned")
    assert module.resolve_version("local") == (module.FALLBACK_VERSION, "local")
    assert module.resolve_version("latest", lookup=lambda repo: ("v4.1.2", "")) == ("v4.1.2", "api")
    assert module.resolve_version("latest", lookup=lambda repo: ("v4.2.0", ""))[0] == module.FALLBACK_VERSION
    assert module.resolve_version("latest", lookup=lambda repo: ("", "rate_limited"))[0] == module.FALLBACK_VERSION
    for gone in ("v4.1.0", "v4.2.0"):
        with pytest.raises(module.AgentError) as caught:
            module.resolve_version(gone)
        assert caught.value.code == "not_pinned", gone


def test_the_agent_passes_the_resolved_tag_to_the_script(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()
    monkeypatch.setitem(module.SCRIPT_SHA256, "v4.2.0", "c" * 64)
    plan = module.command_argv("apply", {"version": "latest"}, lookup=lambda repo: ("v4.2.0", ""))
    assert "--version=v4.2.0" in plan
    assert "--version=latest" not in plan
    assert "--version=local" in module.command_argv("apply", {"version": "local"})
    assert "--version=" + module.FALLBACK_VERSION in module.command_argv("apply", {"version": "latest"}, lookup=lambda repo: ("", "rate_limited"))


def test_the_agent_downloads_the_script_of_the_resolved_version(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()
    seen: dict[str, str] = {}

    def fake_download(url: str, expected: str) -> str:
        seen["url"] = url
        seen["digest"] = expected
        return "/tmp/not-a-script"

    monkeypatch.setattr(module, "read_cache", lambda digest: "")
    monkeypatch.setattr(module, "download", fake_download)
    module.script_source({"version": "v4.1.2"})
    assert seen["url"].endswith("/v4.1.2/install.sh")
    assert seen["digest"] == module.SCRIPT_SHA256["v4.1.2"]
    module.script_source({})
    assert seen["url"].endswith("/%s/install.sh" % module.FALLBACK_VERSION)
    assert seen["digest"] == module.SCRIPT_SHA256[module.FALLBACK_VERSION]


def test_the_agent_recognises_a_rate_limited_api() -> None:
    module = load_agent()
    import io
    import urllib.error
    from email.message import Message

    message = Message()
    message["X-RateLimit-Remaining"] = "0"
    limited = urllib.error.HTTPError("https://api.github.com/x", 403, "forbidden", message, io.BytesIO(b""))
    assert module.rate_limited(limited) is True
    busy = urllib.error.HTTPError("https://api.github.com/x", 429, "slow down", Message(), io.BytesIO(b""))
    assert module.rate_limited(busy) is True
    plain = urllib.error.HTTPError("https://api.github.com/x", 500, "boom", Message(), io.BytesIO(b""))
    assert module.rate_limited(plain) is False


def test_the_agent_api_lookup_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()
    calls: list[int] = []

    class Answer:
        def __enter__(self) -> "Answer":
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def read(self, _limit: int = 0) -> bytes:
            return b'{"tag_name": "v4.1.2"}'

    def answer(request: object, timeout: float = 0) -> Answer:
        calls.append(1)
        return Answer()

    module.API_CACHE.clear()
    monkeypatch.setattr(module.urllib.request, "urlopen", answer)
    assert module.api_tag() == ("v4.1.2", "")
    assert module.api_tag() == ("v4.1.2", "")
    assert len(calls) == 1


def test_the_agent_survives_a_broken_api(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()
    module.API_CACHE.clear()

    def explode(request: object, timeout: float = 0) -> object:
        raise OSError("no route")

    monkeypatch.setattr(module.urllib.request, "urlopen", explode)
    assert module.api_tag() == ("", "unreachable")
    assert module.resolve_version("latest")[0] == module.FALLBACK_VERSION


def test_the_agent_api_lookup_gets_a_real_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()
    module.API_CACHE.clear()
    seen: dict[str, object] = {}

    class Answer:
        def __enter__(self) -> "Answer":
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def read(self, _limit: int = 0) -> bytes:
            return b'{"tag_name": "v4.1.2"}'

    def answer(request: object, timeout: object = 0) -> Answer:
        seen["timeout"] = timeout
        seen["url"] = getattr(request, "full_url", "")
        return Answer()

    monkeypatch.setattr(module.urllib.request, "urlopen", answer)
    assert module.api_tag(module.SCRIPT_REPO) == ("v4.1.2", "")
    assert isinstance(seen["timeout"], (int, float))
    assert seen["url"].endswith("/repos/%s/releases/latest" % module.SCRIPT_REPO)
    assert module.resolve_version("latest") == ("v4.1.2", "api")


def test_only_one_freeturn_version_is_pinned() -> None:
    assert list(freeturn.PINNED_SCRIPT_SHA256) == ["v4.1.2"]
    assert freeturn.FALLBACK_VERSION == "v4.1.2"
    assert freeturn.DEFAULT_VERSION == "v4.1.2"
    assert freeturn.VERSION_CHOICES == ("latest", "v4.1.2")
    module = load_agent()
    assert list(module.SCRIPT_SHA256) == ["v4.1.2"]
    assert module.FALLBACK_VERSION == "v4.1.2"


def test_the_dropped_version_is_refused_everywhere() -> None:
    for version in ("v4.1.0", "4.1.0"):
        with pytest.raises(FtError) as caught:
            freeturn.resolve_version(version)
        assert caught.value.code == "not_pinned"
    module = load_agent()
    with pytest.raises(module.AgentError) as caught:
        module.resolve_version("v4.1.0")
    assert caught.value.code == "not_pinned"


def test_the_plan_passes_the_published_digest_of_a_newer_release(monkeypatch: pytest.MonkeyPatch) -> None:
    control = FtControl(shell=FakeShell())
    monkeypatch.setattr(freeturn.releases, "latest_tag", lambda repo: ("v4.2.0", ""))
    monkeypatch.setattr(freeturn, "release_digest", lambda tag: "d" * 64)
    items = control.plan_argv(["apply", "--version=latest"])
    assert "--version=v4.2.0" in items
    assert "--script-sha256=" + "d" * 64 in items
    assert "releases/download/v4.2.0/install.sh" in " ".join(items)


def test_the_plan_falls_back_when_the_newer_release_publishes_no_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    control = FtControl(shell=FakeShell())
    monkeypatch.setattr(freeturn.releases, "latest_tag", lambda repo: ("v4.2.0", ""))
    monkeypatch.setattr(freeturn, "release_digest", lambda tag: "")
    items = control.plan_argv(["apply", "--version=latest"])
    assert "--version=v4.2.0" not in items
    assert "--version=" + freeturn.FALLBACK_VERSION in items
    assert "--script-sha256=" + freeturn.PINNED_SCRIPT_SHA256[freeturn.FALLBACK_VERSION] in items


def test_the_agent_installs_the_newest_release_with_its_published_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()
    seen: dict[str, str] = {}

    def fake_download(url: str, expected: str) -> str:
        seen["url"] = url
        seen["digest"] = expected
        return "/tmp/not-a-script"

    monkeypatch.setattr(module, "read_cache", lambda digest: "")
    monkeypatch.setattr(module, "download", fake_download)
    monkeypatch.setattr(module, "release_digest", lambda tag: "d" * 64)
    module.script_source({"version": "latest"}, lookup=lambda repo: ("v4.2.0", ""))
    assert seen["url"].endswith("/v4.2.0/install.sh")
    assert seen["digest"] == "d" * 64


def test_the_agent_refuses_a_script_without_a_published_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent()
    monkeypatch.setattr(module, "read_cache", lambda digest: "")
    monkeypatch.setattr(module, "release_digest", lambda tag: "")
    monkeypatch.setattr(module, "download", lambda url, expected: pytest.fail("the download must not start"))
    with pytest.raises(module.AgentError) as caught:
        module.script_source({"version": "latest"}, lookup=lambda repo: ("v4.2.0", ""))
    assert caught.value.code == "not_pinned"


def test_more_than_five_hundred_links_survive() -> None:
    from BOT.freeturn import LINKS_MAX

    state = FtState.from_dict({"installed": True, "running": True})
    for index in range(2040):
        state.remember("peer%04d" % index, "freeturn://%040d" % index)
    assert len(state.links) == 2040
    assert len(state.link_values()) == 2040
    assert LINKS_MAX >= 2040
    back = FtState.from_dict(state.to_dict())
    assert len(back.links) == 2040
    assert back.links["peer2039"] == state.links["peer2039"]


def test_a_long_name_is_refused_instead_of_being_cut() -> None:
    state = FtState.from_dict({"installed": True, "running": True})
    first = "a" * 40 + "-one"
    second = "a" * 40 + "-two"
    state.remember(first, "freeturn://" + "1" * 40)
    state.remember(second, "freeturn://" + "2" * 40)
    assert state.links == {}
    state.remember("ok-name", "freeturn://" + "3" * 40)
    assert list(state.links) == ["ok-name"]


def test_a_bytes_answer_is_parsed_too() -> None:
    answer = freeturn.parse_response(b'{"proto": 3, "result": "ok", "data": {"running": true}}')
    assert answer.result == "ok"
    assert answer.data["running"] is True
    with pytest.raises(FtError):
        freeturn.parse_response(None)


def test_agent_accepts_verified_new_release_tag_with_sha256_and_escapes_sandbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_agent()
    digest = "a" * 64
    flags = {"version": "v4.9.0", "script_sha256": digest, "script_url": "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.9.0/install.sh"}
    monkeypatch.setattr(module, "download", lambda url, expected: (url, expected))
    url, expected = module.script_source(flags)
    assert expected == digest
    assert "v4.9.0/install.sh" in url
    argv = module.command_argv("apply", flags)
    assert "--version=v4.9.0" in argv

    calls: list[list[str]] = []

    class _Done:
        returncode = 0
        stdout = b'{"proto": 3, "result": "ok", "data": {"running": true}}\n'

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        calls.append(list(cmd))
        return _Done()

    monkeypatch.setattr(module, "sandboxed_host", lambda: True)
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    out, code = module.run_script(str(tmp_path / "install.sh"), ["apply", "--json"], 30)
    assert code == 0
    assert '"running": true' in out
    assert calls and calls[0][0] == "systemd-run"


def test_bundled_install_script_seeds_offline_from_streamed_agent_code(tmp_path: Path) -> None:
    import base64 as b64_mod
    import gzip as gzip_mod
    import hashlib as hash_mod
    import subprocess as sp_mod
    import sys as sys_mod

    b64_path = freeturn.SCRIPT_B64_PATH
    assert b64_path.is_file()
    raw_b64 = b64_path.read_text(encoding="ascii")
    unpacked = gzip_mod.decompress(b64_mod.b64decode("".join(raw_b64.split())))
    expected_sha = freeturn.PINNED_SCRIPT_SHA256["v4.1.2"]
    assert hash_mod.sha256(unpacked).hexdigest() == expected_sha
    code_str = freeturn.agent_code()
    assert 'BUNDLED_INSTALL_B64 = ""' not in code_str
    cache_dir = tmp_path / "cache"
    driver = (
        "import hashlib, os\n"
        "ns = {'__name__': 'ft_streamed'}\n"
        "exec(compile(open(%r, encoding='utf-8').read(), '<stream>', 'exec'), ns)\n"
        "ns['CACHE_DIR'] = %r\n"
        "def _no_net(*a, **k): raise OSError('offline')\n"
        "ns['urlopen'] = _no_net\n"
        "seeded = ns['download']('https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.2/install.sh', %r)\n"
        "assert os.path.isfile(seeded)\n"
        "with open(seeded, 'rb') as fh:\n"
        "    assert hashlib.sha256(fh.read()).hexdigest() == %r\n"
        "print('SEEDED_OK')\n"
    )
    src_file = tmp_path / "streamed_agent.py"
    src_file.write_text(code_str, encoding="utf-8")
    proc = sp_mod.run(
        [sys_mod.executable, "-c", driver % (str(src_file), str(cache_dir), expected_sha, expected_sha)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "SEEDED_OK" in proc.stdout


def test_sbin_path_and_systemd_run_fallback_recover_firewall_and_ddos_nft(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_agent()
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    monkeypatch.setattr(module, "SBIN_DIRS", (str(sbin),))
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    module.ensure_sbin_path()
    assert str(sbin) in module.os.environ["PATH"].split(module.os.pathsep)

    ufw_bin = sbin / "ufw"
    ufw_bin.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    ufw_bin.chmod(0o755)
    seen_cmds: list[list[str]] = []

    class _Res:
        def __init__(self, rc: int, out: bytes) -> None:
            self.returncode = rc
            self.stdout = out

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        seen_cmds.append(list(cmd))
        if module.os.path.basename(cmd[0]) == "systemd-run":
            return _Res(1, b"Failed to find executable ufw: No such file or directory\n")
        return _Res(0, b"Rule added\n")

    monkeypatch.setattr(module, "sandboxed_host", lambda: True)
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    rc, out = module.run_tool(["ufw", "allow", "56000/udp"])
    assert rc == 0
    assert "Rule added" in out
    assert len(seen_cmds) == 2
    assert module.os.path.basename(seen_cmds[0][0]) == "systemd-run"
    assert "-E" in seen_cmds[0]
    assert seen_cmds[1][0] == str(ufw_bin)

    nft_file = tmp_path / "ddos.nft"
    nft_file.write_text(
        'table inet obhod_ddos {\n  chain input {\n    iifname "lo" accept\n    udp dport 1-65535 drop\n  }\n}\n',
        encoding="utf-8",
    )
    module.ddos_nft_file_sync(56000, ["udp"], str(nft_file))
    updated = nft_file.read_text(encoding="utf-8")
    assert "udp dport 56000 accept" in updated


def test_tcp_mode_kcp_flags_external_backend_validation_and_owner_link_refresh() -> None:
    tcp_cfg = FtConfig(mode="tcp", listen_port=56000)
    argv = tcp_cfg.server_argv()
    for expected in (
        "--kcp-nodelay=1",
        "--kcp-interval=20",
        "--kcp-resend=2",
        "--kcp-nc=1",
        "--kcp-sndwnd=512",
        "--kcp-rcvwnd=512",
        "--kcp-mtu=1200",
        "--kcp-acknodelay=true",
    ):
        assert expected in argv
    udp_argv = FtConfig(mode="udp", listen_port=56000).server_argv()
    assert not any(item.startswith("--kcp-") for item in udp_argv)

    with pytest.raises(FtError):
        FtConfig(backend="external", connect="").check()
    FtConfig(backend="external", connect="127.0.0.1:51820").check()

    stale = freeturn.encode_link(
        {"v": 1, "provider": "vk", "peer": "89.125.48.221:55000", "transport": "tcp", "mode": "udp", "obf_profile": "rtpopus3", "obf_key": "1" * 64}
    )
    fresh = freeturn.encode_link(
        {"v": 1, "provider": "vk", "peer": "89.125.48.221:56000", "transport": "tcp", "mode": "udp", "obf_profile": "rtpopus3", "obf_key": "2" * 64}
    )
    parsed = freeturn.FtState.from_dict(
        {
            "installed": True,
            "running": True,
            "config": {"listen_port": 56000, "host": "89.125.48.221", "mode": "udp", "transport": "tcp", "obf_profile": "rtpopus3"},
            "links": {"owner": stale},
            "owner": {"name": "owner", "link": fresh},
        }
    )
    decoded_owner = freeturn.decode_link(parsed.links["owner"])
    assert decoded_owner["peer"] == "89.125.48.221:56000"
    assert decoded_owner["obf_key"] == "2" * 64


def test_runtime_drift_auto_reapplies_and_checks_udp_listener_in_tcp_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_agent()
    root = tmp_path / "ft"
    (root / "auth").mkdir(parents=True)
    (root / "clients.list").write_text("owner|00112233445566778899aabbccddeeff|10.13.13.2|pub\n", encoding="utf-8")
    (root / "auth" / "clients.json").write_text('{"client_ids":[]}\n', encoding="utf-8")
    (root / "server").write_text("#!/bin/sh\n", encoding="ascii")
    (root / "server").chmod(0o755)
    (root / "version").write_text("latest\n", encoding="ascii")
    (root / "run.env").write_text('FT_ARGS="-listen 0.0.0.0:56000 -connect 127.0.0.1:51820 -mode tcp -clients-file /x"\n', encoding="utf-8")

    installed = {
        "INSTALL_METHOD": "systemd",
        "BACKEND": "new",
        "LISTEN_PORT": "56000",
        "PROXY_MODE": "tcp",
        "WG_PORT": "51820",
        "WG_NET": "10.13.13.0/24",
        "OBF_PROFILE": "rtpopus3",
        "OBF_KEY": "a" * 64,
        "VERSION": "v4.1.2",
    }
    assert module.runtime_drift(installed, str(root)) is True
    plan = module.reapply_argv(installed, str(root))
    assert plan[0] == "apply"
    assert "--update" in plan

    script_calls: list[list[str]] = []
    proto_checks: list[tuple[int, str]] = []

    def fake_run_script(_script: str, argv: list[str], _timeout: int) -> tuple[str, int]:
        script_calls.append(list(argv))
        if argv[0] == "apply":
            (root / "auth" / "clients.json").write_text('{"client_ids":["00112233445566778899aabbccddeeff"]}\n', encoding="utf-8")
            (root / "version").write_text("v4.1.2\n", encoding="ascii")
            (root / "run.env").write_text(
                'FT_ARGS="-listen 0.0.0.0:56000 -connect 127.0.0.1:51820 -mode tcp -obf-profile rtpopus3 -obf-key ' + ("a" * 64) + ' -clients-file /x"\n',
                encoding="utf-8",
            )
            return '{"proto":3,"result":"ok","data":{"installed":true,"running":true,"config":{"listen_port":56000,"mode":"tcp"}}}', 0
        return '{"proto":3,"result":"ok","data":{"installed":true,"running":true,"config":{"listen_port":56000,"mode":"tcp"}}}', 0

    def fake_port_listening(port: int, proto: str = "udp") -> bool:
        proto_checks.append((port, proto))
        return True

    monkeypatch.setattr(module, "INSTALL_ROOT", str(root))
    monkeypatch.setattr(module, "read_install_conf", lambda: dict(installed))
    monkeypatch.setattr(module, "ensure_apply_port_open", lambda flags, body: None)
    monkeypatch.setattr(module, "run_script", fake_run_script)
    monkeypatch.setattr(module, "port_listening", fake_port_listening)
    monkeypatch.setattr(module, "read_client_links", lambda: {})

    body: dict[str, Any] = {"result": "ok", "data": {"installed": True, "running": True, "config": {"listen_port": 56000, "mode": "tcp"}}}
    module.heal_runtime("/tmp/install.sh", "probe", {}, body)
    assert any(call[0] == "apply" for call in script_calls)
    assert module.runtime_drift(installed, str(root)) is False
    assert proto_checks and all(proto == "udp" for _p, proto in proto_checks)


