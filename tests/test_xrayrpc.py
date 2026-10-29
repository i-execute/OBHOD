from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
import zipfile
from pathlib import Path

import pytest

from BOT.shell import ShellError, ShellOutput, agent_argv
from BOT.xrayrpc import (
    DEFAULT_VERSION,
    agent_code,
    PINNED_SHA256,
    XrayControl,
    XrayError,
    XrayResponse,
    asset_of_arch,
    digest_of,
    parse_dgst,
    parse_response,
    parse_xray_version,
    pinned_digest,
    release_asset,
)

FAKE_CORE = """#!/usr/bin/env python3
import json
import socket
import sys
import time

argv = sys.argv[1:]
if argv[:1] == ["version"]:
    print("Xray 26.10.29 (Xray, Penetrates Everything.)")
    raise SystemExit(0)
if argv[:1] == ["x25519"]:
    print("Private key: cHJpdmF0ZQ")
    print("Public key: cHVibGlj")
    raise SystemExit(0)
if argv[:2] == ["run", "-test"]:
    config = argv[-1]
    body = open(config, "r", encoding="utf-8").read()
    if "\\"inbounds\\"" not in body:
        print("invalid config")
        raise SystemExit(23)
    print("Configuration OK")
    raise SystemExit(0)
if argv[:1] == ["run"]:
    port = 0
    config = argv[-1]
    try:
        data = json.load(open(config, "r", encoding="utf-8"))
        port = int(data["inbounds"][0]["port"])
    except (OSError, ValueError, KeyError, IndexError):
        raise SystemExit(1)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(8)
    print("started", flush=True)
    while True:
        try:
            handle, _ = server.accept()
            handle.close()
        except KeyboardInterrupt:
            break
raise SystemExit(0)
"""

GOOD_CONFIG = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "port": 24443,
            "protocol": "vless",
            "settings": {"clients": [{"id": "11111111-2222-3333-4444-555555555555"}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "none"},
        }
    ],
    "outbounds": [{"protocol": "freedom"}],
}


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def build_zip(target: Path) -> str:
    core = target.parent / "xray"
    core.write_text(FAKE_CORE, encoding="utf-8")
    core.chmod(0o755)
    with zipfile.ZipFile(target, "w") as bundle:
        bundle.write(core, arcname="xray")
        bundle.writestr("geoip.dat", b"geoip")
        bundle.writestr("geosite.dat", b"geosite")
    return hashlib.sha256(target.read_bytes()).hexdigest()


@pytest.fixture()
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    root = tmp_path / "root"
    root.mkdir()
    archive = tmp_path / "core.zip"
    digest = build_zip(archive)
    monkeypatch.setenv("XRAY_ROOT", str(root))
    monkeypatch.setenv("XRAY_NO_SYSTEMD", "1")
    return {"root": str(root), "archive": str(archive), "digest": digest}


def call(*argv: str) -> dict:
    out = subprocess.run(agent_argv(list(argv), agent_code()), capture_output=True, text=True, timeout=180)
    lines = [line for line in out.stdout.splitlines() if line.startswith("{")]
    assert lines, out.stdout + out.stderr
    return json.loads(lines[-1])


def payload(config: dict) -> str:
    return base64.b64encode(json.dumps(config).encode()).decode()


def test_default_version_matches_fallback() -> None:
    assert DEFAULT_VERSION == "v26.10.29"
    assert pinned_digest("x86_64") == "8a5f3e6a1057e4bd0f8a7c57c9d91204b4be0b74222a6e210d070603101163c2"
    assert PINNED_SHA256["64"] == pinned_digest("x86_64")


def test_asset_mapping() -> None:
    assert asset_of_arch("x86_64") == "64"
    assert asset_of_arch("aarch64") == "arm64-v8a"
    assert asset_of_arch("armv7l") == "arm32-v7a"
    assert asset_of_arch("mips") == ""


def test_release_asset_url() -> None:
    url = release_asset("v26.10.29", "64")
    assert url == "https://github.com/XTLS/Xray-core/releases/download/v26.10.29/Xray-linux-64.zip"


def test_parse_dgst_body() -> None:
    body = "MD5= 5adb4bbf\nSHA1= 1068619\nSHA2-256= 0EEC3ED4163C273D8C8BF821F7D219E257921CF584AA3FB970715E458E631978\n"
    assert parse_dgst(body) == "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978"
    assert parse_dgst(body, "MD5") == "5adb4bbf"
    assert parse_dgst("nothing") == ""


def test_parse_xray_version_text() -> None:
    assert parse_xray_version("Xray 26.10.29 (Xray, Penetrates Everything.)") == "26.10.29"
    assert parse_xray_version("") == ""


def test_digest_of() -> None:
    assert digest_of("abc") == hashlib.sha256(b"abc").hexdigest()


def test_agent_argv_has_no_shell() -> None:
    argv = agent_argv(["probe"], "print(1)")
    assert argv[1] == "-c"
    assert argv[2] == "print(1)"
    assert argv[3:] == ["probe"]
    assert not any("sh -c" in item or "bash" in item for item in argv)
    assert agent_argv(["apply", "--config-b64=eyJ9"], "")[-1] == "--config-b64=eyJ9"


def test_parse_response_ok() -> None:
    response = parse_response('log line\n{"proto":3,"result":"ok","data":{"installed":true}}')
    assert response.ok is True
    assert response.data["installed"] is True


def test_parse_response_error() -> None:
    response = parse_response('{"proto":3,"result":"err","code":"download_failed","msg":"no network","stage":"download"}')
    assert response.ok is False
    with pytest.raises(XrayError) as info:
        response.raise_for_status()
    assert "no network" in info.value.message
    assert info.value.code == "download_failed"


def test_parse_response_proto_mismatch() -> None:
    with pytest.raises(XrayError) as info:
        parse_response('{"proto":2,"result":"ok"}')
    assert info.value.code == "proto_mismatch"


def test_parse_response_garbage() -> None:
    with pytest.raises(XrayError):
        parse_response("no json here")
    with pytest.raises(XrayError):
        parse_response('{"proto":3,')


def test_response_dataclass_defaults() -> None:
    response = XrayResponse()
    assert response.proto == 3
    assert response.ok is False


def test_probe_script_reports_clean_host(sandbox: dict[str, str]) -> None:
    body = call("probe")
    assert body["result"] == "ok"
    data = body["data"]
    assert data["installed"] is False
    assert data["pinned"] == "v26.10.29"
    assert data["systemd"] is False
    assert data["ports"] == []


def test_install_core_from_file_url(sandbox: dict[str, str]) -> None:
    body = call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    assert body["result"] == "ok", body
    assert body["data"]["installed"] is True
    assert body["data"]["version"] == "26.10.29"
    assert body["data"]["downloaded"] is True
    assert Path(sandbox["root"], "usr/local/bin/xray").is_file()


def test_install_core_rejects_bad_digest(sandbox: dict[str, str]) -> None:
    body = call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + "0" * 64)
    assert body["result"] == "err"
    assert body["code"] == "digest_mismatch"


def test_install_core_reports_missing_archive(sandbox: dict[str, str]) -> None:
    body = call("install-core", "--version=v26.10.29", "--url=file:///tmp/obhod-missing/core.zip", "--sha256=" + "0" * 64)
    assert body["result"] == "err"
    assert body["code"] == "download_failed"


def test_install_core_latest_falls_back_to_pinned(sandbox: dict[str, str]) -> None:
    body = call(
        "install-core",
        "--version=latest",
        "--tag=v26.10.29",
        "--url=file:///tmp/obhod-missing/latest.zip",
        "--fallback-url=file://" + sandbox["archive"],
        "--fallback-sha256=" + sandbox["digest"],
    )
    assert body["result"] == "ok", body
    assert body["data"]["fallback"] is True
    assert body["data"]["fallback_version"] == "v26.10.29"
    assert body["data"]["version"] == "26.10.29"
    assert any("falling back" in line for line in body["logs"])
    assert Path(sandbox["root"], "usr/local/bin/xray").is_file()


def test_install_core_latest_reports_fallback_log(sandbox: dict[str, str]) -> None:
    body = call(
        "install-core",
        "--version=latest",
        "--tag=v26.10.29",
        "--url=file://" + sandbox["archive"],
        "--sha256=" + sandbox["digest"],
    )
    assert body["result"] == "ok", body
    assert body["data"]["fallback"] is False
    assert body["data"]["version"] == "26.10.29"
    assert any("latest release" in line for line in body["logs"])


def test_install_core_pinned_failure_does_not_fallback(sandbox: dict[str, str]) -> None:
    body = call("install-core", "--version=v26.10.29", "--url=file:///tmp/obhod-missing/x.zip")
    assert body["result"] == "err"
    assert body["code"] == "download_failed"
    assert not any("falling back" in line for line in body["logs"])


def test_install_core_latest_fails_when_fallback_unreachable(sandbox: dict[str, str]) -> None:
    body = call(
        "install-core",
        "--version=latest",
        "--tag=v26.10.29",
        "--url=file:///tmp/obhod-missing/x.zip",
        "--fallback-url=file:///tmp/obhod-missing/pin.zip",
    )
    assert body["result"] == "err"
    assert body["code"] == "download_failed"
    assert any("falling back" in line for line in body["logs"])


def test_apply_installs_latest_with_fallback(sandbox: dict[str, str]) -> None:
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "in-1", "listen": "127.0.0.1", "port": free_port(), "protocol": "socks", "settings": {"udp": False}}
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    body = call(
        "apply",
        "--config-b64=" + payload(config),
        "--version=latest",
        "--tag=v26.10.29",
        "--url=file:///tmp/obhod-missing/latest.zip",
        "--fallback-url=file://" + sandbox["archive"],
        "--fallback-sha256=" + sandbox["digest"],
    )
    assert body["result"] == "ok", body
    assert body["data"]["fallback"] is True
    assert body["data"]["version"] == "26.10.29"


def test_install_core_is_idempotent(sandbox: dict[str, str]) -> None:
    first = call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    assert first["data"]["downloaded"] is True
    second = call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    assert second["result"] == "ok"
    assert second["data"]["downloaded"] is False
    forced = call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"], "--force")
    assert forced["data"]["downloaded"] is True


def test_test_config_validates(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    good = call("test-config", "--config-b64=" + payload(GOOD_CONFIG))
    assert good["result"] == "ok"
    assert good["data"]["valid"] is True
    bad = call("test-config", "--config-b64=" + payload({"outbounds": []}))
    assert bad["result"] == "ok"
    assert bad["data"]["valid"] is False
    rejected = call("apply", "--config-b64=" + payload({"outbounds": []}), "--no-restart")
    assert rejected["result"] == "err"
    assert rejected["code"] == "config_invalid"


def test_apply_requires_inbounds(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("apply", "--config-b64=" + payload({"outbounds": []}))
    assert body["result"] == "err"
    assert body["code"] == "config_invalid"


def test_apply_without_payload(sandbox: dict[str, str]) -> None:
    body = call("apply")
    assert body["result"] == "err"
    assert body["code"] == "config_missing"


def test_apply_start_stop_cycle(sandbox: dict[str, str]) -> None:
    port = free_port()
    config = json.loads(json.dumps(GOOD_CONFIG))
    config["inbounds"][0]["port"] = port
    call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("apply", "--config-b64=" + payload(config), "--version=v26.10.29")
    assert body["result"] == "ok", body
    data = body["data"]
    assert data["applied"] is True
    assert data["ports"] == [port]
    assert data["listening"] == [port]
    assert data["service"] == "active"
    stopped = call("stop")
    assert stopped["result"] == "ok"
    assert stopped["data"]["service"] == "inactive"
    assert stopped["data"]["listening"] == []


def test_apply_no_restart_keeps_service_stopped(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("apply", "--config-b64=" + payload(GOOD_CONFIG), "--no-restart")
    assert body["result"] == "ok"
    assert body["data"]["service"] in {"inactive", "absent"}


def test_restart_without_config(sandbox: dict[str, str]) -> None:
    body = call("restart")
    assert body["result"] == "err"
    assert body["code"] == "not_installed"


def test_x25519_command(sandbox: dict[str, str]) -> None:
    body = call("x25519")
    assert body["result"] == "err"
    call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("x25519")
    assert body["result"] == "ok"
    assert body["data"]["private"] == "cHJpdmF0ZQ"
    assert body["data"]["public"] == "cHVibGlj"


def test_logs_command(sandbox: dict[str, str]) -> None:
    body = call("logs", "--tail=10")
    assert body["result"] == "ok"
    assert isinstance(body["data"]["lines"], list)


def test_uninstall_purges(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    call("apply", "--config-b64=" + payload(GOOD_CONFIG), "--no-restart")
    body = call("uninstall", "--purge")
    assert body["result"] == "ok"
    assert body["data"]["purge"] is True
    state = call("probe")["data"]
    assert state["installed"] is False
    assert state["config_exists"] is False


def test_uninstall_keeps_core_without_purge(sandbox: dict[str, str]) -> None:
    call("install-core", "--version=v26.10.29", "--url=file://" + sandbox["archive"], "--sha256=" + sandbox["digest"])
    body = call("uninstall")
    assert body["result"] == "ok"
    assert call("probe")["data"]["installed"] is True


def test_unknown_command(sandbox: dict[str, str]) -> None:
    body = call("bogus")
    assert body["result"] == "err"
    assert body["code"] == "bad_arg"


def test_bad_base64_payload(sandbox: dict[str, str]) -> None:
    body = call("apply", "--config-b64=!!!!")
    assert body["result"] == "err"
    assert body["code"] in {"bad_arg", "config_missing"}


def test_no_command(sandbox: dict[str, str]) -> None:
    out = subprocess.run(agent_argv([], agent_code()), capture_output=True, text=True, timeout=60)
    body = json.loads([line for line in out.stdout.splitlines() if line.startswith("{")][-1])
    assert body["code"] == "bad_arg"


def test_interpreter_is_absolute() -> None:
    argv = agent_argv(["probe"], "")
    assert os.path.isabs(argv[0])
    assert argv[0].endswith("python3") or argv[0].endswith("python")


def test_control_client_over_fake_shell(sandbox: dict[str, str]) -> None:
    class FakeShell:
        def __init__(self) -> None:
            self.argv: list[list[str]] = []

        async def run_argv(self, argv, stdin=None, timeout=None):
            self.argv.append(list(argv))
            out = subprocess.run(argv, capture_output=True, text=True, timeout=180)
            return ShellOutput(text=out.stdout.strip(), code=out.returncode)

    from BOT.models import SshSettings

    shell = FakeShell()
    control = XrayControl(shell=shell)
    cfg = SshSettings()
    state = asyncio.run(control.probe(cfg))
    assert state.installed is False
    assert state.pinned == "v26.10.29"
    asyncio.run(control.install_core(cfg, url="file://" + sandbox["archive"], sha256=sandbox["digest"]))
    applied = asyncio.run(control.apply(cfg, json.dumps(GOOD_CONFIG), restart=False))
    assert applied.config_exists is True
    valid, output = asyncio.run(control.test_config(cfg, json.dumps(GOOD_CONFIG)))
    assert valid is True
    private, public = asyncio.run(control.x25519(cfg))
    assert private == "cHJpdmF0ZQ"
    assert shell.argv
    for argv in shell.argv:
        assert isinstance(argv, list)
        assert argv[1] == "-c"
        assert "ssh" not in " ".join(argv[:2])


def test_control_client_without_core_raises(sandbox: dict[str, str]) -> None:
    class FakeShell:
        async def run_argv(self, argv, stdin=None, timeout=None):
            return ShellOutput(text='{"proto":3,"result":"err","code":"not_installed","msg":"no core"}', code=1)

    from BOT.models import SshSettings

    control = XrayControl(shell=FakeShell())
    cfg = SshSettings()
    with pytest.raises(XrayError) as info:
        asyncio.run(control.restart(cfg))
    assert info.value.code == "not_installed"


def test_control_client_transport_error() -> None:
    class FakeShell:
        async def run_argv(self, argv, stdin=None, timeout=None):
            raise ShellError("no interpreter")

    from BOT.models import SshSettings

    control = XrayControl(shell=FakeShell())
    cfg = SshSettings()
    with pytest.raises(XrayError) as info:
        asyncio.run(control.probe(cfg))
    assert info.value.code == "transport"


def test_no_stdin_payload_is_passed() -> None:
    seen: list[bytes] = []

    class FakeShell:
        async def run_argv(self, argv, stdin=None, timeout=None):
            seen.append(stdin or b"")
            return ShellOutput(text='{"proto":3,"result":"ok","data":{}}', code=0)

    from BOT.models import SshSettings

    control = XrayControl(shell=FakeShell())
    asyncio.run(control.probe(SshSettings()))
    assert seen and all(item == b"" for item in seen)


def test_remote_script_has_no_python_comments() -> None:
    from BOT.xrayrpc import agent_code

    for line in agent_code().splitlines():
        assert not line.strip().startswith("#")


def test_script_runs_without_leftovers(sandbox: dict[str, str]) -> None:
    body = call("probe")
    assert body["result"] == "ok"
    assert not Path(sandbox["root"], "usr/local/etc/xray/config.json").exists()


def test_wait_for_ports_helper() -> None:
    deadline = time.time() + 1
    assert deadline > time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=2) as probe_socket:
            assert probe_socket.getpeername()[1] == port


def test_e2e_over_the_local_shell(sandbox: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT.models import SshSettings
    from BOT.shell import LocalShell

    monkeypatch.setattr("BOT.shell.os.geteuid", lambda: 0)
    control = XrayControl(shell=LocalShell(command_timeout=180))
    cfg = SshSettings()
    initial = asyncio.run(control.probe(cfg))
    assert initial.installed is False
    installed = asyncio.run(control.install_core(cfg, url="file://" + sandbox["archive"], sha256=sandbox["digest"]))
    assert installed.ok is True
    applied = asyncio.run(control.apply(cfg, json.dumps(GOOD_CONFIG), restart=False))
    assert applied.config_exists is True
    valid, _ = asyncio.run(control.test_config(cfg, json.dumps(GOOD_CONFIG)))
    assert valid is True
    private, public = asyncio.run(control.x25519(cfg))
    assert private and public
    removed = asyncio.run(control.uninstall(cfg, purge=True))
    assert removed.ok is True
    final = asyncio.run(control.probe(cfg))
    assert final.installed is False


def test_local_shell_refuses_without_root(monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT.shell import LocalShell

    monkeypatch.setattr("BOT.shell.os.geteuid", lambda: 1000)
    shell = LocalShell()
    with pytest.raises(ShellError) as info:
        asyncio.run(shell.run_argv(["true"]))
    assert "root" in info.value.message


def test_env_root_prefixing(sandbox: dict[str, str]) -> None:
    body = call("probe")
    assert body["data"]["core_path"].startswith(sandbox["root"])
    assert os.environ["XRAY_ROOT"] == sandbox["root"]


def test_cleanup_removes_sandbox(sandbox: dict[str, str]) -> None:
    target = Path(sandbox["root"])
    shutil.rmtree(target, ignore_errors=True)
    assert not target.exists()
