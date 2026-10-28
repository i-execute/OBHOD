from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import pytest

from BOT import inline, models, panel, shell
from BOT.models import ModelError, valid_port
from BOT.store import Store
from BOT.shell import LocalShell, ShellError, agent_argv
from tests.fakes import make_bot

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "Storage" / "remote" / "sub_server.py"
AGENT = ROOT / "Storage" / "remote" / "xray_agent.py"
SUB_ID = "A" * 64
SUB_KEY = "B" * 64
LINK = "vless://uuid@example.com:443?security=reality&encryption=mlkem768x25519plus.native.0rtt.key"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture()
def live(tmp_path: Path):
    registry = {
        "port": 2096,
        "entries": {
            SUB_ID: {
                "key": SUB_KEY,
                "title": "OBHOD\r\nX-Injected: yes",
                "filename": "../../etc/passwd",
                "enabled": True,
                "path": "/" + SUB_ID + "/" + SUB_KEY,
                "links": [LINK],
                "refresh": 24,
            },
            "C" * 64: {"key": "D" * 64, "enabled": False, "links": [LINK]},
        },
    }
    path = tmp_path / "subscriptions.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    port = free_port()
    env = dict(os.environ, OBHOD_SUB_REGISTRY=str(path), OBHOD_SUB_PORT=str(port), OBHOD_SUB_RATE="10")
    proc = subprocess.Popen([sys.executable, str(SERVER)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.time() + 10
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.1)
    yield port
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def fetch(port: int, path: str, method: str = "GET", timeout: float = 5.0) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_valid_path_serves_the_payload(live) -> None:
    status, headers, body = fetch(live, f"/{SUB_ID}/{SUB_KEY}")
    assert status == 200
    assert "Profile-Title" in headers
    assert headers["Profile-Update-Interval"] == "24"
    assert body


def test_wrong_key_and_unknown_id_are_indistinguishable(live) -> None:
    first = fetch(live, f"/{SUB_ID}/{'E' * 64}")
    second = fetch(live, f"/{'Z' * 64}/{SUB_KEY}")
    assert first[0] == second[0] == 404
    assert first[2] == second[2]


def test_disabled_entry_is_forbidden(live) -> None:
    status, _headers, _body = fetch(live, f"/{'C' * 64}/{'D' * 64}")
    assert status == 403


@pytest.mark.parametrize(
    "path",
    [
        "/../../../etc/passwd",
        "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/" + SUB_ID + "/../../etc/passwd",
        "/" + SUB_ID,
        "/" + SUB_ID + "/" + SUB_KEY + "/extra",
        "/" + ("A" * 63) + "/" + SUB_KEY,
        "/" + ("A" * 65) + "/" + SUB_KEY,
        "/" + SUB_ID + "/" + ("B" * 63) + "%00",
        "/" + SUB_ID + "/" + SUB_KEY.replace("B", "+"),
    ],
)
def test_traversal_and_malformed_paths_are_rejected(live, path: str) -> None:
    status, _headers, body = fetch(live, path)
    assert status in {400, 404}
    assert b"root:" not in body


def test_overlong_path_does_not_crash_the_server(live) -> None:
    status, _headers, _body = fetch(live, "/" + "a" * 20000)
    assert status in {400, 404, 414}
    assert fetch(live, f"/{SUB_ID}/{SUB_KEY}")[0] == 200


def test_response_headers_cannot_be_injected(live) -> None:
    status, headers, _body = fetch(live, f"/{SUB_ID}/{SUB_KEY}")
    assert status == 200
    assert "X-Injected" not in headers
    disposition = headers.get("Content-Disposition", "")
    assert "passwd" not in disposition
    assert headers.get("Content-Disposition", "").startswith("attachment; filename*=UTF-8''obhod")


def test_head_matches_get_without_a_body(live) -> None:
    status, headers, body = fetch(live, f"/{SUB_ID}/{SUB_KEY}", method="HEAD")
    assert status == 200
    assert body == b""
    assert int(headers["Content-Length"]) > 0


def test_flood_is_rate_limited(live) -> None:
    codes = [fetch(live, f"/{SUB_ID}/{SUB_KEY}")[0] for _ in range(20)]
    assert 429 in codes
    assert codes.count(200) <= 11


def test_slow_client_cannot_hold_a_thread(tmp_path: Path) -> None:
    path = tmp_path / "subscriptions.json"
    path.write_text(json.dumps({"entries": {}}), encoding="utf-8")
    port = free_port()
    env = dict(os.environ, OBHOD_SUB_REGISTRY=str(path), OBHOD_SUB_PORT=str(port))
    proc = subprocess.Popen([sys.executable, str(SERVER)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        started = time.time()
        with socket.create_connection(("127.0.0.1", port), timeout=30) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
            sock.settimeout(30)
            data = sock.recv(64)
        assert data or time.time() - started < 30
        assert fetch(port, "/health")[0] in {200, 429}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_release_urls_are_allowlisted() -> None:
    module = load(AGENT, "agent_url_checks")
    assert module.safe_url("https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip")
    for bad in (
        "http://github.com/x.zip",
        "https://evil.example/x.zip",
        "https://raw.githubusercontent.com/x.zip",
        "file:///etc/passwd",
        "file:///usr/bin/passwd.zip",
        "https://github.com/x.sh",
        "ftp://github.com/x.zip",
        "https://github.com@evil.example/x.zip",
    ):
        with pytest.raises(module.ScriptError):
            module.safe_url(bad)


def test_version_string_cannot_reach_the_shell() -> None:
    module = load(AGENT, "agent_version_checks")
    for bad in ("v1.2.3; rm -rf /", "../../x", "latest", "v1", "v1.2.3 && id"):
        with pytest.raises(module.ScriptError):
            module.install_core(bad, "", "", True)


def test_a_missing_digest_blocks_the_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load(AGENT, "agent_digest_checks")
    archive = tmp_path / "core.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("xray", b"binary")
    monkeypatch.setattr(module, "machine", lambda: "x86_64")
    monkeypatch.setattr(module, "download", lambda url, target: __import__("shutil").copyfile(archive, target))
    monkeypatch.setattr(module, "fetch_digest", lambda version, asset, url: "")
    with pytest.raises(module.ScriptError) as info:
        module.install_core("v26.11.1", "https://github.com/x.zip", "", True)
    assert info.value.code == "digest_missing"


def test_agent_argv_keeps_arguments_out_of_a_shell() -> None:
    hostile = "install"
    argv = agent_argv([hostile, "--ignoreip=1.2.3.4; rm -rf /", "--logpath=$(id)"], "print(1)")
    assert argv[0].endswith("python") or argv[0].endswith("python3")
    assert argv[1] == "-c"
    assert argv[2] == "print(1)"
    assert argv[3:] == [hostile, "--ignoreip=1.2.3.4; rm -rf /", "--logpath=$(id)"]
    joined = " ".join(argv)
    assert "sh -c" not in joined
    assert "shell=True" not in joined


def test_no_ssh_transport_module_exists() -> None:
    assert not (ROOT / "BOT" / "sshx.py").exists()
    assert (ROOT / "Storage" / "remote" / "ssh_agent.py").exists()
    source = (ROOT / "BOT" / "shell.py").read_text(encoding="utf-8")
    for token in ("asyncssh", "socket", "getaddrinfo", "connect", "paramiko"):
        assert token not in source, token


def test_shell_refuses_to_run_as_a_plain_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("BOT.shell.os.geteuid", lambda: 1000)
    with pytest.raises(ShellError) as info:
        asyncio.run(LocalShell().run_argv(["true"]))
    assert "root" in info.value.message


def test_shell_never_uses_an_interpreter_from_path(monkeypatch: pytest.MonkeyPatch) -> None:
    argv = agent_argv(["probe"], "print(1)")
    assert argv[0] == sys.executable
    assert os.path.isabs(argv[0])


def test_settings_never_keep_a_credential(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    payload = {
        "ssh": {
            "host": "203.0.113.10",
            "user": "root",
            "password": "pw",
            "key": "k",
            "passphrase": "p",
            "sudo_password": "s",
            "fingerprint": "SHA256:x",
            "auth": "PASSWORD",
            "mode": "SUDO_PASS",
        }
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    ssh = Store(path).load().ssh
    assert ssh.port == 22
    for name in ("host", "user", "password", "key", "passphrase", "sudo_password", "fingerprint", "auth", "mode"):
        assert not hasattr(ssh, name), name
    assert "pw" not in pathlib_dump(ssh)


def pathlib_dump(value: object) -> str:
    return json.dumps(value.to_dict())


def test_admin_cannot_be_claimed_by_a_stranger_after_the_window(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.cfg.admin_id = 0
    bot.state.admin_id = 0
    bot.started_at = time.monotonic() - 10_000

    async def scenario() -> bool:
        from tests.fakes import FakeEvent

        return await bot.guard_admin(FakeEvent(from_id=4242, chat_id=4242))

    assert asyncio.run(scenario()) is False
    assert bot.state.admin_id == 0


def test_admin_claim_works_inside_the_window(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.cfg.admin_id = 0
    bot.state.admin_id = 0

    async def scenario() -> bool:
        from tests.fakes import FakeEvent

        return await bot.guard_admin(FakeEvent(from_id=4242, chat_id=4242))

    assert asyncio.run(scenario()) is True
    assert bot.state.admin_id == 4242


def test_state_file_is_private(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    state = store.load()
    store.save(state)
    assert stat.S_IMODE(os.stat(tmp_path / "state.json").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path).st_mode) == 0o700


@pytest.mark.parametrize("value", ["a..b", "-x.com", "x-.com", "a b", "", "x" * 300])
def test_a_credential_field_cannot_be_written_from_the_outside(value: str) -> None:
    with pytest.raises(models.ModelError):
        models.valid_port(value)


@pytest.mark.parametrize("value", ["0", "65536", "-1", "1e3", ""])
def test_port_validation(value: str) -> None:
    with pytest.raises(ModelError):
        valid_port(value)


def test_input_strips_control_characters() -> None:
    assert "\n" not in inline.clean_value("xr_sub_address", "a\r\nb")
    assert inline.clean_value("xr_sub_address", "a\x00b") == "ab"


@pytest.mark.parametrize("value", ["1.2.3.4\nbanana", "not an ip", "1.2.3.4/99", "'; DROP", "::zz"])
def test_ignore_addresses_are_validated(value: str) -> None:
    with pytest.raises(panel.PanelError):
        panel.parse_addresses(value)


def test_ignore_addresses_accept_ranges() -> None:
    assert panel.parse_addresses("10.0.0.0/8, 192.168.1.5") == ["10.0.0.0/8", "192.168.1.5"]
    assert panel.parse_addresses("2001:db8::/32") == ["2001:db8::/32"]


@pytest.mark.parametrize("value", ["1.1.1.1 & curl evil", "dns\nbanana", "a" * 400])
def test_dns_entries_are_validated(value: str) -> None:
    with pytest.raises(panel.PanelError):
        panel.parse_dns(value)


def test_dns_entries_accept_the_documented_forms() -> None:
    assert panel.parse_dns("1.1.1.1, 8.8.8.8:53, https://dns.google/dns-query") == [
        "1.1.1.1",
        "8.8.8.8:53",
        "https://dns.google/dns-query",
    ]


@pytest.mark.parametrize("value", ["3", "0d", "3dd", "d", "-3d", "3d; id"])
def test_duration_validation(value: str) -> None:
    with pytest.raises(panel.PanelError):
        panel.parse_duration(value)


@pytest.mark.parametrize("value", ["30m", "3d", "1w", "3600s", "12h"])
def test_duration_accepts_suffixes(value: str) -> None:
    assert panel.parse_duration(value) == value


def test_models_module_has_no_auth_modes() -> None:
    assert not hasattr(models, "AUTHS")
    assert not hasattr(models, "AUTH_PASSWORD")
    assert not hasattr(models, "MODES")


def test_fail2ban_ignore_list_is_passed_as_one_argument() -> None:
    argv = agent_argv(["install", "--ignoreip=127.0.0.1/8 ::1", "--ssh_bantime=3d"], "print(1)")
    assert argv[3] == "install"
    assert argv[4] == "--ignoreip=127.0.0.1/8 ::1"
    assert argv[5] == "--ssh_bantime=3d"


def test_bootstrap_rejects_path_traversal_and_shell_metacharacters() -> None:
    from BOT.bootstrap import BootstrapError, BootstrapPlan

    plan = BootstrapPlan(token="123:abc", api_id=1, admin_id=0, install_dir="/opt/obhod;rm -rf /")
    with pytest.raises(BootstrapError):
        plan.validate()
    plan = BootstrapPlan(token="123:abc", api_id=1, admin_id=0, state_dir="../../etc")
    with pytest.raises(BootstrapError):
        plan.validate()
    plan = BootstrapPlan(token="123:abc\nOBHODUNIT", api_id=1, admin_id=0)
    with pytest.raises(BootstrapError):
        plan.validate()
    plan = BootstrapPlan(token="123:abc", api_id=1, admin_id=0, api_hash="x\nOBHODENV\nrm -rf /")
    with pytest.raises(BootstrapError):
        plan.validate()
    BootstrapPlan(token="123:abc", api_id=1, admin_id=7).validate()


def test_bootstrap_script_quotes_the_directories() -> None:
    from BOT.bootstrap import BootstrapPlan, install_script

    plan = BootstrapPlan(token="123:abc", api_id=1, admin_id=7)
    script = install_script(plan, "deps")
    assert "ROOT=/opt/obhod" in script
    assert "STATE=/var/lib/obhod" in script
    assert "ProtectSystem=strict" in install_script(plan, "finalize")


def test_fail2ban_install_writes_three_jails_and_ipv6_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load(ROOT / "Storage" / "remote" / "fail2ban_agent.py", "agent_fail2ban_install")
    etc = tmp_path / "fail2ban"
    for name in ("filter.d", "jail.d", "action.d"):
        (etc / name).mkdir(parents=True)
    monkeypatch.setattr(module, "FAIL2BAN_DIR", str(etc))
    monkeypatch.setattr(module, "FILTER_DIR", str(etc / "filter.d"))
    monkeypatch.setattr(module, "JAIL_DIR", str(etc / "jail.d"))
    monkeypatch.setattr(module, "ACTION_DIR", str(etc / "action.d"))
    monkeypatch.setattr(module, "JAIL_FILE", str(etc / "jail.d" / "obhod-ipl.conf"))
    monkeypatch.setattr(module, "FILTER_FILE", str(etc / "filter.d" / "obhod-ipl.conf"))
    monkeypatch.setattr(module, "ACTION_FILE", str(etc / "action.d" / "obhod-ipl.conf"))
    monkeypatch.setattr(module, "have", lambda tool: True)
    monkeypatch.setattr(module, "run", lambda argv, timeout=120: (0, ""))
    monkeypatch.setattr(module, "report", lambda port: {"ok": True})
    logpath = str(tmp_path / "xray.log")
    data = module.install(
        {
            "port": "2096",
            "bantime": "45",
            "ssh_bantime": "3d",
            "ssh_maxretry": "3",
            "ignoreip": "127.0.0.1/8 ::1",
            "logpath": logpath,
            "sublog": str(tmp_path / "sub.log"),
            "seclog": str(tmp_path / "security.log"),
        }
    )
    assert data == {"ok": True}
    action = (etc / "action.d" / "obhod-ipl.conf").read_text(encoding="utf-8")
    assert "ip6tables -A OBHOD-IPL -s <ip> -j DROP" in action
    assert "-I INPUT" not in action
    assert "iptables -F" not in action
    assert "iptables -P" not in action
    assert "ip6tables -A OBHOD-IPL -p tcp --dport" in action
    assert "exemptports = 22 2096" in action
    jail = (etc / "jail.d" / "obhod-ipl.conf").read_text(encoding="utf-8")
    assert "bantime = 45m" in jail
    assert "bantime = 3d" in jail
    assert "maxretry = 3" in jail
    assert "ignoreip = 127.0.0.1/8 ::1" in jail
    assert "[obhod-subs]" in jail
    assert (etc / "filter.d" / "obhod-subs.conf").read_text(encoding="utf-8").count("failregex") == 1
    assert (tmp_path / "sub.log").is_file()


def test_fail2ban_rejects_a_short_or_broken_duration() -> None:
    module = load(ROOT / "Storage" / "remote" / "fail2ban_agent.py", "agent_fail2ban_duration")
    assert module.duration_of("3d", "3d") == "3d"
    assert module.duration_of("99999", "3d") == "3d"
    assert module.duration_of("3d; reboot", "3d") == "3d"
    assert module.duration_of("", "3d") == "3d"
    assert module.minutes_of("0", 30) == 1
    assert module.minutes_of("abc", 30) == 30


def test_the_removed_transport_is_gone() -> None:
    assert not hasattr(shell, "SshClient")
    assert not hasattr(shell, "local_address")
    for name in ("asyncssh", "SshError", "SshOutput"):
        assert name not in dir(shell)


def test_the_ui_has_no_credential_fields(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    for ident in ("ssh_host", "ssh_user", "ssh_password", "ssh_key", "ssh_sudo"):
        assert ident not in inline.FIELDS
        assert ident not in bot.input_values()
        asyncio.run(bot.dispatch_input(7, ident, "-", "203.0.113.10"))
        assert not hasattr(bot.state.ssh, ident.replace("ssh_", ""))
    values = bot.input_values()
    assert "ssh_new_port" in values
    assert "ssh_pubkey" in inline.FIELDS


def test_a_state_file_cannot_add_a_credential(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"ssh": {"host": "203.0.113.10", "password": "pw", "port": 2222}}), encoding="utf-8")
    ssh = Store(path).load().ssh
    assert ssh.port == 2222
    assert "password" not in ssh.to_dict()
    assert "host" not in ssh.to_dict()


def test_the_installer_has_no_remote_host() -> None:
    from BOT.bootstrap import BootstrapError, BootstrapPlan

    with pytest.raises(TypeError):
        BootstrapPlan(host="203.0.113.10", token="123:abc", api_id=1, admin_id=7)
    plan = BootstrapPlan(token="123:abc", api_id=1, api_hash="x", admin_id=7)
    plan.validate()
    with pytest.raises(BootstrapError):
        plan.install_dir = "/opt/../etc"
        plan.validate()


def test_no_private_key_or_ssh_client_anywhere_in_the_code() -> None:
    for path in sorted((ROOT / "BOT").glob("*.py")):
        if path.name == "strings.py":
            continue
        body = path.read_text(encoding="utf-8")
        for token in ("asyncssh", "paramiko", "OPENSSH PRIVATE KEY", "ssh_keys", "PKey", "load_key"):
            assert token not in body, (path.name, token)
    assert "asyncssh" not in (ROOT / "requirements.txt").read_text(encoding="utf-8")


def test_the_state_file_round_trip_keeps_a_port_and_nothing_else(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    state = store.load()
    state.ssh.port = 2222
    store.save(state)
    raw = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert raw["ssh"] == {"port": 2222, "root_mode": "root"}
    assert store.load().ssh.port == 2222


def test_the_catalog_exposes_no_credential_labels() -> None:
    from BOT import i18n

    for name in i18n.keys("en"):
        assert "SSH_PASSWORD" not in name
        assert "SSH_PRIVATE_KEY" not in name
    assert i18n.t("SSH_NO_PASSWORD")
    for language in i18n.LANGUAGES:
        assert i18n.t("SSH_NO_PASSWORD", language)
        assert i18n.t("SSH_LOCAL_MODE", language)


def test_the_shell_reports_a_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("BOT.shell.os.geteuid", lambda: 0)
    with pytest.raises(ShellError) as info:
        asyncio.run(LocalShell().run_argv(["/nonexistent/obhod-binary"]))
    assert "could not start" in info.value.message


def test_the_shell_trims_output_and_keeps_the_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("BOT.shell.os.geteuid", lambda: 0)
    out = asyncio.run(LocalShell(command_timeout=30).run_argv(["/bin/sh", "-c", "printf ' hi \\n'; exit 3"]))
    assert out.text == "hi"
    assert out.code == 3


def test_the_shell_stops_a_runaway_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("BOT.shell.os.geteuid", lambda: 0)
    with pytest.raises(ShellError) as info:
        asyncio.run(LocalShell(command_timeout=1).run_argv(["/bin/sh", "-c", "sleep 30"]))
    assert "did not finish" in info.value.message
