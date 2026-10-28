from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

import pytest

from BOT import guard
from BOT.models import SshSettings
from BOT.shell import agent_argv
from BOT.xrayrpc import XrayError
from tests.fakes import FakeControl


def test_scripts_live_in_the_repository() -> None:
    for path in (guard.FAIL2BAN_SCRIPT, guard.SSH_SCRIPT):
        assert path.is_file()
        assert path.suffix == ".py"
        source = path.read_text(encoding="utf-8")
        for line in source.splitlines():
            assert not line.strip().startswith("#")


def test_missing_script_raises(tmp_path: Path) -> None:
    with pytest.raises(XrayError):
        guard.script_code(tmp_path / "nope.py", "script")


def test_agent_argv_embeds_the_given_source() -> None:
    source = guard.script_code(guard.SSH_SCRIPT, "ssh script")
    argv = agent_argv(["status"], source)
    assert argv[2] == source
    assert argv[1] == "-c"
    assert argv[-1] == "status"
    assert "print(" in agent_argv(["x"], "print(1)")[2]


def test_ban_state_parsing() -> None:
    state = guard.BanState.from_dict(
        {
            "installed": True,
            "jails": ["3x-ipl", "obhod-sshd"],
            "main": {"banned": ["1.2.3.4"]},
            "ssh": {"banned": ["5.6.7.8"]},
            "chain_rules": ["DROP all -- 1.2.3.4"],
            "port": 2096,
        }
    )
    assert state.active is True
    assert state.banned == ["1.2.3.4"]
    assert state.ssh_banned == ["5.6.7.8"]
    assert state.to_dict()["chain"] == "OBHOD-IPL"


def test_ssh_state_parsing() -> None:
    state = guard.SshState.from_dict({"ports": [2222], "keys": 3, "key_user": "root"})
    assert state.ports == [2222]
    assert state.keys == 3
    assert state.to_dict()["key_user"] == "root"


def test_guard_calls_use_the_fail2ban_script() -> None:
    control = FakeControl()
    client = guard.GuardClient(control)
    cfg = SshSettings()
    captured: list[tuple[str, list[str]]] = []

    async def fake_call(cfg_in: object, argv: list[str], timeout: float | None = None, source: str = "") -> object:
        captured.append((source, argv))
        from BOT.xrayrpc import XrayResponse

        return XrayResponse(result="ok", data={"installed": True, "jails": ["3x-ipl"], "port": 2096})

    control.call = fake_call
    state = asyncio.run(client.install(cfg, port=2096, bantime=45))
    assert state.installed is True
    source, argv = captured[0]
    assert argv[0] == "install"
    assert "--bantime=45" in argv
    assert "--port=2096" in argv
    assert "JAIL_FILE" in source
    assert "SECURITY_FILTER" in source


def test_guard_status_and_ssh_calls() -> None:
    control = FakeControl()
    client = guard.GuardClient(control)
    cfg = SshSettings()
    seen: list[list[str]] = []

    async def fake_call(cfg_in: object, argv: list[str], timeout: float | None = None, source: str = "") -> object:
        seen.append(argv)
        from BOT.xrayrpc import XrayResponse

        return XrayResponse(result="ok", data={"installed": False, "ports": [22], "keys": 1})

    control.call = fake_call
    asyncio.run(client.status(cfg, port=2096))
    asyncio.run(client.ssh_status(cfg))
    asyncio.run(client.ssh_apply(cfg, port=2200, password="no", root="no"))
    asyncio.run(client.ssh_add_key(cfg, "ssh-ed25519 AAAA test"))
    asyncio.run(client.ssh_remove(cfg))
    assert seen[0] == ["status", "--port=2096"]
    assert seen[1] == ["status"]
    assert seen[2] == ["apply", "--port=2200", "--password=no", "--root=no"]
    assert seen[3][0] == "key"
    assert seen[4] == ["remove"]


def test_fail2ban_agent_writes_expected_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("fail2ban_agent", guard.FAIL2BAN_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["fail2ban_agent"] = module
    spec.loader.exec_module(module)
    filter_file = tmp_path / "3x-ipl.conf"
    module.write_file(str(filter_file), module.LIMIT_FILTER)
    body = filter_file.read_text(encoding="utf-8")
    assert "[Definition]" in body
    assert "LIMIT_IP" in body
    assert "<ADDR>" in body
    assert body.count("\n") >= 3
    jail = module.jail_body(30, 1920, 1, "/var/log/xray/access.log", True, [22, 2096])
    assert "[3x-ipl]" in jail
    assert "maxretry = 1" in jail
    assert "findtime = 1920" in jail
    assert "bantime = 30m" in jail
    assert "exemptports" not in jail
    assert "[obhod-sshd]" in jail
    assert "bantime = 3d" in jail
    assert "maxretry = 3" in jail
    assert "findtime = 3600" in jail
    assert "[obhod-subs]" in jail
    assert "filter = obhod-subs" in jail


def test_fail2ban_action_has_exempt_ports(tmp_path: Path) -> None:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("fail2ban_agent_action", guard.FAIL2BAN_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["fail2ban_agent_action"] = module
    spec.loader.exec_module(module)
    body = module.ACTION.replace("__PORTS__", "22 2096")
    assert "iptables -A OBHOD-IPL -s <ip> -j DROP" in body
    assert "ip6tables -A OBHOD-IPL -s <ip> -j DROP" in body
    assert "--dport $p -j RETURN" in body
    assert "exemptports = 22 2096" in body
    for forbidden in ("iptables -F ", "ip6tables -F ", "-I INPUT", "iptables -P ", "restore"):
        assert forbidden not in body, forbidden
    assert "iptables -A INPUT -j OBHOD-IPL" in body
    assert "iptables -S OBHOD-IPL >/dev/null 2>&1 || iptables -N OBHOD-IPL" in body


def test_ssh_agent_parse_and_status(tmp_path: Path) -> None:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("ssh_agent", guard.SSH_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["ssh_agent"] = module
    spec.loader.exec_module(module)
    flags, rest = module.parse_flags(["--port=2222", "extra"])
    assert flags["port"] == "2222"
    assert rest == ["extra"]
    data = module.status({})
    assert data["ports"]
    assert data["key_path"]
    assert "permit_root_login" in data


def test_fail2ban_jail_carries_loopback_exemptions_and_auth_log(tmp_path: Path) -> None:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("fail2ban_agent_ignore", guard.FAIL2BAN_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["fail2ban_agent_ignore"] = module
    spec.loader.exec_module(module)
    jail = module.jail_body(60, 32, 1, "/var/log/xray/access.log", True, [22, 2096], "/var/log/secure", "10.0.0.0/8")
    assert jail.count("ignoreip = 10.0.0.0/8") == 4
    assert "logpath = /var/log/secure" in jail
    assert "logpath = /var/log/xray/access.log" in jail
    default = module.jail_body(60, 32, 1, "/var/log/xray/access.log", False, [22])
    assert "ignoreip = 127.0.0.1/8 ::1" in default
    assert "enabled = false" in default
    assert "logpath = /var/log/auth.log" in default
    assert module.auth_log_path().startswith("/var/log/")


def agent_module(name: str = "ssh_agent_case"):
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location(name, guard.SSH_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def prepared_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import base64

    module = agent_module()
    keys = tmp_path / "authorized_keys"
    dropin = tmp_path / "00-obhod.conf"
    main = tmp_path / "sshd_config"
    main.write_text("Port 22\n", encoding="utf-8")
    monkeypatch.setattr(module, "SSHD_MAIN", str(dropin))
    monkeypatch.setattr(module, "SSHD_CONFIG", str(main))
    monkeypatch.setattr(module, "authorized_key_owner", lambda: ("root", str(keys)))
    monkeypatch.setattr(module, "test_config", lambda: (True, ""))
    monkeypatch.setattr(module, "restart", lambda: None)

    def add(text: str):
        return module.add_key({"key_b64": base64.b64encode(text.encode("utf-8")).decode("ascii")})

    return module, keys, dropin, add


def test_ssh_agent_adds_keys_one_after_another(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, keys, _dropin, add = prepared_agent(tmp_path, monkeypatch)
    add("ssh-ed25519 AAAABBBBCCCCDDDD laptop")
    add("ssh-ed25519 EEEEFFFFGGGGHHHH phone")
    add("sk-ssh-ed25519-IIIIJJJJKKKK touch")
    lines = [line for line in keys.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 3
    assert lines[0].endswith("laptop")
    assert lines[1].endswith("phone")
    assert lines[2].endswith("touch")
    assert module.key_count(str(keys)) == 3
    assert stat.S_IMODE(os.stat(keys).st_mode) == 0o600


def test_ssh_agent_does_not_duplicate_a_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _module, keys, _dropin, add = prepared_agent(tmp_path, monkeypatch)
    add("ssh-ed25519 AAAABBBBCCCCDDDD laptop")
    add("ssh-ed25519 AAAABBBBCCCCDDDD laptop")
    add("ssh-ed25519 AAAABBBBCCCCDDDD another-comment")
    lines = [line for line in keys.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines == ["ssh-ed25519 AAAABBBBCCCCDDDD laptop"]


def test_ssh_agent_refuses_to_disable_the_password_without_a_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, _keys, dropin, _add = prepared_agent(tmp_path, monkeypatch)
    with pytest.raises(module.ScriptError) as info:
        module.apply({"password": "no"})
    assert info.value.code == "no_keys"
    assert "no public key" in info.value.message
    assert not dropin.exists()


def test_ssh_agent_turns_the_password_off_and_back_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, _keys, dropin, add = prepared_agent(tmp_path, monkeypatch)
    add("ssh-ed25519 AAAABBBBCCCCDDDD laptop")
    module.apply({"password": "no"})
    body = dropin.read_text(encoding="utf-8")
    assert "PasswordAuthentication no" in body
    assert "KbdInteractiveAuthentication no" in body
    module.apply({"password": "yes"})
    body = dropin.read_text(encoding="utf-8")
    assert "PasswordAuthentication yes" in body
    assert "KbdInteractiveAuthentication yes" in body
    assert "MaxAuthTries 3" in body
    assert "PermitRootLogin" not in body
    module.apply({"password": "yes", "root": "no"})
    body = dropin.read_text(encoding="utf-8")
    assert "PermitRootLogin no" in body
    assert "PasswordAuthentication yes" in body
