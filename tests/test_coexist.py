from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from BOT.guard import BanState

ROOT = Path(__file__).resolve().parent.parent
AGENT_FAIL2BAN = ROOT / "Storage" / "remote" / "fail2ban_agent.py"

THIRD_PARTY_JAIL = """[3x-ipl]
enabled=true
backend=auto
filter=3x-ipl
action=3x-ipl
logpath=/var/log/x-ui/3xipl.log
maxretry=1
findtime=32
bantime=30m
"""

THIRD_PARTY_FILTER = """[Definition]
datepattern = ^%Y/%m/%d %H:%M:%S
failregex   = \\[LIMIT_IP\\]\\s*Email\\s*=\\s*<F-USER>.+</F-USER>\\s*\\|\\|\\s*Disconnecting OLD IP\\s*=\\s*<ADDR>\\s*\\|\\|\\s*Timestamp\\s*=\\s*\\d+
ignoreregex =
"""

THIRD_PARTY_ACTION = """[INCLUDES]
before = iptables-allports.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -j f2b-<name>

actionban = <iptables> -I f2b-<name> 1 -s <ip> -p tcp -m multiport ! --dports <exemptports> -j <blocktype>

[Init]
name = default
chain = INPUT
exemptports = 22,2053
"""


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, AGENT_FAIL2BAN)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def prepare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str):
    module = load(name)
    etc = tmp_path / "fail2ban"
    for folder in ("filter.d", "jail.d", "action.d"):
        (etc / folder).mkdir(parents=True)
    monkeypatch.setattr(module, "FAIL2BAN_DIR", str(etc))
    monkeypatch.setattr(module, "FILTER_DIR", str(etc / "filter.d"))
    monkeypatch.setattr(module, "JAIL_DIR", str(etc / "jail.d"))
    monkeypatch.setattr(module, "ACTION_DIR", str(etc / "action.d"))
    monkeypatch.setattr(module, "JAIL_FILE", str(etc / "jail.d" / "obhod-ipl.conf"))
    monkeypatch.setattr(module, "FILTER_FILE", str(etc / "filter.d" / "obhod-ipl.conf"))
    monkeypatch.setattr(module, "ACTION_FILE", str(etc / "action.d" / "obhod-ipl.conf"))
    monkeypatch.setattr(module, "SSHD_CONFIG", str(tmp_path / "sshd_config"))
    monkeypatch.setattr(module, "SSHD_DROPIN", str(tmp_path / "sshd_config.d"))
    monkeypatch.setattr(module, "have", lambda tool: True)
    monkeypatch.setattr(module, "run", lambda argv, timeout=120: (0, ""))
    monkeypatch.setattr(module, "report", lambda port: {"installed": True, "coexists_3x_ui": True})
    flags = {
        "port": "2096",
        "logpath": str(tmp_path / "xray" / "access.log"),
        "sublog": str(tmp_path / "xray" / "sub.log"),
        "seclog": str(tmp_path / "obhod" / "security.log"),
    }
    return module, etc, flags


def install_third_party(etc: Path) -> dict[Path, bytes]:
    files = {
        etc / "jail.d" / "3x-ipl.conf": THIRD_PARTY_JAIL,
        etc / "filter.d" / "3x-ipl.conf": THIRD_PARTY_FILTER,
        etc / "action.d" / "3x-ipl.conf": THIRD_PARTY_ACTION,
    }
    for path, body in files.items():
        path.write_text(body, encoding="utf-8")
    return {path: path.read_bytes() for path in files}


def test_the_jail_of_obhod_never_reuses_the_name_of_3x_ui() -> None:
    module = load("coexist_names")
    assert module.JAIL == "obhod-ipl"
    assert module.THIRD_PARTY_JAIL == "3x-ipl"
    for path in (module.JAIL_FILE, module.FILTER_FILE, module.ACTION_FILE):
        assert path.endswith("/obhod-ipl.conf")
        assert "3x-ipl" not in path
    body = module.jail_body(30, 1920, 1, "/var/log/xray/access.log", True, [22])
    assert "[obhod-ipl]" in body
    assert "filter = obhod-ipl" in body
    assert "action = obhod-ipl" in body
    assert "[3x-ipl]" not in body
    assert "filter = 3x-ipl" not in body


def test_the_chain_of_obhod_is_its_own_and_not_the_chain_of_3x_ui() -> None:
    module = load("coexist_chain")
    assert module.CHAIN == "OBHOD-IPL"
    assert "f2b-" not in module.ACTION
    assert "OBHOD-IPL" in module.ACTION
    assert "f2b-" in THIRD_PARTY_ACTION


def test_an_installed_3x_ui_jail_survives_an_obhod_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, etc, flags = prepare(tmp_path, monkeypatch, "coexist_install")
    before = install_third_party(etc)
    module.install(flags)
    for path, payload in before.items():
        assert path.read_bytes() == payload
    assert (etc / "jail.d" / "obhod-ipl.conf").is_file()
    assert (etc / "filter.d" / "obhod-ipl.conf").is_file()
    assert (etc / "action.d" / "obhod-ipl.conf").is_file()
    own = (etc / "jail.d" / "obhod-ipl.conf").read_text(encoding="utf-8")
    assert "[obhod-ipl]" in own
    assert "logpath = " + flags["logpath"] in own


def test_an_installed_3x_ui_jail_survives_an_obhod_remove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, etc, flags = prepare(tmp_path, monkeypatch, "coexist_remove")
    before = install_third_party(etc)
    module.install(flags)
    module.uninstall(flags)
    for path, payload in before.items():
        assert path.read_bytes() == payload
    assert not (etc / "jail.d" / "obhod-ipl.conf").exists()
    assert not (etc / "filter.d" / "obhod-ipl.conf").exists()
    assert not (etc / "action.d" / "obhod-ipl.conf").exists()
    assert not (etc / "filter.d" / "obhod-subs.conf").exists()


def test_the_old_files_of_obhod_are_adopted_and_the_ones_of_3x_ui_are_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, etc, flags = prepare(tmp_path, monkeypatch, "coexist_legacy")
    own_legacy = etc / "filter.d" / "3x-ipl.conf"
    own_legacy.write_text(module.LIMIT_FILTER, encoding="utf-8")
    own_action = etc / "action.d" / "3x-ipl.conf"
    own_action.write_text(module.ACTION.replace("__PORTS__", "22 2096"), encoding="utf-8")
    foreign = etc / "jail.d" / "3x-ipl.conf"
    foreign.write_text(THIRD_PARTY_JAIL, encoding="utf-8")
    module.install(flags)
    assert not own_legacy.exists()
    assert not own_action.exists()
    assert foreign.read_text(encoding="utf-8") == THIRD_PARTY_JAIL


def test_a_foreign_jail_is_reported_and_a_near_match_is_not_mistaken_for_obhod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, etc, _flags = prepare(tmp_path, monkeypatch, "coexist_report")
    assert module.third_party_jail() is False
    install_third_party(etc)
    assert module.third_party_jail() is True
    assert module.legacy_is_ours(etc / "filter.d" / "3x-ipl.conf") is False
    assert module.legacy_is_ours(etc / "action.d" / "3x-ipl.conf") is False
    assert module.legacy_is_ours(etc / "jail.d" / "3x-ipl.conf") is False
    state = BanState.from_dict({"installed": True, "jail": "obhod-ipl", "jails": ["obhod-ipl"], "coexists_3x_ui": True})
    assert state.active is True
    assert state.jail == "obhod-ipl"


def test_the_ssh_port_is_read_from_the_drop_in_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, _etc, _flags = prepare(tmp_path, monkeypatch, "coexist_sshd")
    main = tmp_path / "sshd_config"
    main.write_text("#Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\n", encoding="utf-8")
    dropin = tmp_path / "sshd_config.d"
    dropin.mkdir()
    (dropin / "10-obhod.conf").write_text("Port 2222\n", encoding="utf-8")
    assert module.ssh_port() == [2222]
    ports = module.exempt_ports(["2096"])
    assert 2222 in ports
    assert 2096 in ports
    assert 22 not in ports


def test_a_match_block_never_leaks_a_port(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, _etc, _flags = prepare(tmp_path, monkeypatch, "coexist_match")
    main = tmp_path / "sshd_config"
    main.write_text(
        "Port 22\n"
        "Match Address 10.0.0.0/8\n"
        "    Port 2200\n"
        "    PermitRootLogin no\n",
        encoding="utf-8",
    )
    (tmp_path / "sshd_config.d").mkdir()
    assert module.ssh_port() == [22]


def test_the_defaults_are_migrated_from_the_old_jail_name() -> None:
    from BOT import xray

    assert xray.XrayState().fail2ban_jail == "obhod-ipl"
    assert xray.XrayState.from_dict({"fail2ban_jail": "3x-ipl"}).fail2ban_jail == "obhod-ipl"
    assert xray.XrayState.from_dict({}).fail2ban_jail == "obhod-ipl"
    assert BanState().jail == "obhod-ipl"
    assert BanState.from_dict({"jail": "3x-ipl"}).jail == "obhod-ipl"


def test_the_bot_passes_its_own_jail_name_to_the_agent() -> None:
    from BOT import guard

    captured: list[list[str]] = []

    class Control:
        async def call(self, cfg, argv, timeout=None, source=""):
            captured.append(list(argv))
            from BOT.xrayrpc import XrayResponse

            return XrayResponse(result="ok", data={"installed": True, "jail": "obhod-ipl", "jails": ["obhod-ipl"]})

    import asyncio

    from BOT.models import SshSettings

    client = guard.GuardClient(Control())
    state = asyncio.run(client.install(SshSettings(), port=2096))
    assert state.active is True
    assert captured[0][0] == "install"
    assert not any("3x-ipl" in item for item in captured[0])


def test_the_ssh_jail_switches_to_the_journal_when_no_auth_log_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load("coexist_backend")
    monkeypatch.setattr(module, "auth_log_path", lambda: str(tmp_path / "missing.log"))
    monkeypatch.setattr(module, "systemd_backend_ready", lambda: True)
    assert module.ssh_backend() == "systemd"
    body = module.jail_body(30, 1920, 1, "/var/log/xray/access.log", True, [22], ssh_backend="systemd")
    section = body.split("[obhod-sshd]", 1)[1].split("[obhod-subs]", 1)[0]
    assert "backend = systemd" in section
    assert "logpath" not in section
    assert "maxretry = 3" in section
    assert "bantime = 3d" in section


def test_the_ssh_jail_keeps_the_file_when_the_auth_log_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load("coexist_backend_file")
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    monkeypatch.setattr(module, "auth_log_path", lambda: str(log))
    assert module.ssh_backend() == "auto"
    body = module.jail_body(30, 1920, 1, "/var/log/xray/access.log", True, [22], str(log))
    section = body.split("[obhod-sshd]", 1)[1].split("[obhod-subs]", 1)[0]
    assert "logpath = " + str(log) in section
    assert "backend = auto" in section
    assert "backend = systemd" not in body


def test_a_missing_auth_log_does_not_abort_the_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, etc, flags = prepare(tmp_path, monkeypatch, "coexist_backend_install")
    monkeypatch.setattr(module, "auth_log_path", lambda: str(tmp_path / "missing.log"))
    monkeypatch.setattr(module, "ssh_backend", lambda: "auto")
    monkeypatch.setattr(module, "systemd_backend_ready", lambda: True)
    seen: list[tuple[str, ...]] = []

    def counting_run(argv, timeout=120):
        if argv[:2] == ["fail2ban-client", "-t"]:
            seen.append(tuple(argv))
            if len(seen) == 1:
                return 1, "Have not found any log file for obhod-sshd jail"
            return 0, ""
        return 0, ""

    monkeypatch.setattr(module, "run", counting_run)
    module.install(flags)
    assert len(seen) == 2
    jail = (etc / "jail.d" / "obhod-ipl.conf").read_text(encoding="utf-8")
    section = jail.split("[obhod-sshd]", 1)[1].split("[obhod-subs]", 1)[0]
    assert "backend = systemd" in section
    assert "logpath" not in section
