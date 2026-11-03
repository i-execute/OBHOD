from __future__ import annotations

import importlib.util
import json
import socket
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "Storage" / "remote" / "honeypot_agent.py"


def load(name: str = "obhod_honeypot"):
    spec = importlib.util.spec_from_file_location(name, AGENT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def honey(tmp_path: Path):
    module = load("obhod_honeypot_%d" % id(tmp_path))
    module.LOG_PATH = str(tmp_path / "honeypot.log")
    module.CONF = str(tmp_path / "honeypot.json")
    module.UNIT = str(tmp_path / "obhod-honeypot.service")
    return module


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class Running:
    def __init__(self, module, ports, **extra):
        config = {
            "ports": list(ports),
            "bind": "127.0.0.1",
            "log": str(Path(module.LOG_PATH)),
            "greet": 0.0,
            "idle": 3.0,
            "profiles": {str(item): "ssh" for item in ports},
        }
        config.update(extra)
        self.sink = module.Sink(log_path(config), echo=False)
        self.server = module.Server(config, self.sink)
        self.ports = ports
        self.started = self.server.start()
        time.sleep(0.05)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.server.close()
        time.sleep(0.05)
        return False

    def rows(self, wait=0.2):
        time.sleep(wait)
        return list(self.sink.rows)


def log_path(config) -> str:
    return str(config.get("log", ""))


def talk(port, payload=b"", read=256, wait=0.05):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sock.connect(("127.0.0.1", port))
    data = b""
    try:
        data = sock.recv(read)
    except OSError:
        pass
    if payload:
        try:
            sock.sendall(payload)
        except OSError:
            pass
        time.sleep(wait)
        try:
            data += sock.recv(read)
        except OSError:
            pass
    sock.close()
    return data


def test_the_banner_looks_like_a_real_sshd(honey) -> None:
    port = free_port()
    with Running(honey, [port]) as run:
        data = talk(port, read=512)
        assert run.rows()
    assert data.startswith(b"SSH-2.0-OpenSSH_")
    assert b"\r\n" in data[:80]
    assert b"curve25519-sha256" in data
    assert b"chacha20-poly1305@openssh.com" in data
    assert len(data) > 200


def test_the_kexinit_is_a_well_formed_ssh_packet(honey) -> None:
    packet = honey.kexinit()
    length = int.from_bytes(packet[:4], "big")
    assert length + 4 == len(packet)
    padding = packet[4]
    assert 4 <= padding <= 255
    assert packet[5] == 20
    assert (length + 4) % 8 == 0
    assert honey.kexinit() != honey.kexinit()


def test_credentials_are_read_from_plaintext_protocols(honey) -> None:
    assert honey.credentials(b"USER root\r\nPASS hunter2\r\n") == [("user", "root"), ("pass", "hunter2")]
    assert honey.credentials(b"AUTH mysecret\r\n") == [("pass", "mysecret")]
    assert honey.credentials(b"") == []
    assert honey.credentials(b"USER " + b"A" * 400) == [("user", "A" * 64)]


def test_a_password_never_reaches_the_log_in_the_clear(honey) -> None:
    port = free_port()
    with Running(honey, [port]) as run:
        talk(port, b"USER admin\r\nPASS SuperSecret123\r\n")
        rows = run.rows()
    joined = "\n".join(rows)
    assert "SuperSecret123" not in joined
    assert "secret=" + honey.digest("SuperSecret123") in joined
    assert "role=user" in joined
    assert "user=admin" in joined


def test_one_touch_produces_a_fail2ban_line(honey) -> None:
    port = free_port()
    with Running(honey, [port]) as run:
        talk(port)
        rows = run.rows()
    assert rows
    assert rows[-1].startswith("honeypot ip=127.0.0.1 port=%d proto=ssh event=probe " % port
                               ) or any(" event=probe " in row for row in rows)
    for row in rows:
        body = row.split()
        assert body[0] == "honeypot"
        fields = dict(part.split("=", 1) for part in body[1:] if "=" in part)
        assert fields["proto"] in {"ssh", "ftp", "telnet", "http", "redis", "rdp", "raw"}
        assert fields["event"].isalnum() or "_" in fields["event"]


def test_a_log_injection_cannot_rewrite_the_address(honey) -> None:
    hostile = "1.2.3.4\nhoneypot ip=10.0.0.1 port=22 proto=ssh event=probe\n"
    row = honey.line(hostile, 2222, "ssh", "probe")
    assert "\n" not in row
    assert "ip=0.0.0.0" in row
    assert "ip=10.0.0.1" not in row
    weird = honey.line("127.0.0.1", 2222, "ssh", "auth", user="a=b c\nip=10.0.0.1", secret="x")
    assert weird.count("ip=") == 1
    assert " " not in weird.split("user=")[1].split()[0]
    evil_event = honey.line("127.0.0.1", 2222, "ssh", "probe ip=10.0.0.1 event=ban")
    assert evil_event.count("event=") == 1


def test_the_filter_regex_only_matches_our_own_field_order(honey) -> None:
    pattern = r"^honeypot ip=<HOST> port=\d+ proto=\w+ event=\w+ "
    import re

    good = honey.line("203.0.113.9", 2222, "ssh", "probe", bytes=3)
    assert re.match(pattern.replace("<HOST>", r"\S+"), good)
    sneaky = "honeypot  ip=203.0.113.9 port=2222 proto=ssh event=probe"
    assert not re.match(pattern.replace("<HOST>", r"\S+"), sneaky)
    prefixed = "x honeypot ip=203.0.113.9 port=2222 proto=ssh event=probe"
    assert not re.match(pattern.replace("<HOST>", r"\S+"), prefixed)


def test_huge_and_binary_payloads_are_bounded(honey) -> None:
    port = free_port()
    with Running(honey, [port], limit=4096) as run:
        talk(port, b"A" * 200000, read=64)
        rows = run.rows()
    probe = [row for row in rows if " event=probe " in row]
    assert probe
    fields = dict(part.split("=", 1) for part in probe[-1].split()[1:] if "=" in part)
    assert int(fields["bytes"]) <= 4096


def test_the_per_address_limit_holds(honey) -> None:
    port = free_port()
    with Running(honey, [port], per_ip=2, max_conn=4) as run:
        held = []
        for _ in range(6):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(("127.0.0.1", port))
            held.append(sock)
        time.sleep(0.4)
        rows = run.rows()
        for sock in held:
            sock.close()
    assert any(" event=throttled" in row for row in rows)
    assert len([row for row in rows if " event=throttled" in row]) <= 6


def test_a_slow_reader_does_not_pin_a_thread_forever(honey) -> None:
    port = free_port()
    started = time.time()
    with Running(honey, [port], idle=0.6) as run:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4.0)
        sock.connect(("127.0.0.1", port))
        try:
            sock.recv(16)
        except OSError:
            pass
        time.sleep(1.2)
        rows = run.rows()
        sock.close()
    assert time.time() - started < 6.0
    assert rows


def test_the_agent_never_forwards_a_connection(honey) -> None:
    source = AGENT.read_text(encoding="utf-8")
    for banned in ("socket.create_connection", "urllib", "http.client", "requests", "paramiko", "ftplib", "smtplib", "telnetlib"):
        assert banned not in source
    for banned in ("os.system", "subprocess.Popen(", "eval(", "exec("):
        assert banned not in source
    assert "subprocess.run" in source


def test_the_agent_refuses_to_shadow_a_live_service(honey, monkeypatch) -> None:
    port = free_port()
    with Running(honey, [port]):
        monkeypatch.setattr(honey, "write_config", lambda data: None)
        with pytest.raises(honey.HoneyError) as caught:
            honey.install({"ports": str(port), "log": honey.LOG_PATH})
        assert caught.value.code == "port_busy"


def test_port_lists_are_validated(honey) -> None:
    assert honey.parse_ports("2222,2323") == [2222, 2323]
    assert honey.parse_ports("") == list(honey.DEFAULT_PORTS)
    assert honey.parse_ports("2222,2222") == [2222]
    for bad in ("0", "70000", "a", "22;rm -rf /", "-1", "22 --bind=1.1.1.1"):
        with pytest.raises(honey.HoneyError):
            honey.parse_ports(bad)
    with pytest.raises(honey.HoneyError):
        honey.parse_ports(",".join(str(item) for item in range(1000, 1020)))


def test_the_command_surface_is_small(honey, capsys, monkeypatch) -> None:
    monkeypatch.setattr(honey, "LOG_PATH", honey.LOG_PATH)
    code = honey.main(["rm", "-rf", "/"])
    payload = json.loads(capsys.readouterr().out.strip())
    assert code == 2
    assert payload["ok"] is False
    assert payload["code"] == "bad_command"


def test_events_and_summary_read_the_log(honey, tmp_path) -> None:
    log = tmp_path / "honeypot.log"
    rows = [
        honey.line("203.0.113.1", 2222, "ssh", "probe", bytes=9),
        honey.line("203.0.113.1", 2323, "telnet", "auth", role="user", user="root"),
        honey.line("198.51.100.5", 21, "ftp", "probe"),
        "garbage that is not ours",
        honey.line("127.0.0.1", 2222, "raw", "start"),
    ]
    log.write_text("\n".join(rows) + "\n", encoding="utf-8")
    summary = honey.summarise(log.read_text(encoding="utf-8").splitlines())
    assert summary["total"] >= 4
    assert summary["events"]["probe"] >= 2
    top = dict(summary["top"])
    assert top["203.0.113.1"] == 2
    assert "127.0.0.1" not in top
    assert honey.local_address("127.0.0.1") and honey.local_address("::1") and honey.local_address("0.0.0.0")
    assert not honey.local_address("203.0.113.1")
    result = honey.events({"log": str(log), "limit": "10"})
    assert result["log"] == str(log)
    assert result["rows"]


def test_the_status_survives_a_missing_log(honey) -> None:
    state = honey.status()
    assert state["installed"] is False
    assert state["ports"] == list(honey.DEFAULT_PORTS)
    assert state["summary"]["total"] == 0
    assert state["version"] == honey.VERSION


def test_the_profiles_cover_the_usual_decoy_ports(honey) -> None:
    assert honey.profile(2222) == "ssh"
    assert honey.profile(21) == "ftp"
    assert honey.profile(23) == "telnet"
    assert honey.profile(6379) == "redis"
    assert honey.profile(8081) == "http"
    assert honey.profile(65000) == "raw"


def test_the_service_unit_is_sandboxed(honey) -> None:
    body = honey.unit_body([2222, 2323])
    for line in ("NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true", "ProtectSystem=strict", "MemoryMax=256M", "Restart=always"):
        assert line in body
    assert "User=root" in body
    assert "ExecStart=/usr/bin/env python3" in body


def test_parallel_flood_does_not_raise(honey) -> None:
    port = free_port()
    errors: list[BaseException] = []

    def blast():
        try:
            for _ in range(5):
                talk(port, b"USER x\r\nPASS y\r\n")
        except BaseException as exc:
            errors.append(exc)

    with Running(honey, [port], per_ip=8, max_conn=32) as run:
        threads = [threading.Thread(target=blast) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        time.sleep(0.3)
        rows = run.rows()
    assert not errors
    assert len(rows) > 10
    assert all(row.startswith("honeypot ") for row in rows)


def test_the_selfcheck_talks_to_its_own_decoy(honey, monkeypatch) -> None:
    monkeypatch.setattr(honey, "LOG_PATH", honey.LOG_PATH)
    report = honey.selfcheck({"ports": str(free_port()), "profile": "ssh"})
    assert report["port"]
    assert report["banner"].startswith("SSH-2.0-OpenSSH_")
    assert report["rows"]
    assert report["banned_line"].startswith("honeypot ip=127.0.0.1")
