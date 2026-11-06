from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "Storage" / "remote" / "ddos_agent.py"

TABLE_BODY = """table inet obhod_ddos {
\tset syn_flood {
\t\ttype ipv4_addr
\t\tflags dynamic,timeout
\t\ttimeout 1h
\t\tsize 65536
\t\telements = { 203.0.113.7 timeout 58m20s, 203.0.113.9 timeout 59m }
\t}
\tchain input {
\t\ttype filter hook input priority raw; policy accept;
\t\tct state invalid counter packets 12 bytes 720 drop
\t\ttcp flags & (fin|syn|rst|ack) == 0x0 counter packets 3 bytes 120 drop
\t\tip saddr @syn_flood counter packets 991 bytes 59460 drop
\t\tct state new tcp flags & (fin|syn|rst|ack) == syn update @syn_flood { ip saddr limit rate over 60/second burst 40 packets } counter packets 4242 bytes 254520 accept
\t\tct state new counter packets 77 bytes 4620 accept
\t}
}
"""


def load(name: str = "obhod_ddos"):
    spec = importlib.util.spec_from_file_location(name, AGENT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def script(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture()
def bench(tmp_path: Path):
    module = load("obhod_ddos_%d" % id(tmp_path))
    bins = tmp_path / "bin"
    bins.mkdir()
    log = tmp_path / "calls.log"
    loaded = tmp_path / "loaded.nft"
    nft = script(
        bins / "nft",
        "\n".join(
            [
                "#!/bin/sh",
                'printf "%s\\n" "$*" >> "$STUB_LOG"',
                'case "$1" in',
                '  list) if [ -s "$STUB_LOADED" ]; then cat "$STUB_LOADED"; exit 0; fi; echo "nft: no such file" >&2; exit 1 ;;',
                '  -c) exit "${STUB_CHECK:-0}" ;;',
                '  -f) if [ -f "$STUB_FAIL" ]; then echo "syntax error" >&2; exit 1; fi; cp "$2" "$STUB_LOADED"; exit 0 ;;',
                "  delete) exit 0 ;;",
                "esac",
                "exit 0",
                "",
            ]
        ),
    )
    systemctl = script(
        bins / "systemctl",
        "\n".join(["#!/bin/sh", 'printf "systemctl %s\\n" "$*" >> "$STUB_LOG"', "exit 0", ""]),
    )
    sysctl = script(
        bins / "sysctl",
        "\n".join(["#!/bin/sh", 'printf "sysctl %s\\n" "$*" >> "$STUB_LOG"', "exit 0", ""]),
    )
    ss = script(
        bins / "ss",
        "#!/bin/sh\n"
        "cat <<'EOF'\n"
        'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=11,fd=3))\n'
        'LISTEN 0 4096 0.0.0.0:54321 0.0.0.0:* users:(("x-ui",pid=12,fd=3))\n'
        'LISTEN 0 128 127.0.0.1:10085 0.0.0.0:* users:(("xray",pid=11,fd=4))\n'
        'LISTEN 0 4096 9.9.9.9:6379 0.0.0.0:* users:(("redis-server",pid=13,fd=3))\n'
        'LISTEN 0 4096 bad:port 0.0.0.0:*\n'
        'LISTEN 0 4096 0.0.0.0:99999 0.0.0.0:*\n'
        "EOF\n"
        "exit 0\n",
    )
    env = {
        "STUB_LOG": str(log),
        "STUB_LOADED": str(loaded),
        "STUB_FAIL": str(tmp_path / "fail.flag"),
        "STUB_CHECK": "0",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    for key, value in env.items():
        os.environ[key] = value

    def argv(*extra: str) -> list[str]:
        return [
            "--dir=%s" % tmp_path,
            "--nft=%s" % nft,
            "--systemctl=%s" % systemctl,
            "--sysctl=%s" % sysctl,
            "--ss=%s" % ss,
            *extra,
        ]

    class Bench:
        pass

    holder = Bench()
    holder.module = module
    holder.root = tmp_path
    holder.bins = bins
    holder.log = log
    holder.loaded = loaded
    holder.fail = tmp_path / "fail.flag"
    holder.argv = argv
    holder.env = env

    def run(*extra: str) -> dict:
        proc = subprocess.run(
            [sys.executable, str(AGENT), *((extra or ("status",))[:1]), *argv(), *(extra[1:] if extra else ())],
            capture_output=True,
            text=True,
            timeout=60,
            env={**env, **{key: value for key, value in os.environ.items() if key.startswith("STUB_")}},
        )
        assert proc.stdout.count("\n") == 1, proc.stdout + proc.stderr
        return json.loads(proc.stdout)

    holder.run = run
    return holder


def test_status_without_rules(bench) -> None:
    payload = bench.run("status")
    assert payload["ok"] is True
    assert payload["data"]["installed"] is False
    assert payload["data"]["table"] is False
    assert "nft" in payload["data"]["notice"] or payload["data"]["notice"]


def test_install_writes_and_loads(bench) -> None:
    payload = bench.run("install", "--ports=22,443", "--syn_rate=80")
    data = payload["data"]
    assert payload["ok"] is True
    assert (bench.root / "ddos.nft").is_file()
    assert "limit rate over 80/second" in (bench.root / "ddos.nft").read_text(encoding="utf-8")
    assert json.loads((bench.root / "ddos.json").read_text(encoding="utf-8"))["syn_rate"] == 80
    assert bench.loaded.is_file()
    assert "-c -f" in bench.log.read_text(encoding="utf-8")
    assert data["policy"]["ports"] == "22,443"


def test_the_unit_and_the_sysctl_file_are_written(bench) -> None:
    bench.run("install")
    unit = (bench.root / "obhod-ddos.service").read_text(encoding="utf-8")
    assert "ExecStart=" in unit and "delete table inet obhod_ddos" in unit
    assert "RemainAfterExit=yes" in unit
    knobs = (bench.root / "99-obhod-ddos.conf").read_text(encoding="utf-8")
    assert "net.ipv4.tcp_syncookies = 1" in knobs
    assert "net.core.somaxconn = 4096" in knobs


def test_a_broken_ruleset_is_never_loaded(bench) -> None:
    os.environ["STUB_CHECK"] = "1"
    try:
        payload = bench.run("install")
    finally:
        os.environ["STUB_CHECK"] = "0"
    assert payload["ok"] is False
    assert payload["code"] == "bad_rules"
    assert not (bench.root / "ddos.nft").exists()
    assert not bench.loaded.exists()


def test_a_failed_apply_rolls_back(bench) -> None:
    bench.run("install", "--syn_rate=60")
    first = (bench.root / "ddos.nft").read_text(encoding="utf-8")
    bench.fail.write_text("x", encoding="utf-8")
    payload = bench.run("install", "--syn_rate=120")
    assert payload["ok"] is False
    assert payload["code"] == "apply"
    assert (bench.root / "ddos.nft").read_text(encoding="utf-8") == first
    assert "limit rate over 60/second" in bench.loaded.read_text(encoding="utf-8")


def test_install_is_idempotent(bench) -> None:
    bench.run("install", "--ports=22,443")
    first = (bench.root / "ddos.nft").read_text(encoding="utf-8")
    bench.run("install", "--ports=22,443")
    assert (bench.root / "ddos.nft").read_text(encoding="utf-8") == first


def test_the_ports_cannot_inject_a_rule(bench) -> None:
    payload = bench.run("install", "--ports=22;include /etc/passwd,443")
    body = (bench.root / "ddos.nft").read_text(encoding="utf-8")
    assert "passwd" not in body
    assert "include" not in body
    assert payload["data"]["policy"]["ports"] == "22,443"


def test_absurd_limits_are_clamped(bench) -> None:
    payload = bench.run("install", "--syn_rate=999999999", "--set_size=1", "--ban_timeout=-5")
    policy = payload["data"]["policy"]
    assert policy["syn_rate"] == 100000
    assert policy["set_size"] >= 1024
    assert policy["ban_timeout"] >= 60


def test_status_reads_the_counters(bench) -> None:
    bench.run("install")
    bench.loaded.write_text(TABLE_BODY, encoding="utf-8")
    data = bench.run("status")["data"]
    assert data["table"] is True
    assert data["syn_flood"] == ["203.0.113.7", "203.0.113.9"]
    assert data["counters"]["invalid"] == 12
    assert data["counters"]["syn_drop"] == 991
    assert data["counters"]["syn_new"] == 4242
    assert data["counters"]["accepted"] == 77


def test_remove_takes_everything_away(bench) -> None:
    bench.run("install")
    payload = bench.run("remove")
    assert payload["ok"] is True
    assert not (bench.root / "ddos.nft").exists()
    assert not (bench.root / "obhod-ddos.service").exists()
    assert "delete table inet obhod_ddos" in bench.log.read_text(encoding="utf-8")


def test_disable_keeps_the_files(bench) -> None:
    bench.run("install")
    bench.run("disable")
    assert (bench.root / "ddos.nft").is_file()
    assert "delete table inet obhod_ddos" in bench.log.read_text(encoding="utf-8")


def test_probe_reports_what_is_listening(bench) -> None:
    data = bench.run("probe")["data"]
    ports = [row["port"] for row in data["rows"]]
    assert 443 in ports and 54321 in ports
    assert all(1 <= port <= 65535 for port in ports)
    assert data["count"] == len(data["rows"])


def test_probe_drops_garbage_rows(bench) -> None:
    data = bench.run("probe")["data"]
    assert all(isinstance(row["port"], int) for row in data["rows"])
    assert all(row["address"] in {"", "0.0.0.0", "127.0.0.1", "9.9.9.9"} for row in data["rows"])


def test_the_config_path_cannot_escape(bench) -> None:
    payload = bench.run("status", "--config=../../etc/shadow")
    assert payload["ok"] is False
    assert payload["code"] == "bad_path"


def test_an_unknown_command_is_refused(bench) -> None:
    payload = bench.run("explode")
    assert payload["ok"] is False
    assert payload["code"] == "bad_command"


def test_missing_nft_is_reported_not_hidden(bench) -> None:
    payload = bench.run("install", "--nft=/nonexistent/nft")
    assert payload["ok"] is False
    assert payload["code"] == "no_nft"
    assert (bench.root / "ddos.nft").is_file()


def test_the_render_command_shows_both_files(bench) -> None:
    data = bench.run("render")["data"]
    assert data["rules"].startswith("table inet obhod_ddos {")
    assert "net.ipv4.tcp_syncookies" in data["sysctl"]


def test_concurrent_installs_keep_the_file_whole(bench) -> None:
    def worker(index: int) -> None:
        bench.run("install", "--syn_rate=%d" % (40 + index))

    threads = [threading.Thread(target=worker, args=(item,)) for item in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    body = (bench.root / "ddos.nft").read_text(encoding="utf-8")
    assert body.startswith("table inet obhod_ddos {")
    assert body.count("{") == body.count("}")
    assert json.loads((bench.root / "ddos.json").read_text(encoding="utf-8"))["syn_rate"] >= 40


def test_the_agent_never_prints_a_traceback(bench) -> None:
    for command in ("status", "probe", "info", "render", "disable"):
        payload = bench.run(command)
        assert "Traceback" not in json.dumps(payload)


def test_a_hostile_config_file_is_sanitised(bench) -> None:
    (bench.root / "ddos.json").write_text(
        json.dumps({"ports": "22,443", "syn_rate": True, "ban_timeout": "forever", "set_size": [1, 2], "enabled": "yes"}),
        encoding="utf-8",
    )
    data = bench.run("status")["data"]
    assert data["policy"]["syn_rate"] == 60
    assert data["policy"]["ban_timeout"] == 3600
    assert data["policy"]["set_size"] == 65536


def test_a_broken_config_file_does_not_crash(bench) -> None:
    (bench.root / "ddos.json").write_text("{not json", encoding="utf-8")
    assert bench.run("status")["ok"] is True


def test_the_agent_has_no_writable_state_outside_its_directory(bench) -> None:
    body = AGENT.read_text(encoding="utf-8")
    assert "/tmp/" not in body
    assert "TMPDIR" not in body


def test_ddos_rules_exempt_installed_freeturn_port(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load("obhod_ddos_ft_%d" % id(tmp_path))
    ft_conf = tmp_path / "install.conf"
    ft_conf.write_text('LISTEN_PORT="56696"\nPROXY_MODE="udp"\n', encoding="utf-8")
    real_isfile = module.os.path.isfile
    real_open = open

    def fake_isfile(path: str) -> bool:
        if path == "/opt/free-turn-proxy/install.conf":
            return True
        return real_isfile(path)

    def fake_open(path: str, *args: object, **kwargs: object):
        if path == "/opt/free-turn-proxy/install.conf":
            return real_open(ft_conf, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(module.os.path, "isfile", fake_isfile)
    monkeypatch.setattr("builtins.open", fake_open, raising=False)
    rules = module.rules_text(module.policy_from({}, {}), {})
    assert "udp dport 56696 accept" in rules
    assert rules.index("udp dport 56696 accept") < rules.index("ct state invalid counter drop")
