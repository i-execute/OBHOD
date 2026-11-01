from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from BOT import freeturn, ftscreens, fwguard
from BOT.freeturn import FtControl, FtGuard
from BOT.shell import ShellOutput
from BOT.store import State
from BOT.xray import XrayState

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "Storage" / "remote" / "freeturn_agent.py"

IPTABLES_STUB = '''#!/usr/bin/env python3
import json, os, sys
state = os.environ["STUB_STATE"]
s = json.load(open(state)) if os.path.exists(state) else {"rules": [], "chains": []}
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(" ".join(args) + "\\n")
def save(): json.dump(s, open(state, "w"))
def body(items, positional=False):
    items = list(items)
    if positional and len(items) > 1 and items[1].isdigit():
        items = [items[0]] + items[2:]
    return items
if args[0] == "-S":
    if len(args) > 1 and args[1] in s["chains"]:
        print("-N %s" % args[1])
        for r in s["rules"]:
            if r[0] == args[1]:
                print("-A " + " ".join(r))
        sys.exit(0)
    print("-P INPUT ACCEPT")
    for c in s["chains"]:
        print("-N %s" % c)
    for r in s["rules"]:
        print("-I " + " ".join(r))
    sys.exit(0)
if args[0] == "-N":
    s["chains"].append(args[1]); save(); sys.exit(0)
if args[0] == "-X":
    s["chains"] = [c for c in s["chains"] if c != args[1]]
    s["rules"] = [r for r in s["rules"] if r[0] != args[1]]; save(); sys.exit(0)
if args[0] == "-F":
    target = args[1] if len(args) > 1 else None
    s["rules"] = [r for r in s["rules"] if r[0] != target]; save(); sys.exit(0)
if args[0] == "-C":
    sys.exit(0 if args[1:] in s["rules"] else 1)
if args[0] == "-A":
    s["rules"].append(body(args[1:])); save(); sys.exit(0)
if args[0] == "-I":
    s["rules"].insert(0, body(args[1:], positional=True)); save(); sys.exit(0)
if args[0] == "-D":
    rule = body(args[1:], positional=True)
    if rule in s["rules"]:
        s["rules"].remove(rule); save(); sys.exit(0)
    sys.exit(1)
sys.exit(0)
'''


def agent_env(tmp_path: Path) -> dict[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    binary = bindir / "iptables"
    binary.write_text(IPTABLES_STUB, encoding="utf-8")
    os.chmod(binary, 0o755)
    return {
        "PATH": "%s:/usr/local/bin:/usr/bin:/bin" % bindir,
        "STUB_STATE": str(tmp_path / "state.json"),
        "STUB_LOG": str(tmp_path / "calls.log"),
        "LANG": "C.UTF-8",
    }


def run_agent(tmp_path: Path, *args: str) -> dict[str, Any]:
    done = subprocess.run(
        [sys.executable, str(AGENT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=agent_env(tmp_path),
    )
    payload = [line for line in done.stdout.splitlines() if line.strip().startswith("{")]
    assert payload, done.stdout + done.stderr
    return json.loads(payload[-1])


def test_the_agent_opens_and_closes_the_port(tmp_path: Path) -> None:
    opened = run_agent(tmp_path, "fw-guard", "--mode=open", "--port=56272")
    assert opened["result"] == "ok", opened
    assert opened["data"]["mode"] == "open"
    closed = run_agent(tmp_path, "fw-guard", "--mode=closed", "--port=56272")
    assert closed["data"]["mode"] == "closed"


def test_the_agent_limits_the_port_to_the_given_ranges(tmp_path: Path) -> None:
    applied = run_agent(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=87.240.128.0/18,93.186.224.0/21")
    assert applied["result"] == "ok", applied
    assert applied["data"]["mode"] == "vk"
    assert applied["data"]["cidrs"] == 2
    calls = Path(tmp_path / "calls.log").read_text(encoding="utf-8")
    assert "-s 87.240.128.0/18 -j ACCEPT" in calls
    assert "-s 93.186.224.0/21 -j ACCEPT" in calls
    assert "-j DROP" in calls
    assert "--dport 56272 -j ACCEPT" not in calls.split("OBHOD-FT")[0].replace("-j DROP", "")


def test_the_agent_removes_the_world_rule_when_it_limits(tmp_path: Path) -> None:
    run_agent(tmp_path, "fw-guard", "--mode=open", "--port=56272")
    run_agent(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=87.240.128.0/18")
    state = json.loads(Path(tmp_path / "state.json").read_text(encoding="utf-8"))
    flat = [" ".join(item) for item in state["rules"]]
    world = [item for item in flat if item.startswith("INPUT") and item.endswith("ACCEPT")]
    assert world == [], flat


def test_a_wide_range_is_refused(tmp_path: Path) -> None:
    answer = run_agent(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=10.0.0.0/4")
    assert answer["result"] == "err"
    assert answer["code"] == "bad_arg"
    assert "too wide" in answer["msg"]


def test_a_hostile_range_is_refused(tmp_path: Path) -> None:
    for bad in ("127.0.0.1; reboot", "$(id)", "0.0.0.0/0"):
        answer = run_agent(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=%s" % bad)
        assert answer["result"] == "err", bad
        assert answer["code"] == "bad_arg"
    calls = Path(tmp_path / "calls.log")
    assert not calls.exists()


def test_a_bad_port_is_refused(tmp_path: Path) -> None:
    for port in ("0", "70000", "abc", ""):
        answer = run_agent(tmp_path, "fw-guard", "--mode=status", "--port=%s" % port)
        assert answer["result"] == "err"
        assert answer["code"] == "bad_arg"


def test_an_unknown_mode_is_refused(tmp_path: Path) -> None:
    answer = run_agent(tmp_path, "fw-guard", "--mode=allow", "--port=56272")
    assert answer["result"] == "err"
    assert "not known" in answer["msg"]


def test_the_prefix_parser_filters_ipv6_and_junk() -> None:
    body = json.dumps(
        {
            "data": {
                "prefixes": [
                    {"prefix": "87.240.128.0/18"},
                    {"prefix": "2a00:bdc0::/33"},
                    {"prefix": "10.0.0.0/4"},
                    {"prefix": "not a prefix"},
                    {"prefix": ""},
                ]
            }
        }
    ).encode()
    assert fwguard.prefixes_of(body) == ["87.240.128.0/18"]
    assert fwguard.prefixes_of(b"<html>") == []
    assert fwguard.prefixes_of(b"[]") == []


def test_the_prefix_list_is_collapsed() -> None:
    merged = fwguard.collapse(["87.240.128.0/18", "87.240.128.0/19", "93.186.224.0/21"])
    assert merged == ["87.240.128.0/18", "93.186.224.0/21"]


def test_the_vk_list_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    fwguard.clear()
    calls: list[int] = []

    def fake(asn: int, timeout: float = 0) -> tuple[list[str], str]:
        calls.append(asn)
        return ["87.240.128.0/18"], ""

    monkeypatch.setattr(fwguard, "fetch_asn", fake)
    first, reason = fwguard.vk_cidrs()
    second, _again = fwguard.vk_cidrs()
    assert first == second == ["87.240.128.0/18"]
    assert reason == ""
    assert len(calls) == len(fwguard.ASNS)
    fwguard.clear()


def test_a_failed_lookup_reports_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    fwguard.clear()
    monkeypatch.setattr(fwguard, "fetch_asn", lambda asn, timeout=0: ([], "unreachable"))
    found, reason = fwguard.vk_cidrs()
    assert found == []
    assert reason == "unreachable"
    fwguard.clear()


def test_the_guard_answer_is_parsed() -> None:
    guard = FtGuard.from_dict({"port": 56272, "backend": "firewalld", "mode": "vk", "rules": 97, "cidrs": 95})
    assert guard.mode == "vk"
    assert guard.cidrs == 95
    assert FtGuard.from_dict(None).mode == "unknown"


class FakeShell:
    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.calls: list[list[str]] = []

    async def run_argv(self, argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> ShellOutput:
        self.calls.append(list(argv))
        return ShellOutput(text=self.payload)


def envelope(data: dict[str, Any]) -> str:
    return json.dumps({"proto": 3, "result": "ok", "data": data, "logs": []})


def test_the_control_sends_the_ranges_to_the_agent() -> None:
    shell = FakeShell(envelope({"port": 56272, "backend": "ufw", "mode": "vk", "rules": 96, "cidrs": 95}))
    control = FtControl(shell=shell)
    guard = asyncio.run(control.firewall("vk", 56272, "87.240.128.0/18"))
    assert guard.mode == "vk"
    sent = shell.calls[0]
    assert "fw-guard" in sent
    assert "--mode=vk" in sent
    assert "--port=56272" in sent
    assert "--cidrs=87.240.128.0/18" in sent


def test_the_control_reports_a_refusal() -> None:
    shell = FakeShell(json.dumps({"proto": 3, "result": "err", "code": "fw_unsupported", "msg": "there is no firewalld, ufw or iptables on this host", "data": {}, "logs": []}))
    control = FtControl(shell=shell)
    with pytest.raises(freeturn.FtError) as caught:
        asyncio.run(control.firewall("status", 56272))
    assert "no firewalld" in caught.value.message


def view_with(guard: dict[str, Any] | None = None) -> ftscreens.FtView:
    return ftscreens.FtView(state=State(xray=XrayState()).freeturn, guard=dict(guard or {}))


def test_the_firewall_screen_shows_the_mode() -> None:
    html = ftscreens.fw_screen(view_with({"port": 56272, "backend": "firewalld", "mode": "vk", "rules": 96, "cidrs": 95})).to_html()
    assert "ft:fw:vk" in html
    assert "ft:fw:open" in html
    assert "ft:fw:closed" in html
    assert "56272" in html


def test_the_firewall_screen_survives_an_empty_state() -> None:
    html = ftscreens.fw_screen(view_with()).to_html()
    assert "ft:fw:vk" in html


def test_the_freeturn_home_links_the_firewall() -> None:
    html = ftscreens.home(view_with()).to_html()
    assert "ft:fw" in html


def test_the_panel_applies_the_range_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.fakes import make_bot

    applied: list[tuple] = []

    class GuardControl:
        async def firewall(self, mode: str, port: int, cidrs: str = "", timeout: float = 0) -> FtGuard:
            applied.append((mode, port, cidrs))
            return FtGuard(port=port, backend="firewalld", mode="vk" if mode == "vk" else mode, rules=96, cidrs=2)

    monkeypatch.setattr(fwguard, "vk_cidrs", lambda timeout=0: (["87.240.128.0/18", "93.186.224.0/21"], ""))
    bot = make_bot(tmp_path)
    bot.freeturn.control = GuardControl()
    bot.freeturn.state.config.listen_port = 56272
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw:vk"))
    assert applied == [("vk", 56272, "87.240.128.0/18,93.186.224.0/21")]
    assert bot.freeturn.guard["mode"] == "vk"
    assert "ft:fw:vk" in bot.rendered[-1].to_html()


def test_the_panel_refuses_to_limit_without_a_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.fakes import make_bot

    applied: list[tuple] = []

    class GuardControl:
        async def firewall(self, mode: str, port: int, cidrs: str = "", timeout: float = 0) -> FtGuard:
            applied.append((mode, port, cidrs))
            return FtGuard(port=port, backend="ufw", mode="open")

    monkeypatch.setattr(fwguard, "vk_cidrs", lambda timeout=0: ([], "unreachable"))
    bot = make_bot(tmp_path)
    bot.freeturn.control = GuardControl()
    bot.freeturn.state.config.listen_port = 56272
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw:vk"))
    assert applied == []
    assert "unreachable" in bot.rendered[-1].to_html()


def test_the_panel_reads_the_status(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    class GuardControl:
        async def firewall(self, mode: str, port: int, cidrs: str = "", timeout: float = 0) -> FtGuard:
            return FtGuard(port=port, backend="iptables", mode="vk", rules=97, cidrs=95)

    bot = make_bot(tmp_path)
    bot.freeturn.control = GuardControl()
    bot.freeturn.state.config.listen_port = 56272
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw"))
    assert bot.freeturn.guard["backend"] == "iptables"
    assert bot.freeturn.guard["cidrs"] == 95
