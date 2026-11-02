from __future__ import annotations

import asyncio
import base64
import ipaddress
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


def test_a_destructive_mode_asks_first(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    applied: list[tuple] = []

    class GuardControl:
        async def firewall(self, mode: str, port: int, cidrs: str = "", proto: str = "udp", timeout: float = 0) -> FtGuard:
            applied.append((mode, port, cidrs))
            return FtGuard(port=port, backend="ufw", mode=mode)

    bot = make_bot(tmp_path)
    bot.freeturn.control = GuardControl()
    bot.freeturn.state.config.listen_port = 56272
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw:closed"))
    assert applied == []
    assert "ft:fw:closed:yes" in bot.rendered[-1].to_html()
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw:closed:yes"))
    assert applied == [("closed", 56272, "")]
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw:open"))
    assert applied[-1] == ("open", 56272, "")


def test_an_unknown_mode_never_crashes_the_screen() -> None:
    html = ftscreens.fw_screen(view_with({"port": 56272, "proto": "tcp", "backend": "iptables", "mode": "weird", "rules": 1, "cidrs": 0})).to_html()
    assert "weird" in html


def test_the_freeturn_home_links_the_firewall() -> None:
    html = ftscreens.home(view_with()).to_html()
    assert "ft:fw" in html


def test_the_panel_applies_the_range_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.fakes import make_bot

    applied: list[tuple] = []

    class GuardControl:
        async def firewall(self, mode: str, port: int, cidrs: str = "", proto: str = "udp", timeout: float = 0) -> FtGuard:
            applied.append((mode, port, cidrs))
            return FtGuard(port=port, backend="firewalld", mode="vk" if mode == "vk" else mode, rules=96, cidrs=2)

    monkeypatch.setattr(fwguard, "vk_cidrs", lambda timeout=0: (["87.240.128.0/18", "93.186.224.0/21"], ""))
    bot = make_bot(tmp_path)
    bot.freeturn.control = GuardControl()
    bot.freeturn.state.config.listen_port = 56272
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw:vk"))
    assert applied == []
    assert "ft:fw:vk:yes" in bot.rendered[-1].to_html()
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw:vk:yes"))
    assert applied == [("vk", 56272, "87.240.128.0/18,93.186.224.0/21")]
    assert bot.freeturn.guard["mode"] == "vk"
    assert "ft:fw:vk" in bot.rendered[-1].to_html()


def test_the_panel_refuses_to_limit_without_a_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.fakes import make_bot

    applied: list[tuple] = []

    class GuardControl:
        async def firewall(self, mode: str, port: int, cidrs: str = "", proto: str = "udp", timeout: float = 0) -> FtGuard:
            applied.append((mode, port, cidrs))
            return FtGuard(port=port, backend="ufw", mode="open")

    monkeypatch.setattr(fwguard, "vk_cidrs", lambda timeout=0: ([], "unreachable"))
    bot = make_bot(tmp_path)
    bot.freeturn.control = GuardControl()
    bot.freeturn.state.config.listen_port = 56272
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw:vk:yes"))
    assert applied == []
    assert "unreachable" in bot.rendered[-1].to_html()


def test_the_panel_reads_the_status(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    class GuardControl:
        async def firewall(self, mode: str, port: int, cidrs: str = "", proto: str = "udp", timeout: float = 0) -> FtGuard:
            return FtGuard(port=port, backend="iptables", mode="vk", rules=97, cidrs=95)

    bot = make_bot(tmp_path)
    bot.freeturn.control = GuardControl()
    bot.freeturn.state.config.listen_port = 56272
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw"))
    assert bot.freeturn.guard["backend"] == "iptables"
    assert bot.freeturn.guard["cidrs"] == 95


def test_a_newline_in_the_range_list_is_refused(tmp_path: Path) -> None:
    for bad in ("87.240.128.0/18\n--flush", "87.240.128.0/18\tx", "87.240.128.0/18 93.186.224.0/21"):
        answer = run_agent(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=%s" % bad)
        assert answer["result"] == "err", bad
    assert not Path(tmp_path / "calls.log").exists()


def test_too_many_ranges_are_refused(tmp_path: Path) -> None:
    ranges = ",".join("172.%d.%d.0/24" % (16 + index // 250, index % 250) for index in range(600))
    answer = run_agent(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=%s" % ranges)
    assert answer["result"] == "err"
    assert "too many" in answer["msg"]


def test_the_agent_cannot_be_talked_into_another_chain(tmp_path: Path) -> None:
    answer = run_agent(tmp_path, "fw-guard", "--mode=status", "--port=56272", "--chain=INPUT")
    assert answer["result"] == "err"
    assert answer["code"] == "bad_arg"


FIREWALLD_STUB = '''#!/usr/bin/env python3
import json, os, sys
state = os.environ["FW_STATE"]
data = json.load(open(state)) if os.path.exists(state) else {"permanent": [], "runtime": []}
args = list(sys.argv[1:])
with open(os.environ["FW_LOG"], "a") as fh:
    fh.write(" ".join(args) + "\\n")
permanent = "--permanent" in args
key = "permanent" if permanent else "runtime"
rest = [a for a in args if a != "--permanent"]
def save(): json.dump(data, open(state, "w"))
if "--state" in rest:
    print("running"); sys.exit(0)
if "--list-rich-rules" in rest:
    print("\\n".join(data[key])); sys.exit(0)
for item in rest:
    if item.startswith("--add-rich-rule="):
        rule = item.split("=", 1)[1]
        if rule not in data[key]:
            data[key].append(rule)
        save(); sys.exit(0)
    if item.startswith("--remove-rich-rule="):
        rule = item.split("=", 1)[1]
        data[key] = [r for r in data[key] if r != rule]; save(); sys.exit(0)
    if item.startswith("--add-port="):
        rule = "port:" + item.split("=", 1)[1]
        if rule not in data[key]:
            data[key].append(rule)
        save(); sys.exit(0)
    if item.startswith("--remove-port="):
        rule = "port:" + item.split("=", 1)[1]
        data[key] = [r for r in data[key] if r != rule]; save(); sys.exit(0)
    if item.startswith("--query-port="):
        sys.exit(0 if ("port:" + item.split("=", 1)[1]) in data[key] else 1)
sys.exit(0)
'''


def firewalld_env(tmp_path: Path) -> dict[str, str]:
    bindir = tmp_path / "fw"
    bindir.mkdir(exist_ok=True)
    binary = bindir / "firewall-cmd"
    binary.write_text(FIREWALLD_STUB, encoding="utf-8")
    os.chmod(binary, 0o755)
    return {
        "PATH": "%s:/usr/local/bin:/usr/bin:/bin" % bindir,
        "FW_STATE": str(tmp_path / "fw.json"),
        "FW_LOG": str(tmp_path / "fw.log"),
        "LANG": "C.UTF-8",
    }


def run_firewalld(tmp_path: Path, *args: str) -> dict[str, Any]:
    done = subprocess.run(
        [sys.executable, str(AGENT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=firewalld_env(tmp_path),
    )
    payload = [line for line in done.stdout.splitlines() if line.strip().startswith("{")]
    assert payload, done.stdout + done.stderr
    return json.loads(payload[-1])


UFW_STUB = """#!/usr/bin/env python3
import json, os, re, sys
path = os.environ["UFW_STATE"]
data = json.load(open(path)) if os.path.exists(path) else {"rules": []}
args = list(sys.argv[1:])
with open(os.environ["UFW_LOG"], "a") as fh:
    fh.write(" ".join(args) + chr(10))
def save(): json.dump(data, open(path, "w"))
def add(spec, action, source):
    name, _, proto = spec.partition("/")
    data["rules"].append({"port": name, "proto": proto or "any", "action": action, "from": source})
def show(numbered):
    print("Status: active")
    print("")
    print("     To                         Action      From")
    print("     --                         ------      ----")
    for index, rule in enumerate(data["rules"], start=1):
        head = "[%2d] " % index if numbered else ""
        print(head + ("%s/%s" % (rule["port"], rule["proto"])).ljust(27) + rule["action"].ljust(12) + rule["from"])
if args[:1] == ["status"]:
    show("numbered" in args); sys.exit(0)
if args[:2] == ["--force", "delete"]:
    target = args[2]
    if target.isdigit():
        index = int(target) - 1
        if 0 <= index < len(data["rules"]):
            data["rules"].pop(index); save(); print("Rule deleted"); sys.exit(0)
        sys.exit(1)
    spec = args[3] if len(args) > 3 else ""
    for index, rule in enumerate(data["rules"]):
        if rule["action"] == target.upper() and "%s/%s" % (rule["port"], rule["proto"]) == spec:
            data["rules"].pop(index); save(); print("Rule deleted"); sys.exit(0)
    sys.exit(1)
if args[:1] in (["allow"], ["deny"]):
    add(args[1], args[0].upper(), "Anywhere"); save(); print("Rules updated"); sys.exit(0)
if args[:1] == ["insert"]:
    body = args[2:]
    source = body[body.index("from") + 1]
    port = body[body.index("port") + 1]
    proto = body[body.index("proto") + 1] if "proto" in body else "any"
    data["rules"].insert(int(args[1]) - 1, {"port": port, "proto": proto, "action": "ALLOW", "from": source})
    save(); print("Rule inserted"); sys.exit(0)
sys.exit(1)
"""


def ufw_env(tmp_path: Path) -> dict[str, str]:
    bindir = tmp_path / "ufwbin"
    bindir.mkdir(exist_ok=True)
    binary = bindir / "ufw"
    binary.write_text(UFW_STUB, encoding="utf-8")
    os.chmod(binary, 0o755)
    return {
        "PATH": "%s:/usr/local/bin:/usr/bin:/bin" % bindir,
        "UFW_STATE": str(tmp_path / "ufw.json"),
        "UFW_LOG": str(tmp_path / "ufw.log"),
        "LANG": "C.UTF-8",
    }


def run_ufw(tmp_path: Path, *args: str) -> dict[str, Any]:
    done = subprocess.run(
        [sys.executable, str(AGENT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=ufw_env(tmp_path),
    )
    payload = [line for line in done.stdout.splitlines() if line.strip().startswith("{")]
    assert payload, done.stdout + done.stderr
    return json.loads(payload[-1])


def ufw_verdict(tmp_path: Path, port: int, source: str, proto: str = "udp") -> str:
    state = json.loads(Path(tmp_path / "ufw.json").read_text(encoding="utf-8"))
    for rule in state["rules"]:
        if rule["port"] != str(port):
            continue
        if rule["proto"] not in (proto, "any"):
            continue
        if rule["from"] == "Anywhere" or ipaddress.ip_address(source) in ipaddress.ip_network(rule["from"], strict=False):
            return rule["action"]
    return "DEFAULT"


def ufw_rules(tmp_path: Path) -> list[dict[str, Any]]:
    return json.loads(Path(tmp_path / "ufw.json").read_text(encoding="utf-8"))["rules"]


def test_ufw_opens_the_port_after_the_limited_mode(tmp_path: Path) -> None:
    port = 56272
    assert run_ufw(tmp_path, "fw-guard", "--mode=vk", "--port=%d" % port, "--cidrs=87.240.128.0/18")["result"] == "ok"
    assert ufw_verdict(tmp_path, port, "87.240.128.9") == "ALLOW"
    assert ufw_verdict(tmp_path, port, "8.8.8.8") == "DENY"
    opened = run_ufw(tmp_path, "fw-guard", "--mode=open", "--port=%d" % port)
    assert opened["data"]["mode"] == "open"
    assert ufw_verdict(tmp_path, port, "8.8.8.8") == "ALLOW"


def test_ufw_leaves_nothing_behind_when_closed(tmp_path: Path) -> None:
    port = 56272
    run_ufw(tmp_path, "fw-guard", "--mode=vk", "--port=%d" % port, "--cidrs=87.240.128.0/18")
    closed = run_ufw(tmp_path, "fw-guard", "--mode=closed", "--port=%d" % port)
    assert closed["data"]["mode"] == "closed"
    assert ufw_rules(tmp_path) == []
    assert ufw_verdict(tmp_path, port, "87.240.128.9") == "DEFAULT"


def test_ufw_guards_the_whole_pair_of_protocols(tmp_path: Path) -> None:
    port = 56272
    run_ufw(tmp_path, "fw-guard", "--mode=vk", "--port=%d" % port, "--cidrs=87.240.128.0/18", "--proto=both")
    assert ufw_verdict(tmp_path, port, "8.8.8.8", "udp") == "DENY"
    assert ufw_verdict(tmp_path, port, "8.8.8.8", "tcp") == "DENY"
    assert ufw_verdict(tmp_path, port, "87.240.128.9", "tcp") == "ALLOW"


def test_ufw_status_is_not_fooled_by_a_shorter_port(tmp_path: Path) -> None:
    run_ufw(tmp_path, "fw-guard", "--mode=open", "--port=56000")
    found = run_ufw(tmp_path, "fw-guard", "--mode=status", "--port=5600")
    assert found["data"]["mode"] == "closed"


def test_firewalld_keeps_the_runtime_and_the_permanent_config_in_step(tmp_path: Path) -> None:
    answer = run_firewalld(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=87.240.128.0/18")
    assert answer["result"] == "ok", answer
    assert answer["data"]["backend"] == "firewalld"
    state = json.loads(Path(tmp_path / "fw.json").read_text(encoding="utf-8"))
    for scope in ("permanent", "runtime"):
        rules = state[scope]
        assert any("87.240.128.0/18" in item and "accept" in item for item in rules), (scope, rules)
        assert any("drop" in item for item in rules), (scope, rules)
        assert not any(item.startswith("port:") for item in rules), (scope, rules)
    log = Path(tmp_path / "fw.log").read_text(encoding="utf-8")
    assert "--reload" not in log
    accepts = [item for item in state["runtime"] if "accept" in item]
    drops = [item for item in state["runtime"] if "drop" in item]
    assert int(accepts[0].split('priority="')[1].split('"')[0]) < int(drops[0].split('priority="')[1].split('"')[0])


def test_firewalld_open_puts_the_port_back(tmp_path: Path) -> None:
    run_firewalld(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=87.240.128.0/18")
    answer = run_firewalld(tmp_path, "fw-guard", "--mode=open", "--port=56272")
    assert answer["data"]["mode"] == "open"
    state = json.loads(Path(tmp_path / "fw.json").read_text(encoding="utf-8"))
    assert "port:56272/udp" in state["permanent"]
    assert "port:56272/udp" in state["runtime"]
    assert not [item for item in state["runtime"] if "drop" in item]


def test_firewalld_closed_leaves_nothing(tmp_path: Path) -> None:
    run_firewalld(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=87.240.128.0/18")
    answer = run_firewalld(tmp_path, "fw-guard", "--mode=closed", "--port=56272")
    assert answer["data"]["mode"] == "closed"
    state = json.loads(Path(tmp_path / "fw.json").read_text(encoding="utf-8"))
    assert state["runtime"] == [] and state["permanent"] == []


def test_the_tcp_mode_guards_the_tcp_port(tmp_path: Path) -> None:
    answer = run_agent(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=87.240.128.0/18", "--proto=tcp")
    assert answer["result"] == "ok", answer
    assert answer["data"]["proto"] == "tcp"
    log = Path(tmp_path / "calls.log").read_text(encoding="utf-8")
    assert "-I INPUT 1 -p tcp --dport 56272 -j OBHOD-FT" in log
    assert "-I INPUT 1 -p udp --dport 56272 -j OBHOD-FT" not in log


def test_the_both_mode_guards_both(tmp_path: Path) -> None:
    answer = run_agent(tmp_path, "fw-guard", "--mode=vk", "--port=56272", "--cidrs=87.240.128.0/18", "--proto=both")
    assert answer["data"]["proto"] == "both"
    log = Path(tmp_path / "calls.log").read_text(encoding="utf-8")
    assert "-I INPUT 1 -p udp --dport 56272 -j OBHOD-FT" in log
    assert "-I INPUT 1 -p tcp --dport 56272 -j OBHOD-FT" in log


def test_a_bad_protocol_is_refused(tmp_path: Path) -> None:
    for bad in ("sctp", "", "udp,tcp; rm -rf /"):
        answer = run_agent(tmp_path, "fw-guard", "--mode=status", "--port=56272", "--proto=%s" % bad)
        assert answer["result"] == "err", bad


def test_the_panel_guards_the_protocol_of_the_plan(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    seen: list[str] = []

    class GuardControl:
        async def firewall(self, mode: str, port: int, cidrs: str = "", proto: str = "udp", timeout: float = 0) -> FtGuard:
            seen.append(proto)
            return FtGuard(port=port, proto=proto, backend="ufw", mode="open" if mode == "status" else mode)

    bot = make_bot(tmp_path)
    bot.freeturn.control = GuardControl()
    bot.freeturn.state.config.listen_port = 56272
    bot.freeturn.state.config.mode = "tcp"
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw"))
    bot.freeturn.state.config.mode = "udp"
    asyncio.run(bot.freeturn.route(1, 0, "ft:fw"))
    assert seen == ["tcp", "udp"]


WG_STUB = """#!/usr/bin/env python3
import json, os, sys
args = list(sys.argv[1:])
with open(os.environ["WG_LOG"], "a") as fh:
    fh.write(" ".join(args) + chr(10))
data = json.load(open(os.environ["WG_STATE"]))
if args[:2] == ["show", "all"] and args[2:] == ["dump"]:
    for item in data["interfaces"]:
        print(chr(9).join([item["name"], "priv", "pub", "51820", "off"]))
        for peer in item["peers"]:
            print(chr(9).join([item["name"], peer["pub"], "(none)", peer.get("endpoint", ""), peer.get("allowed", ""), str(peer.get("hs", 0)), str(peer.get("rx", 0)), str(peer.get("tx", 0)), str(peer.get("keepalive", 0))]))
    sys.exit(0)
sys.exit(1)
"""


def wg_env(tmp_path: Path, peers: list[dict], iface: str = "freeturn") -> dict[str, str]:
    bindir = tmp_path / "wgbin"
    bindir.mkdir(exist_ok=True)
    binary = bindir / "wg"
    binary.write_text(WG_STUB, encoding="utf-8")
    os.chmod(binary, 0o755)
    Path(tmp_path / "wg.json").write_text(json.dumps({"interfaces": [{"name": iface, "peers": peers}]}), encoding="utf-8")
    return {
        "PATH": "%s:/usr/local/bin:/usr/bin:/bin" % bindir,
        "WG_STATE": str(tmp_path / "wg.json"),
        "WG_LOG": str(tmp_path / "wg.log"),
        "LANG": "C.UTF-8",
    }


def run_wg(tmp_path: Path, *args: str) -> dict[str, Any]:
    done = subprocess.run(
        [sys.executable, str(AGENT), *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=wg_env(tmp_path, WG_PEERS),
    )
    payload = [line for line in done.stdout.splitlines() if line.strip().startswith("{")]
    assert payload, done.stdout + done.stderr
    return json.loads(payload[-1])


def _wg_key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode("ascii")


WG_PEERS = [
    {"pub": _wg_key(1), "endpoint": "203.0.113.5:51820", "allowed": "10.13.13.2/32", "hs": 1793556000, "rx": 4096, "tx": 2048, "keepalive": 25},
    {"pub": _wg_key(2), "allowed": "10.13.13.3/32"},
    {"pub": "broken"},
]


def test_the_agent_reads_the_wg_peers(tmp_path: Path) -> None:
    answer = run_wg(tmp_path, "wg-peers")
    assert answer["result"] == "ok", answer
    assert answer["data"]["count"] == 2
    assert answer["data"]["interfaces"] == ["freeturn"]
    assert answer["data"]["rx"] == 4096
    assert answer["data"]["tx"] == 2048
    assert answer["data"]["peers"][0]["endpoint"] == "203.0.113.5:51820"
    assert answer["data"]["peers"][1]["hs"] == 0


def test_the_agent_refuses_a_silly_interface(tmp_path: Path) -> None:
    for bad in ("all;rm", "../etc", "a" * 20, "wg0;reboot", "freeturn/x"):
        answer = run_wg(tmp_path, "wg-peers", "--iface=%s" % bad)
        assert answer["result"] == "err", bad
        assert answer["code"] == "bad_arg"


def test_the_agent_refuses_unknown_flags(tmp_path: Path) -> None:
    answer = run_wg(tmp_path, "wg-peers", "--chain=INPUT")
    assert answer["result"] == "err"
    assert answer["code"] == "bad_arg"


def test_the_agent_never_runs_a_shell_for_wg(tmp_path: Path) -> None:
    source = (ROOT / "Storage" / "remote" / "freeturn_agent.py").read_text(encoding="utf-8")
    body = source.split("def wg_command(")[1].split("\ndef ", 1)[0]
    for chunk in ("def wg_peers(", "def wg_main("):
        part = source.split(chunk)[1].split("\ndef ", 1)[0]
        assert "shell=True" not in part
        assert "os.system" not in part
    assert "shell=True" not in body
    assert '["wg", "show"' in source
    assert "WG_MAX_PEERS" in source
    assert "WG_KEY_RE" in source
