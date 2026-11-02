from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
import pytest

from BOT import subs

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "Storage" / "remote" / "sub_server.py"
AGENT = ROOT / "Storage" / "remote" / "xray_agent.py"
from BOT.xray import XrayState, new_inbound


def filled() -> XrayState:
    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.remark = "reality-443"
    inbound.make_client("owner")
    inbound.make_client("phone1")
    state.add(inbound)
    return state


def test_a_raw_address_keeps_the_port() -> None:
    assert subs.local_url("203.0.113.5", 2096) == "http://203.0.113.5:2096"
    assert subs.local_url("vpn.example.com", 2096) == "http://vpn.example.com:2096"


def test_an_explicit_scheme_is_kept() -> None:
    assert subs.local_url("https://vpn.example.com", 2096) == "https://vpn.example.com:2096"
    assert subs.local_url("http://203.0.113.5:2096", 2096) == "http://203.0.113.5:2096"


def test_a_silly_address_is_refused() -> None:
    for bad in ("", " ", "a" * 300, "1.2.3.4;rm", "1.2.3.4 && id"):
        with pytest.raises(subs.SubError):
            subs.local_url(bad, 2096)


def test_a_silly_port_is_refused() -> None:
    for bad in (0, 70000, "x"):
        with pytest.raises(subs.SubError):
            subs.local_url("203.0.113.5", bad)


def test_the_payload_is_base64_of_the_links() -> None:
    payload = subs.payload_of(["vless://one", "freeturn://two"])
    raw = base64.b64decode(payload).decode()
    assert raw == "vless://one\nfreeturn://two\n"


def test_the_payload_is_empty_without_links() -> None:
    assert subs.payload_of([]) == ""
    assert subs.payload_of(None) == ""


def test_the_links_are_cleaned_and_deduped() -> None:
    found = subs.clean_links(["vless://a", "vless://a", "", "  ", "vless://b\nc", "x" * 5000])
    assert found == ["vless://a"]


def test_the_payload_round_trips() -> None:
    links = ["vless://a", "freeturn://b"]
    assert subs.decode(subs.payload_of(links)) == links


def test_a_broken_payload_decodes_to_nothing() -> None:
    assert subs.decode("not base64 !!") == []
    assert subs.decode("") == []


def test_the_aggregate_carries_every_link() -> None:
    state = filled()
    bundle = subs.aggregate(state, ["freeturn://owner"], "203.0.113.5", 2096)
    assert len(bundle.links) == 3
    assert any(item.startswith("freeturn://") for item in bundle.links)
    assert bundle.url("203.0.113.5", 2096).startswith("http://203.0.113.5:2096/")


def test_the_aggregate_is_stable_between_calls() -> None:
    state = filled()
    first = subs.aggregate(state, [], "203.0.113.5", 2096)
    second = subs.aggregate(state, [], "203.0.113.5", 2096)
    assert (first.id, first.key) == (second.id, second.key)


def test_the_aggregate_path_is_two_segments() -> None:
    bundle = subs.aggregate(filled(), [], "203.0.113.5", 2096)
    parts = [item for item in bundle.path().split("/") if item]
    assert len(parts) == 2
    assert len(parts[0]) == 64 and len(parts[1]) == 64
    assert bundle.json_path().endswith("/json")


def test_the_registry_carries_the_aggregate() -> None:
    state = filled()
    registry = state.sub_registry("203.0.113.5", ["freeturn://owner"])
    titles = [entry["title"] for entry in registry["entries"].values()]
    assert "OBHOD all" in titles
    all_entry = [entry for entry in registry["entries"].values() if entry["title"] == "OBHOD all"][0]
    assert len(all_entry["links"]) == 3


def test_the_registry_entries_are_shaped_for_the_server() -> None:
    registry = filled().sub_registry("203.0.113.5")
    for key, entry in registry["entries"].items():
        assert len(key) == 64
        assert len(entry["key"]) == 64
        assert entry["path"] == "/%s/%s" % (key, entry["key"])
        assert isinstance(entry["links"], list)
        assert entry["enabled"] is True


def test_the_json_body_holds_the_links() -> None:
    bundle = subs.aggregate(filled(), [], "203.0.113.5", 2096)
    body = json.loads(subs.json_body(bundle, "203.0.113.5", 2096))
    assert body["count"] == len(bundle.links)
    assert body["url"].startswith("http://203.0.113.5:2096/")


def test_the_aggregate_segments_survive_a_save_and_load(tmp_path: Path) -> None:
    from BOT.store import State, Store

    state = State(xray=filled())
    state.xray.ensure_sub_all()
    store = Store(tmp_path / "state.json")
    store.save(state)
    loaded = store.load()
    assert loaded.xray.ensure_sub_all() == (state.xray.sub_all_id, state.xray.sub_all_key)


def test_a_broken_aggregate_segment_is_replaced() -> None:
    state = filled()
    state.sub_all_id = "short"
    state.sub_all_key = "x" * 64
    found = state.ensure_sub_all()
    assert len(found[0]) == 64
    assert found[1] == "x" * 64


def free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.fixture()
def server(tmp_path: Path):
    root = Path(__file__).resolve().parent.parent
    registry = tmp_path / "subs.json"
    port = free_port()
    state = filled()
    body = {"port": port, "entries": state.sub_registry("127.0.0.1")}
    body["entries"]["%s" % ("a" * 64)] = {"key": "b" * 64, "title": "OBHOD all", "refresh": 12, "enabled": True, "links": ["vless://a", "freeturn://b"], "path": "/%s/%s" % ("a" * 64, "b" * 64)}
    registry.write_text(json.dumps(body), encoding="utf-8")
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "OBHOD_SUB_REGISTRY": str(registry),
        "OBHOD_SUB_PORT": str(port),
        "OBHOD_SUB_BIND": "127.0.0.1",
        "OBHOD_SECLOG": "0",
        "LANG": "C.UTF-8",
    }
    proc = subprocess.Popen([sys.executable, str(root / "Storage" / "remote" / "sub_server.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    try:
        yield port, body, state
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def fetch(url: str) -> tuple[int, bytes, dict[str, str]]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def test_the_server_serves_the_aggregate(server) -> None:
    port, body, _state = server
    url = "http://127.0.0.1:%d/%s/%s" % (port, "a" * 64, "b" * 64)
    code_value, raw, headers = fetch(url)
    assert code_value == 200
    assert base64.b64decode(raw).decode() == "vless://a\nfreeturn://b\n"
    assert headers.get("Profile-Update-Interval") == "12"


def test_the_server_serves_the_json_view(server) -> None:
    port, _body, _state = server
    url = "http://127.0.0.1:%d/%s/%s/json" % (port, "a" * 64, "b" * 64)
    code_value, raw, _headers = fetch(url)
    assert code_value == 200
    body = json.loads(raw)
    assert body["count"] == 2
    assert body["payload"]


def test_the_server_refuses_a_wrong_key(server) -> None:
    port, _body, _state = server
    code_value, _raw, _headers = fetch("http://127.0.0.1:%d/%s/%s" % (port, "a" * 64, "c" * 64))
    assert code_value == 404


def test_the_server_refuses_a_short_segment(server) -> None:
    port, _body, _state = server
    code_value, _raw, _headers = fetch("http://127.0.0.1:%d/short/%s" % (port, "b" * 64))
    assert code_value == 404


def test_the_server_serves_health(server) -> None:
    port, _body, _state = server
    code_value, raw, _headers = fetch("http://127.0.0.1:%d/health" % port)
    assert code_value == 200
    assert raw.strip() == b"ok"


def test_the_server_has_no_shell() -> None:
    root = Path(__file__).resolve().parent.parent
    body = (root / "Storage" / "remote" / "sub_server.py").read_text(encoding="utf-8")
    assert "shell=True" not in body
    assert "os.system" not in body
    assert "eval(" not in body


def test_the_subs_screen_shows_the_aggregate(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    bot = make_bot(tmp_path)
    bot.state.xray = filled()
    rows = bot.xray.sub_rows()
    assert any(item[0] == "one link for everything" for item in rows)
    from BOT import xscreens

    html = xscreens.subs_screen(bot.xray.view(), rows).build()
    assert "http://" in html
    assert "/json" in html


def test_a_freeturn_link_lands_in_the_bundle(tmp_path: Path) -> None:
    from tests.fakes import make_bot

    bot = make_bot(tmp_path)
    bot.state.xray = filled()
    bot.freeturn.state.remember("owner", "freeturn://abcdef")
    bundle = bot.xray.sub_bundle("203.0.113.5")
    assert bundle is not None
    assert "freeturn://abcdef" in bundle.links


def test_a_busy_port_is_reported_and_not_started(tmp_path: Path) -> None:
    import socket
    import subprocess

    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    port = holder.getsockname()[1]
    try:
        done = subprocess.run(
            [sys.executable, str(SERVER)],
            capture_output=True,
            text=True,
            timeout=30,
            env=dict(os.environ, OBHOD_SUB_PORT=str(port), OBHOD_SUB_BIND="127.0.0.1"),
        )
    finally:
        holder.close()
    assert done.returncode == 4
    assert "busy" in done.stderr


def test_the_subscription_sync_checks_the_port_after_the_stop() -> None:
    body = AGENT.read_text(encoding="utf-8")
    sync = body.split("def cmd_sub_sync", 1)[1].split("def cmd_sub_status", 1)[0]
    assert "port_busy" in sync
    assert sync.index("stop_sub()") < sync.index("port_busy")
    assert sync.index("port_busy") < sync.index("start_sub(")


def test_every_client_key_reaches_the_aggregate_bundle_once() -> None:
    state = XrayState()
    for port, net, sec in ((443, "raw", "reality"), (8443, "grpc", "tls")):
        inbound = new_inbound("vless", port, net, sec)
        for name in ("owner", "phone1", "laptop"):
            inbound.make_client(name)
        state.add(inbound)
    extra = [
        "freeturn://%s" % ("a" * 40),
        "freeturn://%s" % ("b" * 40),
    ]
    bundle = subs.aggregate(state, extra, "203.0.113.10", 2096)
    links = bundle.links
    assert len(links) == 8
    assert links[-2:] == extra
    assert all(item.startswith("freeturn://") or item.startswith("vless://") for item in links)
    assert len(set(links)) == len(links)
    for name in ("owner", "phone1", "laptop"):
        assert sum(1 for item in links if item.rsplit("#", 1)[-1].endswith("-%s" % name) or "-%s-" % name in item.rsplit("#", 1)[-1] or item.rsplit("#", 1)[-1].startswith("%s-" % name)) == 2
    registry = state.sub_registry("203.0.113.10", extra)
    entries = list(registry["entries"].values())
    owners = [item for item in entries if item["email"] != subs.ALL_EMAIL]
    aggregate_entry = [item for item in entries if item["email"] == subs.ALL_EMAIL]
    assert len(owners) == 3
    assert all(len(item["links"]) == 2 for item in owners)
    assert len(aggregate_entry) == 1
    assert aggregate_entry[0]["links"] == links


def test_a_client_with_no_links_is_never_silently_dropped() -> None:
    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    state.add(inbound)
    disabled = new_inbound("vless", 8443, "raw", "tls")
    disabled.make_client("owner")
    disabled.enable = False
    state.add(disabled)
    bundle = subs.aggregate(state, [], "203.0.113.10", 2096)
    assert bundle.links
    assert all("8443" not in item for item in bundle.links)


def test_a_large_bundle_is_never_cut_in_the_middle_of_a_link() -> None:
    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    for index in range(2040):
        inbound.make_client("peer%04d" % index)
    state.add(inbound)
    links = subs.aggregate(state, [], "203.0.113.10", 2096).links
    assert len(links) == 2040
    payload = subs.payload_of(links)
    assert len(payload) <= subs.MAX_BODY
    decoded = base64.b64decode(payload).decode("utf-8").strip().split("\n")
    assert decoded == links
    assert subs.dropped(links) == 0


def test_a_bundle_over_the_cap_drops_whole_links_only() -> None:
    long_link = "vless://" + "a" * (subs.MAX_LINK - 40)
    links = [long_link + "-%04d" % index for index in range(subs.MAX_LINKS)]
    payload = subs.payload_of(links)
    decoded = base64.b64decode(payload).decode("utf-8").strip().split("\n")
    assert len(payload) <= subs.MAX_BODY
    assert decoded == links[: len(decoded)]
    assert subs.dropped(links) == len(links) - len(decoded)
    assert subs.dropped(links) > 0


def test_a_client_named_all_never_collides_with_the_aggregate() -> None:
    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("all")
    inbound.make_client("owner")
    state.add(inbound)
    registry = state.sub_registry("203.0.113.10", [])
    emails = [item["email"] for item in registry["entries"].values()]
    assert emails.count(subs.ALL_EMAIL) == 1
    assert emails.count("all") == 1
    aggregate = [item for item in registry["entries"].values() if item["email"] == subs.ALL_EMAIL]
    assert aggregate[0]["title"] == subs.ALL_TITLE
    assert len(aggregate[0]["links"]) == 2
    human = [item for item in registry["entries"].values() if item["email"] == "all"]
    assert len(human[0]["links"]) == 1


def test_a_hostile_address_never_reaches_a_link() -> None:
    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.make_client("owner")
    state.add(inbound)
    hostile = "\u043d\u0435-\u0430\u0434\u0440\u0435\u0441"
    for bad in (hostile, "host with space", "a" * 300, "../etc", "-bad.example"):
        links = state.subscriptions(bad)[0].links
        assert hostile not in links[0]
        assert " " not in links[0].split("@")[1].split(":")[0]
        assert links[0].count("@") == 1
    assert state.address("203.0.113.10") == "203.0.113.10"
    assert state.address("vpn.example.com") == "vpn.example.com"
    state.sub_address = "2001:db8::1"
    assert state.address("") == "2001:db8::1"
    state.sub_address = hostile
    assert state.address("203.0.113.10") == "203.0.113.10"


def test_the_agent_takes_a_large_registry_over_stdin(tmp_path: Path) -> None:
    from BOT.xrayrpc import ARG_LIMIT, payload_arg

    small_flag, small_stdin = payload_arg("registry-b64", b"x" * 32)
    assert small_stdin == b""
    assert small_flag.startswith("--registry-b64=")
    assert len(small_flag) < ARG_LIMIT
    big = b"y" * (ARG_LIMIT * 4)
    big_flag, big_stdin = payload_arg("registry-b64", big)
    assert big_flag == "--registry-b64=-"
    assert len(big_stdin) > ARG_LIMIT
    assert base64.b64decode(big_stdin) == big


def test_the_agent_reads_the_stdin_payload_and_reports_a_bad_one(tmp_path: Path) -> None:
    server = tmp_path / "obhod-sub"
    good = base64.b64encode(json.dumps({"entries": {}, "port": 2096}).encode())
    done = subprocess.run(
        [sys.executable, str(AGENT), "sub-sync", "--registry-b64=-", "--port=2096"],
        input=good,
        capture_output=True,
        timeout=60,
    )
    text = done.stdout.decode("utf-8", "replace")
    assert "not_installed" in text
    assert "bad_arg" not in text
    bad = subprocess.run(
        [sys.executable, str(AGENT), "sub-sync", "--registry-b64=-", "--port=2096"],
        input=b"not-base64!!",
        capture_output=True,
        timeout=60,
    )
    assert "bad_arg" in bad.stdout.decode("utf-8", "replace")
    assert server.name in "obhod-sub"


def test_a_non_iterable_link_list_is_refused_quietly() -> None:
    assert subs.clean_links(1.5) == []
    assert subs.clean_links(None) == []
    assert subs.clean_links({"vless://one"}) == ["vless://one"]
    assert subs.clean_links("vless://two") == ["vless://two"]
    assert subs.clean_links(b"vless://three") == ["vless://three"]
    assert subs.payload_of(1.5) == ""
