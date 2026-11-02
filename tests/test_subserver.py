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

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "Storage" / "remote" / "sub_server.py"
SUB_ID = "A" * 64
SUB_KEY = "B" * 64
LINK = "vless://uuid@example.com:443?security=reality&encryption=mlkem768x25519plus.native.0rtt.key"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture()
def server(tmp_path: Path):
    registry = {
        "port": 2096,
        "entries": {
            SUB_ID: {
                "key": SUB_KEY,
                "title": "OBHOD owner",
                "filename": "obhod-owner",
                "enabled": True,
                "path": "/" + SUB_ID + "/" + SUB_KEY,
                "links": [LINK],
            },
            "C" * 64: {
                "key": "D" * 64,
                "enabled": False,
                "links": [LINK],
            },
        },
    }
    path = tmp_path / "subscriptions.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    port = free_port()
    env = dict(os.environ, OBHOD_SUB_REGISTRY=str(path), OBHOD_SUB_PORT=str(port))
    proc = subprocess.Popen([sys.executable, str(SERVER)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.time() + 10
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.1)
    yield port, path, registry
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def fetch(port: int, path: str, head: bool = False) -> tuple[int, dict[str, str], bytes]:
    url = f"http://127.0.0.1:{port}{path}"
    request = urllib.request.Request(url, method="HEAD" if head else "GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_subscription_returns_base64_links(server) -> None:
    port, _path, _registry = server
    status, headers, body = fetch(port, "/" + SUB_ID + "/" + SUB_KEY)
    assert status == 200
    assert base64.b64decode(body).decode("utf-8").strip() == LINK
    assert headers["Content-Type"].startswith("text/plain")
    assert headers["Profile-Update-Interval"] == "12"
    assert "Subscription-Userinfo" in headers


def test_head_request_has_no_body(server) -> None:
    port, _path, _registry = server
    status, headers, body = fetch(port, "/" + SUB_ID + "/" + SUB_KEY, head=True)
    assert status == 200
    assert body == b""
    assert int(headers["Content-Length"]) > 0


def test_wrong_key_is_not_found(server) -> None:
    port, _path, _registry = server
    assert fetch(port, "/" + SUB_ID + "/" + "Z" * 64)[0] == 404


def test_short_segments_are_not_found(server) -> None:
    port, _path, _registry = server
    assert fetch(port, "/abc/def")[0] == 404
    assert fetch(port, "/" + SUB_ID)[0] == 404
    assert fetch(port, "/" + SUB_ID + "/" + SUB_KEY + "/extra")[0] == 404
    assert fetch(port, "/" + "A" * 63 + "/" + SUB_KEY)[0] == 404


def test_disabled_entry_is_forbidden(server) -> None:
    port, _path, registry = server
    assert fetch(port, "/" + "C" * 64 + "/" + "D" * 64)[0] == 403


def test_health_and_root(server) -> None:
    port, _path, _registry = server
    assert fetch(port, "/health")[0] == 200
    assert fetch(port, "/")[0] == 404
    assert fetch(port, "/favicon.ico")[0] == 404


def test_registry_is_reread_on_every_request(server) -> None:
    port, path, registry = server
    assert fetch(port, "/" + "E" * 64 + "/" + "F" * 64)[0] == 404
    registry["entries"]["E" * 64] = {"key": "F" * 64, "links": [LINK], "enabled": True}
    path.write_text(json.dumps(registry), encoding="utf-8")
    status, _headers, body = fetch(port, "/" + "E" * 64 + "/" + "F" * 64)
    assert status == 200
    assert base64.b64decode(body).decode("utf-8").strip() == LINK


def test_registry_matches_state_builder(tmp_path: Path) -> None:
    from BOT.xray import XrayState, new_inbound

    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    client = inbound.make_client("owner")
    state.add(inbound)
    registry = state.sub_registry("203.0.113.10")
    entry = registry["entries"][client.sub_id]
    assert len(client.sub_id) == 64
    assert len(entry["key"]) == 64
    assert entry["path"] == "/" + client.sub_id + "/" + entry["key"]
    assert entry["links"][0].startswith("vless://")
    assert "/" not in client.sub_id and "/" not in entry["key"]


def test_refresh_interval_comes_from_the_registry() -> None:
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "Storage" / "remote" / "sub_server.py"
    spec = importlib.util.spec_from_file_location("obhod_sub_refresh", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert module.refresh_hours({"refresh": 24}) == "24"
    assert module.refresh_hours({}) == "12"
    assert module.refresh_hours({"refresh": "bad"}) == "12"
    assert module.refresh_hours({"refresh": 0}) == "12"
    assert module.refresh_hours({"refresh": 10000}) == "168"
    headers = dict(module.header_lines({"title": "t", "refresh": 6, "path": "/a/b"}, "obhod"))
    assert headers["Profile-Update-Interval"] == "6"
    assert headers["Content-Type"].startswith("text/plain")


def test_the_real_client_is_read_behind_a_proxy() -> None:
    from Storage.remote import sub_server

    headers = {"X-Forwarded-For": "203.0.113.7", "CF-Connecting-IP": "198.51.100.9"}
    assert sub_server.proxy_client_ip("127.0.0.1", headers) == "203.0.113.7"
    assert sub_server.proxy_client_ip("::1", {"CF-Connecting-IP": "198.51.100.9"}) == "198.51.100.9"
    assert sub_server.proxy_client_ip("100.101.2.3", headers) == "203.0.113.7"


def test_a_remote_peer_cannot_choose_its_address() -> None:
    from Storage.remote import sub_server

    headers = {"X-Forwarded-For": "1.2.3.4", "CF-Connecting-IP": "5.6.7.8"}
    assert sub_server.proxy_client_ip("198.51.100.20", headers) == "198.51.100.20"


def test_a_broken_forwarded_header_falls_back() -> None:
    from Storage.remote import sub_server

    assert sub_server.proxy_client_ip("127.0.0.1", {"X-Forwarded-For": "not-an-ip"}) == "127.0.0.1"
    assert sub_server.proxy_client_ip("127.0.0.1", {"X-Forwarded-For": "10.0.0.1, 203.0.113.9"}) == "203.0.113.9"
