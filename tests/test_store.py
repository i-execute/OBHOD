from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from BOT import i18n
from BOT.store import SCHEMA, State, Store
from BOT.xray import XrayState, new_inbound


def test_state_roundtrip() -> None:
    state = State(xray=XrayState())
    state.ssh.port = 2200
    state.admin_id = 999
    state.log_tail = 500
    state.sub_port = 2097
    state.xray.sub_address = "vpn.example.org"
    state.xray.log_level = "debug"
    inbound = new_inbound("vless", 443, "xhttp", "tls")
    inbound.make_client("owner")
    state.xray.add(inbound)
    clone = State.from_dict(state.to_dict())
    assert clone.ssh.port == 2200
    assert clone.admin_id == 999
    assert clone.log_tail == 500
    assert clone.sub_port == 2097
    assert clone.xray.sub_address == "vpn.example.org"
    assert clone.xray.log_level == "debug"
    assert clone.xray.inbounds[0].network == "xhttp"
    assert clone.xray.inbounds[0].clients[0].email == "owner"
    assert len(clone.xray.inbounds[0].clients[0].sub_key) == 64


def test_state_from_empty_dict() -> None:
    state = State.from_dict(None)
    assert state.ssh.port == 22
    assert state.log_tail == 200
    assert state.sub_port == 2096
    assert state.xray.inbounds == []
    assert state.xray.version == "latest"
    assert state.xray.install_version() == "latest"
    assert state.xray.pinned().startswith("v26")


def test_save_and_load_permissions(tmp_path: Path) -> None:
    store = Store(tmp_path / "nested" / "state.json")
    state = State()
    state.ssh.port = 2222
    store.save(state)
    assert store.path.is_file()
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(store.path.parent).st_mode) == 0o700
    again = store.load()
    assert again.ssh.port == 2222
    raw = json.loads(store.path.read_text())
    assert raw["ssh"]["port"] == 2222
    assert raw["xray"]["inbounds"] == []
    assert raw["schema"] == SCHEMA


def test_language_roundtrip(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    state = State()
    assert state.language == i18n.DEFAULT_LANGUAGE
    state.language = "zh"
    store.save(state)
    again = store.load()
    assert again.language == "zh"
    assert again.to_dict()["language"] == "zh"


def test_language_falls_back_to_default(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text('{"language": "klingon"}', encoding="utf-8")
    assert Store(path).load().language == i18n.DEFAULT_LANGUAGE
    path.write_text('{"language": "ru-RU"}', encoding="utf-8")
    assert Store(path).load().language == "ru"


def test_load_missing_and_broken(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    assert store.load().ssh.port == 22
    store.path.write_text("{broken")
    assert store.load().ssh.port == 22
    store.path.write_text(json.dumps({"ssh": {"port": 2222}}))
    assert store.load().ssh.port == 2222
    store.path.write_text(json.dumps({"ssh": {"port": 0}}))
    assert store.load().ssh.port == 22
    store.path.write_text(json.dumps({"ssh": {"password": "pw"}}))
    assert not hasattr(store.load().ssh, "password")
    store.path.write_text(json.dumps(["not", "a", "dict"]))
    assert store.load().ssh.port == 22


def test_save_is_atomic_and_leaves_no_temp_files(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    state = State()
    for index in range(5):
        state.log_tail = 100 + index
        store.save(state)
    leftovers = [item.name for item in tmp_path.iterdir() if item.name != "state.json"]
    assert leftovers == []
    assert store.load().log_tail == 104


def test_save_overwrites_previous_content(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    first = State()
    first.ssh.port = 2222
    store.save(first)
    second = State()
    second.ssh.port = 2223
    store.save(second)
    body = store.path.read_text()
    assert "2222" not in body
    assert "2223" in body


def test_sub_port_syncs_into_xray_state(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    state = State()
    state.sub_port = 2100
    store.save(state)
    assert store.load().xray.sub_port == 2100


def test_scanner_and_config_settings_roundtrip(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    state = State()
    state.xray.scan_candidates = ["a:443", "b:443"]
    state.xray.scan_sni = "www.google.com"
    state.xray.scan_xver = 2
    state.xray.api_port = 63000
    state.xray.access_log = "/tmp/access.log"
    state.xray.dns_servers = ["1.1.1.1"]
    store.save(state)
    again = store.load()
    assert again.xray.scan_candidates == ["a:443", "b:443"]
    assert again.xray.scan_sni == "www.google.com"
    assert again.xray.scan_xver == 2
    assert again.xray.api_port == 63000
    assert again.xray.access_log == "/tmp/access.log"
    assert again.xray.dns_servers == ["1.1.1.1"]


def test_config_defaults_survive_an_old_state_file(tmp_path: Path) -> None:
    from BOT.xray import API_PORT, DEFAULT_ACCESS_LOG, DEFAULT_METRICS

    path = tmp_path / "state.json"
    path.write_text('{"schema": 5, "xray": {"inbounds": []}}', encoding="utf-8")
    state = Store(path).load()
    assert state.xray.api_port == API_PORT
    assert state.xray.access_log == DEFAULT_ACCESS_LOG
    assert state.xray.metrics == DEFAULT_METRICS
    assert state.xray.api_enabled is True
    assert state.xray.scan_candidates == []
    assert state.xray.candidates()


def test_language_survives_a_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    store = Store(path)
    state = State()
    assert state.language == "en"
    store.save(state)
    assert Store(path).load().language == "en"
    state.language = "zh"
    store.save(state)
    assert Store(path).load().language == "zh"
    state.language = "ZH-hans"
    store.save(state)
    assert Store(path).load().language == "zh"
