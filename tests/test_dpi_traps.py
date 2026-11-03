from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
XRAY = ROOT / "Storage" / "remote" / "xray_agent.py"

TRAPPED = {
    "inbounds": [
        {
            "tag": "in-443-xhttp",
            "port": 443,
            "protocol": "vless",
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": {
                    "path": "/ray",
                    "mode": "auto",
                    "scMaxEachPostBytes": "1000000",
                    "scMinPostsIntervalMs": "30",
                },
            },
        },
        {
            "tag": "in-8443-raw",
            "port": 8443,
            "protocol": "vless",
            "streamSettings": {"network": "tcp", "security": "reality", "tcpSettings": {"header": {"type": "none"}}},
        },
    ],
    "outbounds": [{"protocol": "freedom"}],
}


def load_agent(monkeypatch: pytest.MonkeyPatch, root: Path):
    monkeypatch.setenv("XRAY_ROOT", str(root))
    spec = importlib.util.spec_from_file_location("obhod_xray_agent_traps", XRAY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_config(agent, payload: dict) -> Path:
    target = Path(agent.CONF)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def test_the_agent_finds_the_3xui_trap_keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    agent = load_agent(monkeypatch, tmp_path)
    write_config(agent, TRAPPED)
    report, _ = agent.cmd_dpi_scan({}, [])
    assert report["count"] == 2
    assert report["inbounds"] == 1
    assert report["found"][0]["tag"] == "in-443-xhttp"
    assert sorted(report["found"][0]["keys"]) == ["scMaxEachPostBytes", "scMinPostsIntervalMs"]
    assert report["interval"] == agent.DPI_SAFE_INTERVAL_MS


def test_a_clean_config_reports_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    agent = load_agent(monkeypatch, tmp_path)
    clean = json.loads(json.dumps(TRAPPED))
    settings = clean["inbounds"][0]["streamSettings"]["xhttpSettings"]
    settings.pop("scMaxEachPostBytes")
    settings.pop("scMinPostsIntervalMs")
    write_config(agent, clean)
    report, _ = agent.cmd_dpi_scan({}, [])
    assert report["count"] == 0
    assert report["found"] == []


def test_a_missing_config_is_not_an_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    agent = load_agent(monkeypatch, tmp_path)
    report, _ = agent.cmd_dpi_scan({}, [])
    assert report["config_exists"] is False
    assert report["count"] == 0


def test_the_fix_removes_both_keys_and_keeps_the_rest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    agent = load_agent(monkeypatch, tmp_path)
    target = write_config(agent, TRAPPED)
    monkeypatch.setattr(agent, "test_config", lambda payload: (True, ""))
    monkeypatch.setattr(agent, "start_core", lambda: None)
    monkeypatch.setattr(agent, "stop_core", lambda: None)
    report, _ = agent.cmd_dpi_fix({}, [])
    assert report["stripped"] == 2
    assert report["count"] == 0
    assert report["restarted"] is True
    assert report["backup"].endswith(".bak")
    after = json.loads(target.read_text(encoding="utf-8"))
    settings = after["inbounds"][0]["streamSettings"]["xhttpSettings"]
    assert settings["path"] == "/ray"
    assert settings["mode"] == "auto"
    assert "scMinPostsIntervalMs" not in settings
    assert "scMaxEachPostBytes" not in settings
    assert after["inbounds"][1] == TRAPPED["inbounds"][1]
    assert (tmp_path / "usr" / "local" / "etc" / "xray" / "config.json.bak").exists() or report["backup"]


def test_the_fix_on_a_clean_config_touches_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    agent = load_agent(monkeypatch, tmp_path)
    clean = json.loads(json.dumps(TRAPPED))
    settings = clean["inbounds"][0]["streamSettings"]["xhttpSettings"]
    settings.pop("scMaxEachPostBytes")
    settings.pop("scMinPostsIntervalMs")
    target = write_config(agent, clean)
    before = target.read_bytes()
    report, _ = agent.cmd_dpi_fix({}, [])
    assert report["stripped"] == 0
    assert report["restarted"] is False
    assert target.read_bytes() == before


def test_the_fix_refuses_a_config_the_core_rejects(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    agent = load_agent(monkeypatch, tmp_path)
    target = write_config(agent, TRAPPED)
    before = target.read_bytes()
    monkeypatch.setattr(agent, "test_config", lambda payload: (False, "bad inbound"))
    monkeypatch.setattr(agent, "start_core", lambda: pytest.fail("the core must not be restarted"))
    with pytest.raises(agent.ScriptError) as caught:
        agent.cmd_dpi_fix({}, [])
    assert caught.value.code == "config_invalid"
    assert target.read_bytes() == before


def test_the_scan_survives_hostile_config_shapes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    agent = load_agent(monkeypatch, tmp_path)
    for payload in (
        {"inbounds": None},
        {"inbounds": [None, 3, "x"]},
        {"inbounds": [{"streamSettings": None}]},
        {"inbounds": [{"streamSettings": {"xhttpSettings": "nope"}}]},
        {"inbounds": [{"streamSettings": {"xhttpSettings": {"scMinPostsIntervalMs": None}}}]},
        {},
    ):
        write_config(agent, payload)
        report, _ = agent.cmd_dpi_scan({}, [])
        assert isinstance(report["found"], list)
        monkeypatch.setattr(agent, "test_config", lambda value: (True, ""))
        monkeypatch.setattr(agent, "start_core", lambda: None)
        monkeypatch.setattr(agent, "stop_core", lambda: None)
        agent.cmd_dpi_fix({}, [])
