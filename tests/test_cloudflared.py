from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest

from BOT.cloudflared import CloudflaredControl, CloudflaredState
from BOT.models import SshSettings
from BOT.shell import ShellOutput

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "Storage" / "remote" / "cloudflared_agent.py"


def load_agent(name: str) -> object:
    spec = importlib.util.spec_from_file_location(name, AGENT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_cloudflared_control_embeds_the_agent_and_parses_state() -> None:
    class Shell:
        def __init__(self) -> None:
            self.calls: list[tuple[list[str], float | None]] = []

        async def run_argv(self, argv: list[str], stdin: bytes | None = None, timeout: float | None = None) -> ShellOutput:
            self.calls.append((argv, timeout))
            return ShellOutput(json.dumps({"proto": 1, "result": "ok", "data": {"installed": True, "version": "2026.11.1", "service": "active", "url": "https://short.trycloudflare.com"}}))

    async def exercise() -> None:
        shell = Shell()
        state = await CloudflaredControl(shell=shell).status(SshSettings(port=2222))
        assert state.active and state.url == "https://short.trycloudflare.com"
        argv, timeout = shell.calls[0]
        assert argv[-1] == "status"
        assert argv[1] == "-c" and "obhod-cloudflared.service" in argv[2]
        assert timeout == 90

    asyncio.run(exercise())


def test_cloudflared_state_is_bounded_and_serializable() -> None:
    state = CloudflaredState.from_dict({"installed": 1, "version": "2026.11.1", "service": "active", "url": "https://short.trycloudflare.com", "local_url": "http://127.0.0.1:24567"})
    clone = CloudflaredState.from_dict(state.to_dict())
    assert clone.installed and clone.active
    assert clone.local_url == "http://127.0.0.1:24567"


def test_agent_accepts_only_loopback_http_upstreams() -> None:
    module = load_agent("obhod_cloudflared_url")
    assert module.clean_local_url("http://127.0.0.1:24567") == "http://127.0.0.1:24567"
    assert module.clean_local_url("http://[::1]:24567") == "http://[::1]:24567"
    for value in ("https://127.0.0.1:24567", "http://localhost:24567", "http://8.8.8.8:80", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:80/path"):
        with pytest.raises(module.AgentError):
            module.clean_local_url(value)


def test_agent_latest_lookup_uses_verified_asset_and_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent("obhod_cloudflared_release")

    class Reply:
        def __init__(self, value: dict) -> None:
            self.value = value

        def __enter__(self) -> "Reply":
            return self

        def __exit__(self, exc_type: object, exc: object, trace: object) -> bool:
            return False

        def read(self, limit: int) -> bytes:
            assert limit == 1 << 20
            return json.dumps(self.value).encode("utf-8")

    digest = "a" * 64
    payload = {"tag_name": "v2026.12.3", "assets": [{"name": "cloudflared-linux-amd64", "digest": "sha256:" + digest}]}
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda request, timeout=0: Reply(payload))
    assert module.latest_release("amd64") == ("2026.12.3", digest, "latest")
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda request, timeout=0: (_ for _ in ()).throw(module.urllib.error.URLError("offline")))
    assert module.latest_release("amd64") == (module.PINNED_VERSION, module.PINNED_SHA256["amd64"], "fallback")


def test_agent_persists_quick_tunnel_lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent("obhod_cloudflared_state_%d" % id(tmp_path))
    module.BIN = str(tmp_path / "usr" / "local" / "bin" / "cloudflared")
    module.UNIT = str(tmp_path / "etc" / "systemd" / "system" / "obhod-cloudflared.service")
    module.LOG = str(tmp_path / "var" / "log" / "obhod" / "cloudflared.log")
    module.STATE = str(tmp_path / "var" / "lib" / "obhod" / "cloudflared.json")
    Path(module.BIN).parent.mkdir(parents=True)
    Path(module.BIN).write_text("binary", encoding="utf-8")

    def run(argv: list[str], timeout: int = 120) -> tuple[int, str]:
        if argv[0] == module.BIN:
            return 0, "cloudflared version 2026.11.1"
        if argv[1:2] == ["is-active"]:
            return 0, "active"
        return 0, ""

    monkeypatch.setattr(module, "run", run)
    started = module.up({"url": "http://127.0.0.1:24567"})
    assert started["service"] == "active"
    assert started["local_url"] == "http://127.0.0.1:24567"
    assert "--url http://127.0.0.1:24567" in Path(module.UNIT).read_text(encoding="utf-8")
    Path(module.LOG).write_text("ready https://short.trycloudflare.com\n", encoding="utf-8")
    logged = module.logs({})
    assert logged["url"] == "https://short.trycloudflare.com"
    stopped = module.down({})
    assert stopped["url"] == "" and stopped["local_url"] == ""
    removed = module.remove({})
    assert not removed["installed"] and not removed["unit"]


def test_agent_keeps_state_when_stopping_the_unit_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_agent("obhod_cloudflared_stop_%d" % id(tmp_path))
    module.UNIT = str(tmp_path / "obhod-cloudflared.service")
    module.STATE = str(tmp_path / "cloudflared.json")
    Path(module.UNIT).write_text("unit", encoding="utf-8")
    module.save_state({"url": "https://short.trycloudflare.com", "local_url": "http://127.0.0.1:24567"})
    monkeypatch.setattr(module, "systemctl", lambda *args: (1, "failed"))
    with pytest.raises(module.AgentError) as error:
        module.down({})
    assert error.value.code == "stop_failed"
    assert module.state()["url"] == "https://short.trycloudflare.com"
