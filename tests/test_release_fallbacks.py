from __future__ import annotations

import io
import importlib.util
import re
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from BOT import freeturn, i18n, xrayrpc

ROOT = Path(__file__).resolve().parent.parent
XRAY_AGENT = ROOT / "Storage" / "remote" / "xray_agent.py"
TURN_AGENT = ROOT / "Storage" / "remote" / "freeturn_agent.py"


def load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_every_xray_asset_carries_a_pinned_digest() -> None:
    module = load(XRAY_AGENT, "xray_agent_pins")
    assets = sorted(set(module.ASSETS.values()))
    assert assets
    for asset in assets:
        value = module.DIGESTS.get(asset, "")
        assert re.fullmatch(r"[0-9a-f]{64}", value or ""), asset
        assert xrayrpc.PINNED_SHA256.get(asset) == value, asset


def test_the_bot_and_the_agent_share_the_xray_pins() -> None:
    module = load(XRAY_AGENT, "xray_agent_pins_shared")
    assert set(xrayrpc.ASSET_BY_ARCH) == set(module.ASSETS)
    assert xrayrpc.DEFAULT_VERSION == module.PINNED
    assert xrayrpc.PINNED_SHA256 == module.DIGESTS


def test_a_rate_limited_api_sends_the_pinned_core(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load(XRAY_AGENT, "xray_agent_rate_limit")
    monkeypatch.setattr(module, "latest_tag", lambda timeout=15, use_cache=True: "")
    monkeypatch.setattr(module, "API_REASON", "rate_limited")
    module.LOGS.clear()
    seen: list[str] = []

    def fake_install(version: str, url: str, sha256: str, force: bool) -> dict[str, Any]:
        seen.append(version)
        return {"version": version, "downloaded": True}

    monkeypatch.setattr(module, "install_core", fake_install)
    data = module.pinned_with_fallback("latest", "", "", False)
    assert seen == [module.PINNED]
    assert data["version"] == module.PINNED
    assert any("rate limited" in line for line in module.LOGS)


def test_an_unreachable_api_sends_the_pinned_core(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load(XRAY_AGENT, "xray_agent_unreachable")
    monkeypatch.setattr(module, "latest_tag", lambda timeout=15, use_cache=True: "")
    monkeypatch.setattr(module, "API_REASON", "unreachable")
    module.LOGS.clear()
    monkeypatch.setattr(module, "install_core", lambda version, url, sha256, force: {"version": version})
    data = module.pinned_with_fallback("latest", "", "", False)
    assert data["version"] == module.PINNED
    assert any("unreachable" in line for line in module.LOGS)


def test_the_pinned_fallback_really_carries_the_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load(XRAY_AGENT, "xray_agent_digest_fallback")
    monkeypatch.setattr(module, "machine", lambda: "x86_64")
    monkeypatch.setattr(module, "core_version", lambda: "")
    monkeypatch.setattr(module, "fetch_digest", lambda version, asset, url: "")
    seen: dict[str, str] = {}

    def fake_download(url: str, target: str) -> None:
        seen["url"] = url
        Path(target).write_bytes(b"not the real archive")

    monkeypatch.setattr(module, "download", fake_download)
    with pytest.raises(module.ScriptError) as caught:
        module.install_core(module.PINNED, "", "", True)
    assert caught.value.code == "digest_mismatch"
    assert seen["url"].endswith("/Xray-linux-64.zip")


def test_the_rate_limit_headers_are_understood() -> None:
    module = load(XRAY_AGENT, "xray_agent_headers")
    message = Message()
    message["X-RateLimit-Remaining"] = "0"
    limited = urllib.error.HTTPError("https://api.github.com/x", 403, "forbidden", message, io.BytesIO(b""))
    assert module.api_rate_limited(limited) is True
    late = urllib.error.HTTPError("https://api.github.com/x", 429, "later", Message(), io.BytesIO(b""))
    assert module.api_rate_limited(late) is True
    other = urllib.error.HTTPError("https://api.github.com/x", 403, "forbidden", Message(), io.BytesIO(b""))
    assert module.api_rate_limited(other) is False


def test_a_good_tag_is_cached_and_an_empty_one_is_not_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load(XRAY_AGENT, "xray_agent_cache")
    module.API_CACHE.clear()
    calls: list[int] = []

    class Answer:
        def __enter__(self) -> "Answer":
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def read(self, _limit: int = 0) -> bytes:
            return b'{"tag_name": "v26.10.21"}'

    def answer(request: object, timeout: float = 0) -> Answer:
        calls.append(1)
        return Answer()

    monkeypatch.setattr(module, "open_url", answer)
    assert module.latest_tag() == "v26.10.21"
    assert module.latest_tag() == "v26.10.21"
    assert len(calls) == 1
    assert module.API_REASON == ""


def test_the_new_freeturn_version_is_the_hardcoded_fallback() -> None:
    assert freeturn.FALLBACK_VERSION == "v4.1.1"
    assert freeturn.DEFAULT_VERSION == freeturn.FALLBACK_VERSION
    assert freeturn.PINNED_SCRIPT_SHA256[freeturn.FALLBACK_VERSION] == (
        "91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100"
    )
    assert freeturn.script_url(freeturn.FALLBACK_VERSION).endswith("/v4.1.1/install.sh")


def test_the_not_pinned_error_is_translated_everywhere() -> None:
    for language in i18n.LANGUAGES:
        text = i18n.t("FT_CODE_NOT_PINNED", language=language)
        assert text and not text.startswith("FT_CODE_"), language
    assert freeturn.FT_ERROR_CODES["not_pinned"]
