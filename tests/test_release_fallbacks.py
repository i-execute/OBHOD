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
            return b'{"tag_name": "v26.10.29"}'

    def answer(request: object, timeout: float = 0) -> Answer:
        calls.append(1)
        return Answer()

    monkeypatch.setattr(module, "open_url", answer)
    assert module.latest_tag() == "v26.10.29"
    assert module.latest_tag() == "v26.10.29"
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


RELEASE_ASSETS_V4_1_1 = (
    "server-linux-386",
    "server-linux-amd64",
    "server-linux-arm64",
    "server-linux-armv7",
    "server-linux-mips-softfloat",
    "server-linux-mips64le-softfloat",
    "server-linux-mipsle-softfloat",
    "server-linux-riscv64",
)


def test_every_architecture_maps_to_an_asset_the_release_ships() -> None:
    for arch, asset in freeturn.ASSET_BY_ARCH.items():
        assert asset in RELEASE_ASSETS_V4_1_1, arch
    assert "server-linux-amd64" in freeturn.ASSET_BY_ARCH.values()
    for arch in ("x86_64", "aarch64", "armv7l"):
        assert freeturn.core_url(freeturn.FALLBACK_VERSION, arch).startswith(
            "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.1/"
        )


def test_the_pin_points_at_the_published_release() -> None:
    module = load(TURN_AGENT, "freeturn_agent_published")
    assert module.SCRIPT_REPO == "hackdiaz-dev/free-turn-proxy"
    assert module.FALLBACK_VERSION == "v4.1.1"
    assert module.script_url(module.FALLBACK_VERSION) == (
        "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.1/install.sh"
    )
    assert module.SCRIPT_SHA256["v4.1.1"] == freeturn.PINNED_SCRIPT_SHA256["v4.1.1"] == (
        "91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100"
    )
    assert module.resolve_version("latest", lookup=lambda repo: ("v4.1.1", "")) == ("v4.1.1", "api")


def test_exactly_one_xray_version_is_kept_as_the_fallback() -> None:
    from BOT import xray

    module = load(XRAY_AGENT, "xray_agent_single_pin")
    assert xray.XRAY_VERSION == xrayrpc.DEFAULT_VERSION == module.PINNED == "v26.10.29"
    assert xray.VERSION_CHOICES == (xray.XRAY_VERSION, "latest")
    assert xray.XrayState().install_version() == "latest"
    assert xray.XrayState().pinned() == "v26.10.29"
    state = xray.XrayState()
    state.version = "v26.10.29"
    assert state.install_version() == "v26.10.29"
    state.version = "v0.0.1"
    assert state.install_version() == "latest"


def test_the_xray_pins_are_the_published_release_digests() -> None:
    module = load(XRAY_AGENT, "xray_agent_release_digests")
    published = {
        "64": "8a5f3e6a1057e4bd0f8a7c57c9d91204b4be0b74222a6e210d070603101163c2",
        "arm64-v8a": "afe01f19045b05237420328028ee1ee2e1edd2100eb41a8cbbf50e683b0a6e58",
        "arm32-v7a": "263fa7325c63b3a7f7316405f561e7c790b44c1461992ea648007f0374e9bdf4",
        "arm32-v6": "7c2f4ececc528eb4115a990f326a070a7e9a1712b8be6969ef5dc8f59543895d",
        "32": "a02065c652dd8f25806242edc9656a21495a0afc10b3c2f22dda14cd71b70726",
        "s390x": "cd0ddcde6e0bcf42a62dfd4e18857309b5efe23a931402c9cbb04e921bcbe7fe",
        "riscv64": "ca16e1a932d8a7e58cc06686d08c3787b71c054ed78b5760e4eb8bfd916540a2",
    }
    assert module.DIGESTS == published
    assert xrayrpc.PINNED_SHA256 == published
    assert len(published) == 7


def test_exactly_one_freeturn_version_is_kept_as_the_fallback() -> None:
    module = load(TURN_AGENT, "freeturn_agent_single_pin")
    assert len(freeturn.PINNED_SCRIPT_SHA256) == 1
    assert len(module.SCRIPT_SHA256) == 1
    assert freeturn.FALLBACK_VERSION == module.FALLBACK_VERSION == "v4.1.1"
    assert freeturn.VERSION_CHOICES == ("latest", freeturn.FALLBACK_VERSION)


def test_a_newer_freeturn_release_installs_with_its_published_digest() -> None:
    published = "d" * 64
    assert freeturn.resolve_version("latest", lambda repo: ("v4.2.0", ""), lambda tag: published) == ("v4.2.0", "api")
    assert freeturn.resolve_version("latest", lambda repo: ("v4.2.0", ""), lambda tag: "") == (
        freeturn.FALLBACK_VERSION,
        "not_pinned",
    )
    assert freeturn.resolve_version("latest", lambda repo: ("", "rate_limited"), lambda tag: published) == (
        freeturn.FALLBACK_VERSION,
        "fallback",
    )
    assert freeturn.script_digest("v4.2.0", lambda tag: published) == published
    assert freeturn.script_digest(freeturn.FALLBACK_VERSION) == freeturn.PINNED_SCRIPT_SHA256[freeturn.FALLBACK_VERSION]


def test_the_checksums_file_is_parsed_strictly() -> None:
    body = (
        b"51592ed16012f48d7765ae61b4e8a19179c8903e2cbaa141dd5c11318985ac1a  client-darwin-amd64\n"
        b"91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100  install.sh\n"
    )
    assert freeturn.digest_of_checksums(body) == "91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100"
    assert freeturn.digest_of_checksums(b"") == ""
    assert freeturn.digest_of_checksums(b"not a checksum  install.sh\n") == ""
    assert freeturn.digest_of_checksums(b"zz  install.sh\n") == ""
    module = load(TURN_AGENT, "freeturn_agent_checksums")
    assert module.digest_of_checksums(body) == freeturn.digest_of_checksums(body)


def test_the_checksums_are_read_from_github_only(monkeypatch: pytest.MonkeyPatch) -> None:
    assert freeturn.checksums_url("v4.1.1") == (
        "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.1/checksums.txt"
    )
    assert freeturn.allowed_checksums_url(freeturn.checksums_url("v4.1.1")) is True
    assert freeturn.allowed_checksums_url("https://example.com/checksums.txt") is False
    assert freeturn.allowed_checksums_url("http://github.com/checksums.txt") is False
    module = load(TURN_AGENT, "freeturn_agent_checksum_hosts")
    assert module.allowed_url(freeturn.checksums_url("v4.1.1")) is True
    freeturn.CHECKSUMS_CACHE.clear()
    monkeypatch.setattr(freeturn, "fetch_release_digest", lambda tag, timeout=None: "")
    assert freeturn.release_digest("v4.2.0") == ""
    assert freeturn.CHECKSUMS_CACHE["v4.2.0"][1] == ""
