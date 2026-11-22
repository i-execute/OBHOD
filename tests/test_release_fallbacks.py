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


def test_the_recommended_pins_are_separate_from_xray_minimum() -> None:
    from BOT import dpi, xray

    xr_agent = load(XRAY_AGENT, "xray_recommended")
    ft_agent = load(TURN_AGENT, "freeturn_recommended")
    assert xray.RECOMMENDED_VERSION == xrayrpc.DEFAULT_VERSION == xr_agent.RECOMMENDED_VERSION
    assert dpi.MIN_CORE_TAG == xr_agent.MIN_CORE_TAG
    assert xr_agent.core_numbers(xr_agent.RECOMMENDED_VERSION) >= xr_agent.MIN_CORE
    assert freeturn.RECOMMENDED_VERSION == ft_agent.RECOMMENDED_VERSION == freeturn.FALLBACK_VERSION


def test_a_live_xray_release_takes_priority_over_the_recommended_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load(XRAY_AGENT, "xray_live_release")
    monkeypatch.setattr(module, "latest_tag", lambda timeout=15, use_cache=True: "v26.12.1")
    monkeypatch.setattr(module, "install_core", lambda version, url, sha256, force: {"version": version})
    data = module.pinned_with_fallback("latest", "", "", False)
    assert data["version"] == "v26.12.1"
    assert data["fallback"] is False


def test_xray_official_pinned_release_uses_its_embedded_digest_first(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load(XRAY_AGENT, "xray_pin_priority")
    monkeypatch.setattr(module, "machine", lambda: "x86_64")
    monkeypatch.setattr(module, "core_version", lambda: "")
    def unexpected_fetch(*args: object) -> str:
        pytest.fail("the pinned digest must not depend on a remote checksum")
    monkeypatch.setattr(module, "fetch_digest", unexpected_fetch)
    monkeypatch.setattr(module, "download", lambda url, target: Path(target).write_bytes(b"wrong archive"))
    with pytest.raises(module.ScriptError) as caught:
        module.install_core(module.RECOMMENDED_VERSION, "", "", True)
    assert caught.value.code == "digest_mismatch"


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
            return b'{"tag_name": "v26.10.31"}'

    def answer(request: object, timeout: float = 0) -> Answer:
        calls.append(1)
        return Answer()

    monkeypatch.setattr(module, "open_url", answer)
    assert module.latest_tag() == "v26.10.31"
    assert module.latest_tag() == "v26.10.31"
    assert len(calls) == 1
    assert module.API_REASON == ""


def test_the_new_freeturn_version_is_the_hardcoded_fallback() -> None:
    assert freeturn.MIN_VERSION == "v4.1.2"
    assert freeturn.FALLBACK_VERSION == "v4.2.1"
    assert freeturn.DEFAULT_VERSION == freeturn.FALLBACK_VERSION
    assert freeturn.PINNED_SCRIPT_SHA256[freeturn.FALLBACK_VERSION] == "e17725c29237d344c1607d1391c91d977521834508640dc158f9b21c06414916"
    assert freeturn.script_url(freeturn.FALLBACK_VERSION).endswith("/v4.2.1/install.sh")


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
            "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.2.1/"
        )


def test_the_pin_points_at_the_published_release() -> None:
    module = load(TURN_AGENT, "freeturn_agent_published")
    assert module.SCRIPT_REPO == "hackdiaz-dev/free-turn-proxy"
    assert module.MIN_VERSION == freeturn.MIN_VERSION == "v4.1.2"
    assert module.FALLBACK_VERSION == freeturn.FALLBACK_VERSION == "v4.2.1"
    assert module.script_url(module.FALLBACK_VERSION).endswith("/v4.2.1/install.sh")
    assert module.SCRIPT_SHA256 == freeturn.PINNED_SCRIPT_SHA256
    assert module.resolve_version("latest", lookup=lambda repo: ("v4.2.1", "")) == ("v4.2.1", "api")


def test_exactly_one_xray_version_is_kept_as_the_fallback() -> None:
    from BOT import xray

    module = load(XRAY_AGENT, "xray_agent_single_pin")
    assert xray.XRAY_VERSION == module.MIN_CORE_TAG == "v26.10.31"
    assert xray.RECOMMENDED_VERSION == xrayrpc.DEFAULT_VERSION == module.PINNED == "v26.11.9"
    assert xray.VERSION_CHOICES == (xray.XRAY_VERSION, "latest")
    assert xray.XrayState().install_version() == "latest"
    assert xray.XrayState().pinned() == "v26.10.31"
    state = xray.XrayState()
    state.version = "v26.10.31"
    assert state.install_version() == "v26.10.31"
    state.version = "v0.0.1"
    assert state.install_version() == "latest"


def test_the_xray_pins_are_the_published_release_digests() -> None:
    module = load(XRAY_AGENT, "xray_agent_release_digests")
    published = {
        "64": "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82",
        "arm64-v8a": "64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be",
        "arm32-v7a": "19c51e08a6562705fb1cb032a84fd87df21d7e27b194f035be7e754dbe3a97b3",
        "arm32-v6": "955be2b84854ba566b2afc6c20186967e5a0ce7b2078e0f4e9a99e3aac662f38",
        "32": "225343a01db48e23c1d3091e7fa45971b0d12c20943927846a4a87da374e384d",
        "s390x": "5657912fbd7429d8a0202dccd8815a297fe49d009216a5359af238ebb6f0db4c",
        "riscv64": "296884b8601ee95dba31e6664c6121d80e33697382a1f564f05b028e61601a84",
    }
    assert module.DIGESTS == published
    assert xrayrpc.PINNED_SHA256 == published
    assert len(published) == 7


def test_exactly_one_freeturn_version_is_kept_as_the_fallback() -> None:
    module = load(TURN_AGENT, "freeturn_agent_single_pin")
    assert set(freeturn.PINNED_SCRIPT_SHA256) == {freeturn.MIN_VERSION, freeturn.FALLBACK_VERSION}
    assert module.SCRIPT_SHA256 == freeturn.PINNED_SCRIPT_SHA256
    assert freeturn.MIN_VERSION == module.MIN_VERSION == "v4.1.2"
    assert freeturn.FALLBACK_VERSION == module.FALLBACK_VERSION == "v4.2.1"
    assert freeturn.VERSION_CHOICES == ("latest", freeturn.MIN_VERSION)


def test_a_newer_freeturn_release_installs_with_its_published_digest() -> None:
    published = "d" * 64
    assert freeturn.resolve_version("latest", lambda repo: ("v4.2.0", ""), lambda tag: published) == ("v4.2.0", "api")
    with pytest.raises(freeturn.FtError, match="no published"):
        freeturn.resolve_version("latest", lambda repo: ("v4.2.0", ""), lambda tag: "")
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
    assert freeturn.checksums_url("v4.1.2") == (
        "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.2/checksums.txt"
    )
    assert freeturn.allowed_checksums_url(freeturn.checksums_url("v4.1.2")) is True
    assert freeturn.allowed_checksums_url("https://example.com/checksums.txt") is False
    assert freeturn.allowed_checksums_url("http://github.com/checksums.txt") is False
    module = load(TURN_AGENT, "freeturn_agent_checksum_hosts")
    assert module.allowed_url(freeturn.checksums_url("v4.1.2")) is True
    freeturn.CHECKSUMS_CACHE.clear()
    monkeypatch.setattr(freeturn, "fetch_release_digest", lambda tag, timeout=None: "")
    assert freeturn.release_digest("v4.2.0") == ""
    assert freeturn.CHECKSUMS_CACHE["v4.2.0"][1] == ""


@pytest.mark.parametrize("status", [403, 429])
def test_real_api_rate_limit_uses_recommended_versions_without_tokens(status: int, monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT import releases

    headers = Message()
    headers["X-RateLimit-Remaining"] = "0"
    seen = []

    def limited(request: object, timeout: float = 0) -> None:
        seen.append(request)
        raise urllib.error.HTTPError("https://api.github.com/releases/latest", status, "limited", headers, io.BytesIO(b""))

    releases.clear()
    monkeypatch.setattr(releases.urllib.request, "urlopen", limited)
    assert freeturn.resolve_version("latest") == (freeturn.FALLBACK_VERSION, "fallback")
    ft_agent = load(TURN_AGENT, "freeturn_rate_limit_full")
    ft_agent.API_CACHE.clear()
    assert ft_agent.resolve_version("latest") == (ft_agent.FALLBACK_VERSION, "fallback")
    xr_agent = load(XRAY_AGENT, "xray_rate_limit_full")
    monkeypatch.setattr(xr_agent, "open_url", limited)
    monkeypatch.setattr(xr_agent, "install_core", lambda version, url, sha256, force: {"version": version})
    data = xr_agent.pinned_with_fallback("latest", "", "", False)
    assert data["version"] == xr_agent.PINNED
    assert data["fallback"] is True and data["fallback_version"] == xr_agent.PINNED
    assert seen
    for request in seen:
        assert request.get_header("Authorization") is None
    releases.clear()


def test_latest_releases_must_respect_minimum_even_with_valid_digest() -> None:
    from BOT import dpi

    agent = load(TURN_AGENT, "freeturn_below_min")
    for lookup in (lambda repo: ("v4.1.1", ""),):
        with pytest.raises(freeturn.FtError):
            freeturn.resolve_version("latest", lookup, lambda tag: "a" * 64)
        with pytest.raises(agent.AgentError):
            agent.resolve_version("latest", lookup, lambda tag: "a" * 64)
    assert freeturn.MIN_VERSION == agent.MIN_VERSION == "v4.1.2"
    assert dpi.MIN_CORE_TAG == "v26.10.31"


def test_large_github_release_payload_is_read_completely(monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT import releases

    xr = load(XRAY_AGENT, "xray_large_api")
    body = b'{"tag_name":"v26.12.1","body":"' + b'x' * 100000 + b'"}'

    class Answer:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return None
        def read(self, limit):
            return body[:limit]
        def geturl(self):
            return "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        headers = {}

    monkeypatch.setattr(xr, "open_url", lambda request, timeout: Answer())
    assert xr.latest_tag(use_cache=False) == "v26.12.1"
    monkeypatch.setattr(releases.urllib.request, "urlopen", lambda request, timeout: Answer())
    releases.clear()
    assert releases.latest_tag("XTLS/Xray-core", use_cache=False) == ("v26.12.1", "")
    releases.clear()


def test_no_fallback_when_latest_xray_asset_download_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    xr = load(XRAY_AGENT, "xray_no_download_fallback")
    calls = []
    monkeypatch.setattr(xr, "latest_tag", lambda timeout=15, use_cache=True: "v26.12.1")
    def fail(version, url, sha256, force):
        calls.append(version)
        raise xr.ScriptError("download_failed", "asset unavailable")
    monkeypatch.setattr(xr, "install_core", fail)
    with pytest.raises(xr.ScriptError, match="asset unavailable"):
        xr.pinned_with_fallback("latest", "", "", False)
    assert calls == ["v26.12.1"]



def test_release_tags_have_bounded_numeric_components(monkeypatch: pytest.MonkeyPatch) -> None:
    from BOT import releases

    oversized = "v" + "9" * 7000 + ".1.1"
    assert releases.tag_of(("{\"tag_name\":\"" + oversized + "\"}").encode("ascii")) == ""
    with pytest.raises(freeturn.FtError):
        freeturn.resolve_version(oversized)
    ft_agent = load(TURN_AGENT, "freeturn_oversized_tag")
    with pytest.raises(ft_agent.AgentError):
        ft_agent.resolve_version(oversized)
    xr = load(XRAY_AGENT, "xray_oversized_tag")
    with pytest.raises(xr.ScriptError):
        xr.install_core(oversized, "", "", False)

    class Answer:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return None
        def read(self, _limit):
            return ("{\"tag_name\":\"" + oversized + "\"}").encode("ascii")

    xr.API_CACHE.clear()
    monkeypatch.setattr(xr, "open_url", lambda request, timeout: Answer())
    assert xr.latest_tag(use_cache=False) == ""
    assert xr.API_REASON == "no_tag"
