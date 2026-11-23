from __future__ import annotations

import io
import typing
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from BOT import releases

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "BOT" / "releases.py"


def headers(pairs: dict[str, str]) -> Message:
    message = Message()
    for key, value in pairs.items():
        message[key] = value
    return message


class Answer:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "Answer":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self, _limit: int = 0) -> bytes:
        return self.body


def http_error(code: int, pairs: dict[str, str] | None = None) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.github.com/x", code, "boom", headers(pairs or {}), io.BytesIO(b""))


@pytest.fixture(autouse=True)
def clean_cache() -> None:
    releases.clear()


def test_only_a_semantic_tag_is_accepted() -> None:
    assert releases.tag_of(b'{"tag_name": "v4.1.2"}') == "v4.1.2"
    assert releases.tag_of(b'{"tag_name": "4.1.2"}') == ""
    assert releases.tag_of(b'{"tag_name": "latest"}') == ""
    assert releases.tag_of(b'{"tag_name": "v4.1"}') == ""
    assert releases.tag_of(b"{}") == ""
    assert releases.tag_of(b"not json") == ""
    assert releases.tag_of(b'["v1.0.0"]') == ""


def test_a_rate_limited_answer_is_recognised(monkeypatch: pytest.MonkeyPatch) -> None:
    assert releases.rate_limited(http_error(403, {"X-RateLimit-Remaining": "0"})) is True
    assert releases.rate_limited(http_error(403, {"X-RateLimit-Remaining": "5"})) is False
    assert releases.rate_limited(http_error(429)) is True
    assert releases.rate_limited(http_error(403, {"Retry-After": "60"})) is True
    assert releases.rate_limited(urllib.error.URLError("no route")) is False


def test_a_rate_limited_reply_becomes_an_empty_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(_request: object, timeout: float = 0) -> Answer:
        raise http_error(403, {"X-RateLimit-Remaining": "0"})

    monkeypatch.setattr(releases.urllib.request, "urlopen", explode)
    assert releases.fetch("i-execute/OBHOD") == ("", "rate_limited")
    assert releases.latest_tag("i-execute/OBHOD")[0] == ""


def test_an_unreachable_api_is_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(_request: object, timeout: float = 0) -> Answer:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(releases.urllib.request, "urlopen", explode)
    assert releases.fetch("i-execute/OBHOD") == ("", "unreachable")


def test_a_broken_body_is_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases.urllib.request, "urlopen", lambda request, timeout=0: Answer(b"not json"))
    assert releases.fetch("i-execute/OBHOD") == ("", "no_tag")
    monkeypatch.setattr(releases.urllib.request, "urlopen", lambda request, timeout=0: Answer(b'{"tag_name": "v5.0.0"}'))
    assert releases.fetch("i-execute/OBHOD") == ("v5.0.0", "")


def test_a_successful_answer_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def answer(request: object, timeout: float = 0) -> Answer:
        calls.append(1)
        return Answer(b'{"tag_name": "v4.1.2"}')

    monkeypatch.setattr(releases.urllib.request, "urlopen", answer)
    assert releases.latest_tag("free-turn-proxy") == ("v4.1.2", "")
    assert releases.latest_tag("free-turn-proxy") == ("v4.1.2", "")
    assert len(calls) == 1
    releases.clear()
    assert releases.latest_tag("free-turn-proxy") == ("v4.1.2", "")
    assert len(calls) == 2


def test_a_failure_is_cached_for_a_shorter_time(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def answer(request: object, timeout: float = 0) -> Answer:
        calls.append(1)
        raise http_error(403, {"X-RateLimit-Remaining": "0"})

    monkeypatch.setattr(releases.urllib.request, "urlopen", answer)
    assert releases.latest_tag("free-turn-proxy") == ("", "rate_limited")
    assert releases.latest_tag("free-turn-proxy") == ("", "rate_limited")
    assert len(calls) == 1
    assert releases.FAIL_TTL < releases.OK_TTL


def test_the_fallback_is_used_when_the_api_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(releases.urllib.request, "urlopen", lambda request, timeout=0: Answer(b'{"tag_name": "v4.1.2"}'))
    assert releases.resolve("free-turn-proxy", "v4.1.2", {"v4.1.2": "b"}) == ("v4.1.2", "api")
    releases.clear()
    monkeypatch.setattr(releases.urllib.request, "urlopen", lambda request, timeout=0: Answer(b'{"tag_name": "v4.2.0"}'))
    assert releases.resolve("free-turn-proxy", "v4.1.2", {"v4.1.2": "b"}) == ("v4.1.2", "not_pinned")
    releases.clear()

    def explode(_request: object, timeout: float = 0) -> Answer:
        raise http_error(403, {"X-RateLimit-Remaining": "0"})

    monkeypatch.setattr(releases.urllib.request, "urlopen", explode)
    assert releases.resolve("free-turn-proxy", "v4.1.2", {"v4.1.2": "b"}) == ("v4.1.2", "fallback")


def test_the_lookup_never_carries_a_credential() -> None:
    body = SOURCE.read_text(encoding="utf-8")
    assert "https://api.github.com/repos/%s/releases/latest" in body
    for token in ("Authorization", "GITHUB_TOKEN", "Bearer", "token "):
        assert token not in body
    assert "print(" not in body


def test_a_tag_without_the_v_prefix_is_accepted_for_the_update_page() -> None:
    assert releases.any_tag_of(b'{"tag_name": "1.0.0"}') == "1.0.0"
    assert releases.any_tag_of(b'{"tag_name": "v1.0.0"}') == "v1.0.0"
    assert releases.any_tag_of(b'{"tag_name": "main"}') == ""
    assert releases.any_tag_of(b'{"tag_name": "1.0"}') == ""
    assert releases.tag_of(b'{"tag_name": "1.0.0"}') == ""


def test_conditional_etag_reuses_body_on_304_and_shares_raw_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    import gzip as gzip_mod

    seen_if_none_match: list[str] = []
    calls = 0

    class RichAnswer:
        def __init__(self, body: bytes, hdrs: dict[str, str]) -> None:
            self.body = body
            self.headers = headers(hdrs)

        def __enter__(self) -> "RichAnswer":
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def read(self, _limit: int = 0) -> bytes:
            return self.body

        def geturl(self) -> str:
            return "https://api.github.com/repos/i-execute/OBHOD/releases/latest"

    def responder(request: "typing.Any", timeout: float = 0) -> RichAnswer:
        nonlocal calls
        calls += 1
        inm = request.get_header("If-none-match") or ""
        seen_if_none_match.append(inm)
        if inm == '"etag-1"':
            raise http_error(304, {"ETag": '"etag-1"'})
        compressed = gzip_mod.compress(b'{"tag_name": "v2.3.4"}')
        return RichAnswer(compressed, {"ETag": '"etag-1"', "Content-Encoding": "gzip"})

    monkeypatch.setattr(releases.urllib.request, "urlopen", responder)
    assert releases.latest_tag("i-execute/OBHOD") == ("v2.3.4", "")
    assert releases.latest_tag_any("i-execute/OBHOD") == ("v2.3.4", "")
    assert calls == 1
    key = "i-execute/OBHOD"
    releases.CACHE[key] = (0.0, "v2.3.4", "")
    releases.RAW_CACHE[key] = (0.0, '"etag-1"', b'{"tag_name": "v2.3.4"}', "")
    assert releases.latest_tag("i-execute/OBHOD") == ("v2.3.4", "")
    assert calls == 2
    assert seen_if_none_match[-1] == '"etag-1"'

