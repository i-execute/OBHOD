from __future__ import annotations

import base64
import json
import hashlib
from urllib.request import Request

import pytest

from BOT import serverless


APP_TOKEN = "app" + "123456" + ":" + "A" * 32
SEGMENT = "A" * 64


class Response:
    def __init__(self, data: dict, status: int = 200) -> None:
        self.status = status
        self.data = json.dumps({"ok": True, "result": data}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int = -1) -> bytes:
        return self.data


def test_token_domain_and_private_subscription_path() -> None:
    assert serverless.token_parts(APP_TOKEN)[0] == "123456"
    assert serverless.app_domain("123456") == "https://app123456.tgcloud.ai"
    assert serverless.subscription_path(SEGMENT, SEGMENT) == "base64/base64.txt"
    assert serverless.subscription_url("123456", SEGMENT, SEGMENT) == "https://app123456.tgcloud.ai/base64/base64"
    with pytest.raises(serverless.ServerlessError):
        serverless.token_parts("not-a-token")
    with pytest.raises(serverless.ServerlessError):
        serverless.subscription_path("../x", SEGMENT)


def test_subscription_file_is_one_standard_base64_layer() -> None:
    lines = [
        "vless://00000000-0000-4000-8000-000000000001@example.invalid:443?encryption=none#one",
        "vless://00000000-0000-4000-8000-000000000002@example.invalid:8443?encryption=none#two",
    ]
    output = serverless.subscription_file(lines)
    decoded = base64.b64decode(output.strip(), validate=True).decode()
    assert decoded.splitlines() == lines
    assert serverless.subscription_file([]) == b""


def test_checker_uses_serverless_webhook_status_signature() -> None:
    def enabled(_request: Request, timeout: float):
        assert timeout == 5.0
        return Response({}, 401)

    def missing(_request: Request, timeout: float):
        response = Response({}, 404)
        response.data = b'{"error_type":"APP_NOT_FOUND"}'
        return response

    assert serverless.check_app("123456", opener=enabled)["status"] == "serverless"
    assert serverless.check_app("123456", opener=missing)["status"] == "missing"
    assert serverless.check_app("bad")["status"] == "unknown"


def test_static_publish_preserves_other_files_and_only_deploys_static() -> None:
    content = serverless.subscription_file(["vless://fake@example.invalid:443?encryption=none#test"])
    path = serverless.subscription_path(SEGMENT, SEGMENT)
    blob_hash = hashlib.sha256(content).hexdigest()
    calls = []

    def opener(request: Request, timeout: float):
        calls.append(request)
        method = request.get_method()
        url = request.full_url
        if method == "GET" and url.endswith("/manage/get"):
            return Response({
                "revision": 7,
                "canonical_modules": {"handlers/message.js": "keep"},
                "static": {
                    "manifest": {"index.html": {"hash": "b" * 64, "size": 4}},
                    "config": {"spa": True, "headers": [], "redirects": []},
                },
            })
        if method == "POST" and url.endswith("/manage/static/prepare"):
            body = json.loads(request.data.decode())
            assert body["manifest"]["index.html"]["hash"] == "b" * 64
            assert body["manifest"][path] == {"hash": blob_hash, "size": len(content)}
            assert body["config"]["headers"][-1]["path"] == "/base64/base64.txt"
            assert body["config"]["redirects"] == [{"from": "/base64/base64", "to": "/base64/base64.txt", "status": 302}]
            return Response({"hash": "c" * 64, "missing": [blob_hash]})
        if method == "PUT" and "/manage/static/blob/" in url:
            assert request.data == content
            return Response({})
        if method == "POST" and url.endswith("/manage/deploy"):
            body = json.loads(request.data.decode())
            assert body == {"expected_revision": 7, "static": {"hash": "c" * 64}}
            return Response({"revision": 8})
        pytest.fail("unexpected cloud request: %s %s" % (method, url))

    result = serverless.publish_static(APP_TOKEN, {path: content}, opener=opener)
    assert result["revision"] == 8
    assert result["file_count"] == 1
    assert calls[0].full_url == "https://cloud.telegram.org/app123456/manage/get"
    assert [call.get_method() for call in calls] == ["GET", "POST", "PUT", "POST"]
