from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API_ROOT = "https://cloud.telegram.org"
DOMAIN_SUFFIX = ".tgcloud.ai"
TOKEN_RE = re.compile(r"^(app([0-9]{5,20}):([A-Za-z0-9_-]{20,256}))$")
SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{64}$")
MANAGED_PATH = "base64/base64.txt"
MAX_BLOB = 8 * 1024 * 1024


class ServerlessError(Exception):
    def __init__(self, message: str, status: int = 0, error_type: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.status = int(status or 0)
        self.error_type = str(error_type or "")


def token_parts(token: object) -> tuple[str, str]:
    value = str(token or "").strip()
    match = TOKEN_RE.fullmatch(value)
    if not match:
        raise ServerlessError("paste a Telegram Serverless CLI access token")
    return match.group(2), value


def app_domain(app_id: object) -> str:
    ident = str(app_id or "").strip()
    if not re.fullmatch(r"[0-9]{5,20}", ident):
        raise ServerlessError("the Telegram app id is invalid")
    return "https://app%s%s" % (ident, DOMAIN_SUFFIX)


def subscription_path(sub_id: object, sub_key: object) -> str:
    ident = str(sub_id or "")
    key = str(sub_key or "")
    if not SEGMENT_RE.fullmatch(ident) or not SEGMENT_RE.fullmatch(key):
        raise ServerlessError("the subscription path is invalid")
    return MANAGED_PATH


def subscription_url(app_id: object, sub_id: object, sub_key: object) -> str:
    subscription_path(sub_id, sub_key)
    return app_domain(app_id) + "/base64/base64"


def subscription_file(links: Any) -> bytes:
    import base64

    items = []
    for item in links or []:
        value = str(item or "").strip()
        if value.startswith("vless://") and "\n" not in value and "\r" not in value:
            if value not in items:
                items.append(value)
    if not items:
        return b""
    raw = ("\n".join(items) + "\n").encode("utf-8")
    return (base64.b64encode(raw).decode("ascii") + "\n").encode("ascii")


def _json_body(body: Any) -> bytes:
    return json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def _read_envelope(response: Any, status: int | None = None) -> dict[str, Any]:
    try:
        payload = json.loads(response.read().decode("utf-8", "replace"))
    except Exception as exc:
        raise ServerlessError("Telegram Serverless returned invalid JSON", status or 0) from exc
    if not isinstance(payload, dict) or "ok" not in payload:
        raise ServerlessError("Telegram Serverless returned an invalid response", status or 0)
    if not payload.get("ok"):
        message = str(payload.get("description") or payload.get("error") or "Telegram Serverless request failed")[:300]
        kind = str(payload.get("error_type") or "")[:64]
        code = payload.get("error_code")
        raise ServerlessError(message, int(code or status or 0), kind)
    result = payload.get("result")
    return result if isinstance(result, dict) else {}


def request(token: str, method: str, path: str, body: Any = None, raw: bytes | None = None, opener: Any = None, timeout: float = 20.0) -> dict[str, Any]:
    app_id, clean_token = token_parts(token)
    if not path.startswith("/") or ".." in path or "\\" in path:
        raise ServerlessError("the Telegram Serverless API path is invalid")
    url = "%s/app%s/manage%s" % (API_ROOT, app_id, path)
    headers = {"Authorization": "Bearer " + clean_token}
    data = raw
    if raw is not None:
        headers["Content-Type"] = "application/octet-stream"
        headers["Content-Length"] = str(len(raw))
    elif body is not None:
        headers["Content-Type"] = "application/json"
        data = _json_body(body)
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    call = opener or urllib.request.urlopen
    try:
        response = call(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        try:
            _read_envelope(exc, exc.code)
        except ServerlessError as parsed:
            raise parsed from None
        raise ServerlessError("Telegram Serverless returned HTTP %d" % exc.code, exc.code) from None
    except Exception as exc:
        raise ServerlessError("Telegram Serverless is unreachable: %s" % type(exc).__name__) from None
    with response:
        return _read_envelope(response, getattr(response, "status", 200))


def check_app(app_id: object, opener: Any = None, timeout: float = 5.0) -> dict[str, Any]:
    ident = str(app_id or "").strip()
    if not re.fullmatch(r"[0-9]{5,20}", ident):
        return {"status": "unknown", "http_status": 0, "error_type": ""}
    url = "%s/app%s/webhook" % (API_ROOT, ident)
    request_obj = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
    call = opener or urllib.request.urlopen
    try:
        response = call(request_obj, timeout=timeout)
        with response:
            status = int(getattr(response, "status", 200))
            raw = response.read(4096)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read(4096)
    except Exception:
        return {"status": "unknown", "http_status": 0, "error_type": ""}
    kind = ""
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
        if isinstance(payload, dict):
            kind = str(payload.get("error_type") or "")
    except Exception:
        pass
    if kind == "INTERNAL_ERROR" or (not kind and status == 401):
        verdict = "serverless"
    elif kind == "APP_NOT_FOUND" or (not kind and status == 404):
        verdict = "missing"
    else:
        verdict = "unknown"
    return {"status": verdict, "http_status": status, "error_type": kind}


def verify_token(token: str, opener: Any = None) -> dict[str, Any]:
    app_id, clean = token_parts(token)
    result = request(clean, "GET", "/get", opener=opener)
    return {"app_id": app_id, "revision": int(result.get("revision", 0) or 0), "static": result.get("static") if isinstance(result.get("static"), dict) else None}


def _static_config(static: dict[str, Any] | None) -> dict[str, Any]:
    raw = static.get("config") if isinstance(static, dict) else None
    config = dict(raw) if isinstance(raw, dict) else {"spa": False, "headers": [], "immutable": [], "redirects": []}
    headers = [dict(item) for item in config.get("headers", []) if isinstance(item, dict) and isinstance(item.get("set"), dict)]
    rule = {
        "path": "/base64/base64.txt",
        "set": {"Cache-Control": "no-store", "Content-Disposition": "attachment; filename=subscription.txt"},
    }
    headers = [item for item in headers if item.get("path") != rule["path"]]
    headers.append(rule)
    config["headers"] = headers
    redirects = [dict(item) for item in config.get("redirects", []) if isinstance(item, dict)]
    route = {"from": "/base64/base64", "to": "/base64/base64.txt", "status": 302}
    redirects = [item for item in redirects if item.get("from") != route["from"]]
    redirects.append(route)
    config["redirects"] = redirects
    config.setdefault("immutable", [])
    config.setdefault("spa", False)
    return config


def publish_static(token: str, files: dict[str, bytes], opener: Any = None) -> dict[str, Any]:
    app_id, clean = token_parts(token)
    remote = request(clean, "GET", "/get", opener=opener)
    old_static = remote.get("static") if isinstance(remote.get("static"), dict) else {}
    old_manifest = old_static.get("manifest") if isinstance(old_static.get("manifest"), dict) else {}
    manifest = {
        path: dict(item)
        for path, item in old_manifest.items()
        if isinstance(path, str) and path != MANAGED_PATH and isinstance(item, dict)
    }
    normalized: dict[str, bytes] = {}
    for raw_path, raw_bytes in files.items():
        path = str(raw_path or "")
        if path != MANAGED_PATH:
            raise ServerlessError("a subscription file path is outside the managed file")
        content = bytes(raw_bytes)
        if len(content) > MAX_BLOB:
            raise ServerlessError("a subscription file exceeds the static file limit")
        normalized[path] = content
        manifest[path] = {"hash": hashlib.sha256(content).hexdigest(), "size": len(content)}
    total = sum(len(value) for value in normalized.values())
    if total > 16 * MAX_BLOB:
        raise ServerlessError("the subscription bundle is too large")
    config = _static_config(old_static)
    prepared = request(clean, "POST", "/static/prepare", {"manifest": manifest, "config": config}, opener=opener)
    missing = prepared.get("missing") if isinstance(prepared.get("missing"), list) else []
    by_hash: dict[str, bytes] = {}
    for content in normalized.values():
        by_hash[hashlib.sha256(content).hexdigest()] = content
    for digest in missing:
        content = by_hash.get(str(digest))
        if content is None:
            continue
        bundle = str(prepared.get("hash") or "")
        if not re.fullmatch(r"[A-Fa-f0-9]{32,128}", bundle):
            raise ServerlessError("Telegram Serverless did not return a valid static bundle id")
        request(clean, "PUT", "/static/blob/%s?bundle=%s" % (digest, urllib.parse.quote(bundle, safe="")), raw=content, opener=opener)
    bundle = str(prepared.get("hash") or "")
    if not re.fullmatch(r"[A-Fa-f0-9]{32,128}", bundle):
        raise ServerlessError("Telegram Serverless did not return a valid static bundle id")
    revision = remote.get("revision")
    deploy_body: dict[str, Any] = {"static": {"hash": bundle}}
    if revision is not None:
        deploy_body["expected_revision"] = revision
    deployed = request(clean, "POST", "/deploy", deploy_body, opener=opener)
    return {
        "app_id": app_id,
        "revision": int(deployed.get("revision", 0) or 0),
        "url": app_domain(app_id),
        "file_count": len(normalized),
        "manifest_count": len(manifest),
    }
