from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

PROTO = 3
SCRIPT_REPO = "hackdiaz-dev/free-turn-proxy"
SCRIPT_URL = "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/%s/install.sh"
FALLBACK_VERSION = "v4.1.1"
SCRIPT_SHA256 = {
    "v4.1.1": "91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100",
}
API_URL = "https://api.github.com/repos/%s/releases/latest"
API_TIMEOUT = 8
API_TTL = 600
API_FAIL_TTL = 300
PIN_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
API_CACHE = {}
DEFAULT_URL = SCRIPT_URL % FALLBACK_VERSION
DEFAULT_SHA256 = SCRIPT_SHA256[FALLBACK_VERSION]
CACHE_DIR = "/var/lib/obhod/freeturn"
MAX_SCRIPT_BYTES = 512 * 1024
FETCH_TIMEOUT = 120
ALLOWED_HOSTS = ("github.com", "objects.githubusercontent.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com")
COMMANDS = (
    "probe",
    "apply",
    "stop",
    "restart",
    "logs",
    "client-list",
    "client-add",
    "client-conf",
    "client-remove",
    "uninstall",
)
FLAGS = frozenset({"purge", "update", "yes", "reconfigure", "uninstall"})
TIMEOUTS = {
    "probe": 120,
    "apply": 900,
    "stop": 180,
    "restart": 240,
    "logs": 120,
    "client-list": 120,
    "client-add": 180,
    "client-conf": 120,
    "client-remove": 180,
    "uninstall": 300,
}


class AgentError(Exception):
    def __init__(self, code, message, stage="", logs=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.stage = stage
        self.logs = list(logs or [])


def emit(result, data=None, code="", msg="", stage="", logs=None):
    body = {"proto": PROTO, "result": result, "data": data or {}, "logs": list(logs or [])}
    if result != "ok":
        body["code"] = code or "internal"
        body["msg"] = msg or "internal error"
        body["stage"] = stage or ""
    sys.stdout.write(json.dumps(body, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def parse_argv(argv):
    if not argv:
        raise AgentError("bad_arg", "the command is required", "init")
    command = str(argv[0]).strip()
    if command not in COMMANDS:
        raise AgentError("bad_arg", "unknown command %s" % command[:32], "init")
    flags = {}
    for raw in argv[1:]:
        token = str(raw)
        if not token.startswith("--"):
            raise AgentError("bad_arg", "flags must start with two dashes", "init")
        token = token[2:]
        if "=" in token:
            key, value = token.split("=", 1)
        else:
            key, value = token, "1"
        key = key.strip().lower().replace("-", "_")
        if not key:
            raise AgentError("bad_arg", "empty flag name", "init")
        flags[key] = value
    return command, flags


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def digest_of_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(131072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def script_url(version):
    return SCRIPT_URL % version


def api_tag(repo=SCRIPT_REPO, timeout=API_TIMEOUT):
    cached = API_CACHE.get(repo)
    now = time.monotonic()
    if cached and cached[0] > now:
        return cached[1], cached[2]
    request = urllib.request.Request(
        API_URL % repo,
        headers={"User-Agent": "obhod-freeturn/3", "Accept": "application/vnd.github+json"},
    )
    tag = ""
    reason = "unreachable"
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(65536).decode("utf-8"))
        candidate = str(payload.get("tag_name", "") or "").strip()
        if candidate and PIN_RE.match(candidate):
            tag = candidate
            reason = ""
        else:
            reason = "no_tag"
    except urllib.error.HTTPError as exc:
        reason = "rate_limited" if rate_limited(exc) else "http_%d" % int(getattr(exc, "code", 0) or 0)
    except (OSError, ValueError):
        reason = "unreachable"
    API_CACHE[repo] = (now + (API_TTL if tag else API_FAIL_TTL), tag, reason)
    return tag, reason


def rate_limited(exc):
    code = int(getattr(exc, "code", 0) or 0)
    headers = getattr(exc, "headers", None)
    if code == 429:
        return True
    if headers is None:
        return False
    retry = str(headers.get("Retry-After", "") or "").strip()
    if retry.isdigit():
        return True
    return code == 403 and str(headers.get("X-RateLimit-Remaining", "") or "").strip() == "0"


def resolve_version(requested, lookup=None):
    text = str(requested or "").strip().lower()
    if text == "local":
        return FALLBACK_VERSION, "local"
    if text in {"", "default"}:
        return FALLBACK_VERSION, "default"
    if text not in {"latest", "auto"}:
        tag = text if text.startswith("v") else "v" + text
        if not PIN_RE.match(tag):
            raise AgentError("bad_arg", "the version must be latest or vX.Y.Z", "init")
        if tag not in SCRIPT_SHA256:
            raise AgentError("not_pinned", "the install script of %s is not pinned yet" % tag, "fetch")
        return tag, "pinned"
    found, reason = (lookup or api_tag)(SCRIPT_REPO)
    if found and found in SCRIPT_SHA256:
        return found, "api"
    return FALLBACK_VERSION, "fallback"


def allowed_url(url):
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme != "https":
        return False
    host = (parts.hostname or "").lower()
    return host in ALLOWED_HOSTS


def cache_path(digest):
    return os.path.join(CACHE_DIR, "install-%s.sh" % digest[:16])


def read_cache(digest):
    path = cache_path(digest)
    if not os.path.isfile(path):
        return ""
    try:
        if digest_of_file(path) != digest:
            os.unlink(path)
            return ""
    except OSError:
        return ""
    return path


def write_cache(digest, body):
    try:
        os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
        os.chmod(CACHE_DIR, 0o700)
    except OSError as exc:
        raise AgentError("internal", "the script cache directory is not usable: %s" % exc, "fetch")
    handle, temp = tempfile.mkstemp(dir=CACHE_DIR, prefix=".install-", suffix=".sh")
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, cache_path(digest))
    except OSError as exc:
        if os.path.exists(temp):
            os.unlink(temp)
        raise AgentError("internal", "the script cache file could not be written: %s" % exc, "fetch")
    return cache_path(digest)


def download(url, expected):
    if not allowed_url(url):
        raise AgentError("bad_arg", "the script address must be https on github", "fetch")
    request = urllib.request.Request(url, headers={"User-Agent": "obhod-freeturn/3"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
            final = response.geturl()
            if not allowed_url(final):
                raise AgentError("bad_arg", "the download ended outside github", "fetch")
            body = response.read(MAX_SCRIPT_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise AgentError("download_failed", "the install script answered %s" % exc.code, "fetch")
    except urllib.error.URLError as exc:
        raise AgentError("download_failed", "the install script is not reachable: %s" % exc.reason, "fetch")
    except (OSError, ValueError) as exc:
        raise AgentError("download_failed", "the install script download failed: %s" % exc, "fetch")
    if len(body) > MAX_SCRIPT_BYTES:
        raise AgentError("download_failed", "the install script is larger than allowed", "fetch")
    if not body:
        raise AgentError("download_failed", "the install script is empty", "fetch")
    if b"RPC_COMMANDS" not in body:
        raise AgentError("download_failed", "the file is not the install script", "fetch")
    got = sha256_of(body)
    if expected and got != expected:
        raise AgentError("digest_mismatch", "the install script digest is %s instead of %s" % (got, expected), "fetch")
    return write_cache(got, body)


def script_source(flags, lookup=None):
    tag, _source = resolve_version(flags.get("version", ""), lookup)
    url = str(flags.get("script_url", "") or script_url(tag))
    expected = str(flags.get("script_sha256", "") or SCRIPT_SHA256[tag]).strip().lower()
    if expected and not all(ch in "0123456789abcdef" for ch in expected):
        raise AgentError("bad_arg", "the script digest is not hexadecimal", "fetch")
    if len(expected) not in (0, 64):
        raise AgentError("bad_arg", "the script digest has a wrong length", "fetch")
    cached = read_cache(expected) if expected else ""
    if cached:
        return cached
    return download(url, expected)


def command_argv(command, flags, lookup=None):
    out = [command]
    skip = {"script_url", "script_sha256", "tail", "timeout"}
    order = (
        "method",
        "backend",
        "connect",
        "host",
        "listen_port",
        "wg_port",
        "wg_net",
        "mode",
        "obf_profile",
        "obf_key",
        "version",
        "name",
        "target",
        "web_port",
        "web_ttl",
        "kcp_nodelay",
        "kcp_interval",
        "kcp_resend",
        "kcp_nc",
        "kcp_sndwnd",
        "kcp_rcvwnd",
        "kcp_mtu",
        "kcp_acknodelay",
    )
    tag, _source = resolve_version(flags.get("version", ""), lookup)
    for key in order:
        if key in flags:
            value = str(flags[key])
            if key == "version" and str(value).strip().lower() in {"latest", "auto"}:
                value = tag
            if not value or "\n" in value or "\x00" in value:
                raise AgentError("bad_arg", "flag %s has an unusable value" % key, "init")
            out.append("--%s=%s" % (key.replace("_", "-"), value))
    if command == "logs":
        tail = str(flags.get("tail", "200"))
        if not tail.isdigit() or not 1 <= int(tail) <= 99999:
            raise AgentError("bad_arg", "the tail size must be a number", "init")
        out.append("--tail=%s" % tail)
    for key in sorted(FLAGS):
        if str(flags.get(key, "")) in {"1", "true", "yes", "on"}:
            out.append("--%s" % key.replace("_", "-"))
    unknown = [key for key in flags if key not in skip and key not in order and key not in FLAGS]
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0], "init")
    return out


def run_script(path, argv, timeout):
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "DEBIAN_FRONTEND": "noninteractive",
    }
    try:
        finished = subprocess.run(
            ["bash", path] + argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=env,
            cwd="/",
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise AgentError("start_failed", "the install script did not finish within %d seconds" % timeout, argv[0] if argv else "")
    except OSError as exc:
        raise AgentError("internal", "the install script could not start: %s" % exc, "init")
    return (finished.stdout or b"").decode("utf-8", "replace"), int(finished.returncode or 0)


def last_json(text):
    found = ""
    for line in (text or "").splitlines():
        token = line.strip()
        if token.startswith("{") and token.endswith("}"):
            found = token
    if not found:
        return {}
    try:
        payload = json.loads(found)
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def sanitize(payload):
    if not isinstance(payload, dict):
        return {}
    body = {
        "proto": int(payload.get("proto", 0) or 0),
        "result": str(payload.get("result", "err") or "err"),
        "data": payload.get("data") if isinstance(payload.get("data"), dict) else {},
        "logs": [str(item)[:400] for item in payload.get("logs") or []][-200:],
    }
    if body["result"] != "ok":
        body["code"] = str(payload.get("code", "") or "internal")[:48]
        body["msg"] = str(payload.get("msg", "") or "")[:400]
        body["stage"] = str(payload.get("stage", "") or "")[:48]
    if body["proto"] != PROTO:
        raise AgentError("proto_mismatch", "the install script speaks protocol %s" % body["proto"], "init", body["logs"])
    return body


def main(argv):
    command, flags = parse_argv(argv)
    stage = command.replace("-", "_")
    try:
        script = script_source(flags)
        plan = command_argv(command, flags)
        timeout = TIMEOUTS.get(command, 300)
        text, code = run_script(script, plan, timeout)
        payload = last_json(text)
        if not payload:
            tail = (text or "").strip().splitlines()[-3:]
            raise AgentError("internal", "the install script returned no answer: %s" % " | ".join(item[:160] for item in tail), stage)
        body = sanitize(payload)
        emit(body["result"], body["data"], body.get("code", ""), body.get("msg", ""), body.get("stage", stage), body["logs"])
        return 0 if body["result"] == "ok" else 1
    except AgentError as exc:
        emit("err", {}, exc.code, exc.message, exc.stage or stage, exc.logs)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
