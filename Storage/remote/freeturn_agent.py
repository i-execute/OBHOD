from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
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
FALLBACK_VERSION = "v4.1.2"
SCRIPT_SHA256 = {
    "v4.1.2": "91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100",
}
API_URL = "https://api.github.com/repos/%s/releases/latest"
API_TIMEOUT = 8
API_TTL = 600
API_FAIL_TTL = 300
PIN_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
CHECKSUMS_ASSET = "checksums.txt"
CHECKSUMS_URL = "https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/%s/" + CHECKSUMS_ASSET
CHECKSUMS_MAX = 512 * 1024
CHECKSUMS_TTL = 3600
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKSUMS_CACHE = {}
API_CACHE = {}
DEFAULT_URL = SCRIPT_URL % FALLBACK_VERSION
DEFAULT_SHA256 = SCRIPT_SHA256[FALLBACK_VERSION]
CACHE_DIR = os.path.join(os.environ.get("OBHOD_STATE_DIR") or "/var/lib/obhod", "freeturn")
MAX_SCRIPT_BYTES = 512 * 1024
MAX_SCRIPTS = 64
PROBE_TIMEOUT = 30.0
FETCH_TIMEOUT = 120
ALLOWED_HOSTS = ("github.com", "objects.githubusercontent.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com")
COMMANDS = (
    "fw-guard",
    "wg-peers",
    "scripts-list",
    "scripts-probe",
    "scripts-fetch",
    "net-scan",
    "net-trace",
    "net-ports",
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
GUARD_MODES = ("status", "open", "vk", "closed")
GUARD_PROTOS = ("udp", "tcp", "both")
WG_MAX_PEERS = 8192
WG_IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
WG_FIELDS = 9
WG_CMD_TIMEOUT = 20
GUARD_CHAIN = "OBHOD-FT"
GUARD_MAX_CIDRS = 512
GUARD_MIN_PREFIX = 8
GUARD_TIMEOUT = 30
GUARD_PRIORITY_ALLOW = -10
GUARD_PRIORITY_DROP = 10
CIDR_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}$")
PORT_RE = re.compile(r"^[0-9]{1,5}$")
TIMEOUTS = {
    "fw-guard": 180,
    "wg-peers": 60,
    "scripts-list": 60,
    "scripts-probe": 120,
    "scripts-fetch": 180,
    "net-scan": 240,
    "net-trace": 180,
    "net-ports": 60,
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


def digest_of_checksums(body):
    try:
        text = body.decode("utf-8", "replace")
    except (UnicodeDecodeError, AttributeError):
        return ""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[1] != "install.sh":
            continue
        value = parts[0].strip().lower()
        if DIGEST_RE.match(value):
            return value
    return ""


def fetch_release_digest(tag):
    url = CHECKSUMS_URL % tag
    if not allowed_url(url):
        return ""
    request = urllib.request.Request(url, headers={"User-Agent": "obhod-freeturn/3"})
    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
            if not allowed_url(response.geturl()):
                return ""
            body = response.read(CHECKSUMS_MAX + 1)
    except (OSError, ValueError):
        return ""
    if len(body) > CHECKSUMS_MAX:
        return ""
    return digest_of_checksums(body)


def release_digest(tag):
    if tag in SCRIPT_SHA256:
        return SCRIPT_SHA256[tag]
    hit = CHECKSUMS_CACHE.get(tag)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    digest = fetch_release_digest(tag)
    CHECKSUMS_CACHE[tag] = (time.monotonic() + CHECKSUMS_TTL, digest)
    return digest


def resolve_version(requested, lookup=None, digest_lookup=None):
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
    if not found:
        return FALLBACK_VERSION, "fallback"
    if found in SCRIPT_SHA256:
        return found, "api"
    if (digest_lookup or release_digest)(found):
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


def _verified_tag(flags):
    explicit = str(flags.get("script_sha256", "") or "").strip().lower()
    raw = str(flags.get("version", "") or "").strip().lower()
    if len(explicit) == 64 and all(ch in "0123456789abcdef" for ch in explicit) and raw not in {"", "default", "latest", "auto", "local"}:
        tag = raw if raw.startswith("v") else "v" + raw
        if not PIN_RE.match(tag):
            raise AgentError("bad_arg", "the version must be latest or vX.Y.Z", "init")
        return tag
    return ""


def script_source(flags, lookup=None, digest_lookup=None):
    tag = _verified_tag(flags)
    if not tag:
        tag, _source = resolve_version(flags.get("version", ""), lookup, digest_lookup)
    url = str(flags.get("script_url", "") or script_url(tag))
    expected = str(flags.get("script_sha256", "") or release_digest(tag)).strip().lower()
    if not expected:
        raise AgentError("not_pinned", "the install script of %s has no published digest" % tag, "fetch")
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
    tag = _verified_tag(flags)
    if not tag:
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


MUTATING_RPC = frozenset({"apply", "uninstall", "restart", "stop", "client-add", "client-remove"})


def sandboxed_host():
    if os.geteuid() != 0:
        return False
    if not os.path.isdir("/run/systemd/system") or not shutil.which("systemd-run"):
        return False
    for probe in ("/proc/sys/net/ipv4", "/usr"):
        if os.path.exists(probe) and not os.access(probe, os.W_OK):
            return True
    return False


def run_script(path, argv, timeout):
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "DEBIAN_FRONTEND": "noninteractive",
    }
    command = argv[0] if argv else ""
    if command in MUTATING_RPC and sandboxed_host():
        systemd_cmd = [
            "systemd-run",
            "--pipe",
            "--wait",
            "--quiet",
            "--collect",
            "-p",
            "WorkingDirectory=/",
            "-E",
            "PATH=" + env["PATH"],
            "-E",
            "HOME=/root",
            "-E",
            "LANG=C.UTF-8",
            "-E",
            "LC_ALL=C.UTF-8",
            "-E",
            "TERM=dumb",
            "-E",
            "DEBIAN_FRONTEND=noninteractive",
            "bash",
            path,
        ] + argv
        try:
            escaped = subprocess.run(
                systemd_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                env=env,
                cwd="/",
                check=False,
            )
            out_text = (escaped.stdout or b"").decode("utf-8", "replace")
            if last_json(out_text) or int(escaped.returncode or 0) == 0:
                return out_text, int(escaped.returncode or 0)
        except subprocess.TimeoutExpired:
            raise AgentError("start_failed", "the install script did not finish within %d seconds" % timeout, command)
        except OSError:
            pass
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


def run_tool(argv, timeout=GUARD_TIMEOUT):
    try:
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return int(done.returncode or 0), (done.stdout or b"").decode("utf-8", "replace").strip()


def tool_text(argv, timeout=GUARD_TIMEOUT):
    code, text = run_tool(argv, timeout)
    return text if code == 0 else ""


def wg_command(argv, timeout=WG_CMD_TIMEOUT):
    try:
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    if int(done.returncode or 0) != 0:
        return []
    return (done.stdout or b"").decode("utf-8", "replace").splitlines()


def wg_iface(flags):
    raw = str(flags.get("iface", "all")).strip()
    if raw.lower() in {"", "all"}:
        return "all"
    if not WG_IFACE_RE.match(raw):
        raise AgentError("bad_arg", "the interface name is not usable", "wg_peers")
    return raw


def wg_number(text):
    raw = str(text or "").strip()
    if not raw.isdigit():
        return 0
    return int(raw)


def wg_peers(flags):
    if not shutil.which("wg"):
        raise AgentError("wg_missing", "wireguard tools are not installed on this host", "wg_peers")
    iface = wg_iface(flags)
    lines = wg_command(["wg", "show", iface, "dump"])
    peers = []
    interfaces = []
    for line in lines:
        parts = line.split("\t")
        if iface == "all":
            if len(parts) != WG_FIELDS:
                if len(parts) == 5:
                    interfaces.append(parts[0][:15])
                continue
            name, pub, psk, endpoint, allowed, hs, rx, tx, keepalive = parts
        else:
            if len(parts) != WG_FIELDS - 1:
                continue
            name = iface
            pub, psk, endpoint, allowed, hs, rx, tx, keepalive = parts
            interfaces.append(iface)
        key = str(pub or "").strip()
        if not WG_KEY_RE.match(key):
            continue
        peers.append(
            {
                "iface": str(name)[:15],
                "pub": key,
                "endpoint": str(endpoint or "").strip()[:64],
                "allowed": str(allowed or "").strip()[:64],
                "hs": max(wg_number(hs), 0),
                "rx": max(wg_number(rx), 0),
                "tx": max(wg_number(tx), 0),
                "keepalive": max(wg_number(keepalive), 0),
                "psk": 1 if str(psk or "") not in {"", "(none)"} else 0,
            }
        )
        if len(peers) >= WG_MAX_PEERS:
            break
    seen = []
    for name in interfaces:
        if name not in seen:
            seen.append(name)
    return peers, seen


def wg_main(flags):
    unknown = sorted(key for key in flags if key not in {"iface"})
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0][:24], "wg_peers")
    peers, interfaces = wg_peers(flags)
    rx = sum(item["rx"] for item in peers)
    tx = sum(item["tx"] for item in peers)
    emit(
        "ok",
        {
            "interfaces": interfaces,
            "peers": peers,
            "count": len(peers),
            "rx": rx,
            "tx": tx,
            "up": sum(1 for item in peers if item["hs"] > 0),
        },
        stage="wg_peers",
        logs=["%d peers" % len(peers)],
    )
    return 0


def scripts_list(flags):
    unknown = sorted(key for key in flags if key not in set())
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0][:24], "scripts_list")
    found = []
    try:
        names = sorted(os.listdir(CACHE_DIR))[:MAX_SCRIPTS]
    except OSError:
        names = []
    for name in names:
        if not name.endswith(".sh") or name.startswith("."):
            continue
        path = os.path.join(CACHE_DIR, name)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        try:
            digest = digest_of_file(path)
            stat = os.stat(path)
        except OSError:
            continue
        found.append(
            {
                "key": "freeturn",
                "name": "install.sh",
                "file": name[:64],
                "digest": digest,
                "size": int(stat.st_size),
                "at": int(stat.st_mtime),
            }
        )
    found.sort(key=lambda item: item["at"], reverse=True)
    return {
        "cache": CACHE_DIR,
        "files": found[:MAX_SCRIPTS],
        "count": len(found),
    }


def scripts_probe(flags):
    unknown = sorted(key for key in flags if key not in {"url", "sha256"})
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0][:24], "scripts_probe")
    url = str(flags.get("url", "")).strip()
    if not url:
        raise AgentError("bad_arg", "the script address is required", "scripts_probe")
    if not allowed_url(url):
        raise AgentError("bad_arg", "the script address must be https on github", "scripts_probe")
    request = urllib.request.Request(url, headers={"User-Agent": "obhod-freeturn/3"})
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT) as response:
            final = response.geturl()
            if not allowed_url(final):
                raise AgentError("bad_arg", "the download ended outside github", "scripts_probe")
            body = response.read(MAX_SCRIPT_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise AgentError("download_failed", "the script answered %s" % exc.code, "scripts_probe")
    except urllib.error.URLError as exc:
        raise AgentError("download_failed", "the script is not reachable: %s" % exc.reason, "scripts_probe")
    except (OSError, ValueError) as exc:
        raise AgentError("download_failed", "the script download failed: %s" % exc, "scripts_probe")
    if len(body) > MAX_SCRIPT_BYTES:
        raise AgentError("download_failed", "the script is larger than allowed", "scripts_probe")
    return {"url": url, "digest": sha256_of(body), "size": len(body), "empty": not body}


NET_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
NET_CIDR_RE = re.compile(r"^([0-9]{1,3}(\.[0-9]{1,3}){3})/([0-9]{1,2})$")
NET_MAX_HOSTS = 256
NET_MAX_PORTS = 128
NET_MIN_PREFIX = 24
NET_CONNECT_TIMEOUT = 0.8
NET_MAX_SECONDS = 120.0
NET_MAX_HOPS = 20
NET_TRACE_TIMEOUT = 90.0


def net_target(flags):
    raw = str(flags.get("target", "")).strip()
    if not raw or len(raw) > 253:
        raise AgentError("bad_arg", "the target is required", "net")
    if any(char in raw for char in " \t;|&`$<>\"'\\"):
        raise AgentError("bad_arg", "the target carries forbidden characters", "net")
    if raw.count("/") == 1:
        if not NET_CIDR_RE.match(raw):
            raise AgentError("bad_arg", "the subnet must be an ipv4 cidr", "net")
        try:
            network = ipaddress.IPv4Network(raw, strict=False)
        except ValueError:
            raise AgentError("bad_arg", "the subnet is not a valid network", "net")
        if network.prefixlen < NET_MIN_PREFIX:
            raise AgentError("bad_arg", "the subnet is wider than /24", "net")
        return "subnet", str(network), [str(item) for item in network.hosts()][:NET_MAX_HOSTS]
    host = raw
    if ":" in host and host.count(":") == 1:
        host = host.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise AgentError("bad_arg", "only ipv4 targets are supported", "net")
        if address.is_multicast or address.is_unspecified:
            raise AgentError("bad_arg", "that address is not routable", "net")
        return "host", str(address), [str(address)]
    if not NET_HOST_RE.match(host) or "." not in host:
        raise AgentError("bad_arg", "that is not a host or an address", "net")
    return "host", host, []


def scan_ports(flags):
    raw = str(flags.get("ports", "")).strip() or "22,80,443"
    out = []
    for chunk in raw.split(","):
        item = chunk.strip()
        if not item:
            continue
        if "-" in item:
            left, _, right = item.partition("-")
            if not left.isdigit() or not right.isdigit():
                raise AgentError("bad_arg", "a port range must look like 20-25", "net")
            start, end = int(left), int(right)
            if not 1 <= start <= end <= 65535 or end - start > 1024:
                raise AgentError("bad_arg", "the port range is out of bounds", "net")
            out.extend(range(start, end + 1))
            continue
        if not item.isdigit() or not 1 <= int(item) <= 65535:
            raise AgentError("bad_arg", "a port must be between 1 and 65535", "net")
        out.append(int(item))
    unique = sorted(set(out))
    if not unique:
        raise AgentError("bad_arg", "no ports given", "net")
    if len(unique) > NET_MAX_PORTS:
        raise AgentError("bad_arg", "too many ports, keep it under %d" % NET_MAX_PORTS, "net")
    return unique


def net_scan(flags):
    unknown = sorted(key for key in flags if key not in {"target", "ports"})
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0][:24], "net")
    kind, name, hosts = net_target(flags)
    ports = scan_ports(flags)
    if kind == "host" and not hosts:
        try:
            found = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            raise AgentError("resolve_failed", "the host does not resolve", "net")
        hosts = []
        for item in found:
            address = str(item[4][0])
            if address not in hosts:
                hosts.append(address)
        hosts = hosts[:8]
        if not hosts:
            raise AgentError("resolve_failed", "the host does not resolve", "net")
    started = time.time()
    results = []
    alive = 0
    for host in hosts:
        if time.time() - started > NET_MAX_SECONDS:
            break
        opened = []
        for port in ports:
            if time.time() - started > NET_MAX_SECONDS:
                break
            attempt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            attempt.settimeout(NET_CONNECT_TIMEOUT)
            try:
                attempt.connect((host, port))
                opened.append(port)
            except OSError:
                continue
            finally:
                attempt.close()
        if opened:
            alive += 1
        results.append({"host": host, "open": opened})
    return {
        "kind": kind,
        "target": name,
        "hosts": len(results),
        "alive": alive,
        "ports": ports,
        "results": results[:NET_MAX_HOSTS],
        "spent": round(time.time() - started, 2),
    }


def net_trace(flags):
    unknown = sorted(key for key in flags if key not in {"target", "hops"})
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0][:24], "net")
    kind, name, hosts = net_target(flags)
    if kind == "subnet":
        raise AgentError("bad_arg", "traceroute takes one host", "net")
    raw_hops = str(flags.get("hops", "")).strip() or "12"
    if not raw_hops.isdigit() or not 1 <= int(raw_hops) <= NET_MAX_HOPS:
        raise AgentError("bad_arg", "the hop count must be between 1 and %d" % NET_MAX_HOPS, "net")
    hops = int(raw_hops)
    binary = shutil.which("traceroute") or shutil.which("tracepath")
    if not binary:
        raise AgentError("trace_missing", "traceroute is not installed on the server", "net")
    argv = [binary, "-n", "-m", str(hops), "-w", "2", "-q", "1", name]
    if binary.endswith("tracepath"):
        argv = [binary, "-n", "-m", str(hops), name]
    done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=NET_TRACE_TIMEOUT)
    text = (done.stdout or b"").decode("utf-8", "replace")
    parsed = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue
        address = ""
        rtt = 0.0
        for item in parts[1:]:
            try:
                candidate = ipaddress.ip_address(item.strip("()"))
            except ValueError:
                if item.endswith("ms") and item[:-2].replace(".", "", 1).isdigit():
                    rtt = float(item[:-2])
                continue
            if candidate.version == 4:
                address = str(candidate)
                break
        parsed.append({"index": int(parts[0]), "address": address, "rtt": rtt})
    return {"kind": kind, "target": name, "hops": parsed[:NET_MAX_HOPS], "raw": text[-2000:]}


def scripts_fetch(flags):
    unknown = sorted(key for key in flags if key not in {"url", "sha256"})
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0][:24], "scripts_fetch")
    url = str(flags.get("url", "")).strip()
    if not url:
        raise AgentError("bad_arg", "the script address is required", "scripts_fetch")
    expected = str(flags.get("sha256", "")).strip().lower()
    if expected and (len(expected) != 64 or not all(ch in "0123456789abcdef" for ch in expected)):
        raise AgentError("bad_arg", "the script digest must be 64 hexadecimal characters", "scripts_fetch")
    path = download(url, expected)
    digest = digest_of_file(path)
    if expected and digest != expected:
        raise AgentError("digest_mismatch", "the script digest is %s instead of %s" % (digest, expected), "scripts_fetch")
    return {"file": os.path.basename(path), "digest": digest, "size": os.path.getsize(path)}

def guard_backend():
    if shutil.which("firewall-cmd") and "running" in tool_text(["firewall-cmd", "--state"]).lower():
        return "firewalld"
    if shutil.which("ufw") and "Status: active" in tool_text(["ufw", "status"]):
        return "ufw"
    if shutil.which("iptables"):
        return "iptables"
    return ""


def guard_port(flags):
    raw = str(flags.get("port", "")).strip()
    if not PORT_RE.match(raw) or not 1 <= int(raw) <= 65535:
        raise AgentError("bad_arg", "the port must be a number between 1 and 65535", "fw_guard")
    return int(raw)


def guard_proto(flags):
    raw = str(flags.get("proto", "udp")).strip().lower()
    if raw not in GUARD_PROTOS:
        raise AgentError("bad_arg", "the protocol must be udp, tcp or both", "fw_guard")
    return ("udp", "tcp") if raw == "both" else (raw,)


def guard_cidrs(flags):
    raw = str(flags.get("cidrs", "")).strip()
    found = []
    for item in raw.split(","):
        text = item.strip()
        if not text:
            continue
        if not CIDR_RE.match(text):
            raise AgentError("bad_arg", "a source range must be an ipv4 cidr", "fw_guard")
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise AgentError("bad_arg", "a source range is not a network", "fw_guard") from None
        if network.version != 4 or network.prefixlen < GUARD_MIN_PREFIX:
            raise AgentError("bad_arg", "a source range is too wide, the minimum prefix is /%d" % GUARD_MIN_PREFIX, "fw_guard")
        found.append(str(network))
    if not found:
        raise AgentError("bad_arg", "the vk mode needs at least one source range", "fw_guard")
    if len(found) > GUARD_MAX_CIDRS:
        raise AgentError("bad_arg", "too many source ranges, the limit is %d" % GUARD_MAX_CIDRS, "fw_guard")
    return found


def firewalld_rules(port, permanent=False):
    argv = ["firewall-cmd"]
    if permanent:
        argv.append("--permanent")
    argv.append("--list-rich-rules")
    text = tool_text(argv)
    marker = 'port="%d"' % port
    return [line.strip() for line in text.splitlines() if marker in line]


def firewalld_add(port, cidr="", drop=False, proto="udp"):
    if drop:
        rule = 'rule priority="%d" family="ipv4" port port="%d" protocol="%s" drop' % (
            GUARD_PRIORITY_DROP,
            port,
            proto,
        )
    else:
        rule = 'rule priority="%d" family="ipv4" source address="%s" port port="%d" protocol="%s" accept' % (
            GUARD_PRIORITY_ALLOW,
            cidr,
            port,
            proto,
        )
    run_tool(["firewall-cmd", "--add-rich-rule=%s" % rule])
    return run_tool(["firewall-cmd", "--permanent", "--add-rich-rule=%s" % rule])


def firewalld_clear(port):
    for proto in ("udp", "tcp"):
        for argv in (
            ["firewall-cmd", "--remove-port=%d/%s" % (port, proto)],
            ["firewall-cmd", "--permanent", "--remove-port=%d/%s" % (port, proto)],
        ):
            run_tool(argv)
    for permanent in (False, True):
        for rule in firewalld_rules(port, permanent=permanent):
            argv = ["firewall-cmd"]
            if permanent:
                argv.append("--permanent")
            argv.append("--remove-rich-rule=%s" % rule)
            run_tool(argv)


def mentions_port(text, port):
    return re.search(r"(?<![0-9])%d(?![0-9])" % int(port), str(text or "")) is not None


def ufw_clear(port):
    listing = tool_text(["ufw", "status", "numbered"])
    doomed = set()
    for line in listing.splitlines():
        found = re.match(r"^\[\s*(\d+)\]\s+(.+)$", line.strip())
        if not found:
            continue
        if mentions_port(found.group(2), port):
            doomed.add(int(found.group(1)))
    for number in sorted(doomed, reverse=True):
        run_tool(["ufw", "--force", "delete", str(number)])


def ufw_apply(port, mode, cidrs, protos):
    ufw_clear(port)
    if mode == "closed":
        return 0, "closed"
    for proto in protos:
        if mode == "open":
            run_tool(["ufw", "allow", "%d/%s" % (port, proto)])
            continue
        for cidr in cidrs:
            run_tool(["ufw", "insert", "1", "allow", "from", cidr, "to", "any", "port", str(port), "proto", proto])
        run_tool(["ufw", "deny", "%d/%s" % (port, proto)])
    return 0, mode


def iptables_chain_present():
    return "OBHOD-FT" in tool_text(["iptables", "-S"])


def iptables_clear(port):
    if not shutil.which("iptables"):
        return
    for proto in ("udp", "tcp"):
        while run_tool(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", GUARD_CHAIN])[0] == 0:
            run_tool(["iptables", "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", GUARD_CHAIN])
        while run_tool(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])[0] == 0:
            run_tool(["iptables", "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
    if iptables_chain_present():
        run_tool(["iptables", "-F", GUARD_CHAIN])
        run_tool(["iptables", "-X", GUARD_CHAIN])


def iptables_apply(port, mode, cidrs, protos):
    iptables_clear(port)
    if mode == "closed":
        return 0, "closed"
    if mode == "open":
        for proto in protos:
            if run_tool(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])[0] != 0:
                run_tool(["iptables", "-I", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
        return 0, "open"
    run_tool(["iptables", "-N", GUARD_CHAIN])
    for proto in protos:
        run_tool(["iptables", "-I", "INPUT", "1", "-p", proto, "--dport", str(port), "-j", GUARD_CHAIN])
    run_tool(["iptables", "-A", GUARD_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    for cidr in cidrs:
        run_tool(["iptables", "-A", GUARD_CHAIN, "-s", cidr, "-j", "ACCEPT"])
    run_tool(["iptables", "-A", GUARD_CHAIN, "-j", "DROP"])
    return 0, "vk"


def guard_status(backend, port, protos):
    mode = "unknown"
    rules = 0
    if backend == "firewalld":
        found = [item for item in firewalld_rules(port) if any(proto in item for proto in protos)]
        rules = len(found)
        opened = any(run_tool(["firewall-cmd", "--query-port=%d/%s" % (port, proto)])[0] == 0 for proto in protos)
        if any("drop" in item for item in found):
            mode = "vk"
        elif opened:
            mode = "open"
        else:
            mode = "closed"
    elif backend == "ufw":
        listing = tool_text(["ufw", "status", "numbered"])
        ours = [line for line in listing.splitlines() if mentions_port(line, port)]
        allowed = [line for line in ours if "ALLOW" in line.upper()]
        rules = len(allowed)
        if allowed and any("Anywhere" in line for line in allowed):
            mode = "open"
        elif allowed:
            mode = "vk"
        else:
            mode = "closed"
    elif backend == "iptables":
        if iptables_chain_present():
            listing = tool_text(["iptables", "-S", GUARD_CHAIN])
            mode = "vk"
            rules = len([line for line in listing.splitlines() if "ACCEPT" in line]) - 1
        elif any(run_tool(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])[0] == 0 for proto in protos):
            mode = "open"
        else:
            mode = "closed"
    return mode, max(rules, 0)


def guard_flags(flags):
    allowed = {"mode", "port", "cidrs", "proto", "keep"}
    unknown = sorted(key for key in flags if key not in allowed)
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0][:24], "fw_guard")
    return flags


GUARD_KEEP_MAX = 64


def guard_keep(flags):
    raw = str(flags.get("keep", "")).strip()
    out = []
    for item in raw.split(","):
        text = item.strip()
        if not text:
            continue
        if not text.isdigit() or not 1 <= int(text) <= 65535:
            raise AgentError("bad_arg", "a kept port must be a number between 1 and 65535", "fw_guard")
        out.append(int(text))
    return sorted(set(out))[:GUARD_KEEP_MAX]


def net_ports(flags):
    unknown = sorted(key for key in flags if key != "keep")
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0][:24], "net_ports")
    keep = set(guard_keep(flags))
    binary = shutil.which("ss") or shutil.which("netstat")
    if not binary:
        raise AgentError("netstat_missing", "neither ss nor netstat is installed", "net_ports")
    if binary.endswith("ss"):
        argv = ["ss", "-lntupH"]
    else:
        argv = ["netstat", "-lntup"]
    try:
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentError("internal", "the listener listing failed: %s" % exc, "net_ports")
    text = (done.stdout or b"").decode("utf-8", "replace")
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        if proto not in {"tcp", "udp"}:
            continue
        port = 0
        address = ""
        for part in parts[1:]:
            found = re.match(r"^\[?[0-9a-fA-F.*:%]*\]?[:.](\d{1,5})$", part)
            if found:
                address = part
                port = int(found.group(1))
                break
        if not port:
            continue
        match = re.search(r'users:\(\("([^"]{1,64})"', line) or re.search(r"\d+/([A-Za-z0-9_.-]{1,64})", line)
        process = match.group(1) if match else ""
        rows.append(
            {
                "port": port,
                "proto": proto,
                "address": address[:64],
                "process": process[:64],
                "protected": port in keep or port in {22, 2222},
                "reason": "ssh" if port in {22, 2222} else ("module" if port in keep else ""),
            }
        )
    rows.sort(key=lambda item: (item["port"], item["proto"]))
    return {"ports": rows[:128], "count": len(rows), "keep": sorted(keep)}


def guard_main(flags):
    guard_flags(flags)
    port = guard_port(flags)
    protos = guard_proto(flags)
    mode = str(flags.get("mode", "status")).strip().lower()
    if mode not in GUARD_MODES:
        raise AgentError("bad_arg", "the firewall mode %s is not known" % mode[:16], "fw_guard")
    keep = guard_keep(flags)
    if mode in {"closed", "vk"} and port in keep:
        raise AgentError("port_protected", "port %d belongs to ssh or to another module, the guard will not touch it" % port, "fw_guard")
    if mode == "closed" and port in {22, 2222}:
        raise AgentError("port_protected", "port %d is never closed by the guard" % port, "fw_guard")
    backend = guard_backend()
    if not backend:
        raise AgentError("fw_unsupported", "there is no firewalld, ufw or iptables on this host", "fw_guard")
    proto_label = "both" if len(protos) > 1 else protos[0]
    if mode == "status":
        found_mode, rules = guard_status(backend, port, protos)
        emit(
            "ok",
            {"port": port, "proto": proto_label, "backend": backend, "mode": found_mode, "rules": rules, "cidrs": 0},
            stage="fw_guard",
        )
        return 0
    cidrs = guard_cidrs(flags) if mode == "vk" else []
    if backend == "firewalld":
        firewalld_clear(port)
        for proto in protos:
            if mode == "open":
                run_tool(["firewall-cmd", "--add-port=%d/%s" % (port, proto)])
                run_tool(["firewall-cmd", "--permanent", "--add-port=%d/%s" % (port, proto)])
            for cidr in cidrs:
                firewalld_add(port, cidr, proto=proto)
            if mode == "vk":
                firewalld_add(port, drop=True, proto=proto)
    elif backend == "ufw":
        ufw_apply(port, mode, cidrs, protos)
    else:
        iptables_apply(port, mode, cidrs, protos)
    found_mode, rules = guard_status(backend, port, protos)
    emit(
        "ok",
        {"port": port, "proto": proto_label, "backend": backend, "mode": found_mode, "rules": rules, "cidrs": len(cidrs)},
        stage="fw_guard",
        logs=["%s applied" % mode],
    )
    return 0


def main(argv):
    command, flags = parse_argv(argv)
    stage = command.replace("-", "_")
    if command == "fw-guard":
        try:
            return guard_main(flags)
        except AgentError as exc:
            emit("err", {}, exc.code, exc.message, exc.stage or stage, exc.logs)
            return 1
    if command == "wg-peers":
        try:
            return wg_main(flags)
        except AgentError as exc:
            emit("err", {}, exc.code, exc.message, exc.stage or stage, exc.logs)
            return 1
    if command in {"net-scan", "net-trace", "net-ports"}:
        try:
            if command == "net-scan":
                data = net_scan(flags)
            elif command == "net-trace":
                data = net_trace(flags)
            else:
                data = net_ports(flags)
            emit("ok", data, stage=stage, logs=["%s done" % command])
            return 0
        except AgentError as exc:
            emit("err", {}, exc.code, exc.message, exc.stage or stage, exc.logs)
            return 1
        except subprocess.TimeoutExpired:
            emit("err", {}, "timeout", "the network action ran out of time", stage)
            return 1
    if command in {"scripts-list", "scripts-probe", "scripts-fetch"}:
        try:
            if command == "scripts-list":
                data = scripts_list(flags)
            elif command == "scripts-probe":
                data = scripts_probe(flags)
            else:
                data = scripts_fetch(flags)
            emit("ok", data, stage=stage, logs=["%s done" % command])
            return 0
        except AgentError as exc:
            emit("err", {}, exc.code, exc.message, exc.stage or stage, exc.logs)
            return 1
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
