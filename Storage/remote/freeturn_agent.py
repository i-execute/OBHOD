from __future__ import annotations

import base64
import gzip
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

SBIN_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
BUNDLED_INSTALL_B64 = ""


def ensure_sbin_path():
    if os.geteuid() != 0:
        return
    parts = [item for item in (os.environ.get("PATH") or "").split(":") if item]
    changed = False
    for folder in SBIN_DIRS:
        if folder not in parts:
            parts.append(folder)
            changed = True
    if changed:
        os.environ["PATH"] = ":".join(parts)


ensure_sbin_path()

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
    "fw-guard": 300,
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


def bundled_script_bytes():
    raw = str(BUNDLED_INSTALL_B64 or "").strip()
    if not raw:
        candidates = []
        if "__file__" in globals():
            candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "freeturn_install.b64"))
        candidates.append("/opt/obhod/Storage/remote/freeturn_install.b64")
        for candidate in candidates:
            if os.path.isfile(candidate) and not os.path.islink(candidate):
                try:
                    with open(candidate, "r", encoding="ascii") as handle:
                        raw = handle.read(MAX_SCRIPT_BYTES).strip()
                    if raw:
                        break
                except OSError:
                    continue
    if not raw:
        return b""
    try:
        body = gzip.decompress(base64.b64decode(raw))
    except (OSError, ValueError):
        return b""
    if len(body) > MAX_SCRIPT_BYTES or b"RPC_COMMANDS" not in body:
        return b""
    if sha256_of(body) != DEFAULT_SHA256:
        return b""
    return body


def seed_bundled_cache(digest):
    if digest != DEFAULT_SHA256:
        return ""
    body = bundled_script_bytes()
    if not body:
        return ""
    try:
        return write_cache(digest, body)
    except AgentError:
        return ""


def read_cache(digest):
    path = cache_path(digest)
    if not os.path.isfile(path):
        return seed_bundled_cache(digest)
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
        seeded = seed_bundled_cache(expected)
        if seeded:
            return seeded
        raise AgentError("download_failed", "the install script answered %s" % exc.code, "fetch")
    except urllib.error.URLError as exc:
        seeded = seed_bundled_cache(expected)
        if seeded:
            return seeded
        raise AgentError("download_failed", "the install script is not reachable: %s" % exc.reason, "fetch")
    except (OSError, ValueError) as exc:
        seeded = seed_bundled_cache(expected)
        if seeded:
            return seeded
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
INSTALL_ROOT = "/opt/free-turn-proxy"


def sandboxed_host():
    if os.geteuid() != 0:
        return False
    if not os.path.isdir("/run/systemd/system") or not shutil.which("systemd-run"):
        return False
    for probe in ("/proc/sys/net/ipv4", "/usr", "/etc"):
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
    if command and sandboxed_host():
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
    ensure_sbin_path()
    items = [str(item) for item in (argv or [])]
    if not items:
        return 1, ""
    exe = shutil.which(items[0]) or items[0]
    resolved = [exe] + items[1:]
    tool_env = dict(os.environ)
    tool_env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    tool_env["HOME"] = "/root"
    tool_env["LANG"] = "C.UTF-8"
    tool_env["LC_ALL"] = "C.UTF-8"
    tool_env["TERM"] = "dumb"
    if sandboxed_host():
        systemd_bin = shutil.which("systemd-run") or "systemd-run"
        systemd_cmd = [
            systemd_bin,
            "--pipe",
            "--wait",
            "--quiet",
            "--collect",
            "-p",
            "WorkingDirectory=/",
            "-E",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "-E",
            "HOME=/root",
            "-E",
            "LANG=C.UTF-8",
            "-E",
            "LC_ALL=C.UTF-8",
            "--",
        ] + resolved
        try:
            escaped = subprocess.run(systemd_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=tool_env, check=False)
            out_text = (escaped.stdout or b"").decode("utf-8", "replace").strip()
            code = int(escaped.returncode or 0)
            if code == 0 or not any(
                marker in out_text
                for marker in ("Failed to start transient service unit", "Failed to connect to bus", "Failed to find executable")
            ):
                return code, out_text
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        done = subprocess.run(resolved, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=tool_env, check=False)
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return int(done.returncode or 0), (done.stdout or b"").decode("utf-8", "replace").strip()


def tool_text(argv, timeout=GUARD_TIMEOUT):
    code, text = run_tool(argv, timeout)
    return text if code == 0 else ""


def wg_command(argv, timeout=WG_CMD_TIMEOUT):
    if argv and sandboxed_host():
        code, text = run_tool(argv, timeout)
        return text.splitlines() if code == 0 else []
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


def ufw_line_matches_proto(line, port, protos):
    if not mentions_port(line, port):
        return False
    found = re.search(r"(?<![0-9])%d/([A-Za-z0-9]+)" % int(port), str(line or "").lower())
    if not found:
        return True
    proto = found.group(1)
    if proto == "any":
        return True
    return proto in set(protos)


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
        ours = [line for line in listing.splitlines() if ufw_line_matches_proto(line, port, protos)]
        allowed = [line for line in ours if "ALLOW" in line.upper()]
        rules = len(allowed)
        first_world = ""
        for line in ours:
            upper = line.upper()
            if "ANYWHERE" in upper:
                if "DENY" in upper or "REJECT" in upper:
                    first_world = "deny"
                    break
                if "ALLOW" in upper:
                    first_world = "allow"
                    break
        if first_world == "allow":
            mode = "open"
        elif allowed and any("ANYWHERE" not in line.upper() for line in allowed):
            mode = "vk"
        else:
            mode = "closed"
    elif backend == "iptables":
        chain_bound = iptables_chain_present() and any(
            run_tool(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", GUARD_CHAIN])[0] == 0
            for proto in protos
        )
        if chain_bound:
            listing = tool_text(["iptables", "-S", GUARD_CHAIN])
            rules = max(len([line for line in listing.splitlines() if "ACCEPT" in line]) - 1, 0)
            mode = "vk" if rules > 0 else "closed"
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


def _strip_owner_from_auth(obj, owner_cid):
    if isinstance(obj, list):
        kept = []
        for item in obj:
            if isinstance(item, str):
                if owner_cid and item.strip().lower() == owner_cid:
                    continue
                kept.append(item)
            elif isinstance(item, dict):
                name_val = str(item.get("name") or "").strip()
                cid_val = str(item.get("client_id") or item.get("id") or "").strip().lower()
                if name_val == "owner" or (owner_cid and cid_val == owner_cid):
                    continue
                kept.append(item)
            else:
                kept.append(item)
        return kept
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).strip() == "owner" or (owner_cid and str(k).strip().lower() == owner_cid):
                continue
            if isinstance(v, (list, dict)):
                out[k] = _strip_owner_from_auth(v, owner_cid)
            else:
                out[k] = v
        return out
    return obj


def _strip_owner_wg_peer(wg_conf, pubkey):
    if not wg_conf or not os.path.isfile(wg_conf):
        return False
    try:
        with open(wg_conf, "r", encoding="utf-8", errors="replace") as handle:
            raw = handle.read(262144)
    except OSError:
        return False
    chunks = re.split(r"(?m)^(?=\[Peer\])", raw)
    if len(chunks) <= 1:
        return False
    kept = [chunks[0]]
    changed = False
    for block in chunks[1:]:
        low = block.lower()
        has_owner_tag = bool(re.search(r"(?m)^#\s*(?:client\s*:\s*)?owner\s*$", low))
        has_pub = bool(pubkey and pubkey in block)
        if has_owner_tag or has_pub:
            changed = True
            continue
        kept.append(block)
    if not changed:
        return False
    tmp_path = wg_conf + ".obhod.tmp"
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("".join(kept))
        os.replace(tmp_path, wg_conf)
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return False
    return True


def revoke_owner_client(root=INSTALL_ROOT, wg_conf="/etc/wireguard/ft-wg0.conf"):
    if not os.path.isdir(root):
        raise AgentError("not_installed", "FreeTurn is not installed", "client_remove")
    owner_dir = os.path.join(root, "clients", "owner")
    meta_path = os.path.join(root, "clients.list")
    auth_path = os.path.join(root, "auth", "clients.json")
    owner_cid = ""
    pubkey = ""
    found_any = os.path.isdir(owner_dir)
    for key_file in ("publickey", "owner.pub", "public.key"):
        cand = os.path.join(owner_dir, key_file)
        if os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8", errors="replace") as handle:
                    val = handle.read(256).strip()
                if WG_KEY_RE.match(val):
                    pubkey = val
                    break
            except OSError:
                pass
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
            kept_lines = []
            for raw in lines:
                parts = raw.strip().split("|")
                if parts and parts[0] == "owner":
                    found_any = True
                    if len(parts) >= 2 and not owner_cid:
                        owner_cid = parts[1].strip().lower()
                    for seg in parts[2:]:
                        cand_key = seg.strip()
                        if not pubkey and WG_KEY_RE.match(cand_key):
                            pubkey = cand_key
                    continue
                kept_lines.append(raw)
            if len(kept_lines) != len(lines):
                tmp_meta = meta_path + ".obhod.tmp"
                fd = os.open(tmp_meta, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.writelines(kept_lines)
                os.replace(tmp_meta, meta_path)
        except OSError:
            pass
    if os.path.isfile(auth_path):
        try:
            with open(auth_path, "r", encoding="utf-8", errors="replace") as handle:
                parsed = json.loads(handle.read(262144))
            cleaned = _strip_owner_from_auth(parsed, owner_cid)
            if cleaned != parsed:
                found_any = True
                tmp_auth = auth_path + ".obhod.tmp"
                fd = os.open(tmp_auth, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(cleaned, stream, indent=2)
                os.replace(tmp_auth, auth_path)
        except (OSError, ValueError):
            pass
    if _strip_owner_wg_peer(wg_conf, pubkey):
        found_any = True
    if pubkey and os.geteuid() == 0 and shutil.which("wg"):
        try:
            run_tool(["wg", "set", "ft-wg0", "peer", pubkey, "remove"], timeout=10)
        except Exception:
            pass
    if os.path.isdir(owner_dir):
        shutil.rmtree(owner_dir, ignore_errors=True)
    if not found_any:
        raise AgentError("client_missing", "the owner link is already revoked", "client_remove")
    if os.geteuid() == 0:
        installed = read_install_conf(root)
        method = str(installed.get("INSTALL_METHOD", "systemd") or "systemd").strip().lower()
        try:
            if method == "docker" and shutil.which("docker"):
                run_tool(["docker", "restart", "free-turn-proxy"], timeout=20)
            elif shutil.which("systemctl"):
                run_tool(["systemctl", "try-restart", "free-turn-proxy.service"], timeout=20)
        except Exception:
            pass
    return {"removed": True, "name": "owner"}


def main(argv):
    command, flags = parse_argv(argv)
    stage = command.replace("-", "_")
    if command == "client-remove" and str(flags.get("name") or "") == "owner":
        try:
            data = revoke_owner_client()
            emit("ok", data, stage=stage, logs=["owner link revoked"])
            return 0
        except AgentError as exc:
            emit("err", {}, exc.code, exc.message, exc.stage or stage, exc.logs)
            return 1
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
        if body["result"] == "ok" and os.geteuid() == 0:
            heal_runtime(script, command, flags, body)
        emit(body["result"], body["data"], body.get("code", ""), body.get("msg", ""), body.get("stage", stage), body["logs"])
        return 0 if body["result"] == "ok" else 1
    except AgentError as exc:
        emit("err", {}, exc.code, exc.message, exc.stage or stage, exc.logs)
        return 1


def read_install_conf(root=INSTALL_ROOT):
    conf = os.path.join(root, "install.conf")
    out = {}
    if not os.path.isfile(conf):
        return out
    try:
        with open(conf, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                out[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return {}
    return out


def read_client_links(root=INSTALL_ROOT):
    base = os.path.join(root, "clients")
    out = {}
    if not os.path.isdir(base):
        return out
    try:
        names = sorted(os.listdir(base))[:128]
    except OSError:
        return out
    for name in names:
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$", name):
            continue
        link_file = os.path.join(base, name, "%s.link" % name)
        if not os.path.isfile(link_file) or os.path.islink(link_file):
            continue
        try:
            with open(link_file, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read(4096).strip()
        except OSError:
            continue
        if text.startswith("freeturn://"):
            out[name] = text
    return out


def port_listening(port, proto="udp"):
    if not shutil.which("ss") or not 1 <= int(port or 0) <= 65535:
        return False
    flag = "-Hltn" if proto == "tcp" else "-Hlun"
    code, text = run_tool(["ss", flag, "sport = :%d" % int(port)], timeout=10)
    return code == 0 and bool(text.strip())


DDOS_NFT_PATH = "/etc/obhod/ddos.nft"
WG_IFACE_PATH = "/sys/class/net/ft-wg0"
WG_CONF_PATH = "/etc/wireguard/ft-wg0.conf"


def ddos_nft_file_sync(port, protos, nft_path=DDOS_NFT_PATH):
    if not nft_path or not os.path.isfile(nft_path) or os.path.islink(nft_path):
        return
    try:
        with open(nft_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(262144)
    except OSError:
        return
    missing = [proto for proto in protos if ("%s dport %d accept" % (proto, port)) not in text]
    if not missing:
        return
    lines = text.splitlines()
    inserted = False
    out = []
    for line in lines:
        out.append(line)
        if not inserted and 'iifname "lo" accept' in line:
            for proto in missing:
                out.append("    %s dport %d accept" % (proto, port))
            inserted = True
    if not inserted:
        return
    folder = os.path.dirname(nft_path)
    try:
        fd, temp = tempfile.mkstemp(dir=folder, prefix=".ddos-", suffix=".nft")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(out) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, nft_path)
    except OSError:
        return


def _nft_chain_blocks_port(joined, proto, port):
    has_drop = "policy drop" in joined or bool(re.search(r"(?:^|\s)(drop|reject)(?:\s|$|;)", joined))
    if not has_drop:
        return False
    accept_re = re.compile(r"\b%s\s+dport\s+%d\b[^\n]*\baccept\b" % (re.escape(proto), int(port)))
    drop_re = re.compile(r"(?:^|\s)(drop|reject)(?:\s|$|;)")
    for line in joined.splitlines():
        if accept_re.search(line):
            return False
        if "hook input" not in line and drop_re.search(line):
            return True
    return True


def nft_open_port(port, protos):
    if not shutil.which("nft") or not 1 <= int(port or 0) <= 65535:
        return
    ddos_nft_file_sync(port, protos)
    code, ddos_body = run_tool(["nft", "list", "table", "inet", "obhod_ddos"], timeout=15)
    if code == 0 and ddos_body:
        for flood_set in ("conn_flood", "udp_flood", "port_scan"):
            run_tool(["nft", "flush", "set", "inet", "obhod_ddos", flood_set], timeout=10)
        for proto in protos:
            needle = "%s dport %d accept" % (proto, port)
            if needle not in ddos_body:
                run_tool(["nft", "insert", "rule", "inet", "obhod_ddos", "input", proto, "dport", str(port), "accept"], timeout=10)
    code, ruleset = run_tool(["nft", "list", "ruleset"], timeout=15)
    if code != 0 or not ruleset:
        return
    family = ""
    table_name = ""
    chain_name = ""
    in_input = False
    chain_body = []
    targets = []
    for raw in ruleset.splitlines():
        line = raw.strip()
        table_match = re.match(r"^table\s+(inet|ip|ip6)\s+([A-Za-z0-9_.-]+)\s*\{", line)
        if table_match:
            family = table_match.group(1)
            table_name = table_match.group(2)
            chain_name = ""
            in_input = False
            chain_body = []
            continue
        chain_match = re.match(r"^chain\s+([A-Za-z0-9_.-]+)\s*\{", line)
        if family and table_name and chain_match:
            chain_name = chain_match.group(1)
            in_input = False
            chain_body = []
            continue
        if chain_name:
            chain_body.append(line)
            if "hook input" in line and table_name != "obhod_ddos":
                in_input = True
            if line == "}":
                if in_input:
                    joined = "\n".join(chain_body)
                    targets.append((family, table_name, chain_name, joined))
                chain_name = ""
                in_input = False
                chain_body = []
    for fam, tbl, chn, joined in targets[:8]:
        for proto in protos:
            if _nft_chain_blocks_port(joined, proto, port):
                run_tool(["nft", "insert", "rule", fam, tbl, chn, proto, "dport", str(port), "accept"], timeout=10)


def ensure_wg_forward():
    if not os.path.isdir(WG_IFACE_PATH) or not shutil.which("iptables"):
        return
    if run_tool(["iptables", "-C", "FORWARD", "-i", "ft-wg0", "-j", "ACCEPT"])[0] != 0:
        run_tool(["iptables", "-I", "FORWARD", "1", "-i", "ft-wg0", "-j", "ACCEPT"])
    if run_tool(["iptables", "-C", "FORWARD", "-o", "ft-wg0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])[0] != 0:
        run_tool(["iptables", "-I", "FORWARD", "1", "-o", "ft-wg0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])


def _relax_rp_filter():
    if not shutil.which("sysctl"):
        return
    keys = ["net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"]
    conf_root = "/proc/sys/net/ipv4/conf"
    if os.path.isdir(conf_root):
        try:
            for name in sorted(os.listdir(conf_root))[:32]:
                if re.match(r"^[A-Za-z0-9_.-]+$", name) and name not in {"all", "default", "lo"}:
                    keys.append("net.ipv4.conf.%s.rp_filter" % name)
        except OSError:
            pass
    for key in keys:
        rp = tool_text(["sysctl", "-n", key], timeout=10).strip()
        if rp == "1":
            run_tool(["sysctl", "-q", "-w", "%s=2" % key], timeout=10)


def _iptables_accept_above_drop(bin_name, proto, port):
    listing = tool_text([bin_name, "-S", "INPUT"])
    accept_re = re.compile(r"^-A\s+INPUT\b.*-p\s+%s\b.*--dport\s+%d\b.*-j\s+ACCEPT\b" % (re.escape(proto), int(port)))
    drop_re = re.compile(r"^-A\s+INPUT\b.*-j\s+(DROP|REJECT)\b")
    seen_drop = False
    accepted_first = False
    for line in listing.splitlines():
        row = line.strip()
        if accept_re.search(row) and not seen_drop:
            accepted_first = True
            break
        if drop_re.search(row):
            seen_drop = True
    if accepted_first:
        return
    if listing and seen_drop:
        while run_tool([bin_name, "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])[0] == 0:
            run_tool([bin_name, "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
        run_tool([bin_name, "-I", "INPUT", "1", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
    elif run_tool([bin_name, "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])[0] != 0:
        run_tool([bin_name, "-I", "INPUT", "1", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])


def ensure_apply_port_open(flags, body):
    installed = read_install_conf()
    data_cfg = (body.get("data") or {}).get("config") or {}
    raw_port = str(
        flags.get("listen_port", "")
        or flags.get("listen-port", "")
        or data_cfg.get("listen_port", "")
        or installed.get("LISTEN_PORT", "")
        or ""
    ).strip()
    if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
        return
    port = int(raw_port)
    mode = str(
        flags.get("mode", "")
        or data_cfg.get("mode", "")
        or installed.get("PROXY_MODE", "")
        or installed.get("MODE", "")
        or "udp"
    ).strip().lower()
    protos = ["udp", "tcp"] if mode == "tcp" else ["udp"]
    if shutil.which("sysctl"):
        run_tool(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"], timeout=10)
        _relax_rp_filter()
    ensure_wg_forward()
    nft_open_port(port, protos)
    backend = guard_backend()
    if not backend:
        return
    found_mode, found_rules = guard_status(backend, port, ["udp"])
    if found_mode == "vk" and found_rules > 0:
        return
    if backend in {"ufw", "firewalld"} and shutil.which("iptables") and iptables_chain_present():
        for proto in protos:
            while run_tool(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", GUARD_CHAIN])[0] == 0:
                run_tool(["iptables", "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", GUARD_CHAIN])
    if backend == "ufw" and found_mode != "open":
        ufw_clear(port)
        for proto in protos:
            run_tool(["ufw", "allow", "%d/%s" % (port, proto)])
    elif backend == "firewalld" and found_mode != "open":
        for proto in protos:
            run_tool(["firewall-cmd", "--add-port=%d/%s" % (port, proto)])
            run_tool(["firewall-cmd", "--permanent", "--add-port=%d/%s" % (port, proto)])
    elif backend == "iptables":
        for proto in protos:
            while run_tool(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", GUARD_CHAIN])[0] == 0:
                run_tool(["iptables", "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", GUARD_CHAIN])
            _iptables_accept_above_drop("iptables", proto, port)
            if shutil.which("iptables-legacy"):
                legacy_in = tool_text(["iptables-legacy", "-S", "INPUT"])
                if legacy_in and re.search(r"-j\s+(DROP|REJECT)\b", legacy_in):
                    _iptables_accept_above_drop("iptables-legacy", proto, port)


def owner_allowlisted(root=INSTALL_ROOT):
    meta_path = os.path.join(root, "clients.list")
    auth_path = os.path.join(root, "auth", "clients.json")
    if not os.path.isfile(meta_path) or not os.path.isfile(auth_path):
        return False
    owner_cid = ""
    has_owner = False
    try:
        with open(meta_path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                parts = raw.strip().split("|")
                if len(parts) >= 2 and parts[0] == "owner":
                    has_owner = True
                    owner_cid = parts[1].strip().lower()
                    break
        if not has_owner:
            return True
        if not owner_cid:
            return False
        with open(auth_path, "r", encoding="utf-8", errors="replace") as handle:
            auth_text = handle.read(262144).lower()
    except OSError:
        return False
    return owner_cid in auth_text


def runtime_drift(installed, root=INSTALL_ROOT):
    raw_port = str(installed.get("LISTEN_PORT", "") or "").strip()
    if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
        return False
    if not owner_allowlisted(root):
        return True
    port = int(raw_port)
    method = str(installed.get("INSTALL_METHOD", "systemd") or "systemd").strip().lower()
    backend = str(installed.get("BACKEND", "new") or "new").strip().lower()
    mode = str(installed.get("PROXY_MODE", "") or installed.get("MODE", "udp") or "udp").strip().lower()
    wg_port = str(installed.get("WG_PORT", "51820") or "51820").strip()
    connect = ("127.0.0.1:%s" % wg_port) if backend == "new" else str(installed.get("CONNECT", "") or "").strip()
    obf_profile = str(installed.get("OBF_PROFILE", "rtpopus3") or "rtpopus3").strip()
    obf_key = str(installed.get("OBF_KEY", "") or "").strip().lower()
    if obf_profile != "none" and not (len(obf_key) == 64 and all(ch in "0123456789abcdef" for ch in obf_key)):
        return True
    listen_tok = "0.0.0.0:%d" % port
    if method == "docker":
        info = tool_text(["docker", "inspect", "-f", "{{.State.Status}}|{{json .Args}}", "free-turn-proxy"], timeout=15)
        if not info:
            return True
        for needle in (listen_tok, connect, mode):
            if needle and needle not in info:
                return True
        if obf_profile != "none":
            if obf_profile not in info or obf_key not in info.lower():
                return True
        return False
    bin_path = os.path.join(root, "server")
    ver_path = os.path.join(root, "version")
    env_path = os.path.join(root, "run.env")
    if not os.path.isfile(bin_path) or not os.access(bin_path, os.X_OK):
        return True
    try:
        with open(ver_path, "r", encoding="utf-8", errors="replace") as handle:
            ver_text = handle.read(64).strip()
        with open(env_path, "r", encoding="utf-8", errors="replace") as handle:
            env_text = handle.read(8192)
    except OSError:
        return True
    if not ver_text or ver_text.lower() == "latest":
        return True
    required = [
        "-listen %s" % listen_tok,
        "-connect %s" % connect,
        "-mode %s" % mode,
        "-clients-file ",
    ]
    if obf_profile != "none":
        required.append("-obf-profile %s" % obf_profile)
        required.append("-obf-key %s" % obf_key)
    env_low = env_text.lower()
    for item in required:
        if item.lower() not in env_low:
            return True
    return False


def reapply_argv(installed, root=INSTALL_ROOT):
    backend = str(installed.get("BACKEND", "new") or "new").strip().lower()
    obf_profile = str(installed.get("OBF_PROFILE", "rtpopus3") or "rtpopus3").strip()
    obf_key = str(installed.get("OBF_KEY", "") or "").strip().lower()
    host = str(installed.get("PUBLIC_HOST", "") or "").strip()
    connect = str(installed.get("CONNECT", "") or "").strip()
    ver_raw = str(installed.get("VERSION", "") or "").strip()
    plan_flags = {
        "method": str(installed.get("INSTALL_METHOD", "systemd") or "systemd").strip().lower(),
        "backend": backend,
        "listen_port": str(installed.get("LISTEN_PORT", "56000") or "56000").strip(),
        "mode": str(installed.get("PROXY_MODE", "") or installed.get("MODE", "udp") or "udp").strip().lower(),
        "obf_profile": obf_profile,
        "version": "local" if ver_raw == "local" else FALLBACK_VERSION,
        "script_sha256": DEFAULT_SHA256,
    }
    if backend == "new":
        plan_flags["wg_port"] = str(installed.get("WG_PORT", "51820") or "51820").strip()
        plan_flags["wg_net"] = str(installed.get("WG_NET", "10.13.13.0/24") or "10.13.13.0/24").strip()
    elif connect:
        plan_flags["connect"] = connect
    if host:
        plan_flags["host"] = host
    if obf_profile != "none" and len(obf_key) == 64 and all(ch in "0123456789abcdef" for ch in obf_key):
        plan_flags["obf_key"] = obf_key
    ver_path = os.path.join(root, "version")
    try:
        with open(ver_path, "r", encoding="utf-8", errors="replace") as handle:
            disk_ver = handle.read(64).strip().lower()
    except OSError:
        disk_ver = ""
    if disk_ver == "latest":
        plan_flags["update"] = "1"
    return command_argv("apply", plan_flags, lookup=lambda _repo: (FALLBACK_VERSION, ""))


def heal_runtime(script, command, flags, body):
    if command == "uninstall":
        return
    installed = read_install_conf()
    reapplied = False
    if command in {"probe", "restart", "client-list", "client-conf"} and installed and runtime_drift(installed):
        heal_text, _heal_rc = run_script(script, reapply_argv(installed), TIMEOUTS["apply"])
        heal_payload = last_json(heal_text)
        if heal_payload and heal_payload.get("result") == "ok":
            installed = read_install_conf()
            reapplied = True
    if command in {"apply", "probe", "restart", "client-list", "client-conf"} and (command == "apply" or installed):
        if installed.get("BACKEND", "new") == "new" and os.path.isfile(WG_CONF_PATH) and not os.path.isdir(WG_IFACE_PATH):
            if shutil.which("systemctl"):
                run_tool(["systemctl", "restart", "wg-quick@ft-wg0"], timeout=30)
        ensure_apply_port_open(flags, body)
    if reapplied and command in {"probe", "client-list", "client-conf"}:
        plan = command_argv(command, flags)
        refreshed_text, _ref_rc = run_script(script, plan, TIMEOUTS.get(command, 120))
        refreshed_payload = last_json(refreshed_text)
        if refreshed_payload and refreshed_payload.get("result") == "ok" and isinstance(refreshed_payload.get("data"), dict):
            body["data"] = dict(refreshed_payload["data"])
    if command == "apply":
        apply_data = dict(body.get("data") or {})
        probe_text, _code = run_script(script, ["probe"], TIMEOUTS["probe"])
        probe_payload = last_json(probe_text)
        if probe_payload and probe_payload.get("result") == "ok" and isinstance(probe_payload.get("data"), dict):
            merged = dict(probe_payload["data"])
            for key in ("owner", "obf_key", "needs_restart"):
                if key in apply_data:
                    merged[key] = apply_data[key]
            body["data"] = merged
    if command in {"apply", "probe", "restart", "client-list", "client-conf"}:
        data_dict = body.get("data") if isinstance(body.get("data"), dict) else {}
        cfg = data_dict.get("config") or {}
        port = int(cfg.get("listen_port", 0) or installed.get("LISTEN_PORT", 0) or 0)
        if port and (command == "apply" or installed) and not port_listening(port, "udp"):
            run_script(script, ["restart"], TIMEOUTS["restart"])
            if command in {"apply", "probe"} and isinstance(body.get("data"), dict):
                probe_text, _code = run_script(script, ["probe"], TIMEOUTS["probe"])
                probe_payload = last_json(probe_text)
                if probe_payload and probe_payload.get("result") == "ok" and isinstance(probe_payload.get("data"), dict):
                    for key, value in probe_payload["data"].items():
                        body["data"][key] = value
        if port and command in {"apply", "restart"} and shutil.which("conntrack"):
            run_tool(["conntrack", "-D", "-p", "udp", "--dport", str(port)], timeout=10)
        if command in {"apply", "probe"} and isinstance(body.get("data"), dict):
            links = read_client_links()
            if links:
                body["data"]["links"] = links
            if port:
                body["data"]["listening"] = port_listening(port, "udp")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
