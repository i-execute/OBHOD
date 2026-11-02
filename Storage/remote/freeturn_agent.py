from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
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
CACHE_DIR = "/var/lib/obhod/freeturn"
MAX_SCRIPT_BYTES = 512 * 1024
FETCH_TIMEOUT = 120
ALLOWED_HOSTS = ("github.com", "objects.githubusercontent.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com")
COMMANDS = (
    "fw-guard",
    "wg-peers",
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


def script_source(flags, lookup=None, digest_lookup=None):
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
    allowed = {"mode", "port", "cidrs", "proto"}
    unknown = sorted(key for key in flags if key not in allowed)
    if unknown:
        raise AgentError("bad_arg", "unsupported flag %s" % unknown[0][:24], "fw_guard")
    return flags


def guard_main(flags):
    guard_flags(flags)
    port = guard_port(flags)
    protos = guard_proto(flags)
    mode = str(flags.get("mode", "status")).strip().lower()
    if mode not in GUARD_MODES:
        raise AgentError("bad_arg", "the firewall mode %s is not known" % mode[:16], "fw_guard")
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
