import base64
import hashlib
import io
import ipaddress
import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

PROTO = 3
PINNED = "v26.10.31"
MIN_CORE = (26, 10, 31)
MIN_CORE_TAG = "v26.10.31"
MIN_CORE_ADVISORY = "CVE-2026-98432"
GODEBUG = "multipathtcp=0"
PROC_MPTCP = "/proc/sys/net/mptcp/enabled"
PROC_MIGRATE = "/proc/sys/net/ipv4/tcp_migrate_req"
ASSETS = {
    "x86_64": "64",
    "amd64": "64",
    "aarch64": "arm64-v8a",
    "arm64": "arm64-v8a",
    "armv7l": "arm32-v7a",
    "armv7": "arm32-v7a",
    "armv6l": "arm32-v6",
    "i686": "32",
    "i386": "32",
    "s390x": "s390x",
    "riscv64": "riscv64",
}
DIGESTS = {
    "64": "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214",
    "arm64-v8a": "1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d",
    "arm32-v7a": "2387f55239ee7799fd67d5382e79f589c1da07a97d993e86b058f2290b8e456b",
    "arm32-v6": "28c27bbd262bcc751e2e07115f47ce50d79611289e19e8b499b3065497b0e1ec",
    "32": "4064a12c7712f28f0a85082be3564c088f7861f2220ddb5e4de409c91837511d",
    "s390x": "c83452b49eb7c9064ca9afd68d5e0afaa820d0eae25e763306e68665bdc800c4",
    "riscv64": "1159825b0d448fc7f56ca6f12e4872de2bf80a6639964819e0827fa0ad1283e8",
}
API_URL = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
API_TTL = 600
API_FAIL_TTL = 300
API_CACHE = {}
API_REASON = ""
ROOT = os.environ.get("XRAY_ROOT", "")
LOGS = []


def path_of(base):
    return os.path.join(ROOT, base.lstrip("/")) if ROOT else base


CORE = path_of("/usr/local/bin/xray")
CONF_DIR = path_of("/usr/local/etc/xray")
CONF = os.path.join(CONF_DIR, "config.json")
SHARE = path_of("/usr/local/share/xray")
UNIT_DIR = path_of("/etc/systemd/system")
UNIT = os.path.join(UNIT_DIR, "xray.service")
STATE = path_of("/var/lib/xray-manager")


def note(text):
    LOGS.append(str(text))


def machine():
    return os.uname().machine


def asset_for(arch):
    return ASSETS.get(arch, "")


def sha256_file(target):
    digest = hashlib.sha256()
    with open(target, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def run(argv, timeout=180, check=False):
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raw_out = exc.stdout or b""
        if isinstance(raw_out, str):
            partial = raw_out.strip()
        else:
            partial = raw_out.decode("utf-8", "replace").strip()
        raise ScriptError("timeout", "command timed out after %ss: %s" % (timeout, partial[:320]))
    text = proc.stdout.decode("utf-8", "replace").strip()
    if check and proc.returncode != 0:
        raise ScriptError("internal", "command exited with code %s: %s" % (proc.returncode, text[:400]))
    return proc.returncode, text


_ORIG_RUN = run


def has_systemd():
    if os.environ.get("XRAY_NO_SYSTEMD"):
        return False
    return os.path.isdir("/run/systemd/system") and shutil.which("systemctl") is not None


class ScriptError(Exception):
    def __init__(self, code, message, stage="", data=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.stage = stage
        self.data = dict(data) if isinstance(data, dict) else {}


def core_version():
    if not os.path.isfile(CORE):
        return ""
    try:
        code, text = run([CORE, "version"], timeout=20)
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in text.splitlines():
        token = line.strip()
        if token.startswith("Xray"):
            parts = token.split()
            if len(parts) >= 2:
                return parts[1]
    return ""


def config_digest():
    if not os.path.isfile(CONF):
        return ""
    return sha256_file(CONF)


def read_config():
    if not os.path.isfile(CONF):
        return {}
    try:
        with open(CONF, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def listen_ports(config):
    ports = []
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        port = inbound.get("port")
        if isinstance(port, int) and port not in ports:
            ports.append(port)
    return ports


def port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.5)
        return sock.connect_ex(("127.0.0.1", int(port))) == 0


def unit_state():
    if not os.path.isfile(UNIT):
        if has_systemd():
            return "absent"
        return pid_state()
    if not has_systemd():
        return pid_state()
    code, text = run(["systemctl", "is-active", "xray.service"], timeout=20)
    token = text.strip().splitlines()[0] if text.strip() else ""
    return token or "unknown"


def pid_file():
    return os.path.join(STATE, "xray.pid")


def pid_state():
    target = pid_file()
    if not os.path.isfile(target):
        return "inactive"
    try:
        with open(target, "r", encoding="utf-8") as handle:
            pid = int(handle.read().strip() or 0)
    except (OSError, ValueError):
        return "inactive"
    if pid <= 0:
        return "inactive"
    try:
        os.kill(pid, 0)
    except OSError:
        return "inactive"
    return "active"


def write_state(pid):
    if not os.path.isdir(STATE):
        os.makedirs(STATE, exist_ok=True)
    with open(pid_file(), "w", encoding="utf-8") as handle:
        handle.write(str(pid))


def stop_core():
    if has_systemd() and os.path.isfile(UNIT):
        run(["systemctl", "stop", "xray.service"], timeout=90)
        return
    target = pid_file()
    if not os.path.isfile(target):
        return
    try:
        with open(target, "r", encoding="utf-8") as handle:
            pid = int(handle.read().strip() or 0)
    except (OSError, ValueError):
        pid = 0
    if pid > 0:
        try:
            os.kill(pid, 15)
            for _ in range(40):
                try:
                    os.kill(pid, 0)
                except OSError:
                    break
                time.sleep(0.25)
        except OSError:
            pass
    try:
        os.unlink(target)
    except OSError:
        pass


def start_core():
    if has_systemd():
        write_unit()
        run(["systemctl", "daemon-reload"], timeout=60)
        code, text = run(["systemctl", "enable", "xray.service"], timeout=90)
        if code != 0:
            note("enable: " + text[:200])
        code, text = run(["systemctl", "restart", "xray.service"], timeout=120)
        if code != 0:
            raise ScriptError("start_failed", "systemctl restart: " + text[:400], "start")
        return
    if not os.path.isdir(STATE):
        os.makedirs(STATE, exist_ok=True)
    log_path = os.path.join(STATE, "xray.log")
    env = dict(os.environ)
    env["XRAY_LOCATION_ASSET"] = SHARE
    env["GODEBUG"] = GODEBUG
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(
            [CORE, "run", "-c", CONF],
            stdout=log,
            stderr=log,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    write_state(proc.pid)
    time.sleep(0.8)
    if proc.poll() is not None:
        raise ScriptError("start_failed", "the core exited right after the start", "start")


def write_unit():
    if not os.path.isdir(UNIT_DIR):
        os.makedirs(UNIT_DIR, exist_ok=True)
    body = "\n".join(
        [
            "[Unit]",
            "Description=Xray Service",
            "Documentation=https://github.com/XTLS/Xray-core",
            "After=network.target nss-lookup.target",
            "",
            "[Service]",
            "User=root",
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
            "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
            "NoNewPrivileges=true",
            "Environment=XRAY_LOCATION_ASSET=" + SHARE,
            "Environment=GODEBUG=" + GODEBUG,
            "ExecStart=" + CORE + " run -c " + CONF,
            "Restart=on-failure",
            "RestartPreventExitStatus=23",
            "PrivateTmp=true",
            "PrivateDevices=true",
            "ProtectHome=true",
            "ProtectClock=true",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectControlGroups=true",
            "ProtectKernelLogs=true",
            "ProtectHostname=true",
            "RestrictNamespaces=true",
            "RestrictSUIDSGID=true",
            "LockPersonality=true",
            "LimitNOFILE=1048576",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    with open(UNIT, "w", encoding="utf-8") as handle:
        handle.write(body)
    note("the unit is written")


ALLOWED_HOSTS = ("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")
ALLOWED_FILES = ("/usr/local/bin/", "/tmp/", "/opt/")
SAFE_VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")


def safe_url(url, redirect=False):
    if url.startswith("file://"):
        path = os.path.realpath(url[len("file://") :])
        roots = tuple(os.path.realpath(item).rstrip("/") + "/" for item in ALLOWED_FILES)
        if not any(path.startswith(item) for item in roots):
            raise ScriptError("bad_arg", "a local release must live under /opt, /tmp or /usr/local/bin", "download")
        return url
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise ScriptError("bad_arg", "the release must be fetched over https", "download")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ScriptError("bad_arg", "the release host %s is not allowed" % parsed.hostname, "download")
    if parsed.username or parsed.password:
        raise ScriptError("bad_arg", "the release url must not carry credentials", "download")
    if not redirect and not parsed.path.endswith(".zip") and not parsed.path.endswith(".dgst"):
        raise ScriptError("bad_arg", "only a release archive or its digest can be fetched", "download")
    return url


DOWNLOAD_LIMIT = 256 * 1024 * 1024
MAX_REDIRECTS = 3


class GuardedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe_url(newurl, redirect=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(request, timeout):
    opener = urllib.request.build_opener(GuardedRedirect)
    return opener.open(request, timeout=timeout)


def copy_limited(response, target):
    total = 0
    with open(target, "wb") as handle:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > DOWNLOAD_LIMIT:
                raise ScriptError("download_failed", "the release archive is larger than the allowed size", "download")
            handle.write(chunk)
    return total


def download(url, target):
    url = safe_url(url)
    if url.startswith("file://"):
        source = url[len("file://") :]
        try:
            size = os.path.getsize(source)
        except OSError as exc:
            raise ScriptError("download_failed", "the local release is missing: " + str(exc), "download") from None
        if size > DOWNLOAD_LIMIT:
            raise ScriptError("download_failed", "the local release is larger than the allowed size", "download")
        shutil.copyfile(source, target)
        return
    request = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
    try:
        with open_url(request, 120) as response:
            copy_limited(response, target)
    except ScriptError:
        raise
    except (OSError, ValueError) as exc:
        raise ScriptError("download_failed", "the download failed: " + str(exc)[:200], "download") from None


def api_rate_limited(exc):
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


def latest_tag(timeout=15, use_cache=True):
    global API_REASON
    now = time.monotonic()
    cached = API_CACHE.get("Xray-core")
    if use_cache and cached and cached[0] > now:
        API_REASON = cached[2]
        return cached[1]
    tag = ""
    reason = "unreachable"
    try:
        request = urllib.request.Request(
            API_URL,
            headers={"User-Agent": "curl/8.5.0", "Accept": "application/vnd.github+json"},
        )
        with open_url(request, timeout) as response:
            body = json.loads(response.read(65536).decode("utf-8"))
        candidate = str(body.get("tag_name", "") or "").strip()
        if candidate.startswith("v"):
            tag = candidate
            reason = ""
        else:
            reason = "no_tag"
    except urllib.error.HTTPError as exc:
        reason = "rate_limited" if api_rate_limited(exc) else "http_%d" % int(getattr(exc, "code", 0) or 0)
    except (OSError, ValueError):
        reason = "unreachable"
    API_REASON = reason
    API_CACHE["Xray-core"] = (now + (API_TTL if tag else API_FAIL_TTL), tag, reason)
    return tag


def fetch_digest(version, asset, url):
    if url:
        base = url
    else:
        base = "https://github.com/XTLS/Xray-core/releases/download/%s/Xray-linux-%s.zip" % (version, asset)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "core.dgst")
            download(base + ".dgst", target)
            with open(target, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    token = line.strip()
                    if token.upper().startswith("SHA2-256="):
                        return token.split("=", 1)[1].strip().lower()
    except (OSError, ValueError):
        return ""
    return ""


def core_numbers(tag):
    numbers = re.findall(r"[0-9]+", str(tag or ""))
    return tuple(int(number) for number in numbers[:3])


def core_too_old(tag):
    numbers = core_numbers(tag)
    if len(numbers) < 3:
        return False
    return numbers < MIN_CORE


def read_flag(path):
    try:
        with open(path, "r") as handle:
            return int(str(handle.read()).strip() or "-1")
    except (OSError, ValueError):
        return -1


def mptcp_state():
    return {
        "release": os.uname().release,
        "mptcp": read_flag(PROC_MPTCP),
        "migrate": read_flag(PROC_MIGRATE),
        "godebug": GODEBUG,
    }


def mptcp_warnings(state):
    out = []
    if state.get("mptcp") == 1:
        out.append("net.mptcp.enabled is 1, the kernel still answers mptcp for every program")
    if state.get("migrate") == 1:
        out.append("net.ipv4.tcp_migrate_req is 1, connection migration is open")
    return out


def install_core(version, url, sha256, force):
    if not SAFE_VERSION.match(str(version or "")):
        raise ScriptError("bad_arg", "the version must look like v26.10.31", "download")
    if core_too_old(version):
        raise ScriptError(
            "core_too_old",
            "%s is below %s, it keeps the MPTCP listeners open and allows a remote root through %s"
            % (version, MIN_CORE_TAG, MIN_CORE_ADVISORY),
            "download",
        )
    asset = asset_for(machine())
    if not asset:
        raise ScriptError("unsupported_arch", "architecture %s is not supported" % machine(), "download")
    current = core_version()
    if current and current.lstrip("v") == version.lstrip("v") and os.path.isfile(CORE) and not force:
        note("the core is already installed: " + version)
        return {"version": current, "core_path": CORE, "downloaded": False, "sha256": sha256_file(CORE)}
    if not url:
        url = "https://github.com/XTLS/Xray-core/releases/download/%s/Xray-linux-%s.zip" % (version, asset)
    expected = (sha256 or "").strip().lower()
    if not expected:
        expected = fetch_digest(version, asset, url if not url.startswith("file://") else "")
    if not expected and version == PINNED:
        expected = DIGESTS.get(asset, "")
    note("downloading " + url)
    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, "core.zip")
        try:
            download(url, archive)
        except (OSError, ValueError) as exc:
            raise ScriptError("download_failed", "the download failed: %s" % exc, "download")
        if not expected:
            raise ScriptError("digest_missing", "the release digest is not available, the download is refused", "download")
        if expected:
            actual = sha256_file(archive)
            if actual != expected:
                raise ScriptError(
                    "digest_mismatch",
                    "expected %s, got %s" % (expected, actual),
                    "download",
                )
            note("the digest matches")
        try:
            with zipfile.ZipFile(archive) as bundle:
                member = None
                for name in bundle.namelist():
                    if name.rstrip("/").split("/")[-1] == "xray":
                        member = name
                        break
                if member is None:
                    raise ScriptError("unpack_failed", "the archive has no xray binary", "unpack")
                target_dir = os.path.dirname(CORE)
                if not os.path.isdir(target_dir):
                    os.makedirs(target_dir, exist_ok=True)
                with bundle.open(member) as source, open(CORE, "wb") as handle:
                    shutil.copyfileobj(source, handle, 1 << 20)
                for extra in ("geoip.dat", "geosite.dat"):
                    for name in bundle.namelist():
                        if name.rstrip("/").split("/")[-1] == extra:
                            payload = bundle.read(name)
                            for folder in (SHARE, os.path.dirname(CORE)):
                                if not os.path.isdir(folder):
                                    os.makedirs(folder, exist_ok=True)
                                with open(os.path.join(folder, extra), "wb") as handle:
                                    handle.write(payload)
        except zipfile.BadZipFile as exc:
            raise ScriptError("unpack_failed", "the archive is damaged: %s" % exc, "unpack")
        except OSError as exc:
            raise ScriptError("unpack_failed", "the unpack failed: %s" % exc, "unpack")
    os.chmod(CORE, 0o755)
    installed = core_version()
    if not installed:
        raise ScriptError("start_failed", "the core does not answer version", "verify")
    note("the core is installed: " + installed)
    return {"version": installed, "core_path": CORE, "downloaded": True, "sha256": sha256_file(CORE)}


def test_config(payload):
    if not payload:
        raise ScriptError("config_missing", "no configuration was supplied", "config")
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "the core is not installed", "config")
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "config.json")
        with open(target, "wb") as handle:
            handle.write(payload)
        code, text = run([CORE, "run", "-test", "-c", target], timeout=60)
    return code == 0, text


def write_bytes_atomic(target, payload, mode=0o644):
    folder = os.path.dirname(target) or "."
    if not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)
    handle, tmp = tempfile.mkstemp(dir=folder, prefix=".obhod-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except OSError:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise
    return target


def backup_config():
    if not os.path.isfile(CONF):
        return ""
    try:
        with open(CONF, "rb") as handle:
            previous = handle.read()
    except OSError:
        return ""
    if not previous:
        return ""
    try:
        write_bytes_atomic(CONF + ".bak", previous, 0o600)
    except OSError:
        return ""
    return CONF + ".bak"


def restore_config(backup):
    if not backup or not os.path.isfile(backup):
        return False
    try:
        with open(backup, "rb") as handle:
            previous = handle.read()
        write_bytes_atomic(CONF, previous, 0o600)
    except OSError:
        return False
    note("the previous configuration is restored")
    return True


def write_config(payload):
    if not payload:
        raise ScriptError("config_missing", "no configuration was supplied", "config")
    try:
        config = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ScriptError("config_invalid", "the configuration is not json", "config") from None
    if not isinstance(config, dict) or not config.get("inbounds"):
        raise ScriptError("config_invalid", "the configuration has no inbound", "config")
    ok, text = test_config(payload)
    if not ok:
        raise ScriptError("config_invalid", text[:600] or "the core rejected the configuration", "config")
    backup_config()
    write_bytes_atomic(CONF, payload, 0o600)
    note("the configuration is written")
    return config


def state_report():
    config = read_config()
    ports = listen_ports(config)
    service = unit_state()
    listening = [port for port in ports if port_open(port)]
    mptcp = mptcp_state()
    return {
        "installed": os.path.isfile(CORE),
        "version": core_version(),
        "pinned": PINNED,
        "core_path": CORE,
        "config_path": CONF,
        "config_exists": os.path.isfile(CONF),
        "config_digest": config_digest(),
        "inbounds": len(config.get("inbounds") or []),
        "port": ports[0] if ports else 0,
        "ports": ports,
        "listening": listening,
        "service": service,
        "unit": os.path.isfile(UNIT),
        "systemd": has_systemd(),
        "arch": machine(),
        "asset": asset_for(machine()),
        "min_core": MIN_CORE_TAG,
        "advisory": MIN_CORE_ADVISORY,
        "core_ok": not core_too_old(core_version()),
        "mptcp": mptcp,
        "mptcp_warnings": mptcp_warnings(mptcp),
    }


def parse_flags(tokens):
    flags = {}
    rest = []
    for token in tokens:
        if token.startswith("--"):
            body = token[2:]
            if "=" in body:
                key, value = body.split("=", 1)
                flags[key.replace("-", "_")] = value
            else:
                flags[body.replace("-", "_")] = True
        else:
            rest.append(token)
    return flags, rest


STDIN_MARK = "-"
STDIN_MAX = 16 * 1024 * 1024


def payload_of(flags, name):
    value = flags.get(name, "")
    if not value:
        return b""
    if value == STDIN_MARK:
        raw = sys.stdin.buffer.read(STDIN_MAX + 1)
        if len(raw) > STDIN_MAX:
            raise ScriptError("bad_arg", "the field %s is too large" % name, "args")
        try:
            return base64.b64decode(raw.strip())
        except (ValueError, TypeError):
            raise ScriptError("bad_arg", "the field %s is not decodable" % name, "args")
    try:
        return base64.b64decode(value)
    except (ValueError, TypeError):
        raise ScriptError("bad_arg", "the field %s is not decodable" % name, "args")


def version_of(flags):
    version = str(flags.get("version", PINNED)).strip()
    if version.lower() in {"latest", "auto", ""}:
        return "latest"
    if not version.startswith("v"):
        version = "v" + version
    return version


def cmd_probe(flags, rest):
    return state_report(), None


def wants_latest(version):
    return version.strip().lower() in {"latest", "auto", ""}


def pinned_with_fallback(version, url, sha256, force, tag="", fallback_url="", fallback_sha256=""):
    resolved = version
    requested_latest = wants_latest(version)
    if requested_latest:
        resolved = str(tag or "").strip() or latest_tag()
        if resolved:
            note("latest release: " + resolved)
        else:
            resolved = PINNED
            reason = API_REASON or "unreachable"
            if reason == "rate_limited":
                note("the github api is rate limited, using the pinned " + PINNED)
            else:
                note("the github api is unreachable, using the pinned " + PINNED)
    try:
        data = install_core(resolved, url, sha256, force)
        data["fallback"] = False
        return data
    except ScriptError as exc:
        if exc.code != "download_failed" or not requested_latest:
            raise
        note("the download of " + resolved + " failed, falling back to " + PINNED)
        try:
            data = install_core(PINNED, str(fallback_url or ""), str(fallback_sha256 or ""), True)
        except ScriptError as pinned_exc:
            if pinned_exc.code != "download_failed":
                raise
            spare = latest_tag(use_cache=False)
            if not spare or spare == PINNED:
                raise
            note("the pinned release is gone from github, using the live one: " + spare)
            data = install_core(spare, str(fallback_url or ""), str(fallback_sha256 or ""), True)
            data["fallback"] = True
            data["fallback_version"] = spare
            return data
        data["fallback"] = True
        data["fallback_version"] = PINNED
        return data


OFF_TEXT = {"0", "no", "false", "off", "disabled", "none", ""}


def flag_on(value, default=True):
    if value is None:
        return bool(default)
    if value is True:
        return True
    if value is False:
        return False
    return str(value).strip().lower() not in OFF_TEXT


def cmd_install(flags, rest):
    version = version_of(flags)
    url = str(flags.get("url", ""))
    sha256 = str(flags.get("sha256", ""))
    force = flag_on(flags.get("force"), False)
    tag = str(flags.get("tag", ""))
    fallback_url = str(flags.get("fallback_url", ""))
    fallback_sha256 = str(flags.get("fallback_sha256", ""))
    data = pinned_with_fallback(version, url, sha256, force, tag, fallback_url, fallback_sha256)
    data.update(state_report())
    return data, None


def cmd_apply(flags, rest):
    payload = payload_of(flags, "config_b64")
    if not payload:
        raise ScriptError("config_missing", "no configuration was supplied", "config")
    version = version_of(flags)
    install = {}
    if not os.path.isfile(CORE):
        install = pinned_with_fallback(
            version,
            str(flags.get("url", "")),
            str(flags.get("sha256", "")),
            False,
            str(flags.get("tag", "")),
            str(flags.get("fallback_url", "")),
            str(flags.get("fallback_sha256", "")),
        )
    config = write_config(payload)
    if not flag_on(flags.get("no_restart"), False):
        stop_core()
        start_core()
        ports = listen_ports(config)
        deadline = time.time() + 12
        while time.time() < deadline:
            if all(port_open(port) for port in ports):
                break
            time.sleep(0.4)
        data = state_report()
        failure = ""
        if data["service"] not in ("active", "unknown") and has_systemd():
            failure = "the service is not active: " + str(data["service"])
        elif ports and not data["listening"]:
            failure = "the ports did not open: " + str(ports)
        if failure:
            if restore_config(CONF + ".bak"):
                stop_core()
                start_core()
                raise ScriptError("start_failed", failure + ", the previous configuration is restored", "start")
            raise ScriptError("start_failed", failure, "start")
    else:
        data = state_report()
    data["applied"] = True
    data["config_digest"] = sha256_bytes(payload)
    if install:
        data["fallback"] = bool(install.get("fallback", False))
        if data["fallback"]:
            data["fallback_version"] = str(install.get("fallback_version", PINNED))
    return data, None


def cmd_test(flags, rest):
    payload = payload_of(flags, "config_b64")
    ok, text = test_config(payload)
    return {"valid": ok, "output": text[:4000]}, None


def cmd_restart(flags, rest):
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "the core is not installed", "restart")
    if not os.path.isfile(CONF):
        raise ScriptError("config_missing", "no configuration is set", "restart")
    stop_core()
    start_core()
    time.sleep(0.6)
    return state_report(), None


def cmd_stop(flags, rest):
    stop_core()
    return state_report(), None


def cmd_start(flags, rest):
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "the core is not installed", "start")
    start_core()
    time.sleep(0.6)
    return state_report(), None


def cmd_logs(flags, rest):
    tail = int(str(flags.get("tail", "120")))
    lines = []
    if has_systemd():
        code, text = run(["journalctl", "-u", "xray.service", "-n", str(tail), "--no-pager"], timeout=60)
        lines = [line for line in text.splitlines()]
    log_path = os.path.join(STATE, "xray.log")
    if not lines and os.path.isfile(log_path):
        with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()[-tail:]
    return {"lines": lines[-tail:]}, None


def cmd_x25519(flags, rest):
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "the core is not installed", "keys")
    code, text = run([CORE, "x25519"], timeout=30)
    if code != 0:
        raise ScriptError("internal", "the core returned no keys: " + text[:200], "keys")
    private = ""
    public = ""
    for line in text.splitlines():
        token = line.strip()
        lower = token.lower()
        if lower.startswith("private") or lower.startswith("privatekey"):
            private = token.split(":", 1)[1].strip() if ":" in token else token.split()[-1]
        elif lower.startswith("public") or lower.startswith("password"):
            public = token.split(":", 1)[1].strip() if ":" in token else token.split()[-1]
    if not private or not public:
        raise ScriptError("internal", "the core answer is not parseable: " + text[:200], "keys")
    return {"private": private, "public": public}, None


def api_endpoint():
    try:
        config = read_config()
    except ScriptError:
        return ""
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        port = 0
        try:
            port = int(inbound.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not port or not 1 <= port <= 65535:
            continue
        if str(inbound.get("tag") or "") == "api" or str(inbound.get("protocol") or "") == "tunnel":
            return "127.0.0.1:%d" % port
    return ""


def parse_stats(text):
    found = {}
    raw = (text or "").strip()
    if not raw:
        return found
    items = []
    try:
        document = json.loads(raw)
    except ValueError:
        document = None
    if isinstance(document, dict):
        items = document.get("stat") or document.get("stats") or []
    elif isinstance(document, list):
        items = document
    else:
        for line in raw.splitlines():
            token = line.strip()
            if not token:
                continue
            try:
                items.append(json.loads(token))
            except ValueError:
                continue
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name or len(name) > 300:
            continue
        try:
            number = int(item.get("value") or 0)
        except (TypeError, ValueError):
            number = 0
        found[name] = max(number, 0)
    return found


def cmd_stats(flags, rest):
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "the core is not installed", "stats")
    server = api_endpoint()
    if not server:
        raise ScriptError("not_found", "the api inbound is not in the config, turn the api on in the core settings", "stats")
    pattern = str(flags.get("pattern", "user>>>"))[:64]
    code, text = run([CORE, "api", "statsquery", "--server=" + server, "-pattern", pattern, "-reset=false"], timeout=60)
    if code != 0 or not (text or "").strip():
        code, text = run([CORE, "api", "stats", "--server=" + server, "-pattern", pattern, "-reset=false"], timeout=60)
    if code != 0:
        raise ScriptError("internal", "the stats query failed: " + (text or "").strip()[:200], "stats")
    return {"stats": parse_stats(text), "server": server}, None


def cmd_uninstall(flags, rest):
    stop_core()
    removed = []
    if os.path.isfile(UNIT):
        if has_systemd():
            run(["systemctl", "disable", "xray.service"], timeout=60)
        os.unlink(UNIT)
        if has_systemd():
            run(["systemctl", "daemon-reload"], timeout=60)
        removed.append("unit")
    if flags.get("purge", False):
        for target in (CONF_DIR, SHARE, STATE):
            if os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
                removed.append(target)
        if os.path.isfile(CORE):
            os.unlink(CORE)
            removed.append(CORE)
    return {"removed": removed, "purge": flag_on(flags.get("purge"), False)}, None


def cmd_mldsa65(flags, rest):
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "the core is not installed", "keys")
    code, text = run([CORE, "mldsa65"], timeout=60)
    if code != 0:
        raise ScriptError("internal", "the core returned no ml-dsa-65 keys: " + text[:200], "keys")
    seed = ""
    verify = ""
    for line in text.splitlines():
        token = line.strip()
        lower = token.lower()
        if not token:
            continue
        value = token.split(":", 1)[1].strip() if ":" in token else token.split()[-1]
        if lower.startswith("seed") or lower.startswith("private"):
            seed = value
        elif lower.startswith("verify") or lower.startswith("public"):
            verify = value
    if not seed or not verify:
        raise ScriptError("internal", "the ml-dsa-65 answer is not parseable: " + text[:200], "keys")
    return {"seed": seed, "verify": verify}, None


def cmd_vlessenc(flags, rest):
    if not os.path.isfile(CORE):
        raise ScriptError("not_installed", "the core is not installed", "keys")
    code, text = run([CORE, "vlessenc"], timeout=60)
    if code != 0:
        raise ScriptError("internal", "the core returned no vless encryption: " + text[:200], "keys")
    items = []
    current = {"auth": "", "decryption": "", "encryption": ""}
    for line in text.splitlines():
        token = line.strip()
        if not token:
            continue
        lower = token.lower()
        value = token.split(":", 1)[1].strip() if ":" in token else token.split()[-1]
        if lower.startswith("authentication"):
            if current["decryption"] or current["encryption"]:
                items.append(current)
                current = {"auth": "", "decryption": "", "encryption": ""}
            current["auth"] = value
        elif lower.startswith("decryption"):
            current["decryption"] = value
        elif lower.startswith("encryption") or lower.startswith("password"):
            if not current["encryption"]:
                current["encryption"] = value
    if current["decryption"] or current["encryption"]:
        items.append(current)
    out = {"items": [item for item in items if item["decryption"] or item["encryption"]]}
    out["decryption"] = out["items"][0]["decryption"] if out["items"] else ""
    out["encryption"] = out["items"][0]["encryption"] if out["items"] else ""
    if not out["items"]:
        raise ScriptError("internal", "the core returned no vless encryption: " + text[:200], "keys")
    return out, None


def sub_paths():
    server = os.path.join(path_of("/usr/local/bin"), "obhod-sub")
    registry = os.path.join(STATE, "subscriptions.json")
    unit = os.path.join(UNIT_DIR, "obhod-sub.service")
    return server, registry, unit


def write_sub_unit(server, registry, port):
    unit = sub_paths()[2]
    if not os.path.isdir(UNIT_DIR):
        os.makedirs(UNIT_DIR, exist_ok=True)
    py_exec = (shutil.which("python3") or sys.executable) if run is _ORIG_RUN else sys.executable
    body = "\n".join(
        [
            "[Unit]",
            "Description=OBHOD subscription server",
            "After=network.target",
            "",
            "[Service]",
            "User=root",
            "Environment=OBHOD_SUB_REGISTRY=" + registry,
            "Environment=OBHOD_SUB_PORT=" + str(int(port)),
            "Environment=OBHOD_SUB_BIND=127.0.0.1",
            "Environment=OBHOD_SUB_ACCESS_LOG=" + os.path.join(path_of("/var/log/xray"), "sub.log"),
            "Environment=OBHOD_SECURITY_LOG=" + os.path.join(path_of("/var/log/obhod"), "security.log"),
            "ExecStart=" + py_exec + " " + server,
            "Restart=always",
            "RestartSec=3",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "ReadWritePaths=-" + STATE + " -" + path_of("/var/log/xray") + " -" + path_of("/var/log/obhod"),
            "RestrictAddressFamilies=AF_INET AF_INET6",
            "MemoryDenyWriteExecute=true",
            "LogsDirectory=obhod",
            "LogsDirectoryMode=0700",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    with open(unit, "w", encoding="utf-8") as handle:
        handle.write(body)
    return unit


def stop_sub():
    unit = sub_paths()[2]
    if has_systemd():
        run(["systemctl", "stop", "obhod-sub.service"], timeout=60)
        run(["systemctl", "disable", "obhod-sub.service"], timeout=60)
    pid_file = os.path.join(STATE, "sub.pid")
    if os.path.isfile(pid_file):
        try:
            with open(pid_file, "r", encoding="utf-8") as handle:
                pid = int(handle.read().strip() or 0)
            if pid > 0:
                os.kill(pid, 15)
        except (OSError, ValueError):
            pass
        try:
            os.unlink(pid_file)
        except OSError:
            pass
    if os.path.isfile(unit):
        try:
            os.unlink(unit)
        except OSError:
            pass
        if has_systemd():
            run(["systemctl", "daemon-reload"], timeout=60)


def sub_state(port):
    server, registry, unit = sub_paths()
    entries = 0
    if os.path.isfile(registry):
        try:
            with open(registry, "r", encoding="utf-8") as handle:
                body = json.load(handle)
            entries = len(body.get("entries") or {})
        except (OSError, ValueError):
            entries = 0
    listening = port_open(int(port)) if port else False
    service = "inactive"
    if has_systemd():
        code, text = run(["systemctl", "is-active", "obhod-sub.service"], timeout=30)
        service = text.strip() or "unknown"
    else:
        pid_file = os.path.join(STATE, "sub.pid")
        service = "active" if os.path.isfile(pid_file) else "inactive"
    return {
        "installed": os.path.isfile(server),
        "registry": registry if os.path.isfile(registry) else "",
        "unit": unit if os.path.isfile(unit) else "",
        "entries": entries,
        "port": int(port or 0),
        "listening": bool(listening),
        "service": service,
        "systemd": has_systemd(),
    }


def start_sub(port, registry):
    if has_systemd():
        run(["systemctl", "daemon-reload"], timeout=60)
        run(["systemctl", "enable", "obhod-sub.service"], timeout=90)
        code, text = run(["systemctl", "restart", "obhod-sub.service"], timeout=120)
        if code != 0:
            raise ScriptError("start_failed", "systemctl restart obhod-sub: " + text[:400], "sub")
        return
    if not os.path.isdir(STATE):
        os.makedirs(STATE, exist_ok=True)
    server = sub_paths()[0]
    log_path = os.path.join(STATE, "sub.log")
    env = dict(os.environ)
    env["OBHOD_SUB_REGISTRY"] = registry
    env["OBHOD_SUB_PORT"] = str(int(port))
    env["OBHOD_SUB_BIND"] = "127.0.0.1"
    env["OBHOD_SECURITY_LOG"] = os.path.join(path_of("/var/log/obhod"), "security.log")
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(
            [sys.executable, server],
            stdout=log,
            stderr=log,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    with open(os.path.join(STATE, "sub.pid"), "w", encoding="utf-8") as handle:
        handle.write(str(proc.pid))
    time.sleep(0.8)
    if proc.poll() is not None:
        raise ScriptError("start_failed", "the subscription server exited right after the start", "sub")


SUB_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9-]{1,63}){2,4}(?::(?:[1-9][0-9]{3,4}))?$")


def sub_domain(flags):
    host = str(flags.get("domain", "") or "").strip().lower()
    if not host:
        raise ScriptError("no_domain", "the subscription needs a public domain, bring the tunnel up first", "sub")
    bare = host.split(":", 1)[0]
    if not SUB_DOMAIN_RE.match(host) or bare.replace(".", "").isdigit():
        raise ScriptError("bad_arg", "the subscription domain is not valid", "sub")
    return host


def cmd_sub_install(flags, rest):
    sub_domain(flags)
    payload = payload_of(flags, "server_b64")
    if not payload:
        raise ScriptError("bad_arg", "the subscription server body is required", "sub")
    server, registry, unit = sub_paths()
    if not os.path.isdir(os.path.dirname(server)):
        os.makedirs(os.path.dirname(server), exist_ok=True)
    with open(server, "wb") as handle:
        handle.write(payload)
    os.chmod(server, 0o755)
    note("the subscription server is written")
    return sub_state(int(str(flags.get("port", "2096")))), None


def write_atomic(target, payload, mode=0o600):
    folder = os.path.dirname(target) or "."
    if not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)
    handle, tmp = tempfile.mkstemp(dir=folder, prefix=".obhod-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except OSError:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise
    return target


def cmd_sub_sync(flags, rest):
    sub_domain(flags)
    payload = payload_of(flags, "registry_b64")
    if not payload:
        raise ScriptError("bad_arg", "the subscription registry is required", "sub")
    server, registry, unit = sub_paths()
    if not os.path.isfile(server):
        raise ScriptError("not_installed", "the subscription server is not installed", "sub")
    try:
        body = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ScriptError("bad_arg", "the subscription registry is not json", "sub") from None
    port = int(str(flags.get("port", body.get("port", 2096))))
    if not 1 <= port <= 65535:
        raise ScriptError("bad_arg", "the port must be between 1 and 65535", "sub")
    if os.path.islink(registry):
        raise ScriptError("bad_arg", "the registry path is a symbolic link", "sub")
    write_atomic(registry, json.dumps(body, ensure_ascii=False, sort_keys=True), 0o600)
    state = sub_state(port)
    if state["installed"] and state["listening"] and int(state["port"]) == port and os.path.isfile(unit):
        note("the subscription registry is rewritten, the service keeps running")
        return state, None
    stop_sub()
    deadline = time.time() + 6
    while time.time() < deadline and port_open(port):
        time.sleep(0.3)
    if port_open(port):
        raise ScriptError(
            "port_busy",
            "port %d is held by another service, the subscription server was not restarted, pick another port" % port,
            "sub",
        )
    write_sub_unit(server, registry, port)
    start_sub(port, registry)
    deadline = time.time() + 10
    while time.time() < deadline and not port_open(port):
        time.sleep(0.3)
    note("the subscription registry is written")
    return sub_state(port), None


def cmd_sub_status(flags, rest):
    return sub_state(int(str(flags.get("port", "2096")))), None


def cmd_sub_stop(flags, rest):
    stop_sub()
    return sub_state(int(str(flags.get("port", "2096")))), None


TUNNEL_KEY_RE = re.compile(
    r"(tskey-(?:auth|client)-[A-Za-z0-9_]{4,96}(?:-[A-Za-z0-9_]{2,96}){0,6}(?:\?[A-Za-z0-9_=&%-]{1,96})?)"
)
TUNNEL_API_KEY_RE = re.compile(r"(tskey-api-[A-Za-z0-9_-]{6,160})")
TUNNEL_TAGS_FLAG_RE = re.compile(r"--advertise-tags(?:=|\s+)['\"]?([A-Za-z0-9_:,.-]+)['\"]?")
TUNNEL_TAG_ITEM_RE = re.compile(r"^tag:[A-Za-z0-9_-]{1,48}$")
TUNNEL_HOST_FLAG_RE = re.compile(r"--hostname(?:=|\s+)['\"]?([A-Za-z0-9][A-Za-z0-9-]{0,61})['\"]?")
APPROVAL_URL_RE = re.compile(r"https://(?:login|console)\.tailscale\.com/[^\s\"'<>]+")
TUNNEL_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
TUNNEL_FQDN_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9-]{1,63}){1,4}(?::[0-9]{2,5})?$")
TUNNEL_CODENAME_RE = re.compile(r"^[a-z]{2,16}$")
TUNNEL_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+\.ts\.net(?::[0-9]{2,5})?")
TUNNEL_FUNNEL_PORTS = (8443, 10000)
TAILSCALE_INSTALL_URL = "https://tailscale.com/install.sh"
TAILSCALE_DNS_ADMIN_URL = "https://login.tailscale.com/admin/dns"
AUTOFUNNEL_UNIT = "obhod-ts-autofunnel"
FUNNEL_PROMPT_HINTS = (
    "to enable, visit",
)


def extract_tailnet_key(raw):
    text = str(raw or "").strip()
    if not text:
        return ""
    match = TUNNEL_KEY_RE.search(text)
    return match.group(1) if match else ""


def clean_tunnel_tags(raw):
    found = []
    for part in str(raw or "").split(","):
        token = part.strip()
        if token and TUNNEL_TAG_ITEM_RE.match(token) and token not in found:
            found.append(token)
    return ",".join(found[:8])


def extract_tunnel_tags(raw):
    match = TUNNEL_TAGS_FLAG_RE.search(str(raw or ""))
    if not match:
        return ""
    return clean_tunnel_tags(match.group(1))


def extract_tunnel_host_flag(raw):
    match = TUNNEL_HOST_FLAG_RE.search(str(raw or ""))
    return match.group(1).lower() if match else ""


def pick_funnel_url(text, prefer_port=0):
    candidates = []
    for line in str(text or "").splitlines():
        low = line.lower()
        if "tailnet only" in low and "funnel" not in low:
            continue
        for match in TUNNEL_URL_RE.finditer(line):
            url = match.group(0)[:128]
            if url not in candidates:
                candidates.append(url)
    if not candidates:
        return ""
    if prefer_port:
        suffix = ":%d" % int(prefer_port)
        for item in candidates:
            if item.endswith(suffix):
                return item
    return candidates[0]


TAILSCALE_STABLE_JSON_URL = "https://pkgs.tailscale.com/stable/?mode=json"
TAILSCALE_STABLE_BASE_URL = "https://pkgs.tailscale.com/stable/"
TAILSCALE_ARCH_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "arm",
    "armv7": "arm",
    "armv6l": "arm",
    "i686": "386",
    "i386": "386",
    "riscv64": "riscv64",
}
SYSTEMD_RUN_ERRORS = (
    "Failed to start transient service unit",
    "Failed to connect to bus",
    "Access denied",
)


def ensure_standard_path():
    cur = os.environ.get("PATH", "")
    parts = [item for item in cur.split(":") if item]
    for folder in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"):
        if folder not in parts:
            parts.append(folder)
    os.environ["PATH"] = ":".join(parts)


def sandboxed_host():
    if run is not _ORIG_RUN:
        return False
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return False
    if not has_systemd() or not shutil.which("systemd-run"):
        return False
    for probe in ("/usr/share", "/usr", "/etc", "/proc/sys/net/ipv4"):
        if os.path.exists(probe) and not os.access(probe, os.W_OK):
            return True
    return False


def systemd_run_argv(argv, unit_name=""):
    systemd_bin = shutil.which("systemd-run") or "systemd-run"
    cmd = [
        systemd_bin,
        "--pipe",
        "--wait",
        "--quiet",
        "--collect",
    ]
    if unit_name:
        cmd.append("--unit=" + unit_name)
    cmd.extend(
        [
            "-p",
            "WorkingDirectory=/",
            "-p",
            "KillMode=control-group",
            "-E",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
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
            "--",
        ]
    )
    cmd.extend([str(item) for item in argv])
    return cmd


def run_host(argv, timeout=180, stdin_bytes=None):
    if run is not _ORIG_RUN:
        return run(argv, timeout=timeout)
    ensure_standard_path()
    host_env = dict(os.environ)
    host_env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    host_env["HOME"] = "/root"
    host_env["DEBIAN_FRONTEND"] = "noninteractive"
    if sandboxed_host():
        cmd = systemd_run_argv(argv)
        try:
            escaped = subprocess.run(
                cmd,
                input=stdin_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                env=host_env,
                cwd="/",
                check=False,
            )
            out_text = (escaped.stdout or b"").decode("utf-8", "replace").strip()
            rc = int(escaped.returncode or 0)
            if rc == 0 or not any(marker in out_text for marker in SYSTEMD_RUN_ERRORS):
                return rc, out_text
        except subprocess.TimeoutExpired as exc:
            raw_out = exc.stdout or b""
            partial = raw_out.strip() if isinstance(raw_out, str) else raw_out.decode("utf-8", "replace").strip()
            raise ScriptError("timeout", "command timed out after %ss: %s" % (timeout, partial[:320]))
        except OSError:
            pass
    if stdin_bytes is not None:
        try:
            proc = subprocess.run(
                argv,
                input=stdin_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                env=host_env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raw_out = exc.stdout or b""
            partial = raw_out.strip() if isinstance(raw_out, str) else raw_out.decode("utf-8", "replace").strip()
            raise ScriptError("timeout", "command timed out after %ss: %s" % (timeout, partial[:320]))
        return int(proc.returncode or 0), (proc.stdout or b"").decode("utf-8", "replace").strip()
    return run(argv, timeout=timeout)


def detect_netcheck_ip(found):
    if run is not _ORIG_RUN:
        return ""
    try:
        code, text = run_host([found, "netcheck", "--format=json"], timeout=6)
    except ScriptError:
        return ""
    if code != 0 or not text:
        return ""
    try:
        data = json.loads(text)
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    raw = str(data.get("GlobalV4", "") or "").strip()
    if not raw:
        return ""
    host = raw.rsplit(":", 1)[0] if ":" in raw else raw
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return ""
    if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified or parsed.is_multicast:
        return ""
    return str(parsed)


def run_funnel(argv, timeout=30):
    if run is not _ORIG_RUN:
        return run(argv, timeout=timeout)
    ensure_standard_path()
    unit_name = ""
    spawn_argv = list(argv)
    if sandboxed_host():
        unit_name = "obhod-ts-funnel-%s" % os.urandom(4).hex()
        spawn_argv = systemd_run_argv(argv, unit_name=unit_name)
    proc = subprocess.Popen(
        spawn_argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )
    chunks = []
    deadline = time.time() + float(timeout)
    drain_until = None
    fd = proc.stdout.fileno() if proc.stdout is not None else -1
    try:
        while True:
            now = time.time()
            limit = drain_until if drain_until is not None else deadline
            if now >= limit:
                break
            if fd >= 0:
                ready, _, _ = select.select([fd], [], [], min(0.25, max(0.05, limit - now)))
                if ready:
                    piece = os.read(fd, 4096)
                    if piece:
                        chunks.append(piece)
                        joined = b"".join(chunks).decode("utf-8", "replace")
                        low = joined.lower()
                        if drain_until is None and (
                            APPROVAL_URL_RE.search(joined)
                            or any(hint in low for hint in FUNNEL_PROMPT_HINTS)
                        ):
                            drain_until = min(deadline, time.time() + 0.5)
                    elif proc.poll() is not None:
                        break
            if proc.poll() is not None:
                if fd >= 0:
                    while True:
                        ready, _, _ = select.select([fd], [], [], 0.05)
                        if not ready:
                            break
                        rest = os.read(fd, 4096)
                        if not rest:
                            break
                        chunks.append(rest)
                return proc.returncode, b"".join(chunks).decode("utf-8", "replace").strip()
        if unit_name and shutil.which("systemctl"):
            subprocess.run(
                ["systemctl", "stop", unit_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        return 1, b"".join(chunks).decode("utf-8", "replace").strip()
    finally:
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass


def tunnel_binary():
    if run is _ORIG_RUN:
        ensure_standard_path()
    return shutil.which("tailscale")


def tunnel_state(prefer_port=0):
    found = tunnel_binary()
    out = {
        "installed": bool(found),
        "version": "",
        "backend": "absent",
        "hostname": "",
        "url": "",
        "funnel": False,
        "key_expiry": "",
        "expired": False,
        "have_node_key": False,
        "tags": [],
        "public_ip": "",
    }
    if not found:
        return out
    code, text = run_host([found, "version"], timeout=20)
    if code == 0 and text:
        out["version"] = text.split()[0][:32]
    code, text = run_host([found, "status", "--json"], timeout=30)
    if code == 0 and text:
        try:
            data = json.loads(text)
        except ValueError:
            data = {}
        if isinstance(data, dict):
            out["backend"] = str(data.get("BackendState", "unknown"))[:24]
            out["have_node_key"] = bool(data.get("HaveNodeKey", False))
            self_node = data.get("Self") or {}
            if isinstance(self_node, dict):
                name = str(self_node.get("DNSName", "") or "").rstrip(".")
                if name:
                    out["hostname"] = name[:96]
                raw_tags = self_node.get("Tags") or []
                if isinstance(raw_tags, list):
                    out["tags"] = [str(item) for item in raw_tags if TUNNEL_TAG_ITEM_RE.match(str(item))][:8]
                raw_exp = str(self_node.get("KeyExpiry", "") or "").strip()
                if raw_exp.startswith("0001-"):
                    raw_exp = ""
                expired = bool(self_node.get("Expired", False)) or (out["have_node_key"] and out["backend"] == "NeedsLogin")
                out["expired"] = expired
                if out["backend"] == "Running" and not expired and (not raw_exp or out["tags"]):
                    out["key_expiry"] = "never"
                else:
                    out["key_expiry"] = raw_exp[:32]
    if out["backend"] == "Running":
        out["public_ip"] = detect_netcheck_ip(found)
    code, text = run_host([found, "funnel", "status"], timeout=30)
    if code == 0 and text:
        chosen_url = pick_funnel_url(text, prefer_port)
        if chosen_url:
            out["url"] = chosen_url
            out["funnel"] = True
    return out


def cmd_tunnel_status(flags, rest):
    return tunnel_state(), None


def fetch_url_bytes(url, timeout=120):
    handler = urllib.request.build_opener()
    try:
        with handler.open(url, timeout=timeout) as answer:
            return answer.read()
    except (urllib.error.URLError, OSError) as exc:
        if shutil.which("curl"):
            proc = subprocess.run(
                ["curl", "-fsSL", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                return proc.stdout
        raise ScriptError("internal", "download failed (%s): %s" % (url, str(exc)[:200]), "tunnel")


def fetch_tailscale_installer():
    return fetch_url_bytes(TAILSCALE_INSTALL_URL, timeout=90)


def install_tailscale_tarball():
    machine = os.uname().machine.lower()
    ts_arch = TAILSCALE_ARCH_MAP.get(machine, "")
    if not ts_arch:
        raise ScriptError("unsupported_arch", "tailscale static archive is not available for " + machine, "tunnel")
    meta_raw = fetch_url_bytes(TAILSCALE_STABLE_JSON_URL, timeout=60)
    try:
        meta = json.loads(meta_raw.decode("utf-8", "replace"))
    except ValueError:
        raise ScriptError("internal", "tailscale stable metadata is invalid json", "tunnel")
    tarballs = (meta.get("Tarballs") or {}) if isinstance(meta, dict) else {}
    tar_name = str(tarballs.get(ts_arch, "") or "").strip()
    if not tar_name or "/" in tar_name or not tar_name.endswith(".tgz"):
        raise ScriptError("internal", "tailscale tarball name is missing for " + ts_arch, "tunnel")
    archive_bytes = fetch_url_bytes(TAILSCALE_STABLE_BASE_URL + tar_name, timeout=300)
    bin_dir = path_of("/usr/local/bin")
    os.makedirs(bin_dir, exist_ok=True)
    extracted = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            base = os.path.basename(member.name)
            if base in ("tailscale", "tailscaled"):
                extracted[base] = tar.extractfile(member).read()
    if "tailscale" not in extracted or "tailscaled" not in extracted:
        raise ScriptError("internal", "tailscale tarball did not contain tailscale and tailscaled", "tunnel")
    for name, payload in extracted.items():
        target = os.path.join(bin_dir, name)
        fd, tmp_bin = tempfile.mkstemp(dir=bin_dir, prefix=".obhod-" + name + "-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_bin, 0o755)
            os.replace(tmp_bin, target)
        except OSError:
            if os.path.exists(tmp_bin):
                try:
                    os.unlink(tmp_bin)
                except OSError:
                    pass
            raise
    os.makedirs(UNIT_DIR, exist_ok=True)
    unit_file = os.path.join(UNIT_DIR, "tailscaled.service")
    daemon_bin = os.path.join(bin_dir, "tailscaled")
    unit_body = "\n".join(
        [
            "[Unit]",
            "Description=Tailscale node agent",
            "Documentation=https://tailscale.com/kb/",
            "Wants=network-pre.target",
            "After=network-pre.target NetworkManager.service systemd-resolved.service",
            "",
            "[Service]",
            "ExecStart=" + daemon_bin + " --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock --port=41641",
            "ExecStopPost=" + daemon_bin + " --cleanup",
            "Restart=on-failure",
            "RuntimeDirectory=tailscale",
            "RuntimeDirectoryMode=0755",
            "StateDirectory=tailscale",
            "StateDirectoryMode=0700",
            "CacheDirectory=tailscale",
            "CacheDirectoryMode=0750",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    write_atomic(unit_file, unit_body, 0o644)
    if has_systemd():
        run_host(["systemctl", "daemon-reload"], timeout=60)
        run_host(["systemctl", "enable", "--now", "tailscaled"], timeout=60)


def enable_exit_node_forwarding():
    if run is not _ORIG_RUN:
        return
    sysctl_dir = path_of("/etc/sysctl.d")
    conf_path = os.path.join(sysctl_dir, "99-obhod-tailscale.conf")
    try:
        os.makedirs(sysctl_dir, exist_ok=True)
        write_atomic(conf_path, "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n", 0o644)
    except OSError:
        pass
    try:
        run_host(["sysctl", "-p", conf_path], timeout=15)
    except ScriptError:
        pass


def cmd_tunnel_install(flags, rest):
    found = tunnel_binary()
    if found:
        if has_systemd():
            run_host(["systemctl", "enable", "--now", "tailscaled"], timeout=60)
        return tunnel_state(), None
    if not has_systemd():
        raise ScriptError("unsupported", "tailscale needs systemd", "tunnel")
    if not shutil.which("curl") and shutil.which("apt-get"):
        run_host(["apt-get", "update"], timeout=300)
        run_host(["apt-get", "install", "-y", "curl", "ca-certificates"], timeout=300)
    script = fetch_tailscale_installer()
    if len(script) < 200 or not script.lstrip().startswith(b"#!/bin/sh"):
        raise ScriptError("internal", "tailscale install.sh looks broken", "tunnel")
    code = 1
    text = ""
    if sandboxed_host():
        code, text = run_host(["/bin/sh", "-s"], timeout=900, stdin_bytes=script)
    else:
        fd, script_path = tempfile.mkstemp(prefix="obhod-tailscale-", suffix=".sh")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(script)
            os.chmod(script_path, 0o700)
            code, text = run(["sh", script_path], timeout=900)
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass
    if (code != 0 or not tunnel_binary()) and run is _ORIG_RUN:
        note("install.sh exited with %s, falling back to official static tarball" % code)
        try:
            install_tailscale_tarball()
            code = 0
        except ScriptError as fallback_exc:
            raise ScriptError(
                "internal",
                "tailscale install failed (script: %s; tarball: %s)" % (text[:180], fallback_exc.message[:160]),
                "tunnel",
            )
    if code != 0:
        raise ScriptError("internal", "tailscale install.sh failed: " + text[:300], "tunnel")
    if has_systemd():
        run_host(["systemctl", "enable", "--now", "tailscaled"], timeout=60)
    if not tunnel_binary():
        raise ScriptError("internal", "tailscale is still missing after install.sh", "tunnel")
    return tunnel_state(), None


def stop_funnel_autofinish():
    if run is not _ORIG_RUN:
        return
    if shutil.which("systemctl"):
        subprocess.run(
            ["systemctl", "stop", AUTOFUNNEL_UNIT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )


def start_funnel_autofinish(found, https_port, port):
    if run is not _ORIG_RUN:
        return
    stop_funnel_autofinish()
    loop_script = (
        'ts="$1"; hp="$2"; lp="$3"; i=0; '
        'while [ "$i" -lt 100 ]; do '
        '"$ts" serve --bg --https="$hp" "http://127.0.0.1:$lp" >/dev/null 2>&1 || true; '
        'if "$ts" funnel --bg --https="$hp" "http://127.0.0.1:$lp" >/dev/null 2>&1; then '
        'if "$ts" funnel status 2>/dev/null | grep -q "ts\\.net"; then exit 0; fi; '
        'fi; '
        'i=$((i + 1)); sleep 3; '
        'done'
    )
    shell_argv = ["/bin/sh", "-c", loop_script, "obhod-autofunnel", str(found), str(int(https_port)), str(int(port))]
    systemd_bin = shutil.which("systemd-run")
    if has_systemd() and systemd_bin:
        cmd = [
            systemd_bin,
            "--quiet",
            "--collect",
            "--unit=" + AUTOFUNNEL_UNIT,
            "-p",
            "WorkingDirectory=/",
            "-p",
            "KillMode=control-group",
            "-E",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "-E",
            "HOME=/root",
            "--",
        ] + shell_argv
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        subprocess.Popen(
            shell_argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        pass


def cmd_tunnel_up(flags, rest):
    raw_key = str(flags.get("key", "") or "").strip()
    key = extract_tailnet_key(raw_key)
    if raw_key and not key:
        if TUNNEL_API_KEY_RE.search(raw_key):
            raise ScriptError("api_key_wrong", "tskey-api is a REST API token, paste a tskey-auth auth key instead", "tunnel")
        raise ScriptError("bad_arg", "the tailscale auth key is not valid", "tunnel")
    raw_host = str(flags.get("hostname", "") or "").strip().lower() or extract_tunnel_host_flag(raw_key)
    if not raw_host:
        hostname = ""
    elif TUNNEL_HOST_RE.match(raw_host):
        hostname = raw_host
    elif TUNNEL_FQDN_RE.match(raw_host):
        hostname = raw_host.split(".", 1)[0]
    else:
        raise ScriptError("bad_arg", "the tunnel hostname is not valid", "tunnel")
    port = int(str(flags.get("port", "2096")))
    if not 1 <= port <= 65535 or port == 443:
        raise ScriptError("bad_arg", "the tunnel port is out of range", "tunnel")
    https_port = int(str(flags.get("https_port", "0") or "0"))
    if https_port not in TUNNEL_FUNNEL_PORTS:
        https_port = TUNNEL_FUNNEL_PORTS[os.urandom(1)[0] % len(TUNNEL_FUNNEL_PORTS)]
    found = tunnel_binary()
    if not found and str(flags.get("auto_install", "")) == "1":
        cmd_tunnel_install(flags, rest)
        found = tunnel_binary()
    if not found:
        raise ScriptError("not_installed", "tailscale is not installed", "tunnel")
    stop_funnel_autofinish()
    exit_node = str(flags.get("exit_node", "")) == "1" or "--advertise-exit-node" in raw_key
    if exit_node:
        enable_exit_node_forwarding()
    tags = clean_tunnel_tags(flags.get("tags", "")) or extract_tunnel_tags(raw_key)
    extra_flags = ["--accept-dns=false", "--accept-routes=false"]
    if hostname:
        extra_flags.append("--hostname=" + hostname)
    if tags:
        extra_flags.append("--advertise-tags=" + tags)
    if exit_node:
        extra_flags.append("--advertise-exit-node")
    if key:
        up_cmd = [found, "up", "--authkey=" + key] + extra_flags
        code, text = run_host(up_cmd, timeout=180)
        if code != 0 and "--reset" in (text or ""):
            code, text = run_host(up_cmd + ["--reset"], timeout=180)
        if code != 0:
            cur = tunnel_state(https_port)
            if cur.get("backend") == "Running" and cur.get("have_node_key") and not cur.get("expired"):
                reconf = [found, "up"] + extra_flags
                rc2, txt2 = run_host(reconf, timeout=120)
                if rc2 != 0 and "--reset" in (txt2 or ""):
                    run_host(reconf + ["--reset"], timeout=120)
            else:
                raise ScriptError("internal", "tailscale up failed: " + text[:300], "tunnel")
    else:
        before = tunnel_state(https_port)
        if before.get("expired") or before.get("backend") in {"NeedsLogin", "NoState", "absent"}:
            raise ScriptError("key_expired", "the tailscale node key expired, paste a new tskey-auth key", "tunnel")
        if before.get("backend") != "Running":
            reconf = [found, "up"] + extra_flags
            code, text = run_host(reconf, timeout=120)
            if code != 0 and "--reset" in (text or ""):
                code, text = run_host(reconf + ["--reset"], timeout=120)
            if code != 0:
                raise ScriptError("internal", "tailscale up failed: " + text[:300], "tunnel")
        elif before.get("url"):
            return before, None
    code, text = run_funnel([found, "funnel", "--bg", "--https=%d" % https_port, "http://127.0.0.1:%d" % port], timeout=65)
    if code != 0:
        approval = APPROVAL_URL_RE.search(text or "")
        if not approval and run is _ORIG_RUN:
            _, serve_text = run_funnel(
                [found, "serve", "--bg", "--https=%d" % https_port, "http://127.0.0.1:%d" % port],
                timeout=15,
            )
            if serve_text:
                serve_match = APPROVAL_URL_RE.search(serve_text)
                if serve_match:
                    approval = serve_match
                    text = serve_text
                elif not text:
                    text = serve_text
        cur = tunnel_state(https_port)
        if cur.get("url"):
            return cur, None
        low = (text or "").lower()
        if approval or any(word in low for word in ("funnel", "https", "certificate", "policy", "nodeattrs", "enable", "serve", "dns")):
            approval_link = approval.group(0)[:200] if approval else TAILSCALE_DNS_ADMIN_URL
            step = "funnel"
            if "/f/serve" in approval_link:
                step = "serve"
            elif not approval:
                step = "dns"
            start_funnel_autofinish(found, https_port, port)
            raise ScriptError(
                "funnel_disabled",
                (text or "tailscale funnel is not enabled in the admin console")[:320],
                "tunnel",
                data={
                    "hostname": cur.get("hostname", ""),
                    "key_expiry": cur.get("key_expiry", ""),
                    "expired": bool(cur.get("expired", False)),
                    "have_node_key": bool(cur.get("have_node_key", False)),
                    "approval_url": approval_link,
                    "step": step,
                    "https_port": int(https_port),
                    "public_ip": cur.get("public_ip", ""),
                },
            )
        raise ScriptError(
            "internal",
            "the funnel did not start: " + (text or "")[:300],
            "tunnel",
        )
    state = tunnel_state(https_port)
    for _ in range(5):
        if state["url"]:
            break
        time.sleep(0.6)
        state = tunnel_state(https_port)
    if not state["url"] and state["hostname"].endswith(".ts.net"):
        state["url"] = "https://%s:%d" % (state["hostname"], https_port)
        state["funnel"] = True
    if not state["url"]:
        raise ScriptError("internal", "the funnel is not answering with a ts.net name yet, dns may still be propagating", "tunnel")
    return state, None


def cmd_tunnel_down(flags, rest):
    stop_funnel_autofinish()
    found = tunnel_binary()
    if not found:
        return tunnel_state(), None
    run_host([found, "funnel", "reset"], timeout=60)
    run_host([found, "serve", "reset"], timeout=30)
    return tunnel_state(), None


COMMANDS = {
    "probe": cmd_probe,
    "install-core": cmd_install,
    "apply": cmd_apply,
    "test-config": cmd_test,
    "restart": cmd_restart,
    "stop": cmd_stop,
    "start": cmd_start,
    "logs": cmd_logs,
    "x25519": cmd_x25519,
    "mldsa65": cmd_mldsa65,
    "vlessenc": cmd_vlessenc,
    "sub-install": cmd_sub_install,
    "sub-sync": cmd_sub_sync,
    "stats": cmd_stats,
    "sub-status": cmd_sub_status,
    "sub-stop": cmd_sub_stop,
    "tunnel-status": cmd_tunnel_status,
    "tunnel-install": cmd_tunnel_install,
    "tunnel-up": cmd_tunnel_up,
    "tunnel-down": cmd_tunnel_down,
    "uninstall": cmd_uninstall,
}


def emit(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stdout.flush()


def main(argv):
    if not argv:
        emit({"proto": PROTO, "result": "err", "code": "bad_arg", "msg": "no command was given", "stage": "args"})
        return 2
    name = argv[0]
    handler = COMMANDS.get(name)
    if handler is None:
        emit({"proto": PROTO, "result": "err", "code": "bad_arg", "msg": "unknown command %s" % name, "stage": "args"})
        return 2
    flags, rest = parse_flags(argv[1:])
    try:
        data, _ = handler(flags, rest)
    except ScriptError as exc:
        err_payload = {
            "proto": PROTO,
            "result": "err",
            "code": exc.code,
            "msg": exc.message,
            "stage": exc.stage,
            "logs": LOGS,
        }
        if exc.data:
            err_payload["data"] = exc.data
        emit(err_payload)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        emit({"proto": PROTO, "result": "err", "code": "internal", "msg": str(exc)[:600], "stage": name, "logs": LOGS})
        return 1
    emit({"proto": PROTO, "result": "ok", "data": data, "logs": LOGS})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))