import base64
import hashlib
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
import zipfile

PROTO = 3
PINNED = "v26.10.21"
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
    "64": "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978",
    "arm64-v8a": "d1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c",
    "arm32-v7a": "89978508fa2ebb4a1e661f2c6ed51d241c4091b3cd17f4c65fdf20baae7dedac",
    "arm32-v6": "cbc12722c484c022f9e31593bd29d5cd4593c98397514ebfc3289953eeb36a64",
    "32": "dde802c3c932aa1b8cdc5010de81b54719ff5e334f7c4800354825ed6c9d68b6",
    "s390x": "12797bc3d865c7339f7722b088d1b0bdbdae179c2e50f41ea2566b0a331d5c6b",
    "riscv64": "3045051037f5f543bd9e4787f331de9e8c83db0a072a26e49ef88512da5bfd48",
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
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    text = proc.stdout.decode("utf-8", "replace").strip()
    if check and proc.returncode != 0:
        raise ScriptError("internal", "command exited with code %s: %s" % (proc.returncode, text[:400]))
    return proc.returncode, text


def has_systemd():
    if os.environ.get("XRAY_NO_SYSTEMD"):
        return False
    return os.path.isdir("/run/systemd/system") and shutil.which("systemctl") is not None


class ScriptError(Exception):
    def __init__(self, code, message, stage=""):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.stage = stage


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


def install_core(version, url, sha256, force):
    if not SAFE_VERSION.match(str(version or "")):
        raise ScriptError("bad_arg", "the version must look like v26.10.21", "download")
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
        write_bytes_atomic(CONF, previous, 0o644)
    except OSError:
        return False
    note("the previous configuration is restored")
    return True


def write_config(payload):
    if not payload:
        raise ScriptError("config_missing", "no configuration was supplied", "config")
    config = json.loads(payload.decode("utf-8"))
    if not isinstance(config, dict) or not config.get("inbounds"):
        raise ScriptError("config_invalid", "the configuration has no inbound", "config")
    ok, text = test_config(payload)
    if not ok:
        raise ScriptError("config_invalid", text[:600] or "the core rejected the configuration", "config")
    backup_config()
    write_bytes_atomic(CONF, payload, 0o644)
    note("the configuration is written")
    return config


def state_report():
    config = read_config()
    ports = listen_ports(config)
    service = unit_state()
    listening = [port for port in ports if port_open(port)]
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


def payload_of(flags, name):
    value = flags.get(name, "")
    if not value:
        return b""
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
        data = install_core(PINNED, str(fallback_url or ""), str(fallback_sha256 or ""), True)
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
    out = {}
    for line in text.splitlines():
        token = line.strip()
        if not token:
            continue
        lower = token.lower()
        value = token.split(":", 1)[1].strip() if ":" in token else token.split()[-1]
        if lower.startswith("decryption"):
            out["decryption"] = value
        elif lower.startswith("encryption") or lower.startswith("password"):
            out.setdefault("encryption", value)
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
            "Environment=OBHOD_SUB_ACCESS_LOG=" + os.path.join(path_of("/var/log/xray"), "sub.log"),
            "Environment=OBHOD_SECURITY_LOG=" + os.path.join(path_of("/var/log/obhod"), "security.log"),
            "ExecStart=" + sys.executable + " " + server,
            "Restart=always",
            "RestartSec=3",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
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


def cmd_sub_install(flags, rest):
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
    write_sub_unit(server, registry, port)
    stop_sub()
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
    "sub-status": cmd_sub_status,
    "sub-stop": cmd_sub_stop,
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
        emit(
            {
                "proto": PROTO,
                "result": "err",
                "code": exc.code,
                "msg": exc.message,
                "stage": exc.stage,
                "logs": LOGS,
            }
        )
        return 1
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        emit({"proto": PROTO, "result": "err", "code": "internal", "msg": str(exc)[:600], "stage": name, "logs": LOGS})
        return 1
    emit({"proto": PROTO, "result": "ok", "data": data, "logs": LOGS})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))