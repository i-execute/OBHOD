from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

PROTO = 1
PINNED_VERSION = "2026.11.1"
PINNED_SHA256 = {
    "amd64": "97bb3b02d23a5980fc9c15a1a270e692da1923f103f920d5b16d4931d5ab55e7",
    "arm64": "b155cec3e48e489cfb8e5c602769fb8c771083018d8881d68b4d18a791567c5a",
}
ROOT = os.environ.get("CLOUDFLARED_ROOT", "")
BIN = os.path.join(ROOT, "usr/local/bin/cloudflared") if ROOT else "/usr/local/bin/cloudflared"
UNIT = os.path.join(ROOT, "etc/systemd/system/obhod-cloudflared.service") if ROOT else "/etc/systemd/system/obhod-cloudflared.service"
LOG = os.path.join(ROOT, "var/log/obhod/cloudflared.log") if ROOT else "/var/log/obhod/cloudflared.log"
STATE = os.path.join(ROOT, "var/lib/obhod/cloudflared.json") if ROOT else "/var/lib/obhod/cloudflared.json"
API = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
RELEASE = "https://github.com/cloudflare/cloudflared/releases/download/{version}/cloudflared-linux-{arch}"
SAFE_VERSION = re.compile(r"^\d{4}\.\d{1,2}\.\d{1,2}$")
SAFE_LOCAL = re.compile(r"^http://(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$")
MAX_BINARY = 128 * 1024 * 1024
LOGS: list[str] = []


class AgentError(Exception):
    def __init__(self, code: str, message: str, stage: str = "cloudflared") -> None:
        super().__init__(message)
        self.code, self.message, self.stage = code, message, stage


def note(text: object) -> None:
    LOGS.append(str(text)[:400])


def machine() -> str:
    value = platform.machine().lower()
    if value in {"x86_64", "amd64"}:
        return "amd64"
    if value in {"aarch64", "arm64"}:
        return "arm64"
    return ""


def run(argv: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout or "")[-8000:]


def atomic(path: str, payload: bytes, mode: int = 0o600) -> None:
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".obhod-", dir=folder)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def state() -> dict:
    try:
        with open(STATE, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(value: dict) -> None:
    atomic(STATE, json.dumps(value, sort_keys=True).encode("utf-8"))


def digest(path: str) -> str:
    value = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def binary_version() -> str:
    if not os.path.isfile(BIN):
        return ""
    code, output = run([BIN, "--version"], 30)
    match = re.search(r"(\d{4}\.\d{1,2}\.\d{1,2})", output)
    return match.group(1) if code == 0 and match else ""


def systemctl(*args: str) -> tuple[int, str]:
    return run(["systemctl", *args], 180)


def service_state() -> str:
    if not os.path.isfile(UNIT):
        return "absent"
    code, output = systemctl("is-active", "obhod-cloudflared.service")
    return "active" if code == 0 and output.strip() == "active" else "inactive"


def status() -> dict:
    current = state()
    return {
        "installed": bool(os.path.isfile(BIN)),
        "version": binary_version(),
        "pinned": PINNED_VERSION,
        "fallback": bool(current.get("fallback", False)),
        "fallback_version": str(current.get("fallback_version", ""))[:24],
        "service": service_state(),
        "unit": bool(os.path.isfile(UNIT)),
        "url": str(current.get("url", ""))[:180],
        "local_url": str(current.get("local_url", ""))[:180],
        "latest_source": str(current.get("latest_source", ""))[:16],
    }


def latest_release(arch: str) -> tuple[str, str, str]:
    try:
        request = urllib.request.Request(API, headers={"Accept": "application/vnd.github+json", "User-Agent": "OBHOD"})
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = json.loads(response.read(1 << 20).decode("utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("assets"), list):
            raise ValueError("invalid release metadata")
        version = str(raw.get("tag_name", "")).lstrip("v")
        if not SAFE_VERSION.match(version):
            raise ValueError("bad release tag")
        expected_asset = "cloudflared-linux-" + arch
        for asset in raw.get("assets", []):
            if not isinstance(asset, dict) or str(asset.get("name", "")) != expected_asset:
                continue
            checksum = str(asset.get("digest", ""))
            if checksum.startswith("sha256:") and re.fullmatch(r"[0-9a-f]{64}", checksum[7:]):
                return version, checksum[7:], "latest"
        raise ValueError("release has no verified asset")
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        note("latest lookup failed; using pinned fallback: " + str(exc))
        expected = PINNED_SHA256.get(arch, "")
        if not expected:
            raise AgentError("unsupported_arch", "no pinned Cloudflared binary for this architecture", "download")
        return PINNED_VERSION, expected, "fallback"


def download(version: str, expected: str, arch: str) -> None:
    url = RELEASE.format(version=version, arch=arch)
    with tempfile.TemporaryDirectory() as directory:
        target = os.path.join(directory, "cloudflared")
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "OBHOD"})
            with urllib.request.urlopen(request, timeout=90) as response, open(target, "wb") as handle:
                total = 0
                while True:
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_BINARY:
                        raise AgentError("download_failed", "Cloudflared binary is too large", "download")
                    handle.write(chunk)
        except (OSError, urllib.error.URLError) as exc:
            raise AgentError("download_failed", "Cloudflared download failed: " + str(exc)[:220], "download") from None
        actual = digest(target)
        if actual != expected:
            raise AgentError("digest_mismatch", "Cloudflared digest does not match the release metadata", "download")
        os.chmod(target, 0o755)
        with open(target, "rb") as handle:
            atomic(BIN, handle.read(), 0o755)


def install(flags: dict) -> dict:
    arch = machine()
    if not arch:
        raise AgentError("unsupported_arch", "unsupported Cloudflared architecture", "download")
    requested = str(flags.get("version", "latest") or "latest").lstrip("v")
    if requested == "latest":
        version, expected, source = latest_release(arch)
    elif requested == PINNED_VERSION:
        version, expected, source = PINNED_VERSION, PINNED_SHA256.get(arch, ""), "pinned"
    else:
        raise AgentError("bad_arg", "only latest or the pinned verified version is supported", "download")
    if not expected:
        raise AgentError("unsupported_arch", "no verified digest for this architecture", "download")
    if binary_version() != version or str(flags.get("force", "")) == "1":
        download(version, expected, arch)
    current = state()
    current.update({"fallback": source == "fallback", "fallback_version": PINNED_VERSION if source == "fallback" else "", "latest_source": source})
    save_state(current)
    return status()


def clean_local_url(value: object) -> str:
    text = str(value or "").strip()
    match = SAFE_LOCAL.fullmatch(text)
    if not match or not 1 <= int(match.group(1)) <= 65535:
        raise AgentError("bad_arg", "Cloudflared accepts only a loopback HTTP endpoint with a valid port", "args")
    return text


def write_unit(local_url: str) -> None:
    content = "\n".join([
        "[Unit]", "Description=OBHOD Cloudflared quick tunnel", "After=network-online.target", "Wants=network-online.target", "",
        "[Service]", "Type=simple", "ExecStart=%s tunnel --no-autoupdate --url %s" % (BIN, local_url),
        "Restart=on-failure", "RestartSec=5", "StandardOutput=append:%s" % LOG, "StandardError=append:%s" % LOG,
        "NoNewPrivileges=true", "PrivateTmp=true", "", "[Install]", "WantedBy=multi-user.target", "",
    ])
    atomic(UNIT, content.encode("utf-8"), 0o644)


def up(flags: dict) -> dict:
    local_url = clean_local_url(flags.get("url", ""))
    if not os.path.isfile(BIN):
        install({"version": "latest"})
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    write_unit(local_url)
    code, output = systemctl("daemon-reload")
    if code != 0:
        raise AgentError("no_systemd", "systemd cannot reload the Cloudflared unit: " + output[:180], "service")
    code, output = systemctl("enable", "--now", "obhod-cloudflared.service")
    if code != 0:
        raise AgentError("start_failed", "Cloudflared did not start: " + output[:220], "service")
    current = state()
    current["local_url"] = local_url
    current["url"] = ""
    save_state(current)
    return status()


def down(_flags: dict) -> dict:
    if os.path.isfile(UNIT):
        code, output = systemctl("disable", "--now", "obhod-cloudflared.service")
        if code != 0:
            raise AgentError("stop_failed", "Cloudflared did not stop: " + output[:220], "service")
    current = state()
    current["url"] = ""
    current["local_url"] = ""
    save_state(current)
    return status()


def logs(_flags: dict) -> dict:
    try:
        with open(LOG, "r", encoding="utf-8", errors="replace") as handle:
            body = handle.read()[-16000:]
    except OSError:
        body = ""
    match = re.findall(r"https://[-a-z0-9]+\.trycloudflare\.com", body, flags=re.I)
    current = state()
    if match:
        current["url"] = match[-1]
        save_state(current)
    return {**status(), "lines": body.splitlines()[-120:]}


def remove(_flags: dict) -> dict:
    down({})
    for path in (UNIT, BIN, STATE):
        try:
            os.unlink(path)
        except OSError:
            pass
    systemctl("daemon-reload")
    return status()


def parse(argv: list[str]) -> tuple[str, dict]:
    if not argv:
        raise AgentError("bad_arg", "a command is required", "args")
    flags: dict[str, str] = {}
    for raw in argv[1:]:
        if not raw.startswith("--") or "=" not in raw:
            raise AgentError("bad_arg", "invalid argument", "args")
        key, value = raw[2:].split("=", 1)
        if key not in {"version", "force", "url"} or len(value) > 240:
            raise AgentError("bad_arg", "invalid argument", "args")
        flags[key] = value
    return argv[0], flags


def main(argv: list[str]) -> int:
    try:
        command, flags = parse(argv)
        handlers = {"status": lambda: status(), "install": lambda: install(flags), "up": lambda: up(flags), "down": lambda: down(flags), "logs": lambda: logs(flags), "remove": lambda: remove(flags)}
        if command not in handlers:
            raise AgentError("bad_arg", "unknown command", "args")
        print(json.dumps({"proto": PROTO, "result": "ok", "data": handlers[command](), "logs": LOGS}, sort_keys=True))
        return 0
    except AgentError as exc:
        print(json.dumps({"proto": PROTO, "result": "err", "code": exc.code, "msg": exc.message, "stage": exc.stage, "logs": LOGS}, sort_keys=True))
        return 1
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"proto": PROTO, "result": "err", "code": "internal", "msg": str(exc)[:400], "stage": "cloudflared", "logs": LOGS}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
