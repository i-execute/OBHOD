import fcntl
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "v3.0.0"
MAX_BINARY = 16 * 1024 * 1024
TIMEOUT = 120
HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com"}
ARCHES = {
    "x86_64": ("amd64", "511b3a27af0f21518b8ac17e0c73aa123adc57a01e3eec6db950e9ce386dfc54"),
    "amd64": ("amd64", "511b3a27af0f21518b8ac17e0c73aa123adc57a01e3eec6db950e9ce386dfc54"),
    "aarch64": ("arm64", "9f75c6042a7be49cfa2e131d43f1bcadad025d44bb7bf421373e84f34812c577"),
    "arm64": ("arm64", "9f75c6042a7be49cfa2e131d43f1bcadad025d44bb7bf421373e84f34812c577"),
    "armv7l": ("arm", "964c7c190d4d8ede3ea05092e7a356b8e60bb44e33e0776941849978e7969ec4"),
    "i686": ("386", "1b34b25dfc251a1469b7a0f04b79f8071ce096b5205de614d1e179a905119619"),
    "i386": ("386", "1b34b25dfc251a1469b7a0f04b79f8071ce096b5205de614d1e179a905119619"),
}


class UpstreamError(Exception):
    def __init__(self, code, message, stage="upstream"):
        super().__init__(message)
        self.code = code
        self.message = message
        self.stage = stage


def arch_info():
    arch = platform.machine().lower()
    if arch not in ARCHES:
        raise UpstreamError("unsupported_arch", "no pinned v3.0.0 binary for this architecture")
    return ARCHES[arch]


def root_path(flags):
    path = str(flags.get("dir", "/etc/obhod") or "/etc/obhod")
    if not os.path.isabs(path) or ".." in path.split(os.sep):
        raise UpstreamError("bad_path", "directory must be a simple absolute path")
    return os.path.join(path, "upstream-rkn-guard")


def ensure_private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise UpstreamError("unsafe_path", "upstream directory must be owned by the current user and not writable by others")


def target_path(flags):
    return os.path.join(root_path(flags), "rkn-guard")


def file_digest(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise UpstreamError("unsafe_path", "cannot safely open installed binary: " + str(exc)[:120])
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022 or st.st_size > MAX_BINARY:
            raise UpstreamError("unsafe_path", "installed binary has unsafe ownership, type, permissions or size")
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                data = stream.read(65536)
                if not data:
                    break
                digest.update(data)
        return digest.hexdigest()
    finally:
        os.close(fd)


def safe_url(url):
    try:
        value = urllib.parse.urlsplit(url)
        return value.scheme == "https" and value.hostname in HOSTS and not value.username and not value.password and value.port in (None, 443)
    except ValueError:
        return False


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not safe_url(newurl):
            raise UpstreamError("unsafe_redirect", "upstream redirected to an untrusted host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_info(path):
    try:
        result = subprocess.run([path, "build-info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpstreamError("bad_binary", "cannot run verified upstream binary: " + str(exc)[:120])
    lines = result.stdout.decode("utf-8", "replace").strip().splitlines()
    if result.returncode != 0 or not lines or lines[0].strip() != VERSION:
        raise UpstreamError("bad_binary", "verified binary did not report the pinned version")
    return lines[0].strip(), (lines[1].strip()[:40] if len(lines) > 1 else "")


def status(flags):
    asset, expected = arch_info()
    target = target_path(flags)
    root = root_path(flags)
    if os.path.lexists(root):
        st = os.lstat(root)
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise UpstreamError("unsafe_path", "upstream directory is unsafe")
    actual = file_digest(target)
    valid = bool(actual and actual == expected)
    version, branch = build_info(target) if valid and os.access(target, os.X_OK) else ("", "")
    return {"installed": bool(actual), "verified": bool(valid and version), "version": version, "branch": branch, "architecture": asset, "expected_version": VERSION, "sha256": actual, "path": target, "managed_backend": False}


def install(flags):
    asset, expected = arch_info()
    root = root_path(flags)
    ensure_private_dir(root)
    target = target_path(flags)
    if os.path.lexists(target):
        file_digest(target)
    url = "https://github.com/Flecksis/rkn-guard/releases/download/%s/rkn-guard-linux-%s" % (VERSION, asset)
    if not safe_url(url):
        raise UpstreamError("unsafe_url", "invalid upstream release URL")
    fd, temp = tempfile.mkstemp(prefix=".rkn-download-", dir=root)
    digest = hashlib.sha256()
    count = 0
    started = time.monotonic()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "OBHOD-rkn-guard/1", "Accept": "application/octet-stream"})
        opener = urllib.request.build_opener(Redirects())
        with os.fdopen(fd, "wb") as output:
            try:
                with opener.open(request, timeout=30) as response:
                    if not safe_url(response.geturl()):
                        raise UpstreamError("unsafe_redirect", "upstream returned an untrusted host")
                    while True:
                        if time.monotonic() - started > TIMEOUT:
                            raise UpstreamError("download_failed", "download timed out")
                        chunk = response.read(65536)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > MAX_BINARY:
                            raise UpstreamError("too_large", "upstream binary is too large")
                        digest.update(chunk)
                        output.write(chunk)
            except (urllib.error.URLError, OSError) as exc:
                raise UpstreamError("download_failed", "upstream download failed: " + str(exc)[:120])
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest() != expected:
            raise UpstreamError("digest_mismatch", "upstream binary digest does not match pinned v3.0.0")
        os.chmod(temp, 0o700)
        build_info(temp)
        os.replace(temp, target)
        directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return status(flags)
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def main(argv):
    command = argv[0] if argv else "status"
    flags = {}
    for item in argv[1:]:
        if item.startswith("--") and "=" in item:
            key, value = item[2:].split("=", 1)
            flags[key.replace("-", "_")] = value
    lock = None
    try:
        if command == "status":
            data = status(flags)
        elif command == "install":
            root = root_path(flags)
            ensure_private_dir(root)
            descriptor = os.open(os.path.join(root, ".lock"), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            lock = os.fdopen(descriptor, "a+")
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = install(flags)
        else:
            raise UpstreamError("bad_command", "unknown command")
        print(json.dumps({"proto": 3, "result": "ok", "data": data}, ensure_ascii=True))
        return 0
    except (UpstreamError, OSError, ValueError) as exc:
        print(json.dumps({"proto": 3, "result": "err", "code": getattr(exc, "code", "internal"), "msg": str(exc)[:200], "stage": getattr(exc, "stage", "upstream"), "data": {}}, ensure_ascii=True))
        return 2
    finally:
        if lock is not None:
            lock.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
