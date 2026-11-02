from __future__ import annotations

import base64
import hmac
import json
import os
import re
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def env_int(name, default, low, high):
    raw = os.environ.get(name, "")
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    if value < low or value > high:
        return default
    return value


REGISTRY = os.environ.get("OBHOD_SUB_REGISTRY", "/var/lib/xray-manager/subscriptions.json")
PORT = env_int("OBHOD_SUB_PORT", 2096, 1, 65535)
BIND = os.environ.get("OBHOD_SUB_BIND", "0.0.0.0")
SEGMENT = re.compile(r"^[A-Za-z0-9_-]{64}$")
HOST_HEADER = re.compile(r"^(?:[a-z0-9](?:[a-z0-9.-]{0,251})|\[[0-9a-f:.]{3,45}\])(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$")
CACHE_SECONDS = 60
UA_CLIENT = "v2rayNG"
LOCK = threading.Lock()
ACCESS_LOG = os.environ.get("OBHOD_SUB_ACCESS_LOG", "")
SECURITY_LOG = os.environ.get("OBHOD_SECURITY_LOG", "/var/log/obhod/security.log")
SECLOG_ON = os.environ.get("OBHOD_SECLOG", "1").strip().lower() not in {"0", "off", "no", "false", "disabled"}
BLOCKING = os.environ.get("OBHOD_SUB_BLOCK", "1").strip().lower() not in {"0", "off", "no", "false", "disabled"}
SECLOG_LOCK = threading.Lock()
RATE_LIMIT = env_int("OBHOD_SUB_RATE", 10, 5, 6000)
RATE_WINDOW = 60.0
MAX_CLIENTS = env_int("OBHOD_SUB_MAX_CLIENTS", 64, 4, 512)
SOCKET_TIMEOUT = 15.0
MAX_LINE = 4096
MAX_BODY = env_int("OBHOD_SUB_MAX_BODY", 8 * 1024 * 1024, 65536, 64 * 1024 * 1024)
BLOCK_STEP = 60.0
BLOCK_MAX = 3600.0
NOT_FOUND_STEP = 10
CLEAN = re.compile(r"[^ -~]")
REQUEST_LINE = re.compile(r"\"[A-Z]+ [^\"]*\"")
BUCKETS = {}
BUCKET_LIMIT = 4096
BUCKET_LOCK = threading.Lock()
FAKE_KEY = "0" * 64


def security_note(ip, event, outcome="deny", detail=""):
    if not SECLOG_ON:
        return False
    line = "security ip=%s event=%s outcome=%s actor=0 detail=%s\n" % (
        CLEAN.sub("", str(ip or "-"))[:64] or "-",
        CLEAN.sub("", str(event or "-"))[:32] or "-",
        CLEAN.sub("", str(outcome or "-"))[:16] or "-",
        CLEAN.sub("", str(detail or "-"))[:120] or "-",
    )
    try:
        folder = os.path.dirname(SECURITY_LOG)
        if folder and not os.path.isdir(folder):
            os.makedirs(folder, mode=0o700, exist_ok=True)
        with SECLOG_LOCK:
            if os.path.islink(SECURITY_LOG):
                return False
            descriptor = os.open(SECURITY_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, line.encode("utf-8", "replace"))
            finally:
                os.close(descriptor)
        return True
    except OSError:
        return False


def access_note(ip, status):
    line = "sub %s %s\n" % (status, ip)
    sys.stderr.write(line)
    sys.stderr.flush()
    if ACCESS_LOG:
        try:
            with open(ACCESS_LOG, "a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError:
            pass


class Bucket(object):
    __slots__ = ("window", "count", "seen", "blocked_until", "misses", "offences")

    def __init__(self, now):
        self.window = now
        self.count = 0
        self.seen = now
        self.blocked_until = 0.0
        self.misses = 0
        self.offences = 0


def throttle_state(ip, now):
    entry = BUCKETS.get(ip)
    if entry is None:
        entry = Bucket(now)
        BUCKETS[ip] = entry
    entry.seen = now
    if now - entry.window >= RATE_WINDOW:
        entry.window = now
        entry.count = 0
    entry.count += 1
    return entry


def sweep(now):
    stale = [key for key, value in BUCKETS.items() if now - value.seen > RATE_WINDOW * 2]
    for key in stale:
        BUCKETS.pop(key, None)
    if len(BUCKETS) > BUCKET_LIMIT:
        ordered = sorted(BUCKETS.items(), key=lambda pair: pair[1].seen)
        for key, _value in ordered[: len(BUCKETS) - BUCKET_LIMIT]:
            BUCKETS.pop(key, None)


def penalty_of(entry):
    step = min(BLOCK_MAX, BLOCK_STEP * (2 ** max(0, entry.offences - 1)))
    return step


def block_for(entry, now):
    entry.offences = min(8, entry.offences + 1)
    entry.blocked_until = now + penalty_of(entry)


def throttled(ip):
    now = time.monotonic()
    reason = ""
    with BUCKET_LOCK:
        entry = throttle_state(ip, now)
        if now < entry.blocked_until:
            return True
        if entry.count > RATE_LIMIT:
            reason = "sub_rate"
            if BLOCKING:
                block_for(entry, now)
        elif entry.misses >= NOT_FOUND_STEP:
            reason = "sub_miss"
            if BLOCKING:
                block_for(entry, now)
                entry.misses = 0
        sweep(now)
    if reason and BLOCKING:
        security_note(ip, reason, "block", "the address is blocked temporarily")
    return bool(reason)


def record_miss(ip, missing=True):
    now = time.monotonic()
    with BUCKET_LOCK:
        entry = BUCKETS.get(ip)
        if entry is None:
            entry = Bucket(now)
            BUCKETS[ip] = entry
        entry.seen = now
        if missing:
            entry.misses += 1
        elif entry.count <= RATE_LIMIT:
            entry.offences = 0
            entry.misses = 0


def reset_buckets():
    with BUCKET_LOCK:
        BUCKETS.clear()


def same(one, other):
    return hmac.compare_digest(str(one or "").encode("utf-8"), str(other or "").encode("utf-8"))


def header_safe(value, limit=200):
    text = CLEAN.sub("", str(value or ""))
    return text[:limit]


def read_registry():
    try:
        if os.path.islink(REGISTRY):
            return {"port": PORT, "entries": {}}
        with open(REGISTRY, "r", encoding="utf-8") as handle:
            body = json.load(handle)
    except (OSError, ValueError):
        return {"port": PORT, "entries": {}}
    if not isinstance(body, dict):
        return {"port": PORT, "entries": {}}
    entries = body.get("entries")
    if not isinstance(entries, dict):
        body["entries"] = {}
    return body


def payload_of(entry):
    links = entry.get("links")
    if not isinstance(links, list):
        return ""
    budget = (MAX_BODY // 4) * 3
    kept = []
    size = 0
    for item in links:
        text = str(item).strip()
        if not text:
            continue
        chunk = len(text.encode("utf-8")) + 1
        if kept and size + chunk > budget:
            break
        kept.append(text)
        size += chunk
    if not kept:
        return ""
    body = "\n".join(kept) + "\n"
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return encoded if len(encoded) <= MAX_BODY else ""


def counter(entry, name):
    try:
        return max(int(entry.get(name) or 0), 0)
    except (TypeError, ValueError):
        return 0


def userinfo(entry):
    return "upload=%d; download=%d; total=%d; expire=%d" % (
        counter(entry, "up"),
        counter(entry, "down"),
        counter(entry, "total"),
        counter(entry, "expire"),
    )


def title_header(entry):
    title = header_safe(entry.get("title") or "OBHOD", 120)
    return "base64:" + base64.b64encode(title.encode("utf-8")).decode("ascii")


def base_url(host):
    text = header_safe(host or "", 120).strip().lower()
    if not text or not HOST_HEADER.match(text):
        return ""
    if text.rsplit(":", 1)[-1] == "0" and not text.endswith("]"):
        return ""
    return "http://" + text


def info_body(entry, link_count, base=""):
    used = counter(entry, "up") + counter(entry, "down")
    total = counter(entry, "total")
    return {
        "sId": "",
        "enabled": entry.get("enabled") is not False,
        "isOnline": False,
        "download": counter(entry, "down"),
        "upload": counter(entry, "up"),
        "total": total,
        "used": used,
        "remained": max(total - used, 0) if total else 0,
        "expire": counter(entry, "expire"),
        "lastOnline": 0,
        "downloadByte": counter(entry, "down"),
        "uploadByte": counter(entry, "up"),
        "totalByte": total,
        "subUrl": base + str(entry.get("path") or ""),
        "subJsonUrl": base + str(entry.get("path") or "") + "/json",
        "subClashUrl": "",
        "subTitle": str(entry.get("title") or "OBHOD")[:64],
        "subSupportUrl": str(entry.get("support_url") or ""),
        "subUpdates": int(refresh_hours(entry)),
        "emails": [str(entry.get("email") or "")][:1] if entry.get("email") else [],
        "datepicker": "gregorian",
        "announce": str(entry.get("announce") or "")[:200],
        "links": link_count,
    }


def refresh_hours(entry):
    try:
        value = int(entry.get("refresh") or 12)
    except (TypeError, ValueError):
        value = 12
    return str(max(1, min(168, value)))


def header_lines(entry, filename, base=""):
    return [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("Profile-Title", title_header(entry)),
        ("Profile-Update-Interval", refresh_hours(entry)),
        ("Subscription-Userinfo", userinfo(entry)),
        ("Content-Disposition", "attachment; filename*=UTF-8''" + filename),
        ("Profile-Web-Page-Url", base + header_safe(entry.get("path") or "", 200)),
    ] + announce_lines(entry)


def announce_lines(entry):
    support = header_safe(entry.get("support_url") or "", 200)
    announce = header_safe(entry.get("announce") or "", 200)
    lines = []
    if support.startswith("http://") or support.startswith("https://"):
        lines.append(("Support-Url", support))
    if announce:
        lines.append(("Announce", announce))
    return lines


class Handler(BaseHTTPRequestHandler):
    server_version = "obhod-sub/1"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    timeout = SOCKET_TIMEOUT

    def handle_one_request(self):
        self.raw_requestline = self.rfile.readline(MAX_LINE + 1)
        if len(self.raw_requestline) > MAX_LINE:
            self.raw_requestline = self.raw_requestline[:MAX_LINE]
            self.requestline = ""
            self.request_version = ""
            self.command = ""
            security_note(self.client_address[0], "sub_request", "deny", "request line too long")
            self.send_error(414, "uri too long")
            return
        if not self.raw_requestline:
            self.close_connection = True
            return
        if not self.parse_request():
            return
        method = getattr(self, "do_" + self.command, None)
        if method is None:
            self.send_error(501, "unsupported method")
            return
        method()
        self.wfile.flush()

    def log_message(self, fmt, *args):
        line = header_safe(fmt % args, 300)
        line = REQUEST_LINE.sub("request", line)
        sys.stderr.write("%s %s\n" % (self.address_string(), line))
        sys.stderr.flush()

    def send_plain(self, code, body, extra=None, content_type="text/plain; charset=utf-8"):
        access_note(self.client_address[0], code)
        if code in {403, 404}:
            record_miss(self.client_address[0], True)
            security_note(self.client_address[0], "sub_request", "deny", "unknown subscription")
        elif code == 200:
            record_miss(self.client_address[0], False)
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        if code == 429:
            self.send_header("Retry-After", str(int(RATE_WINDOW)))
        for key, value in (extra or []):
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if throttled(self.client_address[0]):
            self.send_plain(429, "slow down\n")
            return
        raw = self.path[:1024]
        path, _, query = raw.partition("?")
        path = path[:512]
        want = ""
        for pair in query.split("&"):
            key, _, value = pair.partition("=")
            if key.strip().lower() == "format":
                want = value.strip().lower()[:16]
        if path in {"/", "/health", "/favicon.ico"}:
            if path == "/health":
                self.send_plain(200, "ok\n")
            else:
                self.send_plain(404, "not found\n")
            return
        parts = [item for item in path.split("/") if item]
        if len(parts) == 3 and parts[2].lower() in {"json", "info"}:
            want = want or parts[2].lower()
            parts = parts[:2]
        want_json = want in {"json", "info"}
        want_info = want == "info"
        if want == "clash":
            self.send_plain(400, "clash is not served by this server\n")
            return
        if len(parts) != 2 or not SEGMENT.match(parts[0]) or not SEGMENT.match(parts[1]):
            self.send_plain(404, "not found\n")
            return
        with LOCK:
            body = read_registry()
        entries = body.get("entries") or {}
        entry = entries.get(parts[0])
        if not isinstance(entry, dict):
            same(FAKE_KEY, parts[1])
            self.send_plain(404, "not found\n")
            return
        if not same(entry.get("key"), parts[1]):
            self.send_plain(404, "not found\n")
            return
        if entry.get("enabled") is False:
            self.send_plain(403, "disabled\n")
            return
        payload = payload_of(entry)
        if not payload:
            self.send_plain(404, "empty\n")
            return
        base = base_url(self.headers.get("Host"))
        if want_json:
            count = len([item for item in entry.get("links") or [] if str(item).strip()])
            if want_info:
                document = info_body(entry, count, base)
            else:
                document = {
                    "title": str(entry.get("title") or "OBHOD")[:64],
                    "count": count,
                    "refresh": int(refresh_hours(entry)),
                    "userinfo": userinfo(entry),
                    "payload": payload,
                }
            body = json.dumps(document, ensure_ascii=True, sort_keys=True)
            self.send_plain(
                200,
                body + "\n",
                [
                    (key, value)
                    for key, value in header_lines(entry, "obhod", base)
                    if key not in {"Content-Type", "Content-Disposition"}
                ],
                "application/json; charset=utf-8",
            )
            return
        filename = str(entry.get("filename") or "obhod")
        if not re.match(r"^[A-Za-z0-9_.-]{1,64}$", filename):
            filename = "obhod"
        extra = header_lines(entry, filename, base_url(self.headers.get("Host")))
        access_note(self.client_address[0], 200)
        raw = payload.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in extra:
            if key.lower() == "content-type":
                continue
            self.send_header(key, str(value))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(raw)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address, handler):
        self.slots = threading.Semaphore(MAX_CLIENTS)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        request.settimeout(SOCKET_TIMEOUT)
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    try:
        server = Server((BIND, PORT), Handler)
    except OSError as exc:
        code = getattr(exc, "errno", 0)
        sys.stderr.write("obhod-sub: cannot listen on %s:%s: %s\n" % (BIND, PORT, exc))
        if code == 98 or "in use" in str(exc).lower():
            sys.stderr.write("obhod-sub: port %s is busy, another service (for example 3x-ui) holds it\n" % PORT)
            sys.stderr.flush()
            sys.exit(4)
        sys.stderr.flush()
        sys.exit(3)

    def stop(_signum, _frame):
        server.server_close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    sys.stderr.write("obhod-sub listening on %s:%s\n" % (BIND, PORT))
    sys.stderr.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
