import errno
import hashlib
import ipaddress
import json
import os
import random
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

PROTO = 3
VERSION = "1.0.0"
SERVE = "serve"
DEFAULT_PORTS = (2222, 2323, 2121, 8081, 6379)
DEFAULT_READ = 8192
DEFAULT_MAX_CONN = 64
DEFAULT_PER_IP = 2
DEFAULT_IDLE = 20.0
DEFAULT_GREET = 0.35
UNIT_DIR = "/etc/systemd/system"
UNIT = os.path.join(UNIT_DIR, "obhod-honeypot.service")
CONF_DIR = "/etc/obhod"
CONF = os.path.join(CONF_DIR, "honeypot.json")
STATE_DIR = "/var/lib/obhod-honeypot"
LOG_PATH = "/var/log/obhod/honeypot.log"
PROFILE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "http",
    2222: "ssh",
    2121: "ftp",
    2323: "telnet",
    3389: "rdp",
    8080: "http",
    8081: "http",
    6379: "redis",
}
SAFE_TEXT = re.compile(r"[^\x20-\x7e]")
TOKEN = re.compile(r"^[A-Za-z0-9_.:@/+\[\]-]{0,120}$")
MAX_LINE = 512


class HoneyError(Exception):
    def __init__(self, code, message, stage="honeypot"):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.stage = stage


def clean(value, limit=MAX_LINE):
    text = SAFE_TEXT.sub("?", str(value or ""))[:limit]
    return text.replace("=", "_").replace(" ", "_")


def safe_ip(value):
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        raise HoneyError("bad_arg", "the address is not valid", "arg") from None


def ssh_banner():
    path = "/etc/ssh/sshd_config"
    version = ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle.read().splitlines()[:200]:
                token = line.strip()
                if token.lower().startswith("versionaddendum"):
                    parts = token.split(None, 1)
                    if len(parts) == 2:
                        version = parts[1].strip().strip('"')
    except OSError:
        version = ""
    base = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    return base + (" " + clean(version, 40) if version else "") + "\r\n"


KEX_ALGOS = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ext-info-c",
    "kex-strict-c-v00@openssh.com",
]
HOSTKEYS = [
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ecdsa-sha2-nistp256",
    "ssh-ed25519",
]
CIPHERS = ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"]
MACS = ["umac-64-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"]
COMPRESSION = ["none", "zlib@openssh.com"]

HTTP_BODY = (
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.24.0 (Ubuntu)\r\n"
    "Date: {date}\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: {size}\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{body}"
)
HTTP_PAGE = (
    "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head>"
    "<body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is "
    "successfully installed and working.</p></body></html>"
)


def kexinit():
    lists = [
        ",".join(KEX_ALGOS),
        ",".join(HOSTKEYS),
        ",".join(CIPHERS),
        ",".join(CIPHERS),
        ",".join(MACS),
        ",".join(MACS),
        ",".join(COMPRESSION),
        ",".join(COMPRESSION),
        "",
        "",
    ]
    payload = bytearray([20])
    payload.extend(os.urandom(16))
    for item in lists:
        raw = item.encode("ascii")
        payload.extend(struct.pack(">I", len(raw)))
        payload.extend(raw)
    payload.append(0)
    payload.extend(struct.pack(">I", 0))
    block = 8
    pad = block - ((len(payload) + 5) % block)
    if pad < 4:
        pad += block
    packet = struct.pack(">I", len(payload) + pad + 1) + bytes([pad]) + bytes(payload) + os.urandom(pad)
    return packet


def credentials(raw):
    text = raw.decode("utf-8", "replace")
    found = []
    lines = re.split(r"[\r\n\x00]+", text)
    user = ""
    for line in lines[:60]:
        token = line.strip()
        if not token:
            continue
        upper = token.upper()
        if upper.startswith("USER "):
            user = token.split(None, 1)[1][:64]
            found.append(("user", user))
        elif upper.startswith("PASS "):
            found.append(("pass", token.split(None, 1)[1][:64]))
        elif upper.startswith("AUTH "):
            found.append(("pass", token.split(None, 1)[1][:64]))
        elif upper.startswith("LOGIN:") or token.lower() == "login:":
            continue
        elif user and len(found) and found[-1][0] == "user" and len(token) <= 64 and token.isprintable():
            found.append(("pass", token))
    return found[:6]


def digest(value):
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:16]


def profile(port, overrides=None):
    table = overrides if isinstance(overrides, dict) else {}
    chosen = str(table.get(str(int(port)), "") or "").lower()
    if chosen in {"ssh", "ftp", "telnet", "http", "redis", "rdp", "raw"}:
        return chosen
    return PROFILE_PORTS.get(int(port), "raw")


def log_ip(value):
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return "0.0.0.0"


def line(ip, port, proto, event, **extra):
    parts = [
        "honeypot",
        "ip=" + log_ip(ip),
        "port=%d" % int(port),
        "proto=" + (proto if TOKEN.match(proto) else "raw"),
        "event=" + (event if TOKEN.match(event) else "probe"),
    ]
    for key in sorted(extra):
        value = extra[key]
        if value in (None, ""):
            continue
        parts.append("%s=%s" % (key, clean(value)))
    return " ".join(parts)


class Sink:
    def __init__(self, path=LOG_PATH, echo=False):
        self.path = path
        self.echo = echo
        self.lock = threading.Lock()
        self.rows = []
        self.failed = 0
        try:
            folder = os.path.dirname(path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder, exist_ok=True)
        except OSError:
            pass

    def write(self, row):
        with self.lock:
            self.rows.append(row)
            if len(self.rows) > 512:
                self.rows = self.rows[-512:]
            if self.echo:
                sys.stdout.write(row + "\n")
                sys.stdout.flush()
                return
            try:
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(row + "\n")
            except OSError:
                if self.failed < 3:
                    self.failed += 1
                    sys.stderr.write("honeypot log is not writable: " + self.path + "\n")
                    sys.stderr.flush()


class Guard:
    def __init__(self, max_conn=DEFAULT_MAX_CONN, per_ip=DEFAULT_PER_IP):
        self.max_conn = int(max_conn)
        self.per_ip = int(per_ip)
        self.lock = threading.Lock()
        self.active = 0
        self.by_ip = {}

    def take(self, ip):
        with self.lock:
            if self.active >= self.max_conn:
                return False
            if self.by_ip.get(ip, 0) >= self.per_ip:
                return False
            self.active += 1
            self.by_ip[ip] = self.by_ip.get(ip, 0) + 1
            return True

    def drop(self, ip):
        with self.lock:
            self.active = max(self.active - 1, 0)
            left = self.by_ip.get(ip, 0) - 1
            if left <= 0:
                self.by_ip.pop(ip, None)
            else:
                self.by_ip[ip] = left


def read_some(conn, limit, idle):
    conn.settimeout(idle)
    chunks = []
    total = 0
    deadline = time.time() + idle
    while total < limit and time.time() < deadline:
        try:
            chunk = conn.recv(min(1024, limit - total))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if b"\n" in chunk or total >= limit:
            break
    return b"".join(chunks)


class Handler:
    def __init__(self, config, sink, guard):
        self.config = config
        self.sink = sink
        self.guard = guard

    def serve(self, conn, addr, port):
        ip = addr[0]
        proto = profile(port, self.config.get("profiles"))
        started = time.time()
        try:
            time.sleep(float(self.config.get("greet", DEFAULT_GREET)) + random.random() * 0.08)
            conn.settimeout(float(self.config.get("idle", DEFAULT_IDLE)))
            banner = self.greeting(proto)
            if banner:
                conn.sendall(banner)
            raw = read_some(conn, int(self.config.get("limit", DEFAULT_READ)), float(self.config.get("idle", DEFAULT_IDLE)))
            for kind, value in credentials(raw):
                self.sink.write(
                    line(
                        ip,
                        port,
                        proto,
                        "auth",
                        role=kind,
                        user=value if kind == "user" else "",
                        secret=digest(value) if kind == "pass" else "",
                        size=len(value) if kind == "pass" else "",
                    )
                )
            self.reply(conn, proto, raw)
            self.sink.write(
                line(
                    ip,
                    port,
                    proto,
                    "probe",
                    bytes=len(raw),
                    ms=int((time.time() - started) * 1000),
                    head=digest(raw[:256]) if raw else "",
                )
            )
        except (OSError, ValueError):
            self.sink.write(line(ip, port, proto, "reset"))
        except Exception:
            self.sink.write(line(ip, port, proto, "error"))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def greeting(self, proto):
        if proto == "ssh":
            return ssh_banner().encode("ascii") + kexinit()
        if proto == "ftp":
            return b"220 (vsFTPd 3.0.5)\r\n"
        if proto == "telnet":
            return bytes([255, 253, 24, 255, 253, 32, 255, 251, 1, 255, 251, 3]) + b"\r\nlogin: "
        if proto == "redis":
            return b"-NOAUTH Authentication required.\r\n"
        if proto == "http":
            return b""
        if proto == "rdp":
            return b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x02\x00\x00\x00"
        return b""

    def reply(self, conn, proto, raw):
        if proto == "http":
            body = HTTP_PAGE.encode("ascii")
            head = HTTP_BODY.format(
                date=time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
                size=len(body),
                body=HTTP_PAGE,
            )
            conn.sendall(head.encode("ascii"))
            return
        if proto == "ftp":
            conn.sendall(b"530 Login incorrect.\r\n")
            return
        if proto == "telnet":
            conn.sendall(b"Login incorrect\r\n")
            return
        if proto == "redis":
            conn.sendall(b"-ERR invalid password\r\n" if raw else b"")
            return
        if proto in {"ssh", "rdp"}:
            time.sleep(0.05)


class Server:
    def __init__(self, config, sink=None):
        self.config = config
        self.sink = sink or Sink(config.get("log", LOG_PATH))
        self.guard = Guard(config.get("max_conn", DEFAULT_MAX_CONN), config.get("per_ip", DEFAULT_PER_IP))
        self.handler = Handler(config, self.sink, self.guard)
        self.sockets = []
        self.threads = []
        self.stop = threading.Event()
        self.started = time.time()

    def bind(self):
        host = str(self.config.get("bind", "0.0.0.0"))
        ports = [int(item) for item in self.config.get("ports", DEFAULT_PORTS)]
        for port in ports:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                sock.listen(16)
                sock.settimeout(0.5)
            except OSError as exc:
                sock.close()
                self.sink.write(line("127.0.0.1", port, profile(port), "bind_failed", reason=errno.errorcode.get(exc.errno, "error")))
                continue
            self.sockets.append((sock, port))

    def start(self):
        self.bind()
        for sock, port in self.sockets:
            thread = threading.Thread(target=self.accept, args=(sock, port), daemon=True)
            thread.start()
            self.threads.append(thread)
        self.sink.write(line("127.0.0.1", self.sockets[0][1] if self.sockets else 0, "raw", "start", ports=len(self.sockets)))
        return len(self.sockets)

    def run(self):
        self.start()
        while not self.stop.is_set():
            time.sleep(0.3)

    def accept(self, sock, port):
        while not self.stop.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            if not self.guard.take(ip):
                self.sink.write(line(ip, port, profile(port, self.config.get("profiles")), "throttled"))
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            worker = threading.Thread(target=self.serve, args=(conn, addr, port), daemon=True)
            worker.start()

    def serve(self, conn, addr, port):
        ip = addr[0]
        try:
            self.handler.serve(conn, addr, port)
        finally:
            self.guard.drop(ip)

    def close(self):
        self.stop.set()
        for sock, _port in self.sockets:
            try:
                sock.close()
            except OSError:
                pass


def read_text(path, limit=1 << 20):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def conf_path(override=""):
    return str(override or os.environ.get("HONEYPOT_CONF", "") or CONF)


def read_config(path=""):
    body = read_text(conf_path(path))
    if not body:
        return {"ports": list(DEFAULT_PORTS), "bind": "0.0.0.0", "log": LOG_PATH}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {"ports": list(DEFAULT_PORTS), "bind": "0.0.0.0", "log": LOG_PATH}
    return data if isinstance(data, dict) else {"ports": list(DEFAULT_PORTS)}


def write_config(data):
    target = conf_path()
    folder = os.path.dirname(target)
    try:
        if folder:
            os.makedirs(folder, exist_ok=True)
    except OSError:
        pass
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(target, 0o600)


def parse_ports(raw):
    out = []
    for token in str(raw or "").replace(" ", "").split(","):
        if not token:
            continue
        if not token.isdigit():
            raise HoneyError("bad_arg", "the port list holds a value that is not a number", "arg")
        port = int(token)
        if not 1 <= port <= 65535:
            raise HoneyError("bad_arg", "the port must be between 1 and 65535", "arg")
        if port in out:
            continue
        out.append(port)
    if not out:
        return list(DEFAULT_PORTS)
    if len(out) > 12:
        raise HoneyError("bad_arg", "twelve decoy ports are enough", "arg")
    return out


def profiles_of(flags, ports):
    forced = str(flags.get("profile", "") or "").lower()
    table = {}
    if forced in {"ssh", "ftp", "telnet", "http", "redis", "rdp", "raw"}:
        for port in ports:
            table[str(int(port))] = forced
    return table


def unit_body(ports):
    return "\n".join(
        [
            "[Unit]",
            "Description=OBHOD honeypot",
            "After=network.target",
            "",
            "[Service]",
            "Type=simple",
            "ExecStart=/usr/bin/env python3 " + os.path.abspath(__file__) + " serve",
            "Restart=always",
            "RestartSec=3",
            "User=root",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectHome=true",
            "ProtectSystem=strict",
            "ReadWritePaths=" + os.path.dirname(LOG_PATH) + " " + STATE_DIR,
            "MemoryMax=256M",
            "LimitNOFILE=4096",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def run(argv, timeout=120):
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return proc.returncode, proc.stdout.decode("utf-8", "replace").strip()


def have(tool):
    for folder in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if os.path.isfile(os.path.join(folder, tool)):
            return True
    return False


def write_file(path, body, mode=0o644):
    folder = os.path.dirname(path)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, mode)


def port_open(port, host="127.0.0.1"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.4)
    try:
        return sock.connect_ex((host, int(port))) == 0
    except OSError:
        return False
    finally:
        sock.close()


def tail(path, limit=200):
    text = read_text(path)
    return [row for row in text.splitlines() if row.strip()][-limit:]


def local_address(value):
    try:
        parsed = ipaddress.ip_address(str(value or ""))
    except ValueError:
        return True
    return parsed.is_loopback or parsed.is_unspecified


def summarise(rows):
    counts = {}
    ips = {}
    for row in rows:
        parts = row.split()
        if len(parts) < 4 or parts[0] != "honeypot":
            continue
        fields = {}
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                fields[key] = value
        event = fields.get("event", "probe")
        counts[event] = counts.get(event, 0) + 1
        ip = fields.get("ip", "")
        if ip and not local_address(ip) and event not in {"start", "bind_failed"}:
            ips[ip] = ips.get(ip, 0) + 1
    top = sorted(ips.items(), key=lambda item: (-item[1], item[0]))[:8]
    return {"events": counts, "top": top, "total": sum(counts.values())}


def status():
    config = read_config()
    ports = [int(item) for item in config.get("ports", DEFAULT_PORTS)]
    rows = tail(config.get("log", LOG_PATH))
    return {
        "installed": os.path.isfile(UNIT),
        "running": any(port_open(port) for port in ports),
        "ports": ports,
        "profiles": {str(port): profile(port, config.get("profiles")) for port in ports},
        "unit": UNIT,
        "config": conf_path(),
        "log": config.get("log", LOG_PATH),
        "summary": summarise(rows),
        "recent": rows[-12:],
        "version": VERSION,
    }


def install(flags):
    ports = parse_ports(flags.get("ports", ""))
    config = {
        "ports": ports,
        "bind": str(flags.get("bind", "0.0.0.0")),
        "log": str(flags.get("log", LOG_PATH)),
        "max_conn": int(flags.get("max_conn", DEFAULT_MAX_CONN) or DEFAULT_MAX_CONN),
        "per_ip": int(flags.get("per_ip", DEFAULT_PER_IP) or DEFAULT_PER_IP),
        "profiles": profiles_of(flags, ports),
        "idle": float(flags.get("idle", DEFAULT_IDLE) or DEFAULT_IDLE),
        "greet": float(flags.get("greet", DEFAULT_GREET) or DEFAULT_GREET),
    }
    busy = [port for port in ports if port_open(port)]
    if busy:
        raise HoneyError("port_busy", "port %d is already in use, refusing to shadow a real service" % busy[0], "install")
    write_config(config)
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
    except OSError:
        pass
    write_file(UNIT, unit_body(ports))
    if have("systemctl"):
        run(["systemctl", "daemon-reload"], timeout=60)
        run(["systemctl", "enable", "obhod-honeypot.service"], timeout=60)
        code, text = run(["systemctl", "restart", "obhod-honeypot.service"], timeout=120)
        if code != 0:
            raise HoneyError("start_failed", "the honeypot did not start: " + text[:300], "install")
    return status()


def control(action):
    if not have("systemctl"):
        raise HoneyError("no_systemd", "systemd is required to control the honeypot", action)
    code, text = run(["systemctl", action, "obhod-honeypot.service"], timeout=120)
    if code != 0 and action != "stop":
        raise HoneyError("control_failed", text[:300], action)
    return status()


def remove(_flags=None):
    if have("systemctl"):
        run(["systemctl", "disable", "obhod-honeypot.service"], timeout=60)
        run(["systemctl", "stop", "obhod-honeypot.service"], timeout=60)
    for path in (UNIT, conf_path()):
        try:
            os.unlink(path)
        except OSError:
            pass
    if have("systemctl"):
        run(["systemctl", "daemon-reload"], timeout=60)
    return status()


def events(flags):
    path = str(flags.get("log", "") or read_config().get("log", LOG_PATH))
    limit = int(flags.get("limit", 100) or 100)
    limit = max(1, min(limit, 500))
    rows = tail(path, limit)
    return {"rows": rows, "summary": summarise(rows), "log": path}


def selfcheck(flags):
    ports = parse_ports(flags.get("ports", "") or "2222")
    sink = Sink(echo=True)
    forced = profiles_of(flags, ports)
    server = Server({"ports": ports[:1], "bind": "127.0.0.1", "log": "", "greet": 0.0, "idle": 2.0, "profiles": forced}, sink)
    started = server.start()
    if not started:
        raise HoneyError("bind_failed", "no decoy port could be bound", "selfcheck")
    port = server.sockets[0][1]
    result = {"port": port, "banner": "", "proto": profile(port, forced), "rows": [], "banned_line": ""}
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(3.0)
    try:
        probe.connect(("127.0.0.1", port))
        result["banner"] = probe.recv(200)[:90].decode("ascii", "replace")
        probe.sendall(b"USER root\r\nPASS hunter2\r\n\r\n")
        try:
            probe.recv(200)
        except OSError:
            pass
    except OSError as exc:
        raise HoneyError("selfcheck_failed", str(exc)[:200], "selfcheck") from None
    finally:
        probe.close()
        time.sleep(0.3)
        server.close()
    rows = list(sink.rows)
    result["rows"] = rows[:6]
    for row in rows:
        if " event=auth " in row or " event=probe " in row:
            result["banned_line"] = row
            break
    return result


def parse_flags(tokens):
    flags = {}
    for token in tokens:
        if not token.startswith("--"):
            continue
        body = token[2:]
        if "=" in body:
            key, value = body.split("=", 1)
            flags[key.replace("-", "_")] = value
        else:
            flags[body.replace("-", "_")] = True
    return flags


def emit(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv):
    flags = parse_flags(argv[1:])
    command = argv[0] if argv else "status"
    if command == SERVE:
        config = read_config(str(flags.get("config", "") or ""))
        server = Server(config)

        def stop(_signum, _frame):
            server.close()
            raise SystemExit(0)

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        server.run()
        return 0
    try:
        if command == "status":
            payload = status()
        elif command == "install":
            payload = install(flags)
        elif command in {"start", "stop", "restart"}:
            payload = control(command)
        elif command in {"remove", "uninstall"}:
            payload = remove(flags)
        elif command == "events":
            payload = events(flags)
        elif command == "selfcheck":
            payload = selfcheck(flags)
        else:
            raise HoneyError("bad_command", "unknown command: " + command, "arg")
        emit({"ok": True, "data": payload, "log": payload.get("log", "") if isinstance(payload, dict) else ""})
        return 0
    except HoneyError as exc:
        emit({"ok": False, "code": exc.code, "message": exc.message, "stage": exc.stage})
        return 2
    except subprocess.SubprocessError as exc:
        emit({"ok": False, "code": "internal", "message": str(exc)[:200], "stage": command})
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
