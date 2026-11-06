import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

VERSION = "1.0.0"
TABLE = "obhod_ddos"
CONF_DIR = "/etc/obhod"
CONF = os.path.join(CONF_DIR, "ddos.json")
RULES = os.path.join(CONF_DIR, "ddos.nft")
SYSCTL = "/etc/sysctl.d/99-obhod-ddos.conf"
UNIT_DIR = "/etc/systemd/system"
UNIT = os.path.join(UNIT_DIR, "obhod-ddos.service")
NFT = "nft"
SYSCTL_BIN = "sysctl"
SYSTEMCTL = "systemctl"
SETS = ("syn_flood", "conn_flood", "udp_flood", "icmp_flood", "port_scan")
MAX_OUTPUT = 262144
TIMEOUT = 30
RATE_LIMIT = re.compile(r"^(\d{1,6})/(second|minute|hour)$")
SAFE_IP = re.compile(r"^[0-9a-fA-F:.]{2,45}$")
SAFE_NAME = re.compile(r"^[a-z_]{2,24}$")
COUNTER = re.compile(r"counter packets (\d+) bytes (\d+)")
ELEMENT = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?: timeout [0-9a-z]+)?")
SERVICES = {
    "22": "ssh",
    "2222": "ssh",
    "21": "ftp",
    "23": "telnet",
    "80": "http",
    "443": "https",
    "2375": "docker",
    "3306": "mysql",
    "5432": "postgres",
    "6379": "redis",
    "11211": "memcached",
    "27017": "mongodb",
    "10085": "xray-api",
}
PORT_KEYS = ("ports", "syn_rate", "syn_burst", "conn_rate", "conn_burst", "udp_rate", "udp_burst", "icmp_rate", "icmp_burst", "ban_timeout", "set_size", "enabled")


class DDosError(Exception):
    def __init__(self, code, message, stage="ddos"):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.stage = stage


def emit(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


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


def number(value, low, high, fallback):
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return int(fallback)
    return int(max(low, min(parsed, high)))


def truth(value, fallback=True):
    text = str(value).strip().lower()
    if text in ("1", "on", "yes", "true"):
        return True
    if text in ("0", "off", "no", "false"):
        return False
    return bool(fallback)


def ports_text(raw):
    if isinstance(raw, (list, tuple, set)):
        text = ",".join(str(item) for item in raw)
    else:
        text = str(raw or "")
    out = []
    for match in re.finditer(r"(?<![\w-])(\d{1,5})(?!\w)", text):
        value = int(match.group(1))
        if 1 <= value <= 65535 and value not in out:
            out.append(value)
    return ",".join(str(item) for item in out[:16])


def path_of(flags):
    directory = str(flags.get("dir", "") or "")
    if directory:
        if not os.path.isabs(directory) or ".." in directory.split(os.sep):
            raise DDosError("bad_path", "the directory must be a simple absolute path", "arg")
        return directory
    return CONF_DIR


def conf_path(flags):
    override = str(flags.get("config", "") or "") or os.environ.get("DDOS_CONF", "")
    if override:
        if not os.path.isabs(override) or ".." in override.split(os.sep):
            raise DDosError("bad_path", "the config must be a simple absolute path", "arg")
        return override
    return os.path.join(path_of(flags), "ddos.json")


def rules_path(flags):
    return os.path.join(path_of(flags), "ddos.nft")


def sysctl_path(flags):
    directory = path_of(flags)
    if directory == CONF_DIR:
        return SYSCTL
    return os.path.join(directory, "99-obhod-ddos.conf")


def unit_path(flags):
    directory = path_of(flags)
    if directory == CONF_DIR:
        return UNIT
    return os.path.join(directory, "obhod-ddos.service")


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            body = json.load(handle)
    except (OSError, ValueError):
        return {}
    return body if isinstance(body, dict) else {}


def write_atomic(path, text, mode=0o644):
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        raise DDosError("fs", "cannot create %s: %s" % (directory, exc.strerror), "fs")
    handle, temp = tempfile.mkstemp(prefix=".obhod-", dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    except OSError as exc:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise DDosError("fs", "cannot write %s: %s" % (path, exc.strerror), "fs")


def run(argv, timeout=TIMEOUT):
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except OSError as exc:
        return 127, "", str(exc.strerror or exc)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    return proc.returncode, proc.stdout.decode("utf-8", "replace")[:MAX_OUTPUT], proc.stderr.decode("utf-8", "replace")[:4096]


def binary(flags, name, fallback):
    override = str(flags.get(name, "") or "")
    if not override:
        found = shutil.which(fallback)
        return found or ""
    if os.path.isabs(override):
        return override if os.path.isfile(override) and os.access(override, os.X_OK) else ""
    return shutil.which(override) or ""


def policy_from(raw, flags):
    base = {
        "enabled": True,
        "syn_rate": 60,
        "syn_burst": 40,
        "conn_rate": 120,
        "conn_burst": 60,
        "udp_rate": 400,
        "udp_burst": 200,
        "icmp_rate": 20,
        "icmp_burst": 10,
        "ban_timeout": 3600,
        "set_size": 65536,
        "ports": "22,443",
    }
    for key in PORT_KEYS:
        if key in raw:
            base[key] = raw[key]
    for key in PORT_KEYS:
        if key in flags:
            base[key] = flags[key]
    policy = {
        "enabled": truth(base.get("enabled"), True),
        "syn_rate": number(base.get("syn_rate"), 1, 100000, 60),
        "syn_burst": number(base.get("syn_burst"), 1, 100000, 40),
        "conn_rate": number(base.get("conn_rate"), 1, 100000, 120),
        "conn_burst": number(base.get("conn_burst"), 1, 100000, 60),
        "udp_rate": number(base.get("udp_rate"), 1, 200000, 400),
        "udp_burst": number(base.get("udp_burst"), 1, 200000, 200),
        "icmp_rate": number(base.get("icmp_rate"), 1, 10000, 20),
        "icmp_burst": number(base.get("icmp_burst"), 1, 10000, 10),
        "ban_timeout": number(base.get("ban_timeout"), 60, 86400, 3600),
        "set_size": number(base.get("set_size"), 1024, 1048576, 65536),
        "ports": ports_text(base.get("ports")) or "22,443",
    }
    return policy


def port_set(policy):
    return "{ " + ", ".join(policy["ports"].split(",")) + " }"


def freeturn_accept_lines(flags=None):
    if flags and path_of(flags) != CONF_DIR:
        return []
    conf = "/opt/free-turn-proxy/install.conf"
    if not os.path.isfile(conf):
        return []
    port = 0
    mode = "udp"
    try:
        with open(conf, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key == "LISTEN_PORT" and value.isdigit() and 1 <= int(value) <= 65535:
                    port = int(value)
                elif key in ("PROXY_MODE", "MODE") and value.lower() in ("udp", "tcp"):
                    mode = value.lower()
    except OSError:
        return []
    if not port:
        return []
    out = ["    udp dport %d accept" % port]
    if mode == "tcp":
        out.append("    tcp dport %d accept" % port)
    return out


def rules_text(policy, flags=None):
    lines = [
        "table inet %s {" % TABLE,
    ]
    for name in SETS:
        lines.append("  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (name, policy["ban_timeout"], policy["set_size"]))
    lines.extend(
        [
            "  chain input {",
            "    type filter hook input priority raw; policy accept;",
            '    iifname "lo" accept',
        ]
    )
    lines.extend(freeturn_accept_lines(flags))
    lines.extend(
        [
            "    ct state invalid counter drop",
            "    tcp flags & (fin|syn|rst|ack) == 0x0 counter drop",
            "    tcp flags & (fin|syn|psh|rst|ack|urg) == (fin|syn|psh|urg) counter drop",
        ]
    )
    for name in SETS:
        lines.append("    ip saddr @%s counter drop" % name)
    lines.extend(
        [
            "    ct state new tcp flags & (fin|syn|rst|ack) == syn update @syn_flood { ip saddr limit rate over %d/second burst %d packets } counter accept" % (policy["syn_rate"], policy["syn_burst"]),
            "    ct state new update @conn_flood { ip saddr limit rate over %d/second burst %d packets }" % (policy["conn_rate"], policy["conn_burst"]),
            "    udp dport %s update @udp_flood { ip saddr limit rate over %d/second burst %d packets }" % (port_set(policy), policy["udp_rate"], policy["udp_burst"]),
            "    icmp type echo-request update @icmp_flood { ip saddr limit rate over %d/second burst %d packets }" % (policy["icmp_rate"], policy["icmp_burst"]),
            "    tcp dport %s tcp flags & (fin|syn|rst|ack) == syn update @port_scan { ip saddr limit rate over 24/second burst 24 packets }" % port_set(policy),
            "    counter accept",
            "  }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


SYSCTL_ROWS = (
    ("net.ipv4.tcp_syncookies", "1"),
    ("net.ipv4.tcp_max_syn_backlog", "8192"),
    ("net.ipv4.tcp_synack_retries", "2"),
    ("net.ipv4.tcp_syn_retries", "3"),
    ("net.ipv4.tcp_fin_timeout", "15"),
    ("net.ipv4.tcp_rfc1337", "1"),
    ("net.ipv4.tcp_mtu_probing", "1"),
    ("net.ipv4.ip_local_port_range", "10240 65000"),
    ("net.ipv4.conf.all.rp_filter", "2"),
    ("net.ipv4.conf.all.accept_source_route", "0"),
    ("net.ipv4.conf.all.accept_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    ("net.core.somaxconn", "4096"),
    ("net.core.netdev_max_backlog", "16384"),
    ("net.core.default_qdisc", "fq"),
    ("net.ipv4.tcp_congestion_control", "bbr"),
    ("net.netfilter.nf_conntrack_max", "262144"),
)


def sysctl_text():
    return "".join("%s = %s\n" % (key, value) for key, value in SYSCTL_ROWS)


def unit_text(flags):
    return (
        "[Unit]\n"
        "Description=obhod anti flood rules\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        "ExecStart=%s -f %s\n"
        "ExecStop=%s delete table inet %s\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n" % (binary(flags, "nft", NFT) or NFT, rules_path(flags), binary(flags, "nft", NFT) or NFT, TABLE)
    )


def rule_label(line):
    text = line.lower()
    for name in SETS:
        if "update @" + name in text:
            return "syn_new" if name == "syn_flood" else ("conn_new" if name == "conn_flood" else ("udp_new" if name == "udp_flood" else ("icmp_new" if name == "icmp_flood" else "scan_new")))
    for name in SETS:
        if "ip saddr @" + name in text:
            return name.replace("_flood", "_drop").replace("port_scan", "scan_drop")
    if "0x0" in text:
        return "null"
    if "(fin|syn|psh|urg)" in text:
        return "xmas"
    if "ct state invalid" in text:
        return "invalid"
    if "update @syn_flood" in text:
        return "syn_new"
    if "update @conn_flood" in text:
        return "conn_new"
    if "update @udp_flood" in text:
        return "udp_new"
    if "update @icmp_flood" in text:
        return "icmp_new"
    if "update @port_scan" in text:
        return "scan_new"
    if "accept" in text:
        return "accepted"
    return ""


def counters_of(body):
    values = {}
    for line in str(body or "").splitlines():
        match = COUNTER.search(line)
        if not match:
            continue
        label = rule_label(line)
        if not label:
            continue
        try:
            values[label] = values.get(label, 0) + int(match.group(1))
        except ValueError:
            continue
    return values


def set_elements(body, name):
    text = str(body or "")
    start = text.find("set " + name + " {")
    if start < 0:
        return []
    end = text.find("\n  }", start)
    chunk = text[start:end if end > 0 else start + 4096]
    found = []
    for match in ELEMENT.finditer(chunk):
        candidate = match.group(1)
        try:
            address = str(ipaddress.IPv4Address(candidate))
        except ValueError:
            continue
        if address not in found:
            found.append(address)
    return found[:64]


def table_text(flags):
    tool = binary(flags, "nft", NFT)
    if not tool:
        return "", "nft is not installed"
    code, out, err = run([tool, "list", "table", "inet", TABLE])
    if code != 0:
        return "", (err or "table is not loaded").strip()[:120]
    return out, ""


def sample_pps(interval=0.5):
    def totals():
        rx = 0
        try:
            with open("/proc/net/dev", "r", encoding="utf-8") as handle:
                body = handle.read()
        except OSError:
            return 0
        for line in body.splitlines()[2:]:
            if ":" not in line:
                continue
            fields = line.split(":", 1)[1].split()
            if len(fields) < 3:
                continue
            try:
                rx += int(fields[1])
            except (TypeError, ValueError):
                continue
        return rx

    first = totals()
    time.sleep(max(0.05, min(float(interval), 2.0)))
    second = totals()
    return max(0, int((second - first) / max(0.05, float(interval))))


def read_int(path, fallback=0):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return max(0, int(handle.read().strip()))
    except (OSError, ValueError):
        return int(fallback)


def established_count():
    total = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                body = handle.read()
        except OSError:
            continue
        for line in body.splitlines()[1:]:
            parts = line.split()
            if len(parts) > 3 and parts[3] == "01":
                total += 1
    return total


def kernel():
    try:
        with open("/proc/sys/kernel/osrelease", "r", encoding="utf-8") as handle:
            return handle.read().strip()[:32]
    except OSError:
        return ""


def status(flags):
    policy = policy_from(read_json(conf_path(flags)), {})
    body, why = table_text(flags)
    present = bool(body)
    counters = counters_of(body) if present else {}
    payload = {
        "installed": os.path.isfile(rules_path(flags)),
        "enabled": bool(policy.get("enabled", True)),
        "table": present,
        "policy": policy,
        "counters": counters,
        "syn_flood": set_elements(body, "syn_flood") if present else [],
        "conn_flood": set_elements(body, "conn_flood") if present else [],
        "udp_flood": set_elements(body, "udp_flood") if present else [],
        "icmp_flood": set_elements(body, "icmp_flood") if present else [],
        "scan": set_elements(body, "port_scan") if present else [],
        "pps": sample_pps(0.3),
        "connections": established_count(),
        "conntrack": read_int("/proc/sys/net/netfilter/nf_conntrack_count"),
        "conntrack_max": read_int("/proc/sys/net/netfilter/nf_conntrack_max"),
        "kernel": kernel(),
        "notice": why,
    }
    if not payload["installed"] and not why:
        payload["notice"] = "rules are not written yet"
    return payload


def apply_rules(flags, policy):
    tool = binary(flags, "nft", NFT)
    target = rules_path(flags)
    body = rules_text(policy, flags)
    if not tool:
        write_atomic(target, body)
        raise DDosError("no_nft", "nft is not installed, the rules were written but not loaded", "apply")
    check = os.path.join(os.path.dirname(target) or ".", ".obhod-check.nft")
    write_atomic(check, body)
    try:
        code, out, err = run([tool, "-c", "-f", check])
        if code != 0:
            raise DDosError("bad_rules", (err or out or "nft refused the ruleset").strip()[:200], "check")
    finally:
        try:
            os.unlink(check)
        except OSError:
            pass
    previous = ""
    if os.path.isfile(target):
        try:
            with open(target, "r", encoding="utf-8") as handle:
                previous = handle.read()[:MAX_OUTPUT]
        except OSError:
            previous = ""
    write_atomic(target, body)
    run([tool, "delete", "table", "inet", TABLE])
    code, out, err = run([tool, "-f", target])
    if code != 0:
        if previous:
            write_atomic(target, previous)
            run([tool, "-f", target])
        raise DDosError("apply", (err or out or "nft did not load the ruleset").strip()[:200], "apply")
    return body


def apply_sysctl(flags):
    tool = binary(flags, "sysctl", SYSCTL_BIN)
    target = sysctl_path(flags)
    write_atomic(target, sysctl_text())
    if not tool:
        return {"written": target, "applied": False, "note": "sysctl is not available"}
    code, out, err = run([tool, "-p", target])
    return {"written": target, "applied": code == 0, "note": (err or out).strip()[:160]}


def enable_unit(flags):
    tool = binary(flags, "systemctl", SYSTEMCTL)
    target = unit_path(flags)
    write_atomic(target, unit_text(flags))
    if not tool:
        return {"written": target, "enabled": False, "note": "systemd is not available"}
    run([tool, "daemon-reload"])
    code, out, err = run([tool, "enable", "--now", os.path.basename(target)])
    return {"written": target, "enabled": code == 0, "note": (err or out).strip()[:160]}


def install(flags):
    policy = policy_from(read_json(conf_path(flags)), flags)
    if policy.get("enabled"):
        apply_rules(flags, policy)
    else:
        disable(flags)
    write_atomic(conf_path(flags), json.dumps(policy, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    sysctl_result = apply_sysctl(flags)
    unit_result = enable_unit(flags)
    payload = status(flags)
    payload["sysctl"] = sysctl_result
    payload["unit"] = unit_result
    payload["notice"] = "the ruleset is loaded" if payload["table"] else payload["notice"]
    return payload


def disable(flags):
    tool = binary(flags, "nft", NFT)
    if tool:
        run([tool, "delete", "table", "inet", TABLE])
    return {"disabled": True}


def remove(flags):
    disable(flags)
    tool = binary(flags, "systemctl", SYSTEMCTL)
    if tool:
        run([tool, "disable", "--now", os.path.basename(unit_path(flags))])
        run([tool, "daemon-reload"])
    for path in (rules_path(flags), unit_path(flags)):
        try:
            os.unlink(path)
        except OSError:
            pass
    payload = status(flags)
    payload["notice"] = "the ruleset and the unit are gone"
    return payload


def proc_owners():
    owners = {}
    base = "/proc"
    try:
        pids = [name for name in os.listdir(base) if name.isdigit()][:2048]
    except OSError:
        return owners
    for pid in pids:
        try:
            with open(os.path.join(base, pid, "comm"), "r", encoding="utf-8") as handle:
                name = handle.read().strip()[:40].lower().replace(" ", "-")
        except OSError:
            continue
        try:
            fds = os.listdir(os.path.join(base, pid, "fd"))
        except OSError:
            continue
        for fd in fds[:256]:
            try:
                link = os.readlink(os.path.join(base, pid, "fd", fd))
            except OSError:
                continue
            if link.startswith("socket:["):
                try:
                    owners[int(link[8:-1])] = name
                except ValueError:
                    continue
    return owners


def listening_from_proc():
    owners = proc_owners()
    rows = []
    for path, family in (("/proc/net/tcp", 4), ("/proc/net/tcp6", 6)):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                body = handle.read()
        except OSError:
            continue
        for line in body.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":
                continue
            local = parts[1].split(":")
            if len(local) != 2:
                continue
            try:
                port = int(local[1], 16)
                raw = bytes.fromhex(local[0])[::-1]
            except ValueError:
                continue
            try:
                address = str(ipaddress.ip_address(raw))
            except ValueError:
                continue
            try:
                owner = owners.get(int(parts[9]), "")
            except ValueError:
                owner = ""
            rows.append({"port": port, "proto": "tcp", "process": owner, "address": address})
    return rows


def ss_rows(flags):
    tool = binary(flags, "ss", "ss")
    if not tool:
        return []
    code, out, _err = run([tool, "-Hltn"])
    if code != 0:
        return []
    rows = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        address, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        process = ""
        if len(fields) > 5:
            process = fields[5].split(":")[0].strip('"').lower()
        rows.append({"port": int(port), "proto": "tcp", "process": process, "address": address.strip("[]")})
    return rows


def probe(flags):
    rows = ss_rows(flags)
    source = "ss"
    if not rows:
        rows = listening_from_proc()
        source = "proc"
    cleaned = []
    for row in rows[:512]:
        port = row.get("port", 0)
        if not isinstance(port, int) or not 1 <= port <= 65535:
            continue
        address = str(row.get("address", "") or "")[:45]
        if address and not SAFE_IP.match(address):
            address = ""
        name = str(row.get("process", "") or "")[:40]
        if name and not re.match(r"^[a-z0-9_.+-]{1,40}$", name):
            name = ""
        cleaned.append({"port": port, "proto": "tcp", "process": name, "address": address})
    return {"rows": cleaned, "count": len(cleaned), "source": source}


def sysinfo(flags):
    return {
        "kernel": kernel(),
        "nft": bool(binary(flags, "nft", NFT)),
        "sysctl": bool(binary(flags, "sysctl", SYSCTL_BIN)),
        "systemd": bool(binary(flags, "systemctl", SYSTEMCTL)),
        "conf": conf_path(flags),
        "rules": rules_path(flags),
        "conntrack": read_int("/proc/sys/net/netfilter/nf_conntrack_count"),
        "conntrack_max": read_int("/proc/sys/net/netfilter/nf_conntrack_max"),
    }


def render(flags):
    policy = policy_from(read_json(conf_path(flags)), flags)
    return {"rules": rules_text(policy, flags), "sysctl": sysctl_text(), "policy": policy}


def main(argv):
    command = argv[0] if argv else "status"
    try:
        flags = parse_flags(argv[1:])
        if command == "status":
            payload = status(flags)
        elif command == "install":
            payload = install(flags)
        elif command == "remove" or command == "uninstall":
            payload = remove(flags)
        elif command == "disable":
            payload = disable(flags)
        elif command == "probe":
            payload = probe(flags)
        elif command == "info":
            payload = sysinfo(flags)
        elif command == "render":
            payload = render(flags)
        else:
            raise DDosError("bad_command", "unknown command: " + str(command)[:40], "arg")
        emit({"ok": True, "data": payload})
        return 0
    except DDosError as exc:
        emit({"ok": False, "code": exc.code, "message": exc.message, "stage": exc.stage})
        return 2
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        emit({"ok": False, "code": "internal", "message": str(exc)[:200], "stage": command})
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
