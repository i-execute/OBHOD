from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

LEVELS = ("ok", "warn", "bad")
TABLE = "obhod_ddos"
SET_SYN = "syn_flood"
SET_CONN = "conn_flood"
SET_UDP = "udp_flood"
SET_ICMP = "icmp_flood"
SET_SCAN = "port_scan"
DEFAULT_PORTS = (22, 443)
MAX_PORTS = 16
MAX_SET_SIZE = 1 << 20
MAX_WINDOW = 3600
MIN_BURST = 1
MIN_RATE = 1

SYN_RATE = 180
SYN_BURST = 240
CONN_RATE = 300
CONN_BURST = 360
UDP_RATE = 400
UDP_BURST = 200
ICMP_RATE = 20
ICMP_BURST = 10
SCAN_RATE = 60
BAN_TIMEOUT = 3600
SET_SIZE = 65536

PPS_WARN = 60000
PPS_BAD = 200000
CONNTRACK_WARN = 0.70
CONNTRACK_BAD = 0.90
SET_WARN = 8
SET_BAD = 60
DROP_WARN = 200
DROP_BAD = 5000

PANEL_NAMES = ("3x-ui", "x-ui", "xray-ui", "marzban", "hiddify", "v2board", "xpanel", "sspanel")
PANEL_PORTS = (2053, 2083, 2087, 2096, 8443, 54321)
PROXY_PORTS = (1080, 1081, 3128, 7890, 7891, 8118, 8388, 8880, 9000)
DATASTORE_PORTS = (3306, 5432, 6379, 9042, 11211, 27017, 27018)
RISKY_PORTS = {
    21: "ftp",
    23: "telnet",
    25: "smtp",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    445: "smb",
    2049: "nfs",
    2375: "docker socket",
    2376: "docker tls",
    2379: "etcd",
    5900: "vnc",
    6443: "kubernetes api",
    9100: "node exporter",
    10085: "xray api",
    19999: "netdata",
}
PROBE_RANK = {"bad": 3, "warn": 2, "info": 1}

FIELD = re.compile(r"^[a-z_]{2,24}$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class DDoSerror(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def clamp(value: object, low: int, high: int, fallback: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return int(fallback)
    return int(max(low, min(number, high)))


def ports_of(raw: object) -> list[int]:
    if isinstance(raw, (list, tuple, set)):
        text = ",".join(str(item) for item in raw)
    else:
        text = str(raw or "")
    out: list[int] = []
    for match in re.finditer(r"(?<![\w-])(\d{1,5})(?!\w)", text):
        value = int(match.group(1))
        if 1 <= value <= 65535 and value not in out:
            out.append(value)
    return out[:MAX_PORTS]


def ports_text(raw: object) -> str:
    ports = ports_of(raw)
    return ",".join(str(item) for item in ports)


@dataclass
class Policy:
    enabled: bool = True
    syn_rate: int = SYN_RATE
    syn_burst: int = SYN_BURST
    conn_rate: int = CONN_RATE
    conn_burst: int = CONN_BURST
    udp_rate: int = UDP_RATE
    udp_burst: int = UDP_BURST
    icmp_rate: int = ICMP_RATE
    icmp_burst: int = ICMP_BURST
    ban_timeout: int = BAN_TIMEOUT
    set_size: int = SET_SIZE
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))

    def normalise(self) -> "Policy":
        self.syn_rate = clamp(self.syn_rate, MIN_RATE, 100000, SYN_RATE)
        self.syn_burst = clamp(self.syn_burst, MIN_BURST, 100000, SYN_BURST)
        self.conn_rate = clamp(self.conn_rate, MIN_RATE, 100000, CONN_RATE)
        self.conn_burst = clamp(self.conn_burst, MIN_BURST, 100000, CONN_BURST)
        self.udp_rate = clamp(self.udp_rate, MIN_RATE, 200000, UDP_RATE)
        self.udp_burst = clamp(self.udp_burst, MIN_BURST, 200000, UDP_BURST)
        self.icmp_rate = clamp(self.icmp_rate, MIN_RATE, 10000, ICMP_RATE)
        self.icmp_burst = clamp(self.icmp_burst, MIN_BURST, 10000, ICMP_BURST)
        self.ban_timeout = clamp(self.ban_timeout, 60, MAX_WINDOW * 24, BAN_TIMEOUT)
        self.set_size = clamp(self.set_size, 1024, MAX_SET_SIZE, SET_SIZE)
        self.ports = ports_of(",".join(str(item) for item in self.ports)) or list(DEFAULT_PORTS)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.enabled),
            "syn_rate": int(self.syn_rate),
            "syn_burst": int(self.syn_burst),
            "conn_rate": int(self.conn_rate),
            "conn_burst": int(self.conn_burst),
            "udp_rate": int(self.udp_rate),
            "udp_burst": int(self.udp_burst),
            "icmp_rate": int(self.icmp_rate),
            "icmp_burst": int(self.icmp_burst),
            "ban_timeout": int(self.ban_timeout),
            "set_size": int(self.set_size),
            "ports": list(self.ports),
        }

    @staticmethod
    def from_dict(raw: Any) -> "Policy":
        data = raw if isinstance(raw, dict) else {}
        policy = Policy(
            enabled=bool(data.get("enabled", True)),
            syn_rate=clamp(data.get("syn_rate"), MIN_RATE, 100000, SYN_RATE),
            syn_burst=clamp(data.get("syn_burst"), MIN_BURST, 100000, SYN_BURST),
            conn_rate=clamp(data.get("conn_rate"), MIN_RATE, 100000, CONN_RATE),
            conn_burst=clamp(data.get("conn_burst"), MIN_BURST, 100000, CONN_BURST),
            udp_rate=clamp(data.get("udp_rate"), MIN_RATE, 200000, UDP_RATE),
            udp_burst=clamp(data.get("udp_burst"), MIN_BURST, 200000, UDP_BURST),
            icmp_rate=clamp(data.get("icmp_rate"), MIN_RATE, 10000, ICMP_RATE),
            icmp_burst=clamp(data.get("icmp_burst"), MIN_BURST, 10000, ICMP_BURST),
            ban_timeout=clamp(data.get("ban_timeout"), 60, MAX_WINDOW * 24, BAN_TIMEOUT),
            set_size=clamp(data.get("set_size"), 1024, MAX_SET_SIZE, SET_SIZE),
            ports=ports_of(raw.get("ports") if isinstance(raw, dict) else ""),
        )
        return policy.normalise()


def ports_set(policy: Policy) -> str:
    ports = policy.ports or list(DEFAULT_PORTS)
    return "{ " + ", ".join(str(item) for item in ports) + " }"


def nft_table(policy: Policy) -> str:
    policy = policy.normalise()
    lines = [
        "table inet %s {" % TABLE,
        "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_SYN, policy.ban_timeout, policy.set_size),
        "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_CONN, policy.ban_timeout, policy.set_size),
        "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_UDP, policy.ban_timeout, policy.set_size),
        "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_ICMP, policy.ban_timeout, policy.set_size),
        "  set %s { type ipv4_addr; flags dynamic, timeout; timeout %ds; size %d; }" % (SET_SCAN, policy.ban_timeout, policy.set_size),
        "  chain input {",
        "    type filter hook input priority raw; policy accept;",
        '    iifname "lo" accept',
        "    ct state invalid counter drop",
        "    tcp flags & (fin|syn|rst|ack) == 0x0 counter drop",
        "    tcp flags & (fin|syn|psh|rst|ack|urg) == (fin|syn|psh|urg) counter drop",
        "    ip saddr @%s counter drop" % SET_SYN,
        "    ip saddr @%s counter drop" % SET_CONN,
        "    ip saddr @%s counter drop" % SET_UDP,
        "    ip saddr @%s counter drop" % SET_ICMP,
        "    ip saddr @%s counter drop" % SET_SCAN,
        "    ct state new tcp flags & (fin|syn|rst|ack) == syn update @%s { ip saddr limit rate over %d/second burst %d packets } counter accept"
        % (SET_SYN, policy.syn_rate, policy.syn_burst),
        "    ct state new update @%s { ip saddr limit rate over %d/second burst %d packets }" % (SET_CONN, policy.conn_rate, policy.conn_burst),
        "    udp dport %s update @%s { ip saddr limit rate over %d/second burst %d packets }" % (ports_set(policy), SET_UDP, policy.udp_rate, policy.udp_burst),
        "    icmp type echo-request update @%s { ip saddr limit rate over %d/second burst %d packets }" % (SET_ICMP, policy.icmp_rate, policy.icmp_burst),
        "    tcp dport != %s tcp flags & (fin|syn|rst|ack) == syn update @%s { ip saddr limit rate over %d/second burst %d packets }"
        % (ports_set(policy), SET_SCAN, SCAN_RATE, SCAN_RATE),
        "    counter accept",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def sysctl_values(policy: Policy) -> dict[str, str]:
    policy = policy.normalise()
    return {
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.tcp_max_syn_backlog": "8192",
        "net.ipv4.tcp_synack_retries": "2",
        "net.ipv4.tcp_syn_retries": "3",
        "net.ipv4.tcp_fin_timeout": "15",
        "net.ipv4.tcp_keepalive_time": "600",
        "net.ipv4.tcp_max_orphans": "32768",
        "net.ipv4.tcp_rfc1337": "1",
        "net.ipv4.tcp_mtu_probing": "1",
        "net.ipv4.ip_local_port_range": "10240 65000",
        "net.ipv4.conf.all.rp_filter": "2",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.secure_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.log_martians": "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "net.ipv4.icmp_ratelimit": "200",
        "net.ipv4.icmp_ratemask": "88089",
        "net.core.somaxconn": "4096",
        "net.core.netdev_max_backlog": "16384",
        "net.core.rmem_max": "16777216",
        "net.core.wmem_max": "16777216",
        "net.core.default_qdisc": "fq",
        "net.ipv4.tcp_congestion_control": "bbr",
        "net.netfilter.nf_conntrack_max": "262144",
        "net.netfilter.nf_conntrack_tcp_timeout_syn_recv": "30",
        "net.netfilter.nf_conntrack_generic_timeout": str(max(60, min(policy.ban_timeout, 3600))),
    }


def sysctl_text(policy: Policy) -> str:
    rows = sysctl_values(policy)
    return "".join("%s = %s\n" % (key, value) for key, value in sorted(rows.items()))


def parse_counters(raw: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        name = str(key or "").strip().lower()
        if not FIELD.match(name):
            continue
        try:
            out[name] = max(0, int(value))
        except (TypeError, ValueError):
            continue
    return out


def parse_set(raw: Any, limit: int = 64) -> list[str]:
    out: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        text = str(item or "").strip()[:45]
        if not text:
            continue
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        out.append(str(address))
        if len(out) >= limit:
            break
    return out


@dataclass
class Status:
    installed: bool = False
    enabled: bool = True
    table: bool = False
    policy: Policy = field(default_factory=Policy)
    counters: dict[str, int] = field(default_factory=dict)
    syn_flood: list[str] = field(default_factory=list)
    conn_flood: list[str] = field(default_factory=list)
    udp_flood: list[str] = field(default_factory=list)
    icmp_flood: list[str] = field(default_factory=list)
    scan: list[str] = field(default_factory=list)
    pps: int = 0
    connections: int = 0
    conntrack: int = 0
    conntrack_max: int = 0
    kernel: str = ""
    notice: str = ""
    error: str = ""

    @staticmethod
    def from_dict(raw: Any) -> "Status":
        data = raw if isinstance(raw, dict) else {}
        status = Status(
            installed=bool(data.get("installed", False)),
            enabled=bool(data.get("enabled", True)),
            table=bool(data.get("table", False)),
            policy=Policy.from_dict(data.get("policy")),
            counters=parse_counters(data.get("counters")),
            syn_flood=parse_set(data.get("syn_flood")),
            conn_flood=parse_set(data.get("conn_flood")),
            udp_flood=parse_set(data.get("udp_flood")),
            icmp_flood=parse_set(data.get("icmp_flood")),
            scan=parse_set(data.get("scan")),
            pps=clamp(data.get("pps"), 0, 1 << 40, 0),
            connections=clamp(data.get("connections"), 0, 1 << 32, 0),
            conntrack=clamp(data.get("conntrack"), 0, 1 << 32, 0),
            conntrack_max=clamp(data.get("conntrack_max"), 0, 1 << 32, 0),
            kernel=str(data.get("kernel", "") or "")[:32],
            notice=str(data.get("notice", "") or "")[:120],
            error=str(data.get("error", "") or "")[:160],
        )
        return status

    def dropped(self) -> int:
        return sum(value for key, value in self.counters.items() if "drop" in key)

    def offenders(self) -> list[str]:
        seen: list[str] = []
        for group in (self.syn_flood, self.conn_flood, self.udp_flood, self.icmp_flood, self.scan):
            for address in group:
                if address not in seen:
                    seen.append(address)
        return seen[:16]

    def pressure(self) -> float:
        if self.conntrack_max <= 0:
            return 0.0
        return min(1.0, float(self.conntrack) / float(self.conntrack_max))

    def reasons(self) -> list[str]:
        out: list[str] = []
        if not self.installed:
            return out
        if self.error:
            out.append("agent_error")
        if self.enabled and not self.table:
            out.append("table_missing")
        if len(self.syn_flood) >= SET_WARN:
            out.append("syn_flood")
        if len(self.conn_flood) >= SET_WARN:
            out.append("conn_flood")
        if len(self.udp_flood) >= SET_WARN:
            out.append("udp_flood")
        if len(self.scan) >= SET_WARN:
            out.append("port_scan")
        if self.pps >= PPS_WARN:
            out.append("pps")
        if self.pressure() >= CONNTRACK_WARN:
            out.append("conntrack")
        if self.dropped() >= DROP_WARN:
            out.append("drops")
        return out

    def level(self) -> str:
        if not self.installed:
            return "ok"
        reasons = self.reasons()
        if self.error or not self.enabled:
            return "warn" if self.enabled and not self.table else "ok"
        if "table_missing" in reasons:
            return "bad"
        if any(item in reasons for item in ("syn_flood", "udp_flood")) and len(self.syn_flood) >= SET_BAD:
            return "bad"
        if self.pps >= PPS_BAD or self.pressure() >= CONNTRACK_BAD or self.dropped() >= DROP_BAD:
            return "bad"
        if len(self.conn_flood) >= SET_BAD or len(self.scan) >= SET_BAD:
            return "bad"
        return "warn" if reasons else "ok"

    def under_attack(self) -> bool:
        return bool(self.installed) and self.level() == "bad"

    def event_kind(self) -> str:
        reasons = self.reasons()
        for name in ("syn_flood", "udp_flood", "conn_flood", "pps", "conntrack", "drops", "table_missing", "agent_error"):
            if name in reasons:
                return name
        return "load"

    def headline(self) -> str:
        pieces = ["%d pps" % self.pps]
        if self.conntrack_max:
            pieces.append("conntrack %d/%d" % (self.conntrack, self.conntrack_max))
        if self.syn_flood:
            pieces.append("syn %d" % len(self.syn_flood))
        return ", ".join(pieces)

    def to_dict(self) -> dict[str, Any]:
        return {
            "installed": self.installed,
            "enabled": self.enabled,
            "table": self.table,
            "policy": self.policy.to_dict(),
            "counters": dict(self.counters),
            "syn_flood": list(self.syn_flood),
            "conn_flood": list(self.conn_flood),
            "udp_flood": list(self.udp_flood),
            "icmp_flood": list(self.icmp_flood),
            "scan": list(self.scan),
            "pps": int(self.pps),
            "connections": int(self.connections),
            "conntrack": int(self.conntrack),
            "conntrack_max": int(self.conntrack_max),
            "kernel": self.kernel,
            "notice": self.notice,
            "error": self.error,
        }


@dataclass
class Finding:
    code: str
    port: int = 0
    proto: str = "tcp"
    process: str = ""
    address: str = ""
    severity: str = "warn"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "port": int(self.port),
            "proto": self.proto,
            "process": self.process,
            "address": self.address,
            "severity": self.severity,
        }


def socket_rows(raw: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port", 0) or 0)
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        rows.append(
            {
                "port": port,
                "proto": str(item.get("proto", "tcp") or "tcp")[:4].lower(),
                "process": str(item.get("process", "") or "")[:40].lower(),
                "address": str(item.get("address", "") or "")[:45],
            }
        )
    return rows[:512]


def listening_from_proc(tcp_text: str, tcp6_text: str = "", owners: dict[int, str] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    known = owners or {}
    for body, family in ((tcp_text, 4), (tcp6_text, 6)):
        for line in str(body or "").splitlines()[1:]:
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
            if family == 4 and len(raw) == 4:
                address = ".".join(str(item) for item in raw)
            elif family == 6 and len(raw) == 16:
                address = ipaddress.IPv6Address(raw).compressed
            else:
                continue
            inode = parts[9]
            rows.append(
                {
                    "port": port,
                    "proto": "tcp",
                    "process": known.get(_inode_key(inode), ""),
                    "address": address,
                }
            )
    return rows


def _inode_key(inode: str) -> int:
    try:
        return int(inode)
    except (TypeError, ValueError):
        return 0


DECOYS = (21, 23, 2121, 2323, 2222, 3389)
API_PORTS = (10085, 10086, 10087)


def exposure(raw: Any, allow: list[int] | None = None) -> list[Finding]:
    permitted = set(allow or [])
    findings: list[Finding] = []
    for row in socket_rows(raw):
        port = int(row["port"])
        process = str(row["process"])
        address = str(row["address"])
        wildcard = address in {"0.0.0.0", "::", "*"}
        core_name = any(name in process for name in PANEL_NAMES)
        core_api = port in API_PORTS or ("xray" in process and port in API_PORTS)
        if core_name or port in PANEL_PORTS:
            findings.append(Finding("panel", port, row["proto"], process, address, "bad"))
            continue
        if core_api:
            findings.append(Finding("core_api", port, row["proto"], process, address, "bad"))
            continue
        if port in DATASTORE_PORTS:
            findings.append(Finding("datastore", port, row["proto"], process, address, "bad"))
            continue
        if port in permitted:
            continue
        if port in RISKY_PORTS:
            findings.append(Finding("risky", port, row["proto"], process, address, "info" if port in DECOYS else "bad"))
            continue
        if port in PROXY_PORTS:
            findings.append(Finding("proxy", port, row["proto"], process, address, "warn" if wildcard else "info"))
            continue
        if probe_worthy(port):
            findings.append(Finding("unexpected", port, row["proto"], process, address, "warn"))
    return findings[:64]


def probe_worthy(port: int) -> bool:
    if port in (80, 443, 22, 25, 53, 587, 993, 995, 2525):
        return False
    if port in RISKY_PORTS or port in PANEL_PORTS or port in DATASTORE_PORTS or port in PROXY_PORTS:
        return False
    return 1024 <= port <= 65535


def exposure_level(findings: list[Finding]) -> str:
    rank = max([PROBE_RANK.get(item.severity, 0) for item in findings] or [0])
    return "bad" if rank >= 3 else ("warn" if rank == 2 else "ok")


def exposure_rows(findings: list[Finding]) -> list[tuple[str, str, str]]:
    return [(item.severity, item.code, "%d/%s" % (item.port, item.proto)) for item in findings]


def exposure_hint(findings: list[Finding]) -> str:
    codes = {item.code for item in findings}
    for code in ("core_api", "datastore", "panel", "risky", "proxy", "unexpected"):
        if code in codes:
            return code
    return ""


def valid_address(value: object) -> str:
    text = str(value or "").strip()
    if not IPV4.match(text):
        return ""
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return ""
