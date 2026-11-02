from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any

from . import scripts

HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
CIDR_RE = re.compile(r"^([0-9]{1,3}(\.[0-9]{1,3}){3})/([0-9]{1,2})$")
MAX_SUBNET = 24
MAX_HOSTS = 256
MAX_TARGET = 253
MIN_HOPS = 1
MAX_HOPS = 20
DEFAULT_HOPS = 12
DEFAULT_PORTS = "22,80,443"


class NetError(Exception):
    def __init__(self, message: str, code: str = "bad_arg") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass
class Target:
    kind: str
    host: str = ""
    network: ipaddress.IPv4Network | None = None
    port: int = 0

    @property
    def text(self) -> str:
        if self.kind == "subnet" and self.network is not None:
            return str(self.network)
        return self.host

    def hosts(self) -> list[str]:
        if self.kind == "subnet" and self.network is not None:
            return [str(item) for item in self.network.hosts()][:MAX_HOSTS]
        return [self.host]

    @property
    def count(self) -> int:
        return len(self.hosts())


def clean(raw: object) -> str:
    text = str(raw or "").strip()
    if len(text) > MAX_TARGET:
        raise NetError("the target is too long", "bad_arg")
    if any(char in text for char in " \t\r\n;|&`$<>\"'\\"):
        raise NetError("the target carries forbidden characters", "bad_arg")
    return text


def parse(raw: object) -> Target:
    text = clean(raw)
    if not text:
        raise NetError("the target is empty", "bad_arg")
    if text.count("/") == 1:
        match = CIDR_RE.match(text)
        if not match:
            raise NetError("the subnet must be an ipv4 cidr like 203.0.113.0/24", "bad_arg")
        try:
            network = ipaddress.IPv4Network(text, strict=False)
        except ValueError:
            raise NetError("the subnet is not a valid network", "bad_arg") from None
        if network.prefixlen < MAX_SUBNET:
            raise NetError("the subnet is wider than /24", "too_big")
        return Target(kind="subnet", network=network)
    if ":" in text and text.count(":") == 1:
        host, _, port = text.partition(":")
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise NetError("the port must be between 1 and 65535", "bad_arg")
        return parse_host(host, int(port))
    return parse_host(text)


def parse_host(host: str, port: int = 0) -> Target:
    text = str(host or "").strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise NetError("only ipv4 targets are supported", "bad_arg")
        if address.is_multicast or address.is_unspecified or address.is_loopback:
            raise NetError("that address is not routable", "bad_arg")
        if address.is_private and port == 0:
            return Target(kind="host", host=str(address), port=0)
        return Target(kind="host", host=str(address), port=port)
    if not HOST_RE.match(text) or "." not in text:
        raise NetError("that is not a host, an address or a subnet", "bad_arg")
    if len(text) > MAX_TARGET:
        raise NetError("the host is too long", "bad_arg")
    return Target(kind="host", host=text.lower(), port=port)


def parse_ports(raw: object, fallback: str = DEFAULT_PORTS) -> list[int]:
    text = str(raw or "").strip() or fallback
    out: list[int] = []
    for chunk in text.split(","):
        item = chunk.strip()
        if not item:
            continue
        if "-" in item:
            left, _, right = item.partition("-")
            if not left.isdigit() or not right.isdigit():
                raise NetError("a port range must look like 20-25", "bad_arg")
            start, end = int(left), int(right)
            if not 1 <= start <= end <= 65535 or end - start > 1024:
                raise NetError("the port range is out of bounds", "bad_arg")
            out.extend(range(start, end + 1))
            continue
        if not item.isdigit() or not 1 <= int(item) <= 65535:
            raise NetError("a port must be between 1 and 65535", "bad_arg")
        out.append(int(item))
    unique = sorted(set(out))
    if not unique:
        raise NetError("no ports given", "bad_arg")
    return unique[:512]


def parse_hops(raw: object) -> int:
    text = str(raw or "").strip()
    if not text:
        return DEFAULT_HOPS
    if not text.isdigit():
        raise NetError("the hop count must be a number", "bad_arg")
    value = int(text)
    if not MIN_HOPS <= value <= MAX_HOPS:
        raise NetError("the hop count must be between 1 and 20", "bad_arg")
    return value


def resolve(target: Target, timeout: float = 3.0) -> list[str]:
    if target.kind == "subnet":
        return target.hosts()
    try:
        socket.setdefaulttimeout(timeout)
        found = socket.getaddrinfo(target.host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return []
    finally:
        socket.setdefaulttimeout(None)
    out: list[str] = []
    for item in found:
        address = str(item[4][0])
        if address not in out:
            out.append(address)
    return out[:8]


@dataclass
class Hop:
    index: int = 0
    address: str = ""
    rtt: float = 0.0

    def line(self) -> str:
        if not self.address:
            return "%d  *" % self.index
        return "%d  %s  %.1f ms" % (self.index, self.address, self.rtt)


@dataclass
class Answer:
    kind: str = "scan"
    target: str = ""
    started: float = 0.0
    spent: float = 0.0
    hosts: int = 0
    alive: int = 0
    open_ports: list[str] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    error: str = ""
    trace: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "hosts": self.hosts,
            "alive": self.alive,
            "open": list(self.open_ports),
            "hops": [item.line() for item in self.hops],
            "spent": round(self.spent, 2),
            "error": self.error,
        }


def scan_raw(raw: Any, target: str, spent: float) -> Answer:
    answer = Answer(kind="scan", target=target, spent=spent)
    if not isinstance(raw, dict):
        answer.error = "the agent returned an unexpected answer"
        return answer
    hosts = raw.get("results")
    if not isinstance(hosts, list):
        answer.error = str(raw.get("message", "") or "the scan answer is empty")[:160]
        return answer
    answer.hosts = int(raw.get("hosts", 0) or 0) or len(hosts)
    for item in hosts:
        if not isinstance(item, dict):
            continue
        address = str(item.get("host", "") or "")[:45]
        ports = item.get("open")
        if not isinstance(ports, list):
            continue
        if ports:
            answer.alive += 1
        for port in ports[:64]:
            answer.open_ports.append("%s:%s" % (address, str(port)[:5]))
    answer.open_ports = answer.open_ports[:64]
    return answer


def trace_raw(raw: Any, target: str, spent: float) -> Answer:
    answer = Answer(kind="trace", target=target, spent=spent)
    hops = raw.get("hops") if isinstance(raw, dict) else None
    if not isinstance(hops, list):
        answer.error = "the traceroute answer is empty"
        return answer
    for item in hops:
        if not isinstance(item, dict):
            continue
        answer.hops.append(
            Hop(
                index=int(item.get("index", 0) or 0),
                address=str(item.get("address", "") or "")[:45],
                rtt=float(item.get("rtt", 0) or 0),
            )
        )
    answer.hops = answer.hops[:MAX_HOPS]
    return answer


def trace_text(exc: BaseException) -> str:
    import traceback

    import asyncio

    try:
        if isinstance(exc, asyncio.CancelledError):
            return ""
    except AttributeError:
        pass
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-3500:]


def script_report(cache: list[dict[str, Any]], probes: dict[str, dict[str, Any]], tag: str = "") -> scripts.Report:
    return scripts.merge(scripts.parse_cache(cache), probes, tag)
