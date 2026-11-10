from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

BASE = "https://cheburcheck.ru"
HOST = "cheburcheck.ru"
PORT = 443
CHECK_PATH = "/api/v1/check?target="
PROBE_PATH = "/api/v1/probe/"
USER_AGENT = "obhod/2.1 (+cheburcheck)"
CHECK_TIMEOUT = 25
PROBE_CONNECT_TIMEOUT = 25
PROBE_DEADLINE = 150
MAX_BODY = 4194304
CHUNK = 65536
IP_LIST_CAP = 64
SUBNET_LIST_CAP = 32
IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(\.(?!-)[a-z0-9-]{1,63})+$")
CIDR_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$")
ASN_RE = re.compile(r"^(?:as)?(\d{1,10})$")
COMPLAINT_DAYS = 14
REACH_TIMEOUT = 3.5
REACH_ATTEMPTS = 1
STREAM_DONE = ("done", "completed", "finished", "ended")
STREAM_FAIL = ("error", "failed")
PROBE_KINDS = ("ip", "domain")
VERDICT_ORDER = ("tspu_block", "sni_block", "dns_spoofing", "cdn_block", "uncertain", "ok")
BLOCKING = ("tspu_block", "sni_block", "dns_spoofing", "cdn_block")
BLOCK_SHARE = 0.3
ERROR_KEYS = {
    "network": "CHK_ERR_NETWORK",
    "timeout": "CHK_ERR_TIMEOUT",
    "bad_json": "CHK_ERR_JSON",
    "bad_arg": "CHK_ERR_ARG",
    "http_401": "CHK_ERR_TOKEN",
    "http_403": "CHK_ERR_TOKEN",
    "http_429": "CHK_ERR_RATE",
}


def error_key(code: str) -> str:
    name = str(code or "")
    if name in ERROR_KEYS:
        return ERROR_KEYS[name]
    if name.startswith("http_"):
        return "CHK_ERR_HTTP"
    return "CHK_ERR_HTTP"


class CheburError(Exception):
    def __init__(self, message: str, code: str = "api") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass
class Complaint:
    date: str = ""
    count: int = 0


@dataclass
class Geo:
    asn: str = ""
    country: str = ""
    organisation: str = ""
    location: str = ""

    def label(self) -> str:
        parts = [item for item in (self.asn, self.organisation, self.location) if item]
        return ", ".join(parts) or "-"


@dataclass
class Registry:
    target: str = ""
    kind: str = ""
    blocked: bool = False
    ips: list[str] = field(default_factory=list)
    ip_count: int = 0
    subnets: list[str] = field(default_factory=list)
    cdn: dict[str, Any] = field(default_factory=dict)
    geo: Geo = field(default_factory=Geo)
    reverse: list[str] = field(default_factory=list)
    complaints: list[Complaint] = field(default_factory=list)
    context: str = ""
    at: float = 0.0

    def complaint_total(self) -> int:
        return sum(item.count for item in self.complaints)

    def complaint_peak(self) -> int:
        return max((item.count for item in self.complaints), default=0)

    def complaint_spark(self) -> str:
        marks = " .:-=+*#"
        peak = self.complaint_peak()
        if not self.complaints:
            return ""
        out = []
        for item in self.complaints[-COMPLAINT_DAYS:]:
            if peak <= 0:
                out.append(marks[0])
                continue
            step = min(len(marks) - 1, int(round(item.count / peak * (len(marks) - 1))))
            out.append(marks[step])
        return "".join(out)


@dataclass
class Probe:
    provider: str = ""
    region: str = ""
    asn: str = ""
    verdicts: list[str] = field(default_factory=list)
    dpi_hop: int | None = None
    target_hop: int | None = None
    cdn_unblocked: bool | None = None

    def verified(self) -> bool:
        return bool(self.verdicts)


@dataclass
class Live:
    target: str = ""
    online: int = 0
    results: list[Probe] = field(default_factory=list)
    finished: bool = False
    error: str = ""
    started: float = 0.0
    elapsed: float = 0.0

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for item in self.results:
            for verdict in item.verdicts or ["uncertain"]:
                out[verdict] = out.get(verdict, 0) + 1
        return out

    def blocking(self) -> int:
        total = 0
        for item in self.results:
            if set(item.verdicts or ["uncertain"]) & set(BLOCKING):
                total += 1
        return total

    def share(self) -> float:
        total = len(self.results)
        return (self.blocking() / total) if total else 0.0

    def providers_for(self, verdict: str) -> list[str]:
        out = []
        for item in self.results:
            if verdict in (item.verdicts or ["uncertain"]) and item.provider not in out:
                out.append(item.provider)
        return out

    def blocked(self) -> bool:
        return self.blocking() > 0 and self.share() >= BLOCK_SHARE

    def blocking_kinds(self) -> list[str]:
        counts = self.counts()
        found = [(counts.get(name, 0), name) for name in BLOCKING if counts.get(name, 0)]
        return [name for _count, name in sorted(found, reverse=True)]

    def dominant(self) -> str:
        kinds = self.blocking_kinds()
        if kinds:
            return kinds[0]
        counts = self.counts()
        if counts.get("ok", 0):
            return "ok"
        if counts.get("uncertain", 0):
            return "uncertain"
        return "unknown"

    def verdict(self) -> str:
        if not self.results:
            return "unknown"
        if self.blocked():
            return self.dominant()
        counts = self.counts()
        if counts.get("ok", 0) == 0 and counts.get("uncertain", 0):
            return "uncertain"
        if self.blocking():
            return "partial"
        return "clean"


@dataclass
class Answer:
    target: str = ""
    registry: Registry | None = None
    live: Live | None = None
    error: str = ""
    code: str = ""
    reach: Reach | None = None
    at: float = 0.0

    def verdict(self) -> str:
        if self.registry is not None and self.registry.blocked:
            return "registry"
        if self.live is not None and self.live.results:
            return self.live.verdict()
        if self.registry is not None:
            return "clean"
        return "unknown"

    def blocked(self) -> bool:
        if self.registry is not None and self.registry.blocked:
            return True
        return bool(self.live is not None and self.live.blocked())


@dataclass
class Reach:
    host: str = HOST
    addresses: list[str] = field(default_factory=list)
    dns_ok: bool = False
    tcp_ok: bool = False
    latency: float = 0.0
    error: str = ""
    at: float = 0.0

    def state(self) -> str:
        if self.tcp_ok:
            return "ok"
        if self.dns_ok:
            return "tcp"
        return "dns"

    def reachable(self) -> bool:
        return self.tcp_ok


def reach(timeout: float = REACH_TIMEOUT) -> Reach:
    out = Reach(at=time.time())
    started = time.time()
    infos: list[Any] = []
    for family in (socket.AF_INET, socket.AF_UNSPEC):
        try:
            infos = socket.getaddrinfo(HOST, PORT, family, socket.SOCK_STREAM)
        except (socket.gaierror, OSError) as exc:
            out.error = str(exc)[:120]
            continue
        if infos:
            break
    if infos:
        v4 = sorted({str(item[4][0]) for item in infos if item[4] and ":" not in str(item[4][0])})
        v6 = sorted({str(item[4][0]) for item in infos if item[4] and ":" in str(item[4][0])})
        out.addresses = (v4 + v6)[:4]
        out.dns_ok = bool(out.addresses)
    if not out.dns_ok:
        out.latency = time.time() - started
        out.error = out.error or "the name does not resolve"
        return out
    for address in out.addresses[:2]:
        handle = None
        try:
            handle = socket.create_connection((address, PORT), timeout=timeout)
            out.tcp_ok = True
            out.error = ""
            break
        except (TimeoutError, OSError) as exc:
            out.error = str(exc)[:120]
        finally:
            if handle is not None:
                handle.close()
    out.latency = time.time() - started
    return out


def clean_target(text: str) -> tuple[str, str]:
    raw = str(text or "").strip().lower()
    if not raw:
        raise CheburError("the target is empty", "bad_arg")
    if len(raw) > 253:
        raise CheburError("the target is too long", "bad_arg")
    raw = raw.rstrip(".")
    if raw.startswith("http://") or raw.startswith("https://"):
        raw = urllib.parse.urlsplit(raw).hostname or ""
        if not raw:
            raise CheburError("the url has no host", "bad_arg")
    if "/" in raw and not CIDR_RE.match(raw):
        raise CheburError("the target must be an ip address or a domain", "bad_arg")
    if any(char in raw for char in "\\ \t\n\r?#@"):
        raise CheburError("the target must be an ip address or a domain", "bad_arg")
    if raw.startswith("[") and raw.endswith("]"):
        raise CheburError("ipv6 is not supported by the checker", "bad_arg")
    cidr = CIDR_RE.match(raw)
    if cidr:
        octets = [int(item) for item in cidr.groups()[:4]]
        if any(item > 255 for item in octets):
            raise CheburError("the subnet is out of range", "bad_arg")
        if int(cidr.group(5)) > 32:
            raise CheburError("the subnet prefix is out of range", "bad_arg")
        return raw, "subnet"
    asn = ASN_RE.match(raw)
    if asn:
        digits = asn.group(1)
        if raw == digits and len(digits) < 4:
            raise CheburError("the as number needs the as prefix or four digits", "bad_arg")
        number = int(digits)
        if number <= 0 or number > 4294967295:
            raise CheburError("the as number is out of range", "bad_arg")
        return "AS%d" % number, "asn"
    match = IPV4_RE.match(raw)
    if match:
        octets = [int(item) for item in match.groups()]
        if any(item > 255 for item in octets):
            raise CheburError("the ip address is out of range", "bad_arg")
        if octets[0] == 0 or octets[0] >= 224:
            raise CheburError("the ip address is not a host address", "bad_arg")
        return raw, "ip"
    if not DOMAIN_RE.match(raw):
        raise CheburError("the target must be an ip address or a domain", "bad_arg")
    if all(part.isdigit() for part in raw.split(".")):
        raise CheburError("the target looks like a broken ip address", "bad_arg")
    if len(raw.rsplit(".", 1)[-1]) < 2:
        raise CheburError("the domain needs a real top level zone", "bad_arg")
    return raw, "domain"


def probe_supported(kind: str) -> bool:
    return str(kind or "") in PROBE_KINDS


def truth(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def verdict_list(value: Any) -> list[str]:
    if isinstance(value, str):
        text = value.strip()
        return [text[:24]] if text else []
    if not isinstance(value, (list, tuple)):
        return []
    return [str(name)[:24] for name in value if str(name).strip()]


def _request(url: str, accept: str, timeout: float, stream: bool = False) -> Any:
    request = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": USER_AGENT})
    try:
        return urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        raise CheburError("cheburcheck answered %d" % exc.code, "http_%d" % exc.code) from None
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise CheburError("cheburcheck is unreachable: %s" % str(reason)[:120], "network") from None
    except (TimeoutError, OSError) as exc:
        raise CheburError("cheburcheck did not answer in time: %s" % str(exc)[:120], "timeout") from None


def _read_body(handle: Any) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = handle.read(CHUNK)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_BODY:
            raise CheburError("the registry answer is too big", "bad_json")
    return b"".join(chunks)


def check(target: str, timeout: float = CHECK_TIMEOUT) -> Registry:
    host, kind = clean_target(target)
    url = BASE + CHECK_PATH + urllib.parse.quote(host, safe="")
    handle = _request(url, "application/json", timeout)
    try:
        body = _read_body(handle)
    except (TimeoutError, OSError) as exc:
        raise CheburError("the registry answer broke off: %s" % str(exc)[:100], "timeout") from None
    finally:
        handle.close()
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        raise CheburError("the registry answer is not json", "bad_json") from None
    if not isinstance(data, dict):
        raise CheburError("the registry answer has an unexpected shape", "bad_json")
    geo = data.get("geo") if isinstance(data.get("geo"), dict) else {}
    complaints = []
    for item in data.get("complaints") or []:
        if not isinstance(item, dict):
            continue
        try:
            count = int(item.get("count") or 0)
        except (TypeError, ValueError):
            count = 0
        complaints.append(Complaint(date=str(item.get("date") or "")[:10], count=max(count, 0)))
    reverse = [str(item)[:120] for item in (data.get("reverse_lookup") or []) if str(item).strip()]
    subnets = [str(item)[:64] for item in (data.get("blocked_subnets") or []) if str(item).strip()]
    cdn = data.get("cdn_providers") if isinstance(data.get("cdn_providers"), dict) else {}
    ips = [str(item)[:64] for item in (data.get("ips") or []) if str(item).strip()]
    return Registry(
        target=str(data.get("target") or host)[:253],
        kind=kind,
        blocked=truth(data.get("blocked")),
        ips=ips[:IP_LIST_CAP],
        ip_count=len(ips),
        subnets=subnets[:SUBNET_LIST_CAP],
        cdn=cdn,
        geo=Geo(
            asn=str(geo.get("asn") or "")[:24],
            country=str(geo.get("country_code") or "")[:8],
            organisation=str(geo.get("organisation") or "")[:64],
            location=str(geo.get("location") or "")[:64],
        ),
        reverse=reverse,
        complaints=complaints,
        context=str(data.get("id") or "")[:1024],
        at=time.time(),
    )


def probe(context: str, deadline: float = PROBE_DEADLINE, on_result: Callable[[Probe, Live], None] | None = None) -> Live:
    token = str(context or "").strip()
    if not token or len(token) > 1024 or any(char in token for char in "\r\n /"):
        raise CheburError("the probe needs a fresh registry answer", "bad_arg")
    url = BASE + PROBE_PATH + urllib.parse.quote(token, safe="")
    live = Live(target="", started=time.time())
    handle = _request(url, "text/event-stream", PROBE_CONNECT_TIMEOUT)
    stop = live.started + max(deadline, 10)
    event = ""
    try:
        while True:
            if time.time() > stop:
                live.error = "the probe did not finish in time"
                break
            raw = handle.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if line.startswith("event:"):
                event = line[6:].strip()
                continue
            if not line.startswith("data:"):
                continue
            try:
                payload = json.loads(line[5:].strip())
            except ValueError:
                continue
            if not isinstance(payload, dict):
                continue
            if event == "started":
                live.target = str(payload.get("target") or "")[:253]
                try:
                    live.online = max(int(payload.get("online_probes") or 0), 0)
                except (TypeError, ValueError):
                    live.online = 0
                continue
            if event == "result":
                item = Probe(
                    provider=str(payload.get("provider") or "")[:48],
                    region=str(payload.get("region") or "")[:48],
                    asn=str(payload.get("asn") or "")[:24],
                    verdicts=verdict_list(payload.get("verdicts")),
                    dpi_hop=payload.get("dpi_hop") if isinstance(payload.get("dpi_hop"), int) else None,
                    target_hop=payload.get("target_hop") if isinstance(payload.get("target_hop"), int) else None,
                    cdn_unblocked=payload.get("cdn_unblocked") if isinstance(payload.get("cdn_unblocked"), bool) else None,
                )
                live.results.append(item)
                if on_result is not None:
                    on_result(item, live)
                continue
            if event in STREAM_FAIL:
                live.error = str(payload.get("message") or payload.get("error") or "the probe failed")[:120]
                break
            if event in STREAM_DONE:
                live.finished = True
                break
    except (TimeoutError, OSError) as exc:
        live.error = "the probe stream broke off: %s" % str(exc)[:100]
    finally:
        handle.close()
    live.elapsed = time.time() - live.started
    if not live.results and not live.error:
        live.error = "the probe returned nothing"
    return live


def lookup(target: str, live: bool = True, deadline: float = PROBE_DEADLINE, on_result: Callable[[Probe, Live], None] | None = None, diagnose: bool = True) -> Answer:
    host, _kind = clean_target(target)
    started = time.time()
    answer = Answer(target=host, at=started)
    try:
        answer.registry = check(host)
    except CheburError as exc:
        answer.error = exc.message
        answer.code = exc.code
        if diagnose:
            answer.reach = reach()
        return answer
    if live and probe_supported(answer.registry.kind):
        try:
            answer.live = probe(answer.registry.context, deadline=deadline, on_result=on_result)
        except CheburError as exc:
            answer.error = exc.message
            answer.code = exc.code
    answer.at = time.time()
    return answer


def describe(answer: Answer) -> str:
    if answer.error and answer.registry is None:
        return "error"
    return answer.verdict()


def summary(answer: Answer) -> dict[str, Any]:
    live = answer.live
    blocked = live.blocking() if live is not None else 0
    total = len(live.results) if live is not None else 0
    return {
        "target": answer.target,
        "verdict": answer.verdict(),
        "blocked": answer.blocked(),
        "registry": bool(answer.registry is not None and answer.registry.blocked),
        "blocking": blocked,
        "total": total,
        "ok": live.counts().get("ok", 0) if live is not None else 0,
        "share": round(live.share(), 3) if live is not None else 0.0,
        "finished": bool(live is not None and live.finished),
        "error": answer.error,
        "code": answer.code,
    }
