from __future__ import annotations

import base64
import json
import re
import secrets
import string
import uuid as uuidlib
from dataclasses import dataclass, field
from typing import Any

from . import i18n
from .scan import DEFAULT_CANDIDATES

LEGACY_JAIL = "3x-ipl"
DEFAULT_JAIL = "obhod-ipl"


def guard_jail(raw: Any) -> str:
    value = str(raw or "").strip() or DEFAULT_JAIL
    return DEFAULT_JAIL if value == LEGACY_JAIL else value

PROTOCOLS = ("vless",)
NETWORKS = ("raw", "grpc", "xhttp")
SECURITIES = ("reality", "tls", "none")
VLESS_MODES = ("native", "xorpub", "random")
VLESS_TICKETS = ("600s", "0s", "300-600s")
VLESS_CLIENT_MODES = ("0rtt", "1rtt")
XHTTP_MODES = ("auto", "packet-up", "stream-up", "stream-one")
FLOWS = ("", "xtls-rprx-vision")
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized")
VLESS_HANDSHAKE = "mlkem768x25519plus"
DEFAULT_DEST = "www.cloudflare.com:443"
DEFAULT_SNI = "www.cloudflare.com"
DEFAULT_TAG_PREFIX = "in"
PADDING_RE = re.compile(r"^[0-9]+-[0-9]+-[0-9]+$")
TICKET_RE = re.compile(r"^([0-9]+s|[0-9]+-[0-9]+s)$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHORT_ID_RE = re.compile(r"^[0-9a-f]{0,16}$")
SUB_ALPHABET = string.ascii_letters + string.digits + "-_"
SUB_PORT = 2096
XRAY_VERSION = "v26.10.21"
VERSION_CHOICES = (XRAY_VERSION, "latest")
LOG_LEVELS = ("debug", "info", "warning", "error")
SUB_SEGMENT_LEN = 64
API_TAG = "api"
API_LISTEN = "127.0.0.1"
API_PORT = 62789
API_SERVICES = ("HandlerService", "LoggerService", "StatsService", "RoutingService")
DNS_TAG = "dns"
DEFAULT_ACCESS_LOG = "/var/log/xray/access.log"
DEFAULT_SSH_BANTIME = "3d"
DEFAULT_SSH_MAXRETRY = 3
DEFAULT_IGNOREIP = "127.0.0.1/8 ::1"
DEFAULT_ERROR_LOG = "/var/log/xray/error.log"
DEFAULT_METRICS = "127.0.0.1:11111"

P = 2 ** 255 - 19
A24 = 121665
BASE_POINT = bytes([9] + [0] * 31)

RELEVANT_FIELDS = {
    ("reality", "raw"): ("dest", "sni", "short_id", "spider_x", "fingerprint", "mldsa65"),
    ("reality", "grpc"): ("dest", "sni", "short_id", "spider_x", "fingerprint", "mldsa65", "service"),
    ("reality", "xhttp"): ("dest", "sni", "short_id", "spider_x", "fingerprint", "mldsa65", "path", "host_header", "mode"),
    ("tls", "raw"): ("sni", "alpn", "fingerprint", "cert_file", "key_file"),
    ("tls", "grpc"): ("sni", "alpn", "fingerprint", "cert_file", "key_file", "service"),
    ("tls", "xhttp"): ("sni", "alpn", "fingerprint", "cert_file", "key_file", "path", "host_header", "mode"),
    ("none", "raw"): (),
    ("none", "grpc"): ("service",),
    ("none", "xhttp"): ("path", "host_header", "mode"),
}


class XrayError(Exception):
    pass


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))


def _clamp(scalar: bytes) -> int:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(bytes(k), "little")


def x25519(scalar: bytes, point: bytes) -> bytes:
    if len(scalar) != 32 or len(point) != 32:
        raise XrayError("x25519 needs 32 byte keys")
    k = _clamp(scalar)
    u = int.from_bytes(point, "little") & ((1 << 255) - 1)
    x1 = u
    x2, z2, x3, z3 = 1, 0, u, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = pow((da + cb) % P, 2, P)
        z3 = (x1 * pow((da - cb) % P, 2, P)) % P
        x2 = (aa * bb) % P
        z2 = (e * ((aa + A24 * e) % P)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = (x2 * pow(z2, P - 2, P)) % P
    return result.to_bytes(32, "little")


def x25519_keypair() -> tuple[str, str]:
    private = bytearray(secrets.token_bytes(32))
    private[0] &= 248
    private[31] &= 127
    private[31] |= 64
    raw = bytes(private)
    public = x25519(raw, BASE_POINT)
    return _b64url(raw), _b64url(public)


def parse_x25519_output(text: str) -> tuple[str, str]:
    private = ""
    public = ""
    for line in (text or "").splitlines():
        low = line.lower()
        value = line.split(":", 1)[1].strip() if ":" in line else ""
        if not value:
            continue
        if "private" in low and not private:
            private = value
        elif "public" in low and not public:
            public = value
    if not private or not public:
        raise XrayError("xray x25519 returned no key pair")
    try:
        if len(_unb64url(private)) != 32 or len(_unb64url(public)) != 32:
            raise XrayError("x25519 keys have the wrong length")
    except (ValueError, IndexError):
        raise XrayError("x25519 keys are not decodable") from None
    return private, public


def gen_uuid() -> str:
    return str(uuidlib.uuid4())


def gen_short_id(length: int = 8) -> str:
    length = max(2, min(16, int(length)))
    return secrets.token_hex((length + 1) // 2)[:length]


def gen_email(prefix: str = "user") -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]", "", prefix or "user") or "user"
    return clean + "-" + secrets.token_hex(3)


def gen_sub_segment(length: int = SUB_SEGMENT_LEN) -> str:
    return "".join(secrets.choice(SUB_ALPHABET) for _ in range(int(length)))


HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,200}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ALPN_RE = re.compile(r"^[a-z0-9./-]{1,20}$")
FILE_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")


def valid_host_name(value: object, label: str = "the server name") -> str:
    text = str(value or "").strip()
    if not text or not HOST_RE.match(text) or ".." in text:
        raise XrayError("%s is not a valid host name" % label)
    return text


def valid_request_path(value: object, label: str = "the path") -> str:
    text = str(value or "").strip() or "/"
    if not text.startswith("/"):
        text = "/" + text
    if not PATH_RE.match(text) or ".." in text:
        raise XrayError("%s is not a safe request path" % label)
    return text


def valid_token(value: object, label: str = "the value") -> str:
    text = str(value or "").strip()
    if text and not TOKEN_RE.match(text):
        raise XrayError("%s may hold only letters, digits, dot, dash and underscore" % label)
    return text


def valid_alpn(value: object) -> list[str]:
    items = [item.strip() for item in str(value or "").replace(" ", ",").split(",") if item.strip()]
    if not items:
        raise XrayError("the alpn list must not be empty")
    if len(items) > 4:
        raise XrayError("the alpn list is too long")
    for item in items:
        if not ALPN_RE.match(item):
            raise XrayError("the alpn value %s is not supported" % item)
    return items


def valid_cert_path(value: object, label: str = "the certificate path") -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    blocked = ("/proc", "/sys", "/dev")
    if not FILE_RE.match(text) or ".." in text.split("/") or text.startswith(blocked):
        raise XrayError("%s must be a simple absolute path" % label)
    return text


def valid_dest(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        raise XrayError("the destination must not be empty")
    host = text
    port = "443"
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest.lstrip(":") or "443"
    elif text.count(":") == 1:
        host, port = text.split(":", 1)
    if not str(port).isdigit() or not 1 <= int(port) <= 65535:
        raise XrayError("the destination port must be between 1 and 65535")
    import ipaddress

    try:
        ipaddress.ip_address(host)
    except ValueError:
        host = valid_host_name(host, "the destination host")
    return "%s:%d" % (host, int(port))


def sanitize_remark(value: object, limit: int = 40) -> str:
    text = "".join(char for char in str(value or "") if char.isprintable()).strip()
    if not text:
        raise XrayError("the name must not be empty")
    return text[:limit]


def valid_sub_segment(value: object) -> str:
    text = str(value or "")
    if len(text) != SUB_SEGMENT_LEN:
        raise XrayError("a subscription segment must be exactly %d characters" % SUB_SEGMENT_LEN)
    for char in text:
        if char not in SUB_ALPHABET:
            raise XrayError("a subscription segment must use the url safe base64 alphabet")
    return text


def valid_email(value: object) -> str:
    text = str(value or "").strip()
    if not EMAIL_RE.match(text):
        raise XrayError("a client name must be letters, digits, dot, dash or underscore, up to 64 characters")
    return text


def valid_short_id(value: object) -> str:
    text = str(value or "").strip().lower()
    if not SHORT_ID_RE.match(text):
        raise XrayError("a short id must be up to 16 hex characters")
    return text


def valid_padding(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if not PADDING_RE.match(text):
        raise XrayError("padding must look like 100-111-1111")
    return text


def valid_ticket(value: object) -> str:
    text = str(value or "").strip() or "600s"
    if not TICKET_RE.match(text):
        raise XrayError("a ticket must look like 600s or 300-600s")
    return text


def split_authority(value: str) -> tuple[str, int]:
    text = (value or "").strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest.lstrip(":")
    elif text.count(":") == 1:
        host, port = text.split(":", 1)
    else:
        host, port = text, ""
    try:
        number = int(port or 0)
    except ValueError:
        raise XrayError("a port must be a number") from None
    if not 1 <= number <= 65535:
        raise XrayError("a port must be between 1 and 65535")
    return host.strip(), number


def join_authority(host: str, port: int) -> str:
    host = (host or "").strip().strip("[]")
    return "[%s]:%d" % (host, int(port)) if ":" in host else "%s:%d" % (host, int(port))


@dataclass
class VlessEncryption:
    mode: str = "native"
    ticket: str = "600s"
    padding: str = ""
    private_key: str = ""
    public_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "ticket": self.ticket,
            "padding": self.padding,
            "private_key": self.private_key,
            "public_key": self.public_key,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "VlessEncryption":
        data = raw or {}
        return VlessEncryption(
            mode=str(data.get("mode", "native") or "native"),
            ticket=str(data.get("ticket", "600s") or "600s"),
            padding=str(data.get("padding", "") or ""),
            private_key=str(data.get("private_key", "") or ""),
            public_key=str(data.get("public_key", "") or ""),
        )

    def generate(self) -> "VlessEncryption":
        if self.mode not in VLESS_MODES:
            raise XrayError("the vless encryption mode must be one of " + ", ".join(VLESS_MODES))
        self.ticket = valid_ticket(self.ticket)
        self.padding = valid_padding(self.padding)
        self.private_key, self.public_key = x25519_keypair()
        return self

    def decryption(self) -> str:
        parts = [VLESS_HANDSHAKE, self.mode, self.ticket]
        if self.padding:
            parts.append(self.padding)
        parts.append(self.private_key)
        return ".".join(item for item in parts if item)

    def encryption(self, mode: str = "0rtt") -> str:
        if mode not in VLESS_CLIENT_MODES:
            raise XrayError("the client encryption mode must be 0rtt or 1rtt")
        parts = [VLESS_HANDSHAKE, self.mode, mode]
        if self.padding:
            parts.append(self.padding)
        parts.append(self.public_key)
        return ".".join(item for item in parts if item)


@dataclass
class XrayClient:
    email: str = ""
    ident: str = ""
    flow: str = ""
    limit_ip: int = 0
    total_gb: int = 0
    expiry_ms: int = 0
    enable: bool = True
    comment: str = ""
    sub_id: str = ""
    sub_key: str = ""

    def ensure_subscription(self) -> tuple[str, str]:
        if not self.sub_id:
            self.sub_id = gen_sub_segment()
        if not self.sub_key:
            self.sub_key = gen_sub_segment()
        return self.sub_id, self.sub_key

    def sub_path(self) -> str:
        if not self.sub_id or not self.sub_key:
            return ""
        return "/%s/%s" % (self.sub_id, self.sub_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "ident": self.ident,
            "flow": self.flow,
            "limit_ip": int(self.limit_ip),
            "total_gb": int(self.total_gb),
            "expiry_ms": int(self.expiry_ms),
            "enable": bool(self.enable),
            "comment": self.comment,
            "sub_id": self.sub_id,
            "sub_key": self.sub_key,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "XrayClient":
        data = raw or {}
        return XrayClient(
            email=str(data.get("email", "")),
            ident=str(data.get("ident", "")),
            flow=str(data.get("flow", "")),
            limit_ip=int(data.get("limit_ip", 0) or 0),
            total_gb=int(data.get("total_gb", 0) or 0),
            expiry_ms=int(data.get("expiry_ms", 0) or 0),
            enable=bool(data.get("enable", True)),
            comment=str(data.get("comment", "")),
            sub_id=str(data.get("sub_id", "") or ""),
            sub_key=str(data.get("sub_key", "") or ""),
        )

    def entry(self) -> dict[str, Any]:
        body: dict[str, Any] = {"id": self.ident, "email": self.email}
        if self.flow:
            body["flow"] = self.flow
        if self.limit_ip:
            body["limitIp"] = int(self.limit_ip)
        if self.total_gb:
            body["totalGB"] = int(self.total_gb) * 1024 ** 3
        if self.expiry_ms:
            body["expiryTime"] = int(self.expiry_ms)
        body["enable"] = bool(self.enable)
        if self.comment:
            body["comment"] = self.comment
        return body


@dataclass
class XrayInbound:
    id: int = 0
    remark: str = ""
    protocol: str = "vless"
    port: int = 443
    listen: str = ""
    network: str = "raw"
    security: str = "reality"
    tag: str = ""
    enable: bool = True
    clients: list[XrayClient] = field(default_factory=list)
    dest: str = DEFAULT_DEST
    sni: str = DEFAULT_SNI
    short_ids: list[str] = field(default_factory=list)
    spider_x: str = ""
    fingerprint: str = "chrome"
    mldsa65_seed: str = ""
    mldsa65_verify: str = ""
    reality_private: str = ""
    reality_public: str = ""
    alpn: list[str] = field(default_factory=list)
    cert_file: str = ""
    key_file: str = ""
    path: str = "/"
    host_header: str = ""
    xhttp_mode: str = "auto"
    service_name: str = ""
    multi_mode: bool = False
    encryption: VlessEncryption = field(default_factory=VlessEncryption)

    def client(self, email: str) -> XrayClient | None:
        for item in self.clients:
            if item.email == email:
                return item
        return None

    def make_client(self, email: str) -> XrayClient:
        name = valid_email(email)
        if self.client(name) is not None:
            raise XrayError("a client with this name already exists")
        client = XrayClient(email=name, ident=gen_uuid())
        if self.security in {"reality", "tls"} and self.network == "raw":
            client.flow = "xtls-rprx-vision"
        client.ensure_subscription()
        self.clients.append(client)
        return client

    def remove_client(self, email: str) -> bool:
        before = len(self.clients)
        self.clients = [item for item in self.clients if item.email != email]
        return len(self.clients) != before

    def post_quantum(self) -> bool:
        return bool(self.encryption.private_key and self.encryption.public_key)

    def settings(self) -> dict[str, Any]:
        if not self.post_quantum():
            raise XrayError("vless encryption needs a generated post quantum key pair")
        return {
            "clients": [client.entry() for client in self.clients],
            "decryption": self.encryption.decryption(),
            "fallbacks": [],
        }

    def stream(self) -> dict[str, Any]:
        network = "tcp" if self.network == "raw" else self.network
        stream: dict[str, Any] = {"network": network, "security": self.security}
        if self.network == "raw":
            stream["tcpSettings"] = {"acceptProxyProtocol": False, "header": {"type": "none"}}
        if self.network == "grpc":
            stream["grpcSettings"] = {"serviceName": self.service_name or self.tag or self.remark, "multiMode": bool(self.multi_mode)}
        if self.network == "xhttp":
            settings: dict[str, Any] = {"path": self.path or "/", "mode": self.xhttp_mode or "auto"}
            if self.host_header:
                settings["host"] = self.host_header
            stream["xhttpSettings"] = settings
        if self.security == "reality":
            names = [item for item in {self.sni, self.host_header} if item]
            reality: dict[str, Any] = {
                "show": False,
                "xver": 0,
                "dest": self.dest,
                "serverNames": names or [DEFAULT_SNI],
                "privateKey": self.reality_private,
                "shortIds": self.short_ids or [""],
                "spiderX": self.spider_x or "/",
            }
            if self.mldsa65_seed:
                reality["mldsa65Seed"] = self.mldsa65_seed
            stream["realitySettings"] = reality
        elif self.security == "tls":
            tls: dict[str, Any] = {"serverName": self.sni, "alpn": self.alpn or ["h2", "http/1.1"]}
            if self.cert_file and self.key_file:
                tls["certificates"] = [{"certificateFile": self.cert_file, "keyFile": self.key_file}]
            stream["tlsSettings"] = tls
        return stream

    def to_json(self) -> dict[str, Any]:
        return {
            "tag": self.tag or "%s-%d" % (DEFAULT_TAG_PREFIX, self.port),
            "listen": self.listen,
            "port": int(self.port),
            "protocol": self.protocol,
            "settings": self.settings(),
            "streamSettings": self.stream(),
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": int(self.id),
            "remark": self.remark,
            "protocol": self.protocol,
            "port": int(self.port),
            "listen": self.listen,
            "network": self.network,
            "security": self.security,
            "tag": self.tag,
            "enable": bool(self.enable),
            "clients": [item.to_dict() for item in self.clients],
            "dest": self.dest,
            "sni": self.sni,
            "short_ids": list(self.short_ids),
            "spider_x": self.spider_x,
            "fingerprint": self.fingerprint,
            "mldsa65_seed": self.mldsa65_seed,
            "mldsa65_verify": self.mldsa65_verify,
            "reality_private": self.reality_private,
            "reality_public": self.reality_public,
            "alpn": list(self.alpn),
            "cert_file": self.cert_file,
            "key_file": self.key_file,
            "path": self.path,
            "host_header": self.host_header,
            "xhttp_mode": self.xhttp_mode,
            "service_name": self.service_name,
            "multi_mode": bool(self.multi_mode),
            "encryption": self.encryption.to_dict(),
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "XrayInbound":
        data = raw or {}
        return XrayInbound(
            id=int(data.get("id", 0) or 0),
            remark=str(data.get("remark", "")),
            protocol=str(data.get("protocol", "vless")),
            port=int(data.get("port", 443) or 443),
            listen=str(data.get("listen", "")),
            network=str(data.get("network", "raw")),
            security=str(data.get("security", "reality")),
            tag=str(data.get("tag", "")),
            enable=bool(data.get("enable", True)),
            clients=[XrayClient.from_dict(item) for item in data.get("clients") or [] if isinstance(item, dict)],
            dest=str(data.get("dest", DEFAULT_DEST)),
            sni=str(data.get("sni", DEFAULT_SNI)),
            short_ids=[str(item) for item in data.get("short_ids") or []],
            spider_x=str(data.get("spider_x", "")),
            fingerprint=str(data.get("fingerprint", "chrome")),
            mldsa65_seed=str(data.get("mldsa65_seed", "") or ""),
            mldsa65_verify=str(data.get("mldsa65_verify", "") or ""),
            reality_private=str(data.get("reality_private", data.get("private_key", "")) or ""),
            reality_public=str(data.get("reality_public", data.get("public_key", "")) or ""),
            alpn=[str(item) for item in data.get("alpn") or []],
            cert_file=str(data.get("cert_file", "") or ""),
            key_file=str(data.get("key_file", "") or ""),
            path=str(data.get("path", "/")),
            host_header=str(data.get("host_header", "")),
            xhttp_mode=str(data.get("xhttp_mode", "auto") or "auto"),
            service_name=str(data.get("service_name", "")),
            multi_mode=bool(data.get("multi_mode", False)),
            encryption=VlessEncryption.from_dict(data.get("encryption")),
        )


def relevant_fields(security: str, network: str) -> tuple[str, ...]:
    if security not in SECURITIES:
        raise XrayError("security must be one of " + ", ".join(SECURITIES))
    if network not in NETWORKS:
        raise XrayError("network must be one of " + ", ".join(NETWORKS))
    return RELEVANT_FIELDS[(security, network)]


def field_applies(security: str, network: str, name: str) -> bool:
    return name in relevant_fields(security, network)


def security_needs_target(security: str) -> bool:
    return security == "reality"


def security_supports_mldsa65(security: str) -> bool:
    return security == "reality"


def new_inbound(
    protocol: str = "vless",
    port: int = 443,
    network: str = "raw",
    security: str = "reality",
    remark: str = "",
) -> XrayInbound:
    if protocol not in PROTOCOLS:
        raise XrayError("protocol must be vless")
    if network not in NETWORKS:
        raise XrayError("network must be one of " + ", ".join(NETWORKS))
    if security not in SECURITIES:
        raise XrayError("security must be one of " + ", ".join(SECURITIES))
    inbound = XrayInbound(
        protocol=protocol,
        port=int(port),
        network=network,
        security=security,
        remark=remark or "vless-%d-%s" % (port, network),
    )
    inbound.tag = "in-%d-%s" % (port, network)
    inbound.encryption = VlessEncryption().generate()
    if security == "reality":
        inbound.reality_private, inbound.reality_public = x25519_keypair()
        inbound.short_ids = [gen_short_id()]
        inbound.sni = DEFAULT_SNI
        inbound.dest = DEFAULT_DEST
        inbound.spider_x = ""
    if security == "tls":
        inbound.alpn = ["h2", "http/1.1"]
    return inbound


def policy_block(levels: tuple[int, ...] = (0,)) -> dict[str, Any]:
    table: dict[str, Any] = {}
    for level in levels:
        table[str(int(level))] = {
            "statsUserUplink": True,
            "statsUserDownlink": True,
            "statsUserOnline": True,
            "connIdle": 300,
            "uplinkOnly": 2,
            "downlinkOnly": 5,
        }
    return {
        "levels": table,
        "system": {
            "statsInboundUplink": True,
            "statsInboundDownlink": True,
            "statsOutboundUplink": False,
            "statsOutboundDownlink": False,
        },
    }


def api_block(tag: str = API_TAG) -> dict[str, Any]:
    return {"tag": tag, "services": list(API_SERVICES)}


def api_inbound(tag: str = API_TAG, port: int = API_PORT) -> dict[str, Any]:
    return {
        "listen": API_LISTEN,
        "port": int(port),
        "protocol": "tunnel",
        "settings": {"rewriteAddress": API_LISTEN},
        "tag": tag,
    }


def routing_block(tag: str = API_TAG, dns_tag: str = "") -> dict[str, Any]:
    rules: list[dict[str, Any]] = [{"type": "field", "inboundTag": [tag], "outboundTag": tag}]
    if dns_tag:
        rules.append({"type": "field", "inboundTag": [dns_tag], "outboundTag": dns_tag})
    rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"})
    rules.append({"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"})
    return {"domainStrategy": "AsIs", "rules": rules}


def outbound_block() -> list[dict[str, Any]]:
    return [
        {
            "protocol": "freedom",
            "settings": {
                "finalRules": [
                    {"action": "block", "ip": ["geoip:private"]},
                    {"action": "allow"},
                ]
            },
            "tag": "direct",
        },
        {"protocol": "blackhole", "settings": {}, "tag": "blocked"},
    ]


def log_block(log_level: str = "warning", access: str = DEFAULT_ACCESS_LOG, error: str = DEFAULT_ERROR_LOG, mask: str = "") -> dict[str, Any]:
    return {
        "loglevel": str(log_level or "warning"),
        "access": access,
        "error": error,
        "dnsLog": False,
        "maskAddress": mask,
    }


def dns_block(servers: list[str], dns_tag: str = "dns") -> dict[str, Any]:
    return {"servers": list(servers), "queryStrategy": "UseIPv4v6", "disableCache": False, "tag": dns_tag}


def config_json(
    inbounds: list[XrayInbound],
    log_level: str = "warning",
    access_log: str = DEFAULT_ACCESS_LOG,
    error_log: str = DEFAULT_ERROR_LOG,
    api_enabled: bool = True,
    api_port: int = API_PORT,
    metrics: str = DEFAULT_METRICS,
    dns_servers: list[str] | None = None,
    levels: tuple[int, ...] = (0,),
) -> dict[str, Any]:
    active = [item for item in inbounds if item.enable]
    servers = [str(item).strip() for item in (dns_servers or []) if str(item).strip()]
    config: dict[str, Any] = {
        "log": log_block(log_level, access_log, error_log),
        "inbounds": [item.to_json() for item in active],
        "outbounds": outbound_block(),
        "routing": routing_block(API_TAG, DNS_TAG if servers else ""),
        "policy": policy_block(levels),
        "stats": {},
    }
    if api_enabled:
        config["api"] = api_block(API_TAG)
        config["inbounds"] = [api_inbound(API_TAG, api_port)] + config["inbounds"]
    if metrics:
        config["metrics"] = {"listen": metrics, "tag": "metrics_out"}
    if servers:
        config["dns"] = dns_block(servers, DNS_TAG)
        config["outbounds"] = config["outbounds"] + [{"protocol": "dns", "settings": {"nonIPQuery": "drop", "rewriteAddress": API_LISTEN}, "tag": DNS_TAG}]
    return config


def config_text(
    inbounds: list[XrayInbound],
    log_level: str = "warning",
    access_log: str = DEFAULT_ACCESS_LOG,
    error_log: str = DEFAULT_ERROR_LOG,
    api_enabled: bool = True,
    api_port: int = API_PORT,
    metrics: str = DEFAULT_METRICS,
    dns_servers: list[str] | None = None,
    levels: tuple[int, ...] = (0,),
) -> str:
    return json.dumps(
        config_json(inbounds, log_level, access_log, error_log, api_enabled, api_port, metrics, dns_servers, levels),
        ensure_ascii=False,
        indent=2,
        sort_keys=False,
    )


def _remark_suffix(inbound: XrayInbound, email: str) -> str:
    base = inbound.remark or "vless-%d" % inbound.port
    parts = [base, email]
    if inbound.security != "none":
        parts.append(inbound.security)
    parts.append(inbound.network)
    return "-".join(item for item in parts if item)


def _stream_params(inbound: XrayInbound, params: dict[str, str]) -> None:
    params["type"] = "tcp" if inbound.network == "raw" else inbound.network
    if inbound.network == "raw":
        params["headerType"] = "none"
    if inbound.network == "grpc":
        params["serviceName"] = inbound.service_name or inbound.tag
        params["mode"] = "multi" if inbound.multi_mode else "gun"
    if inbound.network == "xhttp":
        params["path"] = inbound.path or "/"
        params["mode"] = inbound.xhttp_mode or "auto"
        if inbound.host_header:
            params["host"] = inbound.host_header


def _security_params(inbound: XrayInbound, params: dict[str, str]) -> None:
    if inbound.security == "reality":
        params["security"] = "reality"
        params["sni"] = inbound.sni or DEFAULT_SNI
        params["fp"] = inbound.fingerprint or "chrome"
        params["pbk"] = inbound.reality_public
        params["sid"] = (inbound.short_ids or [""])[0]
        if inbound.spider_x:
            params["spx"] = inbound.spider_x
        if inbound.mldsa65_verify:
            params["pqv"] = inbound.mldsa65_verify
        return
    if inbound.security == "tls":
        params["security"] = "tls"
        params["sni"] = inbound.sni
        params["fp"] = inbound.fingerprint or "chrome"
        if inbound.alpn:
            params["alpn"] = ",".join(inbound.alpn)
        return
    params["security"] = "none"


def _query(params: dict[str, str]) -> str:
    from urllib.parse import quote

    pairs = []
    for key, value in params.items():
        if value is None or value == "":
            continue
        pairs.append("%s=%s" % (quote(str(key), safe=""), quote(str(value), safe="")))
    return "&".join(pairs)


def vless_link(inbound: XrayInbound, client: XrayClient, address: str, port: int | None = None) -> str:
    if not inbound.post_quantum():
        raise XrayError("the inbound has no post quantum vless key pair")
    params: dict[str, str] = {}
    _stream_params(inbound, params)
    _security_params(inbound, params)
    params["encryption"] = inbound.encryption.encryption("0rtt")
    if client.flow and inbound.network == "raw" and inbound.security in {"reality", "tls"}:
        params["flow"] = client.flow
    host = join_authority(address, port or inbound.port)
    remark = _remark_suffix(inbound, client.email)
    return "vless://%s@%s?%s#%s" % (client.ident, host, _query(params), _remark_url(remark))


def link_for(inbound: XrayInbound, client: XrayClient, address: str, port: int | None = None) -> str:
    if inbound.protocol != "vless":
        raise XrayError("only vless links are supported")
    return vless_link(inbound, client, address, port)


def links_for(inbound: XrayInbound, address: str, port: int | None = None) -> list[tuple[str, str]]:
    return [(item.email, link_for(inbound, item, address, port)) for item in inbound.clients]


def _remark_url(value: str) -> str:
    from urllib.parse import quote

    return quote(value or "", safe="")


def parse_link(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if not text.startswith("vless://"):
        raise XrayError("a link must start with vless://")
    from urllib.parse import parse_qs, unquote, urlparse

    parsed = urlparse(text)
    params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    encryption = params.get("encryption", "")
    if not encryption:
        raise XrayError("the link has no vless encryption")
    if not encryption.startswith(VLESS_HANDSHAKE + "."):
        raise XrayError("the link uses encryption that is not post quantum: " + encryption)
    return {
        "protocol": "vless",
        "host": parsed.hostname or "",
        "port": parsed.port or 0,
        "user": unquote(parsed.username or ""),
        "remark": unquote(parsed.fragment or ""),
        "params": params,
        "encryption": encryption,
        "post_quantum": True,
        "reality_pq": bool(params.get("pqv")),
    }


def subscription_payload(links: list[str]) -> str:
    body = "\n".join(item for item in links if item)
    return base64.b64encode(body.encode("utf-8")).decode("ascii")


def summary(inbound: XrayInbound, language: str = i18n.DEFAULT_LANGUAGE) -> list[tuple[str, str]]:
    lang = i18n.normalize(language)
    rows = [
        (i18n.t("SUM_PROTOCOL", lang), inbound.protocol),
        (i18n.t("SUM_PORT", lang), str(inbound.port)),
        (i18n.t("SUM_NETWORK", lang), inbound.network),
        (i18n.t("SUM_SECURITY", lang), inbound.security),
        (i18n.t("SUM_CLIENTS", lang), str(len(inbound.clients))),
        (i18n.t("SUM_ENCRYPTION", lang), VLESS_HANDSHAKE + "." + inbound.encryption.mode),
    ]
    fields = relevant_fields(inbound.security, inbound.network)
    if "dest" in fields:
        rows.append((i18n.t("FIELD_DEST", lang), inbound.dest))
    if "sni" in fields:
        rows.append((i18n.t("FIELD_SNI", lang), inbound.sni))
    if "short_id" in fields:
        rows.append((i18n.t("FIELD_SHORT_ID", lang), (inbound.short_ids or [""])[0]))
    if "mldsa65" in fields:
        rows.append((i18n.t("SUM_MLDSA", lang), i18n.t("UI_ON" if inbound.mldsa65_seed else "UI_OFF", lang)))
    if "path" in fields:
        rows.append((i18n.t("FIELD_PATH", lang), inbound.path))
    if "service" in fields:
        rows.append((i18n.t("FIELD_SERVICE", lang), inbound.service_name or inbound.tag))
    if "cert_file" in fields:
        rows.append((i18n.t("FIELD_CERT_FILE", lang), inbound.cert_file or i18n.t("UI_NOT_SET", lang)))
    return rows


@dataclass
class Subscription:
    email: str
    inbound_id: int
    sub_id: str
    sub_key: str
    link: str
    links: list[str] = field(default_factory=list)

    def path(self) -> str:
        return "/%s/%s" % (self.sub_id, self.sub_key)

    def url(self, address: str, port: int) -> str:
        host = (address or "").strip()
        if host and not host.startswith("http"):
            host = "http://" + join_authority(host, port)
        return host.rstrip("/") + self.path()

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "inbound_id": int(self.inbound_id),
            "sub_id": self.sub_id,
            "sub_key": self.sub_key,
            "link": self.link,
            "links": list(self.links),
        }


@dataclass
class XrayState:
    inbounds: list[XrayInbound] = field(default_factory=list)
    version: str = XRAY_VERSION
    log_level: str = "warning"
    scan_targets: list[str] = field(default_factory=list)
    scan_results: list[dict[str, Any]] = field(default_factory=list)
    last_core: dict[str, Any] = field(default_factory=dict)
    sub_port: int = SUB_PORT
    sub_enabled: bool = False
    sub_address: str = ""
    fail2ban_enabled: bool = False
    fail2ban_bantime: int = 30
    fail2ban_ssh_bantime: str = DEFAULT_SSH_BANTIME
    fail2ban_ssh_maxretry: int = DEFAULT_SSH_MAXRETRY
    fail2ban_ignoreip: str = DEFAULT_IGNOREIP
    fail2ban_jail: str = DEFAULT_JAIL
    scan_candidates: list[str] = field(default_factory=list)
    scan_sni: str = ""
    scan_xver: int = 0
    access_log: str = DEFAULT_ACCESS_LOG
    error_log: str = DEFAULT_ERROR_LOG
    sub_refresh: int = 12
    api_enabled: bool = True
    api_port: int = API_PORT
    metrics: str = DEFAULT_METRICS
    dns_servers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "inbounds": [item.to_dict() for item in self.inbounds],
            "version": self.version,
            "log_level": self.log_level,
            "scan_targets": list(self.scan_targets),
            "scan_results": list(self.scan_results),
            "last_core": dict(self.last_core),
            "sub_port": int(self.sub_port),
            "sub_enabled": bool(self.sub_enabled),
            "sub_address": self.sub_address,
            "fail2ban_enabled": bool(self.fail2ban_enabled),
            "fail2ban_bantime": int(self.fail2ban_bantime),
            "fail2ban_ssh_bantime": self.fail2ban_ssh_bantime,
            "fail2ban_ssh_maxretry": int(self.fail2ban_ssh_maxretry),
            "fail2ban_ignoreip": self.fail2ban_ignoreip,
            "fail2ban_jail": self.fail2ban_jail,
            "scan_candidates": list(self.scan_candidates),
            "scan_sni": self.scan_sni,
            "scan_xver": int(self.scan_xver),
            "access_log": self.access_log,
            "error_log": self.error_log,
            "sub_refresh": int(self.sub_refresh),
            "api_enabled": bool(self.api_enabled),
            "api_port": int(self.api_port),
            "metrics": self.metrics,
            "dns_servers": list(self.dns_servers),
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "XrayState":
        data = raw or {}
        targets = [str(item) for item in data.get("scan_targets") or []]
        return XrayState(
            inbounds=[XrayInbound.from_dict(item) for item in data.get("inbounds") or [] if isinstance(item, dict)],
            version=str(data.get("version", XRAY_VERSION) or XRAY_VERSION),
            log_level=str(data.get("log_level", "warning") or "warning"),
            scan_targets=targets,
            scan_results=[item for item in data.get("scan_results") or [] if isinstance(item, dict)],
            last_core=dict(data.get("last_core") or {}),
            sub_port=int(data.get("sub_port", SUB_PORT) or SUB_PORT),
            sub_enabled=bool(data.get("sub_enabled", False)),
            sub_address=str(data.get("sub_address", "") or ""),
            fail2ban_enabled=bool(data.get("fail2ban_enabled", False)),
            fail2ban_bantime=int(data.get("fail2ban_bantime", 30) or 30),
            fail2ban_ssh_bantime=str(data.get("fail2ban_ssh_bantime", DEFAULT_SSH_BANTIME) or DEFAULT_SSH_BANTIME),
            fail2ban_ssh_maxretry=int(data.get("fail2ban_ssh_maxretry", DEFAULT_SSH_MAXRETRY) or DEFAULT_SSH_MAXRETRY),
            fail2ban_ignoreip=str(data.get("fail2ban_ignoreip", DEFAULT_IGNOREIP) or DEFAULT_IGNOREIP),
            fail2ban_jail=guard_jail(data.get("fail2ban_jail")),
            scan_candidates=[str(item) for item in data.get("scan_candidates") or []],
            scan_sni=str(data.get("scan_sni", "") or ""),
            scan_xver=int(data.get("scan_xver", 0) or 0),
            access_log=str(data.get("access_log", DEFAULT_ACCESS_LOG) or DEFAULT_ACCESS_LOG),
            error_log=str(data.get("error_log", DEFAULT_ERROR_LOG) or DEFAULT_ERROR_LOG),
            sub_refresh=int(data.get("sub_refresh", 12) or 12),
            api_enabled=bool(data.get("api_enabled", True)),
            api_port=int(data.get("api_port", API_PORT) or API_PORT),
            metrics=str(data.get("metrics", DEFAULT_METRICS) or ""),
            dns_servers=[str(item) for item in data.get("dns_servers") or []],
        )

    def inbound(self, ident: object) -> XrayInbound | None:
        try:
            key = int(ident)
        except (TypeError, ValueError):
            return None
        for item in self.inbounds:
            if item.id == key:
                return item
        return None

    def by_remark(self, remark: str) -> XrayInbound | None:
        for item in self.inbounds:
            if item.remark == remark:
                return item
        return None

    def next_id(self) -> int:
        used = {item.id for item in self.inbounds}
        value = 1
        while value in used:
            value += 1
        return value

    def add(self, inbound: XrayInbound) -> XrayInbound:
        for item in self.inbounds:
            if item.port == inbound.port:
                raise XrayError("port %d is already used by inbound %s" % (inbound.port, item.remark))
        inbound.id = self.next_id()
        self.inbounds.append(inbound)
        return inbound

    def remove(self, ident: object) -> bool:
        item = self.inbound(ident)
        if item is None:
            return False
        self.inbounds.remove(item)
        return True

    def ports(self) -> list[int]:
        return [item.port for item in self.inbounds]

    def enabled(self) -> list[XrayInbound]:
        return [item for item in self.inbounds if item.enable]

    def adopt_scan(self, ident: object, host: str, sni: str, port: int) -> XrayInbound:
        item = self.inbound(ident)
        if item is None:
            raise XrayError("inbound not found")
        host = host.strip()
        sni = sni.strip()
        if not host:
            raise XrayError("a target address is required")
        item.dest = join_authority(host, int(port or 443))
        if sni:
            item.sni = sni
        return item

    def set_reality_keys(self, ident: object, private: str, public: str) -> None:
        item = self.inbound(ident)
        if item is None:
            raise XrayError("inbound not found")
        if item.security != "reality":
            raise XrayError("reality keys need the reality security")
        item.reality_private = private
        item.reality_public = public

    def set_mldsa65(self, ident: object, seed: str, verify: str) -> None:
        item = self.inbound(ident)
        if item is None:
            raise XrayError("inbound not found")
        if item.security != "reality":
            raise XrayError("ml-dsa-65 needs the reality security")
        if not seed or not verify:
            raise XrayError("an ml-dsa-65 key pair needs both a seed and a verify key")
        item.mldsa65_seed = seed
        item.mldsa65_verify = verify

    def clear_mldsa65(self, ident: object) -> None:
        item = self.inbound(ident)
        if item is None:
            raise XrayError("inbound not found")
        item.mldsa65_seed = ""
        item.mldsa65_verify = ""

    def candidates(self) -> list[str]:
        return list(self.scan_candidates) or list(DEFAULT_CANDIDATES)

    def candidates_csv(self) -> str:
        return ",".join(self.candidates())

    def dns_csv(self) -> str:
        return ", ".join(self.dns_servers)

    def protocol_label(self) -> str:
        return PROTOCOLS[0]

    def encryption_label(self) -> str:
        return VLESS_HANDSHAKE

    def pinned(self) -> str:
        value = str(self.version or "")
        return value if value in VERSION_CHOICES and value != "latest" else XRAY_VERSION

    def sub_path_pattern(self) -> str:
        return "/<%d>/<%d>" % (SUB_SEGMENT_LEN, SUB_SEGMENT_LEN)

    def address(self, fallback: str = "") -> str:
        return (self.sub_address or fallback or "").strip()

    def canonical_subscription(self, email: str, skip: Any = None) -> tuple[str, str] | None:
        for inbound in self.inbounds:
            for client in inbound.clients:
                if client is skip:
                    continue
                if client.email == email and client.sub_id and client.sub_key:
                    return client.sub_id, client.sub_key
        return None

    def subscriptions(self, address: str = "") -> list[Subscription]:
        host = self.address(address)
        order: list[str] = []
        links: dict[str, list[str]] = {}
        canon: dict[str, tuple[int, str, str]] = {}
        for inbound in self.inbounds:
            for client in inbound.clients:
                if not client.sub_id or not client.sub_key:
                    continue
                if client.email not in links:
                    order.append(client.email)
                    links[client.email] = []
                    canon[client.email] = (inbound.id, client.sub_id, client.sub_key)
                try:
                    link = link_for(inbound, client, host or "127.0.0.1", inbound.port)
                except XrayError:
                    link = ""
                if link:
                    links[client.email].append(link)
        out: list[Subscription] = []
        for email in order:
            inbound_id, sub_id, sub_key = canon[email]
            items = links[email]
            out.append(
                Subscription(
                    email=email,
                    inbound_id=inbound_id,
                    sub_id=sub_id,
                    sub_key=sub_key,
                    link=items[0] if items else "",
                    links=items,
                )
            )
        return out

    def subscription_of(self, email: str) -> Subscription | None:
        for item in self.subscriptions():
            if item.email == email:
                return item
        return None

    def rotate_subscription(self, email: str) -> Subscription | None:
        sub_id = gen_sub_segment()
        sub_key = gen_sub_segment()
        found = False
        for inbound in self.inbounds:
            for client in inbound.clients:
                if client.email == email:
                    client.sub_id = sub_id
                    client.sub_key = sub_key
                    found = True
        if not found:
            return None
        return self.subscription_of(email)

    def sub_registry(self, address: str = "") -> dict[str, Any]:
        entries: dict[str, Any] = {}
        for item in self.subscriptions(address):
            entries[item.sub_id] = {
                "key": item.sub_key,
                "email": item.email,
                "inbound": int(item.inbound_id),
                "title": "OBHOD " + item.email,
                "refresh": int(self.sub_refresh),
                "filename": "obhod-" + item.email,
                "enabled": True,
                "path": item.path(),
                "links": list(item.links),
            }
        return {"port": int(self.sub_port), "sub_id_len": SUB_SEGMENT_LEN, "entries": entries}

    def to_config(self) -> str:
        return config_text(
            self.inbounds,
            self.log_level,
            self.access_log,
            self.error_log,
            self.api_enabled,
            self.api_port,
            self.metrics,
            self.dns_servers,
            tuple(sorted({0})),
        )
