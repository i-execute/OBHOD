from __future__ import annotations

import asyncio
import base64
import calendar
import ipaddress
import os
import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any

class ScanError(Exception):
    pass

SCAN_TIMEOUT = 10.0
DISCOVER_TIMEOUT = 4.0
CONCURRENCY = 32
DISCOVER_MAX_IPS = 256
SCAN_MAX_TOTAL = 512
PROXY_V1 = 1
PROXY_V2 = 2

GROUP_X25519 = 0x001D
GROUP_X25519_MLKEM768 = 0x11EC
GROUP_P256_MLKEM768 = 0x11EB
GROUP_X25519_KYBER768_DRAFT = 0x6399
PQ_GROUPS = {
    GROUP_X25519_MLKEM768: "X25519MLKEM768",
    GROUP_P256_MLKEM768: "P256MLKEM768",
}
MLKEM768_EK_SIZE = 1184
X25519_KEY_SIZE = 32
HYBRID_SHARE_SIZE = MLKEM768_EK_SIZE + X25519_KEY_SIZE
HELLO_RETRY_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
ML_DSA65_CHAIN_MIN = 3500
GROUP_YES = "yes"
GROUP_RETRY = "retry"
GROUP_NO = "no"
GROUP_LABELS = {
    "X25519MLKEM768": "x25519mlkem768",
    "P256MLKEM768": "p256mlkem768",
}

MLKEM768_EK_B64 = (
    "1gFKdZs0j6SClKVb+KIZcyRbwRk1EpOZBSlqD+e09bBpmoMiN0tn9fauXwGajZiUrhsONia0GbiV"
    "c0gJ0AmUhmmJ/8bBepsM4hsxztWnFchyRRcgNSQ50ALMz9PGVnjINtMA/jJCt5sRUKqUShlLXygv"
    "usRPe8ZN44cN6gCDOFJIahAMfWMTctJ4RSq9y5weV5uCeHlnObpZRfNnyayXz0l2AzrBF/QWwXjO"
    "arJhsuaDrzApsfZwB4MeYZJfY3Qx7xHGoGcpCIop/WTESgZiPEkYojYTpnOPfwyEMRuQK9sFM+Ia"
    "FXy4YlY0SzpQ9TsjdewnHuGtU/Uk1AOp/oJhG6IpR1WTPNN1wARnw/BgGlSK23WRzCGM2mKOPdF8"
    "lSkkT3C7zjyNiVmvnWRVkch+KqqFY/qr1AgT2KiU93ad2CK07qaKDxFPCAXGwMKlowC+shePS0OE"
    "8Lqad7ii9TAvg2StQoCypDSobDUH2lZiOMRKEpo4ePYIoFrJkIibWKeCfEcLs5Q9osRCtPR1oBEC"
    "/twgbPG9IocMkRQh6FSPMMR3r7tUgPNLYhgdiSwsfRlc1IlyQBhhwcOAl1bKdUljnZiJtkBiunOg"
    "/ANR6iRWsWs+phx60/VxDqILQKKWdmNR6+kGPMyZiHKYKFyXVdGAXTQGubeFtFW8BkSkaWFNg9R1"
    "3gVoFOpUCvl+iSA4Z1ZsrlRVAApVLaF4niGEkOFhGInMlMK6HSGTUqlAy0HD9WGIXwmJLpIMrMpo"
    "6HlW0hhp3wqzI2JZBvV9ERZwT6y+vXYzFqKiYrUd8Tx6wkCn07HFFNhsSuESFyunG7useiwNpGuu"
    "3nZZEaEIoashLdsTA9qUjpuT1EemrrHFOiJ40SWk4fESYChBEoZ0xxwV3xO66cd61bN8hrnE4MBz"
    "A1h1leuDylKXQ+LJntCLSQwZKqqAUfuNwidfgvg2ykw3uiB7VYEn7ukxMoe+8NufNvAq37hETSxN"
    "DyIeRGazQZRZB2FrlHF2/3kuO8LHI/HO1cA6tcyh73XPCRhgXdM6uXt1OMy4DRd3OhduIiRv98iU"
    "B6MUCUJWtWR14gJGvYpnNuStMFTFG4wegmoNtKImlrSvVDmCtXesmdSUc4Q3sZTICMYrFhg/r8is"
    "lDhflAYj5dmER9xFYuChotJtvaZ4tTEIg1aseVQaRZjFvQMMc7dm1JFB7Vp/ijmbbdsfNgER7LBG"
    "N4JGQRDCYOCI7ztfCvEfrgNGJkOgbuYDpNcwc1tq5XF/wNw4RUarmOa6DmuVvPsFEfOrqwPI5aiV"
    "qycQwCojbAiqPYXFBIaFyPG18rQ6yrlKS5FSctlSFXBRvWOLTQogARsAtgJiC9okygRo14aCfOy+"
    "PJN2W9I3juZztPGNBmZ553Szf0jBp2hnxDepwreuUlqqSxexy5jLSmjFIDCIS1eKJOGzVYaJwzGZ"
    "yDyv2zqterpAsrs+ppF3+bUU0cIXDTeE2FqBgZCzYSgsM2U43CSrRUOlLbZRICafe3da13ceeBCO"
    "M7Kg+AN74mpUn2GFPDftonm+TRGcMdAwgp9Wej/1R5AR+4wao6y1M/pCcqA="
)

DEFAULT_CANDIDATES = (
    "www.google.com:443", "dl.google.com:443", "www.microsoft.com:443", "www.nvidia.com:443",
    "www.amazon.com:443", "www.samsung.com:443", "www.nordstrom.com:443", "www.ibm.com:443",
    "www.macys.com:443", "aws.amazon.com:443", "www.snapchat.com:443", "www.cisco.com:443",
    "www.mozilla.org:443", "go.dev:443", "www.xbox.com:443", "www.adidas.com:443",
    "brave.com:443", "www.ubisoft.com:443", "www.oracle.com:443", "www.ea.com:443",
    "www.asus.com:443", "www.pinterest.com:443", "www.wise.com:443", "www.twitch.tv:443",
    "www.bing.com:443", "www.rakuten.co.jp:443", "www.mastercard.com:443", "www.twilio.com:443",
    "www.hulu.com:443", "www.paypal.com:443", "www.quora.com:443", "www.revolut.com:443",
    "www.klarna.com:443", "www.docker.com:443", "www.max.com:443", "gitlab.com:443",
    "www.rust-lang.org:443", "www.primevideo.com:443", "www.emag.ro:443", "www.linkedin.com:443",
    "www.zalando.com:443", "www.grammarly.com:443", "www.canva.com:443", "www.box.com:443",
    "www.coursera.org:443", "www.figma.com:443", "www.motorola.com:443", "www.duolingo.com:443",
    "soundcloud.com:443", "www.atlassian.com:443", "www.intercom.com:443", "www.boots.com:443",
    "www.zoom.us:443", "www.douglas.de:443", "www.sony.com:443", "www.target.com:443",
    "www.lowes.com:443", "www.etsy.com:443", "www.ebay.com:443", "www.khanacademy.org:443",
    "telegram.org:443", "www.alibaba.com:443", "www.saturn.de:443", "www.mediamarkt.de:443",
    "www.apple.com:443", "www.cloudflare.com:443", "www.intel.com:443", "www.sephora.com:443",
    "www.icloud.com:443", "discord.com:443", "www.amd.com:443", "www.nike.com:443",
    "www.zendesk.com:443", "www.farfetch.com:443", "www.asos.com:443", "www.lenovo.com:443",
    "www.whatsapp.com:443", "www.dell.com:443", "www.lg.com:443", "www.uniqlo.com:443",
    "www.hubspot.com:443", "open.spotify.com:443", "www.walgreens.com:443", "www.hp.com:443",
    "vimeo.com:443", "www.underarmour.com:443", "medium.com:443", "www.upwork.com:443",
    "stackoverflow.com:443", "www.reddit.com:443", "www.ikea.com:443", "www.zara.com:443",
    "www.hm.com:443", "pypi.org:443", "www.panasonic.com:443", "www.nintendo.com:443",
    "www.decathlon.com:443", "www.newbalance.com:443", "www.python.org:443", "nodejs.org:443",
    "www.flipkart.com:443", "www.fujitsu.com:443", "signal.org:443", "www.indeed.com:443",
    "www.epicgames.com:443", "www.glassdoor.com:443", "www.adobe.com:443", "www.tumblr.com:443",
    "www.udemy.com:443", "www.salesforce.com:443", "www.npmjs.com:443", "www.shopify.com:443",
    "www.notion.so:443", "www.siemens.com:443", "www.alza.cz:443", "www.nokia.com:443",
    "www.ericsson.com:443", "www.philips.com:443", "www.wayfair.com:443", "www.deezer.com:443",
    "www.bestbuy.com:443", "www.aliexpress.com:443", "www.costco.com:443", "www.homedepot.com:443",
    "www.walmart.com:443", "allegro.pl:443", "google.com:443", "google.co.uk:443",
    "google.ca:443", "google.de:443", "google.fr:443", "google.it:443",
    "google.es:443", "google.nl:443", "google.ru:443", "google.com.br:443",
    "google.com.mx:443", "google.com.tr:443", "google.co.in:443", "google.com.hk:443",
    "google.com.ar:443", "google.com.eg:443", "youtube.com:443", "youtu.be:443",
    "gmail.com:443", "googlemail.com:443", "googleusercontent.com:443", "googleapis.com:443",
    "googledrive.com:443", "blogger.com:443", "blogspot.com:443", "appspot.com:443",
    "recaptcha.net:443", "android.com:443", "googlecode.com:443", "googlecommerce.com:443",
    "feedburner.com:443", "admob.com:443", "googletagmanager.com:443", "yimg.com:443",
    "yahoo.net:443", "yahooapis.com:443", "twitter.com:443", "ebay.com:443",
    "ebayinc.com:443", "evernote.com:443", "mozilla.org:443", "mozilla.com:443",
    "theguardian.com:443", "bbc.co.uk:443", "bbc.com:443", "telegraph.co.uk:443",
    "usatoday.com:443", "huffingtonpost.com:443", "huffpost.com:443", "engadget.com:443",
    "flipboard.com:443", "buzzfeed.com:443", "marketwatch.com:443", "wsj.com:443",
    "fortune.com:443", "cbsnews.com:443", "npr.org:443", "nfl.com:443",
    "cbssports.com:443", "thehill.com:443", "salon.com:443", "aarp.org:443",
    "fcc.gov:443", "bankofamerica.com:443", "paypal.com:443", "paypalobjects.com:443",
    "linkedin.com:443", "pinterest.com:443", "flickr.com:443", "slideshare.com:443",
    "issuu.com:443", "mediafire.com:443", "archive.org:443", "speedtest.net:443",
    "tripadvisor.com:443", "groupon.com:443", "stubhub.com:443", "foursquare.com:443",
    "olx.com:443", "accuweather.com:443", "weatherbug.com:443", "mapquest.com:443",
    "digicert.com:443", "globalsign.com:443", "geotrust.com:443", "typography.com:443",
    "hp.com:443", "ea.com:443", "zynga.com:443", "king.com:443",
    "clashofclans.com:443", "surveymonkey.com:443", "qualtrics.com:443", "logmein.com:443",
    "olark.com:443", "optimizely.com:443", "alexa.com:443", "digg.com:443",
    "kinja.com:443",
)

OID_CN = bytes.fromhex("550403")
OID_SAN = bytes.fromhex("551d11")
OID_KEY_USAGE = bytes.fromhex("551d0f")
OID_ORG = bytes.fromhex("55040a")
OID_RSA = bytes.fromhex("2a864886f70d010101")
OID_EC = bytes.fromhex("2a8648ce3d0201")
OID_ED25519 = bytes.fromhex("2b6570")
OID_ED448 = bytes.fromhex("2b6571")
OID_RSA_PSS = bytes.fromhex("2a864886f70d01010a")

SIG_ALGS = {
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "ED25519",
    "1.3.101.113": "ED448",
}

TAG_CONSTRUCTED = 0x20
TAG_CLASS_CONTEXT = 0x80


def blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def public_answers(addresses) -> tuple[list[str], list[str]]:
    private: list[str] = []
    public: list[str] = []
    for raw in addresses:
        try:
            item = ipaddress.ip_address(str(raw))
        except ValueError:
            continue
        bucket = private if blocked_ip(item) else public
        bucket.append(str(item))
    return private, public


async def getaddrinfo_async(host: str, port: int):
    import socket

    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=SCAN_TIMEOUT)


async def resolve_public(host: str, port: int, allow_private: bool = False) -> tuple[str, bool]:
    try:
        literal = ipaddress.ip_address(host)
        if blocked_ip(literal) and not allow_private:
            return "", True
        return str(literal), False
    except ValueError:
        pass
    try:
        infos = await getaddrinfo_async(host, port)
    except (asyncio.TimeoutError, OSError):
        raise ScanError("a host name could not be resolved") from None
    addresses = []
    for info in infos:
        raw = info[4][0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ScanError("a host name has no usable address")
    private = [item for item in addresses if blocked_ip(item)]
    if private and not allow_private:
        return "", True
    return str(addresses[0]), False


INVISIBLE = "\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad"
SCHEMES = ("vless://", "https://", "http://", "tls://", "h2://", "h3://", "reality://", "quic://")
DEFAULT_TARGET_PORT = 443
HOST_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def clean_target_text(value: object) -> str:
    text = str(value or "")
    for char in INVISIBLE:
        text = text.replace(char, "")
    text = text.strip().strip("\"'`<>(),;").strip()
    low = text.lower()
    for scheme in SCHEMES:
        if low.startswith(scheme):
            text = text[len(scheme):]
            break
    else:
        if "://" in text:
            text = text.split("://", 1)[1]
    text = text.split("#", 1)[0].split("?", 1)[0]
    if "/" in text and not re.search(r"\d+\.\d+\.\d+\.\d+/\d+$", text):
        text = text.split("/", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    return text.strip().strip("/").strip()


def normalize_host(value: object) -> str:
    text = clean_target_text(value).strip("[]").strip()
    if not text:
        raise ScanError("a host or address is required")
    if any(char.isspace() for char in text):
        raise ScanError("a host must not contain spaces")
    if len(text) > 253:
        raise ScanError("a host is too long")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    text = text.rstrip(".").lower()
    if not text:
        raise ScanError("a host or address is required")
    try:
        text = text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise ScanError("a host has characters that are not allowed") from None
    for label in text.split("."):
        if not label:
            raise ScanError("a host must not have empty labels")
        if not HOST_LABEL.match(label):
            raise ScanError("a host label is not valid: " + label[:63])
    return text


def is_subnet(value: object) -> bool:
    text = clean_target_text(value)
    if "/" not in text:
        return False
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


def split_target(target: str) -> tuple[str, int]:
    text = clean_target_text(target)
    if not text:
        raise ScanError("a target in host:port form is required")
    text = text.rstrip(".")
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port_text = rest.lstrip(":")
    elif text.count(":") > 1:
        host, port_text = text, ""
    elif ":" in text:
        host, port_text = text.split(":", 1)
    else:
        host, port_text = text, ""
    host = normalize_host(host)
    port_text = str(port_text or "").strip()
    if not port_text:
        port = DEFAULT_TARGET_PORT
    else:
        try:
            port = int(port_text)
        except ValueError:
            raise ScanError("a port must be a number") from None
    if not 1 <= port <= 65535:
        raise ScanError("a port must be between 1 and 65535")
    return host, port


def normalize_target(target: object) -> str:
    text = clean_target_text(target)
    if not text:
        raise ScanError("a target is required")
    if is_subnet(text):
        net = ipaddress.ip_network(text, strict=False)
        return str(net)
    host, port = split_target(text)
    if ":" in host:
        return "[%s]:%d" % (host, port)
    return "%s:%d" % (host, port)


def normalize_targets(text: object, limit: int = SCAN_MAX_TOTAL) -> tuple[list[str], list[str]]:
    raw = str(text or "")
    for char in ",;\n\r\t|":
        raw = raw.replace(char, " ")
    out: list[str] = []
    bad: list[str] = []
    for token in raw.split():
        try:
            item = normalize_target(token)
        except ScanError as exc:
            bad.append("%s: %s" % (clean_target_text(token)[:64] or "empty", str(exc)))
            continue
        if item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out, bad


def enumerate_cidr(cidr: str, limit: int = DISCOVER_MAX_IPS) -> list[str]:
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError as exc:
        raise ScanError("a subnet is not valid: " + str(exc)) from None
    out: list[str] = []
    for address in net:
        out.append(str(address))
        if len(out) >= limit:
            break
    return out


def tls_version_name(version: str | None) -> str:
    mapping = {
        "TLSv1.3": "1.3",
        "TLSv1.2": "1.2",
        "TLSv1.1": "1.1",
        "TLSv1": "1.0",
    }
    return mapping.get(version or "", version or "")


def group_name(number: int) -> str:
    if number in PQ_GROUPS:
        return PQ_GROUPS[number]
    if number == GROUP_X25519:
        return "X25519"
    if not number:
        return ""
    return "group0x%04x" % number


def _tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset + 2 > len(data):
        raise ScanError("a DER element is truncated")
    tag = data[offset]
    length = data[offset + 1]
    head = 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or offset + 2 + count > len(data):
            raise ScanError("a DER length is truncated")
        length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
        head = 2 + count
    start = offset + head
    end = start + length
    if end > len(data):
        raise ScanError("a DER value is truncated")
    return tag, start, end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    offset = start
    while offset < end:
        tag, inner_start, inner_end = _tlv(data, offset)
        out.append((tag, inner_start, inner_end))
        offset = inner_end
    return out


def _decode_string(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def _oid_text(raw: bytes) -> str:
    if not raw:
        return ""
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _decode_time(tag: int, raw: bytes) -> str:
    text = raw.decode("ascii", errors="replace")
    try:
        if tag == 0x17:
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900
            rest = text[2:]
        else:
            year = int(text[0:4])
            rest = text[4:]
        month = int(rest[0:2])
        day = int(rest[2:4])
        hour = int(rest[4:6])
        minute = int(rest[6:8])
        second = int(rest[8:10])
    except (ValueError, IndexError):
        return ""
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (year, month, day, hour, minute, second)


@dataclass
class Certificate:
    subject_cn: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    not_before: str = ""
    not_after: str = ""
    dns_names: list[str] = field(default_factory=list)
    chain_bytes: int = 0
    leaf_bytes: int = 0
    key_type: str = ""
    key_bits: int = 0
    sig_alg: str = ""
    sig_alg_oid: str = ""
    serial: str = ""
    days_left: int = 0


def parse_certificate(der: bytes) -> Certificate:
    cert = Certificate(chain_bytes=len(der), leaf_bytes=len(der))
    tag, start, end = _tlv(der, 0)
    if tag != 0x30:
        raise ScanError("a certificate is not a SEQUENCE")
    parts = _children(der, start, end)
    if not parts:
        raise ScanError("a certificate is empty")
    tbs_tag, tbs_start, tbs_end = parts[0]
    tbs = _children(der, tbs_start, tbs_end)
    index = 0
    if tbs and (tbs[0][0] & 0xE0) == (TAG_CLASS_CONTEXT | TAG_CONSTRUCTED):
        index = 1
    if len(tbs) < index + 6:
        raise ScanError("tbsCertificate is too short")
    serial = tbs[index]
    cert.serial = der[serial[1] : serial[2]].hex()
    sig = tbs[index + 1]
    sig_parts = _children(der, sig[1], sig[2])
    if sig_parts:
        oid = _oid_text(der[sig_parts[0][1] : sig_parts[0][2]])
        cert.sig_alg_oid = oid
        cert.sig_alg = SIG_ALGS.get(oid, oid)
    issuer = _children(der, tbs[index + 2][1], tbs[index + 2][2])
    validity = tbs[index + 3]
    subject = _children(der, tbs[index + 4][1], tbs[index + 4][2])
    spki = tbs[index + 5]
    cert.subject_cn = _name_value(der, subject, OID_CN)
    cert.issuer_cn = _name_value(der, issuer, OID_CN)
    cert.issuer_org = _name_value(der, issuer, OID_ORG)
    times = _children(der, validity[1], validity[2])
    if len(times) >= 2:
        cert.not_before = _decode_time(times[0][0], der[times[0][1] : times[0][2]])
        cert.not_after = _decode_time(times[1][0], der[times[1][1] : times[1][2]])
    cert.days_left = _days_left(cert.not_after)
    cert.key_type, cert.key_bits = _spki_key(der, spki)
    for entry in tbs[index + 6 :]:
        if (entry[0] & 0xE0) != (TAG_CLASS_CONTEXT | TAG_CONSTRUCTED):
            continue
        if (entry[0] & 0x1F) != 3:
            continue
        inner = _children(der, entry[1], entry[2])
        if not inner:
            continue
        for ext in _children(der, inner[0][1], inner[0][2]):
            fields = _children(der, ext[1], ext[2])
            if len(fields) < 2:
                continue
            oid = der[fields[0][1] : fields[0][2]]
            if oid != OID_SAN:
                continue
            value = fields[-1]
            names = _children(der, value[1], value[2])
            if names and names[0][0] == 0x30:
                names = _children(der, names[0][1], names[0][2])
            cert.dns_names = [_decode_string(der[item[1] : item[2]]) for item in names if item[0] == 0x82]
    return cert


def _days_left(not_after: str) -> int:
    if not not_after:
        return 0
    try:
        stamp = time.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return 0
    expires = calendar.timegm(stamp)
    return int((expires - time.time()) // 86400)


def _spki_key(der: bytes, spki: tuple[int, int, int]) -> tuple[str, int]:
    try:
        parts = _children(der, spki[1], spki[2])
        if len(parts) < 2:
            return "", 0
        alg = _children(der, parts[0][1], parts[0][2])
        if not alg:
            return "", 0
        oid = der[alg[0][1] : alg[0][2]]
        key_type = "unknown"
        if oid == OID_RSA or oid == OID_RSA_PSS:
            key_type = "RSA"
        elif oid == OID_EC:
            key_type = "EC"
        elif oid == OID_ED25519:
            key_type = "Ed25519"
        elif oid == OID_ED448:
            key_type = "Ed448"
        bits = 0
        if key_type == "RSA":
            raw = der[parts[1][1] : parts[1][2]]
            inner = raw[1:] if raw[:1] == b"\x00" else raw
            try:
                tag, start, end = _tlv(inner, 0)
                integers = _children(inner, start, end)
                if integers:
                    modulus = inner[integers[0][1] : integers[0][2]]
                    while modulus[:1] == b"\x00":
                        modulus = modulus[1:]
                    bits = len(modulus) * 8
            except ScanError:
                bits = 0
        return key_type, bits
    except ScanError:
        return "", 0


def parse_chain(items: list[bytes]) -> Certificate:
    if not items:
        raise ScanError("a certificate chain is empty")
    cert = parse_certificate(items[0])
    cert.chain_bytes = sum(len(item) for item in items)
    cert.leaf_bytes = len(items[0])
    return cert


def _name_value(der: bytes, entries: list[tuple[int, int, int]], oid: bytes) -> str:
    for rdn in entries:
        for attribute in _children(der, rdn[1], rdn[2]):
            parts = _children(der, attribute[1], attribute[2])
            if len(parts) < 2:
                continue
            if der[parts[0][1] : parts[0][2]] == oid:
                return _decode_string(der[parts[1][1] : parts[1][2]])
    return ""


@dataclass
class ScanResult:
    target: str = ""
    host: str = ""
    ip: str = ""
    port: int = 443
    feasible: bool = False
    private_target: bool = False
    tls13: bool = False
    tls_version: str = ""
    h2: bool = False
    alpn: str = ""
    x25519: bool = False
    curve_id: str = ""
    pq_hybrid: bool = False
    pq_group: str = ""
    pq_draft: bool = False
    groups: dict[str, str] = field(default_factory=dict)
    cert_valid: bool = False
    cert_chain_valid: bool = False
    cert_chain_bytes: int = 0
    cert_leaf_bytes: int = 0
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_key_type: str = ""
    cert_key_bits: int = 0
    cert_sig_alg: str = ""
    not_after: str = ""
    days_left: int = 0
    ml_dsa_ready: bool = False
    server_names: list[str] = field(default_factory=list)
    latency_ms: int = 0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "ip": self.ip,
            "port": int(self.port),
            "feasible": bool(self.feasible),
            "private_target": bool(self.private_target),
            "tls13": bool(self.tls13),
            "tls_version": self.tls_version,
            "h2": bool(self.h2),
            "alpn": self.alpn,
            "x25519": bool(self.x25519),
            "curve_id": self.curve_id,
            "pq_hybrid": bool(self.pq_hybrid),
            "pq_group": self.pq_group,
            "pq_draft": bool(self.pq_draft),
            "groups": dict(self.groups),
            "cert_valid": bool(self.cert_valid),
            "cert_chain_valid": bool(self.cert_chain_valid),
            "cert_chain_bytes": int(self.cert_chain_bytes),
            "cert_leaf_bytes": int(self.cert_leaf_bytes),
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_key_type": self.cert_key_type,
            "cert_key_bits": int(self.cert_key_bits),
            "cert_sig_alg": self.cert_sig_alg,
            "not_after": self.not_after,
            "days_left": int(self.days_left),
            "ml_dsa_ready": bool(self.ml_dsa_ready),
            "server_names": list(self.server_names),
            "latency_ms": int(self.latency_ms),
            "reason": self.reason,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "ScanResult":
        data = raw or {}
        return ScanResult(
            target=str(data.get("target", "")),
            host=str(data.get("host", "")),
            ip=str(data.get("ip", "")),
            port=int(data.get("port", 443) or 443),
            feasible=bool(data.get("feasible", False)),
            private_target=bool(data.get("private_target", False)),
            tls13=bool(data.get("tls13", False)),
            tls_version=str(data.get("tls_version", "")),
            h2=bool(data.get("h2", False)),
            alpn=str(data.get("alpn", "")),
            x25519=bool(data.get("x25519", False)),
            curve_id=str(data.get("curve_id", "")),
            pq_hybrid=bool(data.get("pq_hybrid", False)),
            pq_group=str(data.get("pq_group", "")),
            pq_draft=bool(data.get("pq_draft", False)),
            groups={str(key): str(value) for key, value in (data.get("groups") or {}).items()},
            cert_valid=bool(data.get("cert_valid", False)),
            cert_chain_valid=bool(data.get("cert_chain_valid", False)),
            cert_chain_bytes=int(data.get("cert_chain_bytes", 0) or 0),
            cert_leaf_bytes=int(data.get("cert_leaf_bytes", 0) or 0),
            cert_subject=str(data.get("cert_subject", "")),
            cert_issuer=str(data.get("cert_issuer", "")),
            cert_key_type=str(data.get("cert_key_type", "")),
            cert_key_bits=int(data.get("cert_key_bits", 0) or 0),
            cert_sig_alg=str(data.get("cert_sig_alg", "")),
            not_after=str(data.get("not_after", "")),
            days_left=int(data.get("days_left", 0) or 0),
            ml_dsa_ready=bool(data.get("ml_dsa_ready", False)),
            server_names=[str(item) for item in data.get("server_names") or []],
            latency_ms=int(data.get("latency_ms", 0) or 0),
            reason=str(data.get("reason", "")),
        )

    def line(self) -> str:
        mark = "ok" if self.feasible else "no"
        bits = [mark, self.target]
        if self.tls_version:
            bits.append("tls" + self.tls_version)
        if self.alpn:
            bits.append(self.alpn)
        if self.pq_group:
            bits.append(self.pq_group)
        if self.latency_ms:
            bits.append(str(self.latency_ms) + "ms")
        if self.cert_subject:
            bits.append(self.cert_subject)
        if self.reason:
            bits.append(self.reason)
        return " ".join(bits)

    def pq_group_names(self) -> list[str]:
        names = [GROUP_LABELS.get(name, name.lower()) for name, answer in (self.groups or {}).items() if answer in {GROUP_YES, GROUP_RETRY}]
        if not names and self.pq_hybrid and self.pq_group:
            names = [GROUP_LABELS.get(self.pq_group, self.pq_group.lower())]
        return names

    def group_state(self, group: str) -> str:
        if not group:
            return GROUP_YES
        wanted = group.lower()
        if self.groups:
            for name, answer in self.groups.items():
                if GROUP_LABELS.get(name, name.lower()).lower() == wanted:
                    return answer
            return GROUP_NO
        if self.pq_hybrid and GROUP_LABELS.get(self.pq_group, self.pq_group.lower()).lower() == wanted:
            return GROUP_YES
        if self.pq_hybrid and not self.pq_group and wanted == GROUP_LABELS["X25519MLKEM768"]:
            return GROUP_YES
        return GROUP_NO

    def supports_group(self, group: str) -> bool:
        return self.group_state(group) in {GROUP_YES, GROUP_RETRY}

    def missing(self) -> list[str]:
        gaps: list[str] = []
        if not self.tls13:
            gaps.append("tls 1.3")
        if not self.h2:
            gaps.append("http/2")
        if not self.x25519:
            gaps.append("x25519")
        if not self.cert_valid:
            gaps.append("certificate")
        if self.days_left < 0:
            gaps.append("expiry")
        return gaps


def parse_candidates(csv: str | None) -> list[str]:
    out: list[str] = []
    for token in str(csv or "").replace(";", ",").replace("\n", ",").split(","):
        value = token.strip()
        if value and value not in out:
            out.append(value)
    return out or list(DEFAULT_CANDIDATES)


def feasible_of(result: ScanResult) -> bool:
    return bool(
        result.tls13
        and result.h2
        and result.x25519
        and result.cert_valid
        and result.days_left >= 0
    )


def reality_fit(result: ScanResult) -> tuple[bool, str]:
    gaps = result.missing()
    if gaps:
        return False, "missing " + ", ".join(gaps)
    if result.days_left <= 0:
        return False, "the certificate has expired"
    return True, "tls 1.3, http/2, x25519, x25519mlkem768 and a valid chain"


def ml_dsa_fit(result: ScanResult) -> tuple[bool, str]:
    if not result.ml_dsa_ready:
        return False, "the chain is shorter than %d bytes, ml-dsa-65 does not fit" % ML_DSA65_CHAIN_MIN
    if result.cert_key_type and result.cert_key_type != "RSA":
        return True, "the chain is long enough, an ecdsa target is tighter than rsa"
    return True, "the chain has room for the ml-dsa-65 signature"


def tls_fit(result: ScanResult) -> tuple[bool, str]:
    if not result.tls13:
        return False, "the target does not negotiate tls 1.3"
    if not result.pq_hybrid:
        return False, "the target does not negotiate x25519mlkem768"
    return True, "a tls 1.3 target with the hybrid post quantum group"


KIND_ALIASES = {
    "reality-pq": "reality-x25519mlkem768",
    "reality-mldsa": "reality-mldsa65",
    "reality-mldsa-pq": "reality-mldsa65-x25519mlkem768",
    "tls-pq": "tls-x25519mlkem768",
}
REALITY_KINDS = {
    "reality": "",
    "reality-x25519mlkem768": "x25519mlkem768",
    "reality-p256mlkem768": "p256mlkem768",
    "reality-mldsa65": "",
    "reality-mldsa65-x25519mlkem768": "x25519mlkem768",
}
TLS_KINDS = {
    "tls": "",
    "tls-x25519mlkem768": "x25519mlkem768",
    "tls-p256mlkem768": "p256mlkem768",
}
SECURITY_KINDS = tuple(REALITY_KINDS) + tuple(TLS_KINDS)
STRONGEST_FIRST = (
    "reality-mldsa65-x25519mlkem768",
    "reality-mldsa65",
    "reality-x25519mlkem768",
    "reality-p256mlkem768",
    "reality",
    "tls-x25519mlkem768",
    "tls-p256mlkem768",
    "tls",
)


def canonical_kind(kind: str) -> str:
    name = KIND_ALIASES.get(str(kind or ""), str(kind or ""))
    if name not in SECURITY_KINDS:
        raise ValueError("security must be one of " + ", ".join(SECURITY_KINDS))
    return name


def kind_group(kind: str) -> str:
    name = canonical_kind(kind)
    return REALITY_KINDS[name] if name in REALITY_KINDS else TLS_KINDS[name]


def kind_is_tls(kind: str) -> bool:
    return canonical_kind(kind) in TLS_KINDS


def kind_has_mldsa(kind: str) -> bool:
    return "mldsa65" in canonical_kind(kind)


def reality_gaps(result: ScanResult) -> list[str]:
    gaps: list[str] = []
    if not result.tls13:
        gaps.append("tls 1.3")
    if not result.h2:
        gaps.append("http/2")
    if not result.x25519:
        gaps.append("x25519")
    if not result.cert_valid:
        gaps.append("certificate")
    if result.days_left < 0:
        gaps.append("expiry")
    return gaps


def security_fit(result: ScanResult, kind: str) -> tuple[bool, str]:
    name = canonical_kind(kind)
    group = kind_group(name)
    if name == "tls":
        if not result.tls13:
            return False, "the target does not negotiate tls 1.3"
        return True, "a tls 1.3 handshake, the certificate stays on our side"
    if kind_is_tls(name):
        if not result.tls13:
            return False, "the target does not negotiate tls 1.3"
        if not result.supports_group(group):
            return False, "the target does not negotiate " + group
        if result.group_state(group) == GROUP_RETRY:
            return True, "tls 1.3, the target asks for a hello retry on %s, the certificate stays on our side" % group
        return True, "tls 1.3 with the %s group, the certificate stays on our side" % group
    gaps = reality_gaps(result)
    if gaps:
        return False, "missing " + ", ".join(gaps)
    if group and not result.supports_group(group):
        return False, "the target does not negotiate " + group
    retry = group and result.group_state(group) == GROUP_RETRY
    if kind_has_mldsa(name):
        if not result.ml_dsa_ready:
            return False, "the chain is %d bytes, %d bytes short of the %d byte minimum" % (
                result.cert_chain_bytes,
                max(ML_DSA65_CHAIN_MIN - result.cert_chain_bytes, 0),
                ML_DSA65_CHAIN_MIN,
            )
        if retry:
            return True, "a chain of %d bytes carries the ml-dsa-65 signature, the target asks for a hello retry on %s" % (result.cert_chain_bytes, group)
        if group:
            return True, "a chain of %d bytes carries the ml-dsa-65 signature, the %s group fits" % (result.cert_chain_bytes, group)
        return True, "a chain of %d bytes carries the ml-dsa-65 signature" % result.cert_chain_bytes
    if retry:
        return True, "tls 1.3, http/2, the target asks for a hello retry on %s and a valid chain" % group
    if group:
        return True, "tls 1.3, http/2, %s and a valid chain" % group
    return True, "tls 1.3, http/2, x25519 and a valid chain"


def security_fits(result: ScanResult) -> list[tuple[str, bool, str]]:
    return [(kind,) + security_fit(result, kind) for kind in SECURITY_KINDS]


def recommended_security(result: ScanResult) -> str:
    fits = {kind for kind, ok, _ in security_fits(result) if ok}
    for kind in STRONGEST_FIRST:
        if kind in fits:
            return kind
    return ""


def proxy_header(kind: int, local: tuple[str, int], remote: tuple[str, int]) -> bytes:
    if kind >= PROXY_V2:
        head = bytes([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21])
        try:
            src = ipaddress.ip_address(local[0]).packed
            dst = ipaddress.ip_address(remote[0]).packed
        except ValueError:
            return b""
        family = 0x11 if len(src) == 4 else 0x21
        addresses = src + dst + local[1].to_bytes(2, "big") + remote[1].to_bytes(2, "big")
        return head + bytes([family]) + len(addresses).to_bytes(2, "big") + addresses
    try:
        src_ip = ipaddress.ip_address(local[0])
        dst_ip = ipaddress.ip_address(remote[0])
    except ValueError:
        return b""
    family = "TCP4" if src_ip.version == 4 else "TCP6"
    line = "PROXY %s %s %s %d %d\r\n" % (family, src_ip, dst_ip, local[1], remote[1])
    return line.encode("ascii")


def _context(verify: bool, hostname: str, only_x25519: bool, alpn: bool) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
        if not hostname:
            ctx.check_hostname = False
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, OSError):
        pass
    if only_x25519 and hasattr(ctx, "set_ecdh_curve"):
        try:
            ctx.set_ecdh_curve("X25519")
        except (ValueError, ssl.SSLError):
            return ctx
    return ctx


def mlkem768_public_key() -> bytes:
    raw = base64.b64decode(MLKEM768_EK_B64)
    if len(raw) != MLKEM768_EK_SIZE:
        raise ScanError("the embedded ml-kem-768 key has the wrong length")
    return raw


def _extension(kind: int, body: bytes) -> bytes:
    return struct.pack("!HH", kind, len(body)) + body


def client_hello(host: str, key_share: bytes, extra_share: bytes, group: int = GROUP_X25519_MLKEM768, offered: list[int] | None = None) -> bytes:
    random = os.urandom(32)
    session = os.urandom(32)
    try:
        name = host.encode("idna") if host else b""
    except (UnicodeError, ValueError):
        name = host.encode("ascii", "ignore") if host else b""
    server_name = b"\x00" + struct.pack("!H", len(name)) + name
    shares: list[tuple[int, bytes]] = []
    if key_share:
        shares.append((group, key_share))
    if extra_share:
        shares.append((GROUP_X25519, extra_share))
    groups = list(offered) if offered else [item for item, _ in shares]
    share_body = struct.pack("!H", sum(4 + len(item) for _, item in shares))
    for item_group, item in shares:
        share_body += struct.pack("!HH", item_group, len(item)) + item
    extensions = (
        _extension(0x0000, struct.pack("!H", len(server_name)) + server_name)
        + _extension(0x000A, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", item) for item in groups))
        + _extension(0x000D, struct.pack("!H", 4) + b"\x08\x04\x04\x03")
        + _extension(0x002B, b"\x04" + b"\x03\x04\x03\x03")
        + _extension(0x0033, share_body)
    )
    suites = struct.pack("!H", 2) + b"\x13\x01"
    body = (
        b"\x03\x03"
        + random
        + b"\x20"
        + session
        + suites
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def parse_server_hello(message: bytes) -> tuple[int, bool]:
    if not message or message[0] != 2:
        return 0, False
    body = message[4:]
    if len(body) < 38:
        return 0, False
    retry = body[2:34] == HELLO_RETRY_RANDOM
    position = 34
    if position >= len(body):
        return 0, retry
    position += 1 + body[position]
    position += 3
    if position + 2 > len(body):
        return 0, retry
    size = struct.unpack("!H", body[position : position + 2])[0]
    position += 2
    end = min(len(body), position + size)
    while position + 4 <= end:
        kind, length = struct.unpack("!HH", body[position : position + 4])
        position += 4
        if kind == 0x0033 and length >= 2:
            return struct.unpack("!H", body[position : position + 2])[0], retry
        position += length
    return 0, retry


async def pq_group_probe(host: str, port: int = 443, group: int = GROUP_X25519_MLKEM768, timeout: float = SCAN_TIMEOUT, sni: str = "") -> str:
    name = sni or host
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return GROUP_NO
    try:
        key_share = mlkem768_public_key() + os.urandom(X25519_KEY_SIZE)
        offered = [group, GROUP_X25519]
        payload = client_hello(name, key_share, os.urandom(X25519_KEY_SIZE), group=group, offered=offered)
        writer.write(payload)
        await writer.drain()
        buffer = b""
        deadline = time.monotonic() + timeout
        while len(buffer) < 5:
            if time.monotonic() > deadline:
                return GROUP_NO
            chunk = await asyncio.wait_for(reader.read(65536), timeout=max(0.1, deadline - time.monotonic()))
            if not chunk:
                return GROUP_NO
            buffer += chunk
        if buffer[0] != 0x16:
            return GROUP_NO
        need = 5 + struct.unpack("!H", buffer[3:5])[0]
        while len(buffer) < need:
            if time.monotonic() > deadline:
                return GROUP_NO
            chunk = await asyncio.wait_for(reader.read(65536), timeout=max(0.1, deadline - time.monotonic()))
            if not chunk:
                break
            buffer += chunk
        chosen, retry = parse_server_hello(buffer[5:need])
        if chosen == group and not retry:
            return GROUP_YES
        if chosen == group and retry:
            return GROUP_RETRY
        return GROUP_NO
    except (asyncio.TimeoutError, OSError, ssl.SSLError, ScanError):
        return GROUP_NO
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


async def pq_probe(host: str, port: int = 443, timeout: float = SCAN_TIMEOUT, sni: str = "") -> tuple[bool, str, bool]:
    name = sni or host
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return False, "", False
    try:
        payload = client_hello(name, mlkem768_public_key() + os.urandom(X25519_KEY_SIZE), os.urandom(X25519_KEY_SIZE))
        writer.write(payload)
        await writer.drain()
        buffer = b""
        deadline = time.monotonic() + timeout
        while len(buffer) < 5:
            if time.monotonic() > deadline:
                return False, "", False
            chunk = await asyncio.wait_for(reader.read(65536), timeout=max(0.1, deadline - time.monotonic()))
            if not chunk:
                return False, "", False
            buffer += chunk
        if buffer[0] != 0x16:
            return False, "", False
        need = 5 + struct.unpack("!H", buffer[3:5])[0]
        while len(buffer) < need:
            if time.monotonic() > deadline:
                return False, "", False
            chunk = await asyncio.wait_for(reader.read(65536), timeout=max(0.1, deadline - time.monotonic()))
            if not chunk:
                break
            buffer += chunk
        group, retry = parse_server_hello(buffer[5:need])
        if not group:
            return False, "", False
        return group in PQ_GROUPS, group_name(group), False
    except (asyncio.TimeoutError, OSError, ssl.SSLError, ScanError):
        return False, "", False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


async def probe_groups(host: str, port: int = 443, sni: str = "", timeout: float = SCAN_TIMEOUT) -> dict[str, str]:
    names = [PQ_GROUPS[group] for group in (GROUP_X25519_MLKEM768, GROUP_P256_MLKEM768)]
    answers = await asyncio.gather(
        pq_group_probe(host, port, GROUP_X25519_MLKEM768, timeout, sni),
        pq_group_probe(host, port, GROUP_P256_MLKEM768, timeout, sni),
    )
    out = {}
    for name, answer in zip(names, answers):
        out[name] = answer
    return out


async def probe(
    host: str,
    port: int = 443,
    sni: str = "",
    timeout: float = SCAN_TIMEOUT,
    xver: int = 0,
    allow_private: bool = False,
    bulk: bool = False,
) -> ScanResult:
    result = ScanResult(target=format_target(host, port), host=sni or host, port=port)
    try:
        address = ipaddress.ip_address(host)
        result.ip = str(address)
        if blocked_ip(address) and not allow_private:
            result.private_target = True
            result.reason = "a private or local address is blocked"
            return result
    except ValueError:
        pass
    try:
        target, private = await resolve_public(host, port, allow_private)
    except ScanError as exc:
        result.reason = str(exc)
        return result
    if private:
        result.private_target = True
        result.reason = "a private or local address is blocked"
        return result
    start = time.monotonic()
    try:
        info = await asyncio.wait_for(_connect_info(target, port, sni or host, timeout, xver), timeout=timeout + 2)
    except (asyncio.TimeoutError, OSError, ssl.SSLError, ScanError) as exc:
        result.reason = "connection failed: " + type(exc).__name__ + ": " + str(exc)
        return result
    result.ip = info.get("ip", result.ip) or target
    try:
        peer = ipaddress.ip_address(result.ip)
    except ValueError:
        peer = None
    if peer is not None and blocked_ip(peer) and not allow_private:
        result.private_target = True
        result.feasible = False
        result.reason = "the peer address is private or local"
        return result
    result.latency_ms = int((time.monotonic() - start) * 1000)
    result.tls_version = tls_version_name(info.get("version"))
    result.tls13 = info.get("version") == "TLSv1.3"
    result.alpn = info.get("alpn") or ""
    result.h2 = result.alpn == "h2"
    cert = info.get("cert")
    if isinstance(cert, Certificate):
        result.cert_chain_bytes = cert.chain_bytes
        result.cert_leaf_bytes = cert.leaf_bytes
        result.cert_subject = cert.subject_cn or (cert.dns_names[0] if cert.dns_names else "")
        result.cert_issuer = cert.issuer_org or cert.issuer_cn
        result.cert_key_type = cert.key_type
        result.cert_key_bits = cert.key_bits
        result.cert_sig_alg = cert.sig_alg
        result.not_after = cert.not_after
        result.days_left = cert.days_left
        result.ml_dsa_ready = cert.chain_bytes >= ML_DSA65_CHAIN_MIN
        result.server_names = [name for name in cert.dns_names if name and not name.startswith("*.")]
        if not sni and result.server_names and _is_ip(host):
            result.host = result.server_names[0]
            result.target = format_target(result.host, port)
    elif info.get("cert_error"):
        result.reason = "the certificate is not readable: " + str(info.get("cert_error"))
    else:
        result.reason = "no certificate was returned"
    if bulk and not result.tls_version:
        return result
    result.x25519 = await _supports_x25519(host, port, result.host, timeout, xver)
    result.curve_id = "X25519" if result.x25519 else ""
    try:
        result.groups = await probe_groups(host, port, result.host or sni, timeout)
    except (OSError, asyncio.TimeoutError, ScanError):
        result.groups = {}
    pq_ok, pq_group, pq_draft = await pq_probe(host, port, timeout, result.host or sni)
    result.pq_hybrid = pq_ok
    result.pq_group = pq_group
    result.pq_draft = pq_draft
    if pq_ok and pq_group:
        result.curve_id = pq_group
    elif result.x25519:
        result.curve_id = "X25519"
    verify_host = result.host or sni
    if verify_host:
        chain_ok, name_ok, why = await _verify(host, port, verify_host, timeout, xver)
        result.cert_chain_valid = chain_ok
        result.cert_valid = chain_ok and name_ok
        if not result.cert_valid and not result.reason:
            result.reason = why or "the certificate does not verify"
    else:
        result.reason = result.reason or "the certificate has no usable name"
    result.feasible = feasible_of(result)
    if not result.feasible and not result.reason:
        gaps = result.missing()
        result.reason = "not usable: " + ", ".join(gaps) if gaps else "not usable"
    return result


async def _connect_info(host: str, port: int, sni: str, timeout: float, xver: int) -> dict[str, Any]:
    ctx = _context(False, sni, False, True)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    info: dict[str, Any] = {}
    try:
        peer = writer.get_extra_info("peername")
        if peer:
            info["ip"] = str(peer[0])
        if xver:
            local = writer.get_extra_info("sockname") or ("0.0.0.0", 0)
            header = proxy_header(xver, (local[0], local[1]), (peer[0] if peer else host, peer[1] if peer else port))
            if header:
                writer.write(header)
                await writer.drain()
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=sni or None)
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    writer.write(pending)
                    await writer.drain()
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                except asyncio.TimeoutError:
                    raise ScanError("the tls handshake timed out") from None
                if not chunk:
                    raise ScanError("the peer closed during the handshake")
                incoming.write(chunk)
        tail = outgoing.read()
        if tail:
            writer.write(tail)
            await writer.drain()
        info["version"] = obj.version()
        info["alpn"] = obj.selected_alpn_protocol()
        chain = _chain_of(obj)
        if chain:
            try:
                info["cert"] = parse_chain(chain)
            except ScanError as exc:
                info["cert_error"] = str(exc)
        else:
            der = obj.getpeercert(binary_form=True)
            if der:
                try:
                    info["cert"] = parse_certificate(der)
                except ScanError as exc:
                    info["cert_error"] = str(exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass
    return info


def _chain_of(obj: Any) -> list[bytes]:
    for name in ("get_unverified_chain", "get_verified_chain"):
        handler = getattr(obj, name, None)
        if handler is None:
            continue
        try:
            items = handler()
        except (ValueError, ssl.SSLError):
            continue
        out: list[bytes] = []
        for item in items or []:
            if isinstance(item, bytes):
                out.append(item)
                continue
            der = getattr(item, "public_bytes", None)
            if der is None:
                continue
            try:
                out.append(der())
            except (ValueError, TypeError):
                continue
        if out:
            return out
    return []


async def _supports_x25519(host: str, port: int, sni: str, timeout: float, xver: int) -> bool:
    ctx = _context(False, sni, True, False)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return False
    try:
        if xver:
            local = writer.get_extra_info("sockname") or ("0.0.0.0", 0)
            peer = writer.get_extra_info("peername") or (host, port)
            header = proxy_header(xver, (local[0], local[1]), (peer[0], peer[1]))
            if header:
                writer.write(header)
                await writer.drain()
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=sni or None)
        while True:
            try:
                obj.do_handshake()
                return True
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    writer.write(pending)
                    await writer.drain()
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    return False
                incoming.write(chunk)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


async def _verify(host: str, port: int, sni: str, timeout: float, xver: int) -> tuple[bool, bool, str]:
    def run_check(check_hostname: bool) -> tuple[bool, str]:
        ctx = _context(True, sni or host, False, True)
        ctx.check_hostname = check_hostname
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as tls:
                tls.getpeercert()
                return True, ""

    loop = asyncio.get_running_loop()
    try:
        chain_ok, _ = await loop.run_in_executor(None, run_check, False)
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        return False, False, "the chain does not verify: " + str(exc)
    try:
        await loop.run_in_executor(None, run_check, True)
        return chain_ok, True, ""
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        return chain_ok, False, "the certificate name does not match: " + str(exc)


def rank(results: list[ScanResult]) -> list[ScanResult]:
    best: dict[str, ScanResult] = {}
    order: list[str] = []
    for item in results:
        if item is None:
            continue
        existing = best.get(item.target)
        if existing is None:
            best[item.target] = item
            order.append(item.target)
        elif _better(item, existing):
            best[item.target] = item
    out = [best[key] for key in order]
    out.sort(key=lambda r: (not r.feasible, r.latency_ms if r.latency_ms else 10 ** 9))
    return out


def _better(candidate: ScanResult, current: ScanResult) -> bool:
    if candidate.feasible != current.feasible:
        return candidate.feasible
    if candidate.ml_dsa_ready != current.ml_dsa_ready:
        return candidate.ml_dsa_ready
    return candidate.latency_ms > 0 and (current.latency_ms == 0 or candidate.latency_ms < current.latency_ms)


async def scan_targets(
    targets: list[str],
    sni: str = "",
    xver: int = 0,
    allow_private: bool = False,
    concurrency: int = CONCURRENCY,
    candidates: list[str] | None = None,
) -> list[ScanResult]:
    tokens = [item.strip() for item in targets if str(item).strip()]
    if not tokens:
        fallback = DEFAULT_CANDIDATES if candidates is None else candidates
        tokens = [item.strip() for item in fallback if str(item).strip()]
    if not tokens:
        raise ScanError("at least one target is required")
    tasks: list[tuple[str, int, str, float, bool]] = []
    invalid: list[ScanResult] = []
    for token in tokens:
        if len(tasks) >= SCAN_MAX_TOTAL:
            break
        if "/" in token:
            try:
                ips = enumerate_cidr(token)
            except ScanError as exc:
                invalid.append(ScanResult(target=token, reason=str(exc)))
                continue
            for ip in ips:
                if len(tasks) >= SCAN_MAX_TOTAL:
                    break
                tasks.append((ip, 443, "", DISCOVER_TIMEOUT, True))
            continue
        try:
            host, port = split_target(token)
        except ScanError as exc:
            invalid.append(ScanResult(target=token, reason=str(exc)))
            continue
        if _is_ip(host):
            tasks.append((host, port, sni, DISCOVER_TIMEOUT, False))
        else:
            tasks.append((host, port, sni or host, SCAN_TIMEOUT, False))
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    results: list[ScanResult | None] = [None] * len(tasks)

    async def run_one(index: int, host: str, port: int, name: str, timeout: float, bulk: bool) -> None:
        async with sem:
            try:
                item = await probe(host, port, name, timeout, xver, allow_private, bulk)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                item = ScanResult(target=format_target(host, port), host=name or host, port=port, reason="probe failed: " + type(exc).__name__ + ": " + str(exc))
            if bulk and not item.tls_version:
                results[index] = None
            else:
                results[index] = item

    await asyncio.gather(*(run_one(i, *task) for i, task in enumerate(tasks)))
    clean = [item for item in results if item is not None]
    return rank(clean + invalid)


def format_target(host: str, port: int) -> str:
    return "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def best_candidate(results: list[ScanResult]) -> ScanResult | None:
    for item in results:
        if item.feasible:
            return item
    return None
