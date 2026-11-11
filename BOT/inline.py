from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Any

from . import i18n
from .xray import FINGERPRINTS, FLOWS, LOG_LEVELS

TOKEN_LEN = 10
MAX_QUERY = 256
MAX_VALUE = MAX_QUERY - TOKEN_LEN - 1
MAX_REGISTRY = 512
MAX_RESULTS = 50
ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
MARKER = chr(0x1F4DD)
SEPARATOR = chr(0x2063)
MODE_INPUT = "i"
MODE_LIST = "l"
KIND_INPUT = "i"
KIND_OPTION = "o"
KIND_STALE = "s"
TITLE_CYCLE = ("ABXY", "\u2191\u2193\u2190\u2192")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
TOKEN_RE = re.compile(r"^[a-z2-7]{10}$")
PAYLOAD_RE = re.compile(r"^([a-z2-7]{10})([ios])([a-z2-7])([a-z2-7]*)$")


class InlineError(Exception):
    pass


@dataclass(frozen=True)
class Field:
    ident: str
    label_key: str
    hint_key: str
    example: str = ""
    secret: bool = False

    def label(self, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
        return i18n.t(self.label_key, lang)

    def hint(self, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
        return i18n.t(self.hint_key, lang)


FIELDS: dict[str, Field] = {
    "ssh_new_port": Field("ssh_new_port", "FLD_SSH_NEW_PORT", "FLH_SSH_NEW_PORT", "2222"),
    "ssh_pubkey": Field("ssh_pubkey", "FLD_SSH_PUBKEY", "FLH_SSH_PUBKEY", "ssh-ed25519 AAAA"),
    "xr_remark": Field("xr_remark", "FLD_XR_REMARK", "FLH_XR_REMARK", "reality-443"),
    "xr_port": Field("xr_port", "FLD_XR_PORT", "FLH_XR_PORT", "443"),
    "xr_sni": Field("xr_sni", "FLD_XR_SNI", "FLH_XR_SNI", "www.cloudflare.com"),
    "xr_dest": Field("xr_dest", "FLD_XR_DEST", "FLH_XR_DEST", "www.cloudflare.com:443"),
    "xr_short_id": Field("xr_short_id", "FLD_XR_SHORT_ID", "FLH_XR_SHORT_ID", "a1b2c3d4"),
    "xr_spider_x": Field("xr_spider_x", "FLD_XR_SPIDER_X", "FLH_XR_SPIDER_X", "/"),
    "xr_fingerprint": Field("xr_fingerprint", "FLD_XR_FINGERPRINT", "FLH_XR_FINGERPRINT", "firefox"),
    "xr_alpn": Field("xr_alpn", "FLD_XR_ALPN", "FLH_XR_ALPN", "h2,http/1.1"),
    "xr_cert_file": Field("xr_cert_file", "FLD_XR_CERT_FILE", "FLH_XR_CERT_FILE", "/etc/ssl/fullchain.pem"),
    "xr_key_file": Field("xr_key_file", "FLD_XR_KEY_FILE", "FLH_XR_KEY_FILE", "/etc/ssl/key.pem"),
    "xr_path": Field("xr_path", "FLD_XR_PATH", "FLH_XR_PATH", "/obhod"),
    "xr_host_header": Field("xr_host_header", "FLD_XR_HOST_HEADER", "FLH_XR_HOST_HEADER", "example.com"),
    "xr_service": Field("xr_service", "FLD_XR_SERVICE", "FLH_XR_SERVICE", "grpc-obhod"),
    "xr_padding": Field("xr_padding", "FLD_XR_PADDING", "FLH_XR_PADDING", "60-40-0"),
    "xr_mldsa65_seed": Field("xr_mldsa65_seed", "FLD_XR_MLDSA_SEED", "FLH_XR_MLDSA_SEED", "", True),
    "xr_mldsa65_verify": Field("xr_mldsa65_verify", "FLD_XR_MLDSA_VERIFY", "FLH_XR_MLDSA_VERIFY", ""),
    "dbg_target": Field("dbg_target", "FLD_DBG_TARGET", "FLH_DBG_TARGET", "203.0.113.0/24"),
    "dbg_ports": Field("dbg_ports", "FLD_DBG_PORTS", "FLH_DBG_PORTS", "22,80,443"),
    "dbg_chk_target": Field("dbg_chk_target", "FLD_DBG_CHK_TARGET", "FLH_DBG_CHK_TARGET", "31.77.12.187"),
    "dbg_hops": Field("dbg_hops", "FLD_DBG_HOPS", "FLH_DBG_HOPS", "12"),
    "xr_scan_targets": Field("xr_scan_targets", "FLD_XR_SCAN_TARGETS", "FLH_XR_SCAN_TARGETS", ""),
    "xr_scan_manual": Field("xr_scan_manual", "FLD_XR_SCAN_MANUAL", "FLH_XR_SCAN_MANUAL", "1.1.1.1:443"),
    "xr_subnet_cidr": Field("xr_subnet_cidr", "FLD_XR_SUBNET_CIDR", "FLH_XR_SUBNET_CIDR", "185.199.108.0/24"),
    "xr_scan_sni": Field("xr_scan_sni", "FLD_XR_SCAN_SNI", "FLH_XR_SCAN_SNI", "www.google.com"),
    "xr_scan_xver": Field("xr_scan_xver", "FLD_XR_SCAN_XVER", "FLH_XR_SCAN_XVER", "0"),
    "xr_log_level": Field("xr_log_level", "FLD_XR_LOG_LEVEL", "FLH_XR_LOG_LEVEL", "warning"),
    "xr_sub_port": Field("xr_sub_port", "FLD_XR_SUB_PORT", "FLH_XR_SUB_PORT", "2096"),
    "xr_sub_address": Field("xr_sub_address", "FLD_XR_SUB_ADDRESS", "FLH_XR_SUB_ADDRESS", "203.0.113.10"),
    "xr_sub_support": Field("xr_sub_support", "FLD_XR_SUB_SUPPORT", "FLH_XR_SUB_SUPPORT", "https://t.me/your_support"),
    "xr_sub_announce": Field("xr_sub_announce", "FLD_XR_SUB_ANNOUNCE", "FLH_XR_SUB_ANNOUNCE", "the server works, keep the traffic low"),
    "xr_sub_refresh": Field("xr_sub_refresh", "FLD_XR_SUB_REFRESH", "FLH_XR_SUB_REFRESH", "12"),
    "xr_ban_ip": Field("xr_ban_ip", "FLD_XR_BAN_IP", "FLH_XR_BAN_IP", "203.0.113.10"),
    "xr_bantime": Field("xr_bantime", "FLD_XR_BANTIME", "FLH_XR_BANTIME", "30"),
    "xr_ssh_bantime": Field("xr_ssh_bantime", "FLD_XR_SSH_BANTIME", "FLH_XR_SSH_BANTIME", "7d"),
    "xr_ssh_maxretry": Field("xr_ssh_maxretry", "FLD_XR_SSH_MAXRETRY", "FLH_XR_SSH_MAXRETRY", "3"),
    "xr_ignoreip": Field("xr_ignoreip", "FLD_XR_IGNOREIP", "FLH_XR_IGNOREIP", "127.0.0.1/8, ::1"),
    "xr_scan_candidates": Field("xr_scan_candidates", "FLD_XR_SCAN_CANDIDATES", "FLH_XR_SCAN_CANDIDATES", "www.google.com:443"),
    "xr_dns_servers": Field("xr_dns_servers", "FLD_XR_DNS_SERVERS", "FLH_XR_DNS_SERVERS", "1.1.1.1, 8.8.8.8"),
    "xr_api_port": Field("xr_api_port", "FLD_XR_API_PORT", "FLH_XR_API_PORT", "62789"),
    "xr_access_log": Field("xr_access_log", "FLD_XR_ACCESS_LOG", "FLH_XR_ACCESS_LOG", "/var/log/xray/access.log"),
    "xr_tunnel_host": Field("xr_tunnel_host", "FLD_XR_TUNNEL_HOST", "FLH_XR_TUNNEL_HOST", "obhod"),
    "xr_tunnel_key": Field("xr_tunnel_key", "FLD_XR_TUNNEL_KEY", "FLH_XR_TUNNEL_KEY", "tskey-auth-xxxx", True),
    "ft_port": Field("ft_port", "FLD_FT_PORT", "FLH_FT_PORT", "56000"),
    "ft_wg_port": Field("ft_wg_port", "FLD_FT_WG_PORT", "FLH_FT_WG_PORT", "51820"),
    "ft_wg_net": Field("ft_wg_net", "FLD_FT_WG_NET", "FLH_FT_WG_NET", "10.13.13.0/24"),
    "ft_host": Field("ft_host", "FLD_FT_HOST", "FLH_FT_HOST", "203.0.113.10"),
    "ft_connect": Field("ft_connect", "FLD_FT_CONNECT", "FLH_FT_CONNECT", "127.0.0.1:51820"),
    "ft_key": Field("ft_key", "FLD_FT_KEY", "FLH_FT_KEY", "64 hex", True),
    "ft_client": Field("ft_client", "FLD_FT_CLIENT", "FLH_FT_CLIENT", "phone"),
}

OPTIONS: dict[str, tuple[str, ...]] = {
    "ssh_new_port": ("22", "2222", "2200", "2022"),
    "xr_port": ("443", "8443", "2053", "2087"),
    "xr_spider_x": ("/", "/index.html", "/home", "/about"),
    "xr_fingerprint": tuple(FINGERPRINTS),
    "xr_alpn": ("h2,http/1.1", "h2", "http/1.1"),
    "xr_scan_xver": ("0", "1", "2", "3"),
    "xr_log_level": tuple(LOG_LEVELS),
    "xr_bantime": ("30", "60", "300", "600"),
    "xr_ssh_bantime": ("1d", "7d", "4w"),
    "xr_ssh_maxretry": ("3", "5", "10"),
    "xr_sub_port": ("2096", "8080", "8443", "9443"),
    "xr_sub_refresh": ("6", "12", "24"),
    "ft_port": ("56000", "56123", "443", "8443"),
    "ft_wg_port": ("51820", "51821", "51830"),
    "ft_wg_net": ("10.13.13.0/24", "10.44.0.0/24", "10.8.0.0/24"),
    "ft_connect": ("127.0.0.1:51820", "127.0.0.1:51821"),
}

_SECRET: bytes = os.urandom(32)
_REGISTRY: dict[str, tuple[str, str, str]] = {}
_PENDING: list[tuple[str, str, int, str]] = []


def configure(secret: str = "") -> None:
    global _SECRET
    token = str(secret or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", token):
        _SECRET = bytes.fromhex(token)
    elif token:
        _SECRET = hashlib.sha256(token.encode("utf-8")).digest()
    else:
        _SECRET = os.urandom(32)
    _REGISTRY.clear()
    _PENDING.clear()


def remember_pending(token: str, kind: str, index: int, value: str) -> None:
    _PENDING.clear()
    _PENDING.append((str(token or ""), str(kind or KIND_INPUT), int(index), str(value or "")))


def consume_pending() -> tuple[str, str, int, str]:
    if not _PENDING:
        return "", "", -1, ""
    return _PENDING.pop(0)


def field(ident: str) -> Field:
    item = FIELDS.get(ident)
    if item is None:
        raise InlineError("unknown input field: %s" % str(ident)[:32])
    return item


def _digest(text: str) -> str:
    payload = hmac.new(_SECRET, text.encode("utf-8"), hashlib.sha256).digest()
    out = ""
    for byte in payload:
        out += ALPHABET[byte % 32]
        if len(out) >= TOKEN_LEN:
            break
    return out


def normalize_ctx(ctx: object) -> str:
    text = CONTROL.sub("", str(ctx if ctx is not None else "")).strip()
    if text in ("", "-"):
        return ""
    return text[:32]


def token_for(ident: str, ctx: object = "", mode: str = MODE_INPUT) -> str:
    field(ident)
    clean = normalize_ctx(ctx)
    kind = MODE_LIST if str(mode) == MODE_LIST else MODE_INPUT
    token = _digest("%s|%s|%s" % (kind, ident, clean))
    current = _REGISTRY.get(token)
    if current is not None and current[:2] != (ident, clean):
        token = _digest("%s|%s|%s|salt" % (kind, ident, clean))
    _REGISTRY[token] = (ident, clean, kind)
    while len(_REGISTRY) > MAX_REGISTRY:
        _REGISTRY.pop(next(iter(_REGISTRY)))
    return token


def resolve(token: str) -> tuple[str, str, str]:
    return _REGISTRY.get(str(token or "").strip().lower(), ("", "", ""))


def prefill(ident: str, ctx: object = "-") -> str:
    return token_for(ident, ctx, MODE_INPUT) + " "


def list_query(ident: str, ctx: object = "-") -> str:
    return token_for(ident, ctx, MODE_LIST)


def has_options(ident: str) -> bool:
    return bool(OPTIONS.get(ident))


def options(ident: str) -> tuple[str, ...]:
    return tuple(OPTIONS.get(ident, ()))


def marker_text() -> str:
    return MARKER


def title_symbol(length: int, index: int = 0) -> str:
    cycle = TITLE_CYCLE[max(int(index), 0) % len(TITLE_CYCLE)]
    return cycle[max(int(length), 0) % len(cycle)]


def query_body(query: str) -> str:
    raw = CONTROL.sub("", str(query or ""))
    if raw.startswith(" "):
        return raw[1:]
    return raw


def clean_value(ident: str, value: str, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    item = field(ident)
    raw = CONTROL.sub("", str(value or ""))
    text = " ".join(raw.split())
    if ident == "ssh_pubkey":
        text = raw.strip()
    if ident in {"xr_scan_targets", "xr_scan_manual", "xr_scan_candidates", "xr_dns_servers"}:
        text = ", ".join(part.strip() for part in raw.replace(";", ",").split(",") if part.strip())
    if ident == "xr_tunnel_key" and len(text) > MAX_VALUE:
        from .xray import compact_tailscale_input

        text = compact_tailscale_input(text)
    if len(text) > MAX_VALUE:
        raise InlineError(i18n.t("INL_TOO_LONG", lang, label=item.label(lang), limit=MAX_VALUE))
    return text


def article(rid: str, title: str, description: str, text: str, src: str) -> dict:
    ident = rid if len(rid) <= 64 else rid[:64]
    if src == "mt":
        return {
            "_": "inputBotInlineResult",
            "id": ident,
            "type": "article",
            "title": title[:120],
            "description": description[:240],
            "send_message": {"_": "inputBotInlineMessageText", "no_webpage": True, "message": text},
        }
    return {
        "type": "article",
        "id": ident,
        "title": title[:120],
        "description": description[:240],
        "input_message_content": {"message_text": text, "disable_web_page_preview": True},
    }


def inline_kbd(rows_spec: list[list[dict[str, Any]]], src: str) -> Any:
    raw = {"inline_keyboard": [row for row in rows_spec if row]}
    if src == "mt":
        from goygram.types.kbd import kbd_to_tl

        return kbd_to_tl(raw)
    return raw


def html_article(
    rid: str,
    title: str,
    description: str,
    html_text: str,
    src: str,
    reply_markup: list[list[dict[str, Any]]] | None = None,
) -> dict:
    ident = rid if len(rid) <= 64 else rid[:64]
    kbd = inline_kbd(reply_markup, src) if reply_markup else None
    if src == "mt":
        from goygram.sugar import html_to_entities

        plain, ents = html_to_entities(html_text)
        msg: dict[str, object] = {"_": "inputBotInlineMessageText", "no_webpage": True, "message": plain}
        if ents:
            msg["entities"] = ents
        if kbd is not None:
            msg["reply_markup"] = kbd
        return {
            "_": "inputBotInlineResult",
            "id": ident,
            "type": "article",
            "title": title[:120],
            "description": description[:240],
            "send_message": msg,
        }
    out: dict[str, Any] = {
        "type": "article",
        "id": ident,
        "title": title[:120],
        "description": description[:240],
        "input_message_content": {
            "message_text": html_text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        },
    }
    if kbd is not None:
        out["reply_markup"] = kbd
    return out


def rich_article(
    rid: str,
    title: str,
    description: str,
    rich: Any,
    src: str,
    reply_markup: list[list[dict[str, Any]]] | None = None,
) -> dict:
    ident = rid if len(rid) <= 64 else rid[:64]
    kbd = inline_kbd(reply_markup, src) if reply_markup else None
    if src == "mt":
        payload_mt = rich.to_tl() if hasattr(rich, "to_tl") else {"_": "inputRichMessageHTML", "html": str(rich)}
        msg: dict[str, Any] = {
            "_": "inputBotInlineMessageRichMessage",
            "rich_message": payload_mt,
        }
        if kbd is not None:
            msg["reply_markup"] = kbd
        return {
            "_": "inputBotInlineResult",
            "id": ident,
            "type": "article",
            "title": title[:120],
            "description": description[:240],
            "send_message": msg,
        }
    payload_bot = rich.to_msg() if hasattr(rich, "to_msg") else {"html": str(rich)}
    out: dict[str, Any] = {
        "type": "article",
        "id": ident,
        "title": title[:120],
        "description": description[:240],
        "input_message_content": {
            "rich_message": payload_bot,
        },
    }
    if kbd is not None:
        out["reply_markup"] = kbd
    return out


def parse_query(query: str) -> tuple[str, str]:
    raw = CONTROL.sub("", str(query or "")).strip()
    if not raw:
        return "", ""
    parts = raw.split(None, 1)
    token = parts[0].strip().lower()
    value = parts[1].strip() if len(parts) > 1 else ""
    if not TOKEN_RE.match(token):
        return "", raw
    return token, value


def parse_result_id(rid: str) -> tuple[str, str, int]:
    parts = str(rid or "").split(":")
    if len(parts) != 2:
        return "", "", -1
    kind, token = parts
    if kind not in {KIND_INPUT, KIND_OPTION, KIND_STALE}:
        return "", "", -1
    if not TOKEN_RE.match(token):
        return "", "", -1
    return kind, token, -1


def parse_option_id(rid: str) -> tuple[str, str, int]:
    parts = str(rid or "").split(":")
    if len(parts) != 3 or parts[0] != KIND_OPTION:
        return "", "", -1
    token = parts[1]
    if not TOKEN_RE.match(token) or not parts[2].isdigit():
        return "", "", -1
    return KIND_OPTION, token, int(parts[2])


def payload_text(token: str, kind: str, index: int, value: str, src: str = "bot") -> str:
    body = ""
    if kind == KIND_OPTION and 0 <= index < len(ALPHABET):
        return MARKER + SEPARATOR + token + KIND_OPTION + ALPHABET[index]
    if value:
        body = _encode(value)
    return MARKER + SEPARATOR + token + KIND_INPUT + ALPHABET[0] + body


def parse_payload(text: str) -> tuple[str, str, int, str]:
    raw = str(text or "")
    if not raw.startswith(MARKER):
        return "", "", -1, ""
    rest = raw[len(MARKER):]
    if SEPARATOR not in rest:
        return "", "", -1, ""
    code = rest.split(SEPARATOR, 1)[1].strip()
    match = PAYLOAD_RE.match(code)
    if not match:
        return "", "", -1, ""
    token, kind, slot, body = match.groups()
    if kind == KIND_OPTION:
        return token, KIND_OPTION, ALPHABET.index(slot), ""
    if kind == KIND_STALE:
        return "", "", -1, ""
    return token, KIND_INPUT, -1, _decode(body)


def _encode(value: str) -> str:
    data = str(value or "").encode("utf-8")
    out = ""
    for index in range(0, len(data), 5):
        chunk = int.from_bytes(data[index:index + 5].ljust(5, b"\x00"), "big")
        for shift in (35, 30, 25, 20, 15, 10, 5, 0):
            out += ALPHABET[(chunk >> shift) & 31]
    return out


def _decode(body: str) -> str:
    if not body:
        return ""
    body = body.lower()
    if len(body) % 8:
        return ""
    data = b""
    for index in range(0, len(body), 8):
        chunk = 0
        for char in body[index:index + 8]:
            if char not in ALPHABET:
                return ""
            chunk = (chunk << 5) | ALPHABET.index(char)
        data += chunk.to_bytes(5, "big")
    return data.rstrip(b"\x00").decode("utf-8", "replace")


def input_article(token: str, item: Field, value: str, current: str, lang: str, index: int = 0, src: str = "bot") -> dict:
    title = "%s %s" % (item.label(lang), title_symbol(len(value), index))
    if value:
        description = i18n.t("INL_SAVE_DESC", lang)
    elif current:
        description = i18n.t("INL_CURRENT", lang, value=current)
    else:
        description = item.hint(lang)
        if item.example:
            description = i18n.t("INL_HINT_EXAMPLE", lang, hint=description, example=item.example)
    remember_pending(token, KIND_INPUT, -1, value)
    return article("%s:%s" % (KIND_INPUT, token), title, description, MARKER, src)


def option_article(token: str, index: int, value: str, item: Field, lang: str, src: str = "bot") -> dict:
    shown = value or i18n.t("INL_EMPTY_VALUE", lang)
    return article(
        "%s:%s:%d" % (KIND_OPTION, token, index),
        shown,
        i18n.t("INL_OPTION_DESC", lang, label=item.label(lang)),
        MARKER,
        src,
    )


def stale_article(token: str, lang: str, src: str = "bot") -> dict:
    head = token[:TOKEN_LEN] if TOKEN_RE.match(token[:TOKEN_LEN]) else ALPHABET[0] * TOKEN_LEN
    return article("%s:%s" % (KIND_STALE, head), i18n.t("INL_STALE", lang), i18n.t("INL_STALE_HINT", lang), MARKER, src)


def results_for(query: str, src: str = "bot", current: dict[str, str] | None = None, lang: str = i18n.DEFAULT_LANGUAGE) -> list[dict]:
    shown = current or {}
    token, value = parse_query(query)
    if not token:
        return []
    ident, _ctx, mode = resolve(token)
    if not ident:
        return [stale_article(token, lang, src)]
    item = field(ident)
    if len(query_body(query)) > MAX_QUERY:
        err = i18n.t("INL_TOO_LONG", lang, label=item.label(lang), limit=MAX_VALUE)
        return [article("%s:%s" % (KIND_INPUT, token), item.label(lang), err, marker_text(), src)]
    if value:
        try:
            clean = clean_value(ident, value, lang)
        except InlineError as exc:
            return [article("%s:%s" % (KIND_INPUT, token), item.label(lang), str(exc), marker_text(), src)]
        return [input_article(token, item, clean, shown.get(ident, ""), lang, 0, src)]
    if mode == MODE_LIST and has_options(ident):
        head = input_article(token_for(ident, _ctx, MODE_INPUT), item, "", shown.get(ident, ""), lang, 0, src)
        head["description"] = i18n.t("INL_LIST_DESC", lang, label=item.label(lang))
        out = [head]
        for index, option in enumerate(options(ident)):
            out.append(option_article(token, index, option, item, lang, src))
            if len(out) >= MAX_RESULTS:
                break
        return out
    if mode == MODE_LIST:
        head = input_article(token_for(ident, _ctx, MODE_INPUT), item, "", shown.get(ident, ""), lang, 0, src)
        head["description"] = i18n.t("INL_LIST_EMPTY", lang)
        return [head]
    return [input_article(token, item, "", shown.get(ident, ""), lang, 0, src)]


def value_for(kind: str, token: str, index: int, query: str = "", lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    ident, _ctx, _mode = resolve(token)
    if not ident:
        raise InlineError(i18n.t("INL_STALE", lang))
    if kind == KIND_OPTION:
        items = options(ident)
        if index < 0 or index >= len(items):
            raise InlineError(i18n.t("INL_STALE", lang))
        return items[index]
    item = field(ident)
    if len(query_body(query)) > MAX_QUERY:
        raise InlineError(i18n.t("INL_TOO_LONG", lang, label=item.label(lang), limit=MAX_VALUE))
    _token, raw = parse_query(query)
    return clean_value(ident, raw, lang)


def value_from_payload(token: str, kind: str, index: int, body: str, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    ident, _ctx, _mode = resolve(token)
    if not ident:
        raise InlineError(i18n.t("INL_STALE", lang))
    if kind == KIND_OPTION:
        items = options(ident)
        if index < 0 or index >= len(items):
            raise InlineError(i18n.t("INL_STALE", lang))
        return items[index]
    return clean_value(ident, body, lang)
