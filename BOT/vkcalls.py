from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from . import i18n, vkscreens

VK_API_VERSION = "5.199"
VK_API_BASE = "https://api.vk.ru/method/"
VK_HOST_URL = "https://vkhost.github.io/"
TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{20,512}$")
TOKEN_QUERY_RE = re.compile(r"(?:^|[?&#])access_token=([^&#]+)")
CALL_ID_RE = re.compile(r"^[A-Fa-f0-9-]{36}$")
ALLOWED_LINK_HOSTS = {"vk.com", "www.vk.com", "m.vk.com", "vk.ru", "www.vk.ru", "vk.me", "www.vk.me"}
MAX_RESPONSE = 1024 * 1024
MAX_CALLS = 100
AUTH_TTL = 600.0
TOKEN_DELETE_DELAY = 10.0
log = logging.getLogger("obhod.vkcalls")


class VKCallsError(Exception):
    def __init__(self, code: str, vk_code: int = 0) -> None:
        super().__init__(code)
        self.code = str(code or "internal")
        self.vk_code = int(vk_code or 0)


class VKCallsAPIError(VKCallsError):
    pass


class VKCallsNetworkError(VKCallsError):
    pass


def valid_token(value: object) -> bool:
    return bool(TOKEN_RE.fullmatch(str(value or "").strip()))


def extract_vk_token(text: object) -> str:
    value = str(text or "").strip()
    if not value:
        return ""
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        parts = None
    if parts is not None and parts.scheme.lower() in {"http", "https"}:
        for section in (parts.query, parts.fragment):
            fields = urllib.parse.parse_qs(section, keep_blank_values=False, strict_parsing=False)
            candidates = fields.get("access_token", [])
            if candidates and valid_token(candidates[0]):
                return candidates[0]
        match = TOKEN_QUERY_RE.search(value)
        if match:
            candidate = urllib.parse.unquote(match.group(1))
            return candidate if valid_token(candidate) else ""
        return ""
    return value if valid_token(value) else ""


def contains_vk_token_url(text: object) -> bool:
    value = str(text or "").strip()
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    return parts.scheme.lower() in {"http", "https"} and bool(extract_vk_token(value))


def safe_vk_url(value: object) -> str:
    text = str(value or "").strip()
    if len(text) > 2048 or any(char in text for char in "\r\n\x00"):
        return ""
    try:
        parts = urllib.parse.urlsplit(text)
        port = parts.port
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if parts.scheme.lower() != "https" or host not in ALLOWED_LINK_HOSTS or port not in (None, 443):
        return ""
    if parts.username or parts.password or parts.fragment:
        return ""
    return text


def _safe_text(value: object, limit: int = 128) -> str:
    text = str(value or "").strip()
    if any(char in text for char in "\r\n\x00"):
        return ""
    return text[:limit]


def _read_json(path: Path, max_size: int) -> dict[str, Any]:
    if path.is_symlink():
        return {}
    try:
        if path.stat().st_size > max_size:
            return {}
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _atomic_write(path: Path, content: bytes) -> None:
    if path.is_symlink():
        raise VKCallsError("unsafe_storage")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


class VKCallsAPIClient:
    def __init__(self, opener: Callable[..., Any] | None = None, timeout: float = 15.0) -> None:
        self.opener = opener
        self.timeout = max(1.0, min(float(timeout), 30.0))

    @staticmethod
    def _vk_error(payload: Any) -> int:
        if not isinstance(payload, dict):
            return 0
        error = payload.get("error")
        if not isinstance(error, dict):
            return 0
        try:
            return int(error.get("error_code", 0) or 0)
        except (TypeError, ValueError):
            return 0

    async def call(self, token: str, method: str, **params: Any) -> Any:
        if not valid_token(token) or method not in {"users.get", "calls.start", "calls.forceFinish"}:
            raise VKCallsError("bad_request")
        values = {str(key): str(value) for key, value in params.items() if value is not None}
        values["access_token"] = token
        values["v"] = VK_API_VERSION
        body = urllib.parse.urlencode(values).encode("ascii")
        request = urllib.request.Request(
            VK_API_BASE + method,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", "User-Agent": "OBHOD-VKCalls/1"},
            method="POST",
        )
        opener = self.opener or urllib.request.urlopen
        try:
            response = await asyncio.to_thread(opener, request, timeout=self.timeout)
            with response:
                status = int(getattr(response, "status", 200) or 200)
                raw = response.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            try:
                error_body = exc.read(MAX_RESPONSE + 1)
                payload = json.loads(error_body.decode("utf-8")) if len(error_body) <= MAX_RESPONSE else {}
            except Exception:
                payload = {}
            code = self._vk_error(payload)
            log.warning("VK API HTTP failure method=%s status=%s vk_code=%s", method, int(exc.code), code)
            raise VKCallsAPIError("api_http", code or int(exc.code)) from None
        except Exception as exc:
            log.warning("VK API transport failed method=%s type=%s", method, type(exc).__name__)
            raise VKCallsNetworkError("network") from None
        if status != 200 or len(raw) > MAX_RESPONSE:
            log.warning("VK API response rejected method=%s status=%s", method, status)
            raise VKCallsAPIError("api_http", status)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise VKCallsAPIError("bad_response") from None
        if not isinstance(payload, dict):
            raise VKCallsAPIError("bad_response")
        code = self._vk_error(payload)
        if code:
            log.warning("VK API returned an error method=%s vk_code=%s", method, code)
            raise VKCallsAPIError("api_error", code)
        if "response" not in payload:
            raise VKCallsAPIError("bad_response")
        return payload["response"]


class VKCallsService:
    def __init__(self, state_dir: str | os.PathLike[str], api: VKCallsAPIClient | None = None) -> None:
        self.root = Path(state_dir)
        self.token_path = self.root / "vk_calls.token"
        self.calls_path = self.root / "vk_calls.json"
        self.api = api or VKCallsAPIClient()
        self.token = self._load_token()
        self.user_id = 0
        self._calls = self._load_calls()
        self._create_lock = asyncio.Lock()
        self._finish_lock = asyncio.Lock()

    def _load_token(self) -> str:
        if self.token_path.is_symlink():
            return ""
        try:
            if self.token_path.stat().st_size > 1024:
                return ""
            descriptor = os.open(str(self.token_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                value = stream.read(1025).strip()
        except OSError:
            return ""
        return value if valid_token(value) else ""

    def _normalize_call(self, raw: Any) -> dict[str, Any] | None:
        if not isinstance(raw, dict):
            return None
        call_id = _safe_text(raw.get("call_id"), 64)
        join_link = safe_vk_url(raw.get("join_link"))
        if not CALL_ID_RE.fullmatch(call_id):
            return None
        credentials = raw.get("short_credentials") if isinstance(raw.get("short_credentials"), dict) else {}
        created = raw.get("created_at", 0)
        try:
            created_at = max(0, min(int(created), int(time.time()) + 86400))
        except (ValueError, TypeError, OverflowError):
            created_at = 0
        return {
            "call_id": call_id,
            "join_link": join_link,
            "short_credentials": {
                "id": _safe_text(credentials.get("id")),
                "password": _safe_text(credentials.get("password")),
                "link_with_password": safe_vk_url(credentials.get("link_with_password")),
            },
            "created_at": created_at,
        }

    def _load_calls(self) -> dict[str, dict[str, Any]]:
        data = _read_json(self.calls_path, 1024 * 1024)
        source = data.get("calls") if isinstance(data.get("calls"), dict) else {}
        calls = {}
        for call_id, raw in list(source.items())[-MAX_CALLS:]:
            record = self._normalize_call(raw)
            if record and str(call_id) == record["call_id"]:
                calls[record["call_id"]] = record
        return calls

    def _save_calls(self) -> None:
        payload = json.dumps({"version": 1, "calls": self._calls}, ensure_ascii=True, sort_keys=True).encode("utf-8")
        _atomic_write(self.calls_path, payload)

    def _set_token(self, token: str) -> None:
        if not valid_token(token):
            raise VKCallsError("bad_token")
        _atomic_write(self.token_path, (token + "\n").encode("ascii"))
        self.token = token
        self.user_id = 0

    def clear_token(self) -> None:
        if self.token_path.is_symlink():
            raise VKCallsError("unsafe_storage")
        try:
            self.token_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            raise VKCallsError("storage") from None
        self.token = ""
        self.user_id = 0

    async def authorize(self, raw: object) -> int:
        token = extract_vk_token(raw)
        if not token:
            raise VKCallsError("bad_token")
        result = await self.api.call(token, "users.get")
        if not isinstance(result, list) or not result or not isinstance(result[0], dict):
            raise VKCallsAPIError("bad_response")
        try:
            user_id = int(result[0].get("id", 0) or 0)
        except (ValueError, TypeError, OverflowError):
            user_id = 0
        if user_id <= 0:
            raise VKCallsAPIError("bad_response")
        self._set_token(token)
        self.user_id = user_id
        return user_id

    async def check_token(self) -> int:
        if not self.token:
            raise VKCallsError("not_authorized")
        result = await self.api.call(self.token, "users.get")
        if not isinstance(result, list) or not result or not isinstance(result[0], dict):
            raise VKCallsAPIError("bad_response")
        try:
            user_id = int(result[0].get("id", 0) or 0)
        except (ValueError, TypeError, OverflowError):
            user_id = 0
        if user_id <= 0:
            raise VKCallsAPIError("bad_response")
        self.user_id = user_id
        return user_id

    async def ensure_authorized(self) -> int:
        if not self.token:
            raise VKCallsError("not_authorized")
        if self.user_id > 0:
            return self.user_id
        return await self.check_token()

    async def create_call(self) -> dict[str, Any]:
        async with self._create_lock:
            await self.ensure_authorized()
            response = await self.api.call(self.token, "calls.start")
            if not isinstance(response, dict):
                raise VKCallsAPIError("bad_response")
            record = self._normalize_call({
                "call_id": response.get("call_id"),
                "join_link": response.get("join_link"),
                "short_credentials": response.get("short_credentials"),
                "created_at": int(time.time()),
            })
            if record is None:
                raise VKCallsAPIError("bad_response")
            self._calls[record["call_id"]] = record
            if len(self._calls) > MAX_CALLS:
                oldest = sorted(self._calls, key=lambda key: self._calls[key].get("created_at", 0))
                for call_id in oldest[:len(self._calls) - MAX_CALLS]:
                    self._calls.pop(call_id, None)
            self._save_calls()
            return dict(record)

    def active_calls(self) -> list[dict[str, Any]]:
        return [dict(item) for item in sorted(self._calls.values(), key=lambda call: call.get("created_at", 0), reverse=True)]

    def get_call(self, call_id: object) -> dict[str, Any] | None:
        key = _safe_text(call_id, 64)
        if not CALL_ID_RE.fullmatch(key):
            return None
        record = self._calls.get(key)
        return dict(record) if record else None

    async def finish_call(self, call_id: object) -> bool:
        key = _safe_text(call_id, 64)
        if not CALL_ID_RE.fullmatch(key):
            raise VKCallsError("call_not_found")
        async with self._finish_lock:
            if key not in self._calls:
                return True
            await self.ensure_authorized()
            response = await self.api.call(self.token, "calls.forceFinish", call_id=key)
            if response not in (1, True):
                return False
            self._calls.pop(key, None)
            self._save_calls()
            return True

    def latest_join_link(self) -> str:
        for record in self.active_calls():
            if record.get("join_link"):
                return str(record["join_link"])
        return ""


class VKCallsPanel:
    def __init__(self, bot: Any, service: VKCallsService | None = None) -> None:
        self.bot = bot
        self.service = service or VKCallsService(getattr(bot.cfg, "state_dir", "/var/lib/obhod"))
        self.auth_pending: dict[int, float] = {}
        self.last_create = 0.0

    def tr(self):
        return i18n.translator(getattr(self.bot.state, "language", i18n.DEFAULT_LANGUAGE))

    def contains_vk_token_url(self, text: object) -> bool:
        return contains_vk_token_url(text)

    async def auth_link(self) -> str:
        app = getattr(self.bot, "app", None)
        if app is None:
            return ""
        username = ""
        getter = getattr(app, "get_me", None)
        if callable(getter):
            try:
                info = await getter()
                if isinstance(info, dict):
                    username = str(info.get("username", "") or "")
            except Exception:
                username = ""
        if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", username):
            return ""
        return "https://t.me/%s?start=vk_auth" % username

    async def auth_screen(self, chat_id: int, msg_id: int, notice: str = "", error: str = "") -> None:
        t = self.tr()
        deeplink = await self.auth_link()
        await self.bot.render(chat_id, msg_id, vkscreens.auth_screen(
            lang=t.language,
            authorized=bool(self.service.token),
            user_id=self.service.user_id,
            notice=notice,
            error=error,
            deeplink=deeplink,
        ))

    async def begin_auth(self, chat_id: int, msg_id: int) -> None:
        if int(chat_id or 0) != int(self.bot.admin_id or 0) or not chat_id:
            await self.bot.render(chat_id, msg_id, vkscreens.home_screen(self.tr().language, error=self.tr()("VKCALLS_PRIVATE_AUTH")))
            return
        self.auth_pending[int(self.bot.admin_id)] = time.monotonic() + AUTH_TTL
        await self.auth_screen(chat_id, msg_id)

    async def delete_token_message(self, chat_id: int, msg_id: int, immediate: bool = False) -> None:
        await asyncio.sleep(0.0 if immediate else TOKEN_DELETE_DELAY)
        await self.bot.drop_marker(chat_id, msg_id)

    async def schedule_token_delete(self, chat_id: int, msg_id: int, immediate: bool = False) -> None:
        if msg_id:
            await self.bot.track(self.delete_token_message(chat_id, msg_id, immediate), "vk-token-delete")

    async def handle_message(self, evt: object, text: str) -> bool:
        who = int(getattr(evt, "from_id", 0) or 0)
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        msg_id = int(getattr(evt, "msg_id", 0) or getattr(evt, "id", 0) or 0)
        pending_until = self.auth_pending.get(who, 0.0)
        pending = pending_until > time.monotonic()
        if pending_until and not pending:
            self.auth_pending.pop(who, None)
        if pending and str(text or "").strip().lower().startswith("tskey-"):
            return False
        token = extract_vk_token(text) if pending else ""
        if not pending:
            try:
                parts = urllib.parse.urlsplit(str(text or "").strip())
            except ValueError:
                parts = None
            if parts is not None and parts.scheme.lower() in {"http", "https"}:
                token = extract_vk_token(text)
            if not token:
                return False
        if pending:
            if chat_id != int(self.bot.admin_id or 0):
                await self.schedule_token_delete(chat_id, msg_id, immediate=True)
                await self.bot.send(chat_id, vkscreens.home_screen(self.tr().language, error=self.tr()("VKCALLS_PRIVATE_AUTH")))
                return True
            await self.schedule_token_delete(chat_id, msg_id)
            if not token:
                await self.bot.send(chat_id, vkscreens.home_screen(self.tr().language, error=self.tr()("VKCALLS_BAD_TOKEN")))
                return True
            if self.bot.is_busy():
                await self.bot.send(chat_id, vkscreens.home_screen(self.tr().language, error=self.tr()("TOAST_BUSY")))
                return True
            try:
                user_id = await self.service.authorize(token)
            except VKCallsError as exc:
                await self.bot.send(chat_id, vkscreens.home_screen(self.tr().language, error=self.error_text(exc)))
                return True
            self.auth_pending.pop(who, None)
            await self.bot.send(chat_id, vkscreens.home_screen(self.tr().language, notice=self.tr()("VKCALLS_AUTH_OK", user_id=user_id), authorized=True))
            return True
        if token:
            await self.schedule_token_delete(chat_id, msg_id, immediate=chat_id != int(self.bot.admin_id or 0))
            await self.bot.send(chat_id, vkscreens.home_screen(self.tr().language, error=self.tr()("VKCALLS_AUTH_REQUIRED")))
            return True
        return False

    def error_text(self, exc: VKCallsError) -> str:
        t = self.tr()
        code = int(getattr(exc, "vk_code", 0) or 0)
        if code == 5:
            return t("VKCALLS_TOKEN_EXPIRED")
        if code in {6, 9, 29}:
            return t("VKCALLS_RATE_LIMIT")
        if code == 14:
            return t("VKCALLS_CAPTCHA")
        key = "VKCALLS_ERR_%s" % exc.code.upper()
        if i18n.has_key(key, t.language):
            return t(key)
        if code:
            return t("VKCALLS_API_CODE", code=code)
        return t("VKCALLS_API_FAILED")

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        t = self.tr()
        if int(chat_id or 0) != int(self.bot.admin_id or 0):
            await self.bot.render(chat_id, msg_id, vkscreens.home_screen(t.language, error=t("VKCALLS_PRIVATE_AUTH")))
            return
        parts = str(data or "").split(":")
        action = parts[1] if len(parts) > 1 else "home"
        if action in {"", "home"}:
            await self.bot.render(chat_id, msg_id, vkscreens.home_screen(t.language, authorized=bool(self.service.token), user_id=self.service.user_id))
            return
        if action == "auth":
            subaction = parts[2] if len(parts) > 2 else ""
            if subaction == "clear":
                try:
                    self.service.clear_token()
                except VKCallsError as exc:
                    await self.auth_screen(chat_id, msg_id, error=self.error_text(exc))
                    return
                await self.auth_screen(chat_id, msg_id, notice=t("VKCALLS_AUTH_CLEARED"))
                return
            if subaction == "check":
                try:
                    user_id = await self.service.check_token()
                except VKCallsError as exc:
                    await self.auth_screen(chat_id, msg_id, error=self.error_text(exc))
                    return
                await self.auth_screen(chat_id, msg_id, notice=t("VKCALLS_TOKEN_VALID", user_id=user_id))
                return
            await self.begin_auth(chat_id, msg_id)
            return
        if action in {"active", "calls"}:
            await self.bot.render(chat_id, msg_id, vkscreens.calls_screen(t.language, self.service.active_calls()))
            return
        if action == "create":
            now = time.monotonic()
            if now - self.last_create < 3.0:
                await self.bot.render(chat_id, msg_id, vkscreens.home_screen(t.language, authorized=bool(self.service.token), error=t("VKCALLS_COOLDOWN")))
                return
            self.last_create = now
            await self.bot.render(chat_id, msg_id, vkscreens.busy_screen(t.language, t("VKCALLS_CREATING")))
            try:
                record = await self.service.create_call()
            except VKCallsError as exc:
                await self.bot.render(chat_id, msg_id, vkscreens.home_screen(t.language, authorized=bool(self.service.token), error=self.error_text(exc)))
                return
            await self.bot.render(chat_id, msg_id, vkscreens.call_screen(t.language, record))
            return
        if action == "detail" and len(parts) > 2:
            record = self.service.get_call(parts[2])
            await self.bot.render(chat_id, msg_id, vkscreens.detail_screen(t.language, record))
            return
        if action == "finish" and len(parts) > 2:
            call_id = parts[2]
            await self.bot.render(chat_id, msg_id, vkscreens.busy_screen(t.language, t("VKCALLS_FINISHING")))
            try:
                finished = await self.service.finish_call(call_id)
            except VKCallsError as exc:
                await self.bot.render(chat_id, msg_id, vkscreens.detail_screen(t.language, self.service.get_call(call_id), error=self.error_text(exc)))
                return
            if not finished:
                await self.bot.render(chat_id, msg_id, vkscreens.detail_screen(t.language, self.service.get_call(call_id), error=t("VKCALLS_API_FAILED")))
                return
            await self.bot.render(chat_id, msg_id, vkscreens.home_screen(t.language, authorized=bool(self.service.token), notice=t("VKCALLS_FINISHED", call_id=call_id)))
            return
        if action == "authlink":
            await self.auth_screen(chat_id, msg_id)
            return
        await self.bot.render(chat_id, msg_id, vkscreens.home_screen(t.language, error=t("HOME_NOTICE_UNKNOWN")))

    async def deep_auth_command(self, chat_id: int, text: str) -> bool:
        parts = str(text or "").strip().split()
        if len(parts) < 2 or parts[1].split("@", 1)[0] != "vk_auth":
            return False
        if chat_id != int(self.bot.admin_id or 0):
            await self.bot.send(chat_id, vkscreens.home_screen(self.tr().language, error=self.tr()("VKCALLS_PRIVATE_AUTH")))
            return True
        self.auth_pending[int(self.bot.admin_id)] = time.monotonic() + AUTH_TTL
        await self.bot.send(chat_id, vkscreens.auth_screen(self.tr().language, authorized=bool(self.service.token), user_id=self.service.user_id, deeplink=await self.auth_link()))
        return True

    def latest_join_link(self) -> str:
        return self.service.latest_join_link()
