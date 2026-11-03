from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import socket
import time
from typing import Any

from goygram import GoyGram

from . import commands, cores, dscreens, ftscreens, i18n, inline, notify, screens, ui, xscreens
from .config import Config, ConfigError
from .dbg import DebugPanel
from .freeturn import FtControl, FtError
from .ftpanel import FtPanel
from .guard import DEFAULT_BANTIME, BanState, GuardClient, SshState, honey_events
from .models import ModelError, valid_port
from .panel import PanelError, XrayPanel
from .audit import Audit
from .seclog import SecurityLog
from .ratelimit import CALLBACK_LIMIT, CLAIM_LIMIT, EXPENSIVE_LIMIT, INLINE_LIMIT, MESSAGE_LIMIT, Limiter
from .shell import LocalShell, ShellError
from .store import State, Store
from .ui import button, code, muted, quote, row, screen
from .update import UpdateError, Updater
from .xrayrpc import XrayControl, XrayError as RpcError
from .xray import API_PORT, SUB_PORT

log = logging.getLogger("obhod.app")

DRAFT_ID = 1
CLAIM_WINDOW = 900.0
INLINE_DUPLICATE_WINDOW = 8.0
BUSY_QUIET = 5.0
BUSY_TTL = 900.0
RENDER_QUIET = 5.0
LOADING_MARKS = ("xr:", "ft:", "dbg:", "upd:", "fb:", "sshd:", "ssh:")
LOADING_SKIP = ("nav:", "lang:", "set:", "dbg:home", "dbg:emoji", "dbg:info", "ft:home", "xr:home")
RENDER_CACHE = 64
DENY_LIMIT = 1
DENY_WINDOW = 60.0
NAVIGATE_LIMIT = 40
HOME_QUIET = 3.0
RATE_QUIET = 10.0
UPDATE_QUIET = 10.0


def public_address() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return ""
    try:
        sock.settimeout(1.0)
        sock.connect(("198.51.100.1", 53))
        found = sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()
    try:
        parsed = ipaddress.ip_address(found)
    except ValueError:
        return ""
    if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified or parsed.is_multicast:
        return ""
    return str(parsed)


class Bot:
    def __init__(
        self,
        cfg: Config,
        control: XrayControl | None = None,
        guard: GuardClient | None = None,
        shell: LocalShell | None = None,
        updater: Updater | None = None,
    ) -> None:
        self.cfg = cfg
        self.store = Store(cfg.state_dir / "state.json")
        self.state: State = self.store.load()
        self.control = control or XrayControl(shell=shell)
        self.guard = guard or GuardClient(self.control)
        self.xray = XrayPanel(self, self.control)
        self.freeturn = FtPanel(self, FtControl(shell=shell))
        self.debug = DebugPanel(self)
        self.updater = updater or Updater(shell=shell, state_dir=cfg.state_dir)
        self.update_info: dict[str, object] = {}
        self.update_result: dict[str, object] = {}
        self.update_notice: dict[str, object] = {}
        self.update_error = ""
        self.app: GoyGram | None = None
        self.ban: BanState | None = None
        self.sshd: SshState | None = None
        self.busy = False
        self.busy_until = 0.0
        self.render_seen: dict[tuple[int, int], tuple[str, float]] = {}
        self.quiet_marks: dict[str, float] = {}
        self.started_at = time.monotonic()
        self.limiter = Limiter()
        self.audit = Audit(sink=SecurityLog())
        self.message_limit = MESSAGE_LIMIT
        self.callback_limit = CALLBACK_LIMIT
        self.expensive_limit = EXPENSIVE_LIMIT
        self.inline_limit = INLINE_LIMIT
        self.inline_seen: dict[tuple[str, str, str], float] = {}
        self.subs_digest = ""
        self.subs_failed = 0.0
        self.notify = notify.Centre(notify.Settings.from_dict(self.state.notify))
        self.notify_task: Any = None
        self.notify_seen_bans: set[str] = set()
        self.notify_seen_ssh: set[str] = set()
        self.notify_poll_error = ""
        self.notify_poll_at = 0.0
        ui.use_icons(self.emoji_enabled)
        self.seed_ports()

    def seed_ports(self) -> None:
        sub = int(getattr(self.cfg, "sub_port", 0) or 0)
        api = int(getattr(self.cfg, "api_port", 0) or 0)
        changed = False
        if 1 <= sub <= 65535 and int(self.state.sub_port) == SUB_PORT and sub != SUB_PORT:
            self.state.sub_port = sub
            self.state.xray.sub_port = sub
            changed = True
        if 1 <= api <= 65535 and int(self.state.xray.api_port) == API_PORT and api != API_PORT:
            self.state.xray.api_port = api
            changed = True
        if changed:
            self.save()

    def is_busy(self) -> bool:
        if not self.busy:
            return False
        return self.busy_until == 0.0 or time.monotonic() < self.busy_until

    def busy_begin(self) -> bool:
        if self.is_busy():
            return False
        self.busy = True
        self.busy_until = time.monotonic() + BUSY_TTL
        return True

    def busy_end(self) -> None:
        self.busy = False
        self.busy_until = 0.0

    def quiet(self, name: str, span: float) -> bool:
        now = time.monotonic()
        last = self.quiet_marks.get(name, 0.0)
        if last and now - last < span:
            return False
        self.quiet_marks[name] = now
        if len(self.quiet_marks) > RENDER_CACHE * 4:
            keep = sorted(self.quiet_marks.items(), key=lambda pair: pair[1])[-RENDER_CACHE:]
            self.quiet_marks = dict(keep)
        return True

    def render_digest(self, rich: object) -> str:
        dump = getattr(rich, "to_html", None)
        try:
            body = dump() if callable(dump) else str(rich)
        except Exception:
            body = ""
        return hashlib.sha256(str(body).encode("utf-8", "replace")).hexdigest()

    @property
    def admin_id(self) -> int:
        return int(self.cfg.admin_id or self.state.admin_id or 0)

    @property
    def language(self) -> str:
        return i18n.normalize(self.state.language)

    @property
    def emoji_enabled(self) -> bool:
        if self.state.emoji is None:
            return bool(getattr(self.cfg, "emoji_default", False))
        return bool(self.state.emoji)

    def apply_emoji(self) -> bool:
        ui.use_icons(self.emoji_enabled)
        return self.emoji_enabled

    def claim_open(self) -> bool:
        if self.admin_id:
            return False
        if self.state.admin_id:
            return False
        reached = getattr(self, "started_at", 0.0)
        if not reached:
            return False
        return time.monotonic() - reached <= CLAIM_WINDOW

    def tr(self) -> i18n.Translator:
        return i18n.translator(self.language)

    def address(self) -> str:
        return self.state.xray.sub_address or public_address() or ""

    def save(self) -> None:
        self.store.save(self.state)

    def subs_payload(self) -> dict[str, Any]:
        state = self.state.xray
        extra: list[str] = []
        freeturn = getattr(self, "freeturn", None)
        if freeturn is not None:
            try:
                extra = freeturn.state.link_values()
            except Exception:
                extra = []
        return state.sub_registry(self.address(), extra)

    async def subs_sync(self, force: bool = False) -> bool:
        state = self.state.xray
        if not state.sub_enabled and not force:
            return False
        domain = state.tunnel_host if state.tunnel_enabled else ""
        if not domain:
            return False
        try:
            registry = self.subs_payload()
        except Exception as exc:
            log.debug("the subscription registry was skipped: %s", exc)
            return False
        digest = hashlib.sha256(json.dumps(registry, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        if not force and digest == self.subs_digest:
            return False
        try:
            await self.control.sub_sync(self.state.ssh, registry, state.sub_port, domain)
        except Exception as exc:
            self.subs_failed = time.monotonic()
            log.warning("the subscription registry was not pushed: %s", exc)
            return False
        self.subs_digest = digest
        return True

    def view(self, notice: str = "", error: str = "", busy: str = "") -> screens.View:
        notice = notice or self.update_notice_text()
        return screens.View(
            state=self.state,
            core=dict(self.xray.core),
            ban=self.ban,
            sshd=self.sshd,
            notice=notice,
            error=error,
            busy=busy,
            lang=self.language,
            emoji_default=bool(getattr(self.cfg, "emoji_default", False)),
            ft_clients=len(getattr(self.freeturn, "clients", []) or []),
        )

    def ban_view(self, notice: str = "", error: str = "") -> screens.View:
        return self.view(notice=notice, error=error)

    def sshd_view(self, notice: str = "", error: str = "") -> screens.View:
        return self.view(notice=notice, error=error)

    async def boot(self) -> GoyGram:
        app = GoyGram(
            bot_token=self.cfg.bot_token,
            api_id=self.cfg.api_id,
            api_hash=self.cfg.api_hash,
            session_name=self.cfg.session_name,
            default_transport="mtproto",
            intake="mtproto",
            app_name="OBHOD",
            app_version="3.0",
            device_model="desktop",
            system_version="linux",
            mt_host=self.cfg.dc_host,
            mt_port=self.cfg.dc_port,
        )
        app.on_msg(fn=self.on_message)
        app.on_cb(fn=self.on_callback)
        app.on_inline(fn=self.on_inline)
        app.on_update(fn=self.on_chosen)
        self.app = app
        return app

    async def notify_start(self) -> None:
        if self.notify_task is not None and not self.notify_task.done():
            return
        self.notify_task = asyncio.create_task(self.notify_loop())

    async def notify_loop(self, span: float = 120.0) -> None:
        while True:
            try:
                await asyncio.sleep(span)
                await self.notify_poll()
            except asyncio.CancelledError:
                return
            except Exception as exc:
                self.notify_poll_error = type(exc).__name__
                log.debug("the notification poll failed: %s", exc)

    async def notify_send(self, event: Any, test: bool = False) -> bool:
        target = notify.delivery_target(self)
        if not target:
            return False
        if test:
            t = self.tr()
            payload = dscreens.notify_message(notify.Event(notify.KIND_CORE, address="0.0.0.0", detail=t("NTF_TEST_TITLE")), t)
        else:
            payload = dscreens.notify_message(event, self.tr())
        try:
            await self.send(target, payload)
        except Exception as exc:
            log.debug("the notification was not delivered: %s", exc)
            return False
        return True

    async def notify_poll(self) -> list[Any]:
        cfg = getattr(self.state, "ssh", None)
        raised: list[Any] = []
        try:
            events = await honey_events(self.guard, cfg, 200)
        except Exception as exc:
            self.notify_poll_error = type(exc).__name__
            events = {}
        for obs in notify.parse_events(events):
            raised.extend(self.notify.observe(obs))
        try:
            ban = await self.guard.status(cfg, int(getattr(self.state.xray, "sub_port", 0) or 0))
        except Exception as exc:
            self.notify_poll_error = type(exc).__name__
            ban = None
        if ban is not None:
            for address in ban.ssh_banned:
                if address not in self.notify_seen_ssh:
                    self.notify_seen_ssh.add(address)
                    raised.extend(self.notify.force(notify.KIND_SSH, address, "banned"))
            for address in ban.banned + ban.honey_banned + ban.sub_banned:
                if address not in self.notify_seen_bans:
                    self.notify_seen_bans.add(address)
                    raised.extend(self.notify.force(notify.KIND_BAN, address, "jail"))
        if len(self.notify_seen_bans) > 4096:
            self.notify_seen_bans = set(list(self.notify_seen_bans)[-2048:])
        if len(self.notify_seen_ssh) > 4096:
            self.notify_seen_ssh = set(list(self.notify_seen_ssh)[-2048:])
        self.notify_poll_at = time.time()
        for event in raised:
            await self.notify_send(event)
        self.notify.drain()
        return raised

    async def run(self) -> None:
        await self.verify_update()
        app = await self.boot()
        try:
            await self.register_commands()
        except Exception as exc:
            log.warning("the command menu was skipped: %s", exc)
        try:
            await self.notify_start()
        except Exception as exc:
            log.warning("the notification poller was skipped: %s", exc)
        await app.run()

    async def verify_update(self) -> None:
        try:
            self.update_notice = await self.updater.verify()
        except (UpdateError, ShellError) as exc:
            log.warning("the update check failed: %s", getattr(exc, "message", exc))
            self.update_notice = {}
        except Exception as exc:
            log.debug("the update check was skipped: %s", exc)
            self.update_notice = {}

    def update_notice_text(self) -> str:
        data = self.update_notice
        if not data:
            return ""
        self.update_notice = {}
        t = self.tr()
        commit = str(data.get("commit") or data.get("to") or "")[:12]
        if data.get("healthy"):
            return t("UPD_NOTICE_VERIFIED", commit=commit, state=str(data.get("state") or "active"))
        return t("UPD_NOTICE_BROKEN", commit=commit)

    async def send(self, chat_id: int, rich: object) -> None:
        if self.app is None:
            return
        await self.app.send_rich(chat_id, rich, via="mt")

    async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
        if self.app is None:
            return
        key = (int(chat_id or 0), int(msg_id or 0))
        digest = self.render_digest(rich)
        now = time.monotonic()
        last = self.render_seen.get(key)
        if last and last[0] == digest and now - last[1] < RENDER_QUIET:
            return
        self.render_seen[key] = (digest, now)
        if len(self.render_seen) > RENDER_CACHE:
            extra = len(self.render_seen) - RENDER_CACHE
            for item in sorted(self.render_seen.items(), key=lambda pair: pair[1][1])[:extra]:
                self.render_seen.pop(item[0], None)
        if msg_id:
            try:
                await self.app.edit_rich(chat_id, msg_id, rich, via="mt")
                return
            except Exception as exc:
                log.warning("edit failed: %s", exc)
        if not msg_id or self.quiet("send:%d" % key[0], RENDER_QUIET):
            await self.send(chat_id, rich)

    async def toast(self, evt: object, text: str, alert: bool = False) -> None:
        try:
            await evt.answer(text or self.tr()("TOAST_DONE"), alert=alert)
        except Exception as exc:
            log.debug("answer failed: %s", exc)

    def private_chat(self, evt: object) -> bool:
        who = int(getattr(evt, "from_id", 0) or 0)
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        return who > 0 and chat_id == who

    def allowed(self, who: int, scope: str = "any", limit: int = 0, window: float = 0.0) -> bool:
        return self.limiter.allow(str(who), scope=scope, limit=limit, window=window)

    async def guard_admin(self, evt: object) -> bool:
        who = int(getattr(evt, "from_id", 0) or 0)
        bot_id = str(self.cfg.bot_token or "").partition(":")[0]
        raw = getattr(evt, "raw", None)
        if (not who or (bot_id.isdigit() and who == int(bot_id))
                or getattr(evt, "outgoing", False) or getattr(evt, "is_outgoing", False)
                or (isinstance(raw, dict) and raw.get("out"))):
            return False
        if self.admin_id == 0:
            if who > 0 and self.claim_open() and self.private_chat(evt) and self.allowed(who, "claim", CLAIM_LIMIT, 60.0):
                self.state.admin_id = who
                self.save()
                log.info("admin claimed: %s", who)
                return True
        elif who == self.admin_id:
            return True
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        log.warning("blocked non-admin: who=%s, chat_id=%s", who, chat_id)
        if self.allowed(str(chat_id or who), "deny", DENY_LIMIT, DENY_WINDOW):
            await self.send(chat_id, screens.denied(self.language))
        return False

    def input_values(self) -> dict[str, str]:
        state = self.state
        values = {
            "ssh_new_port": str(self.sshd.ports[0] if self.sshd and self.sshd.ports else state.ssh.port),
            "xr_log_level": state.xray.log_level,
            "xr_scan_targets": ", ".join(state.xray.scan_targets),
            "xr_scan_manual": "",
            "xr_sub_port": str(state.xray.sub_port),
            "xr_sub_address": state.xray.sub_address,
            "xr_bantime": str(state.xray.fail2ban_bantime),
            "xr_ssh_bantime": state.xray.fail2ban_ssh_bantime,
            "xr_ssh_maxretry": str(state.xray.fail2ban_ssh_maxretry),
            "xr_ignoreip": state.xray.fail2ban_ignoreip,
            "xr_ban_ip": "",
            "ft_port": str(state.freeturn.config.listen_port),
            "ft_wg_port": str(state.freeturn.config.wg_port),
            "ft_wg_net": state.freeturn.config.wg_net,
            "ft_host": state.freeturn.config.host or state.xray.sub_address,
            "ft_key": "",
            "ft_client": "",
        }
        if state.xray.inbounds:
            inbound = state.xray.inbounds[0]
            values["xr_remark"] = inbound.remark
            values["xr_port"] = str(inbound.port)
            values["xr_sni"] = inbound.sni
            values["xr_dest"] = inbound.dest
            values["xr_fingerprint"] = inbound.fingerprint
        return values

    async def on_inline(self, evt: object) -> None:
        query = str(getattr(evt, "query", "") or "")
        src = str(getattr(evt, "src", "mt") or "mt")
        who = int(getattr(evt, "from_id", 0) or 0)
        results: list[dict] = []
        allowed = who > 0 and who == self.admin_id and self.allowed(who, "inline", self.inline_limit, 60.0)
        if allowed:
            results = inline.results_for(query, src=src, current=self.input_values(), lang=self.language)
        try:
            await evt.answer(results=results, cache_time=0, is_personal=True)
        except Exception as exc:
            log.warning("inline answer failed: %s", exc)

    async def on_chosen(self, evt: object) -> None:
        if str(getattr(evt, "update_type", "") or "") != "chosen_inline_result":
            return
        raw = getattr(evt, "raw", None)
        payload = raw.get("chosen_inline_result") if isinstance(raw, dict) else None
        payload = payload if isinstance(payload, dict) else {}
        who = int(((payload.get("from") or {}).get("id")) or getattr(evt, "from_id", 0) or 0)
        if not self.admin_id or who != self.admin_id:
            log.warning("a foreign user picked an inline result: %s", who)
            return
        if not self.allowed(who, "inline", self.inline_limit, 60.0):
            return
        rid = str(payload.get("result_id", "") or "")
        query = str(payload.get("query", "") or "")
        kind, token, index = inline.parse_option_id(rid)
        if not kind:
            kind, token, index = inline.parse_result_id(rid)
        if not kind:
            log.warning("an inline result id is not recognised: %s", rid[:48])
            return
        try:
            value = inline.value_for(kind, token, index, query, self.language)
        except inline.InlineError as exc:
            log.warning("the inline value was rejected: %s", exc)
            return
        await self.apply_inline_value(token, kind, value, index, "chosen")

    async def apply_inline_value(self, token: str, kind: str, value: str, index: int, source: str) -> None:
        ident, ctx, _mode = inline.resolve(token)
        if not ident:
            log.warning("an inline token is not registered any more")
            return
        if self.recent_inline(ident, ctx, value):
            log.debug("a duplicate inline value was skipped: %s", ident)
            return
        await self.dispatch_input(self.admin_id, ident, ctx, value)

    def recent_inline(self, ident: str, ctx: str, value: str) -> bool:
        now = time.monotonic()
        stamp = (ident, ctx, value)
        for key, moment in list(self.inline_seen.items()):
            if now - moment > INLINE_DUPLICATE_WINDOW:
                del self.inline_seen[key]
        if stamp in self.inline_seen:
            return True
        self.inline_seen[stamp] = now
        return False

    async def on_message(self, evt: object) -> None:
        if not await self.guard_admin(evt):
            return
        who = int(getattr(evt, "from_id", 0) or 0)
        if not self.allowed(who, "message", self.message_limit, 60.0):
            if self.quiet("rate:%d" % who, RATE_QUIET):
                await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
            return
        text = str(getattr(evt, "text", "") or "")
        if text.startswith(inline.marker_text()):
            await self.on_marker(evt, text)
            return
        if self.is_busy():
            if self.quiet("busy", BUSY_QUIET):
                await self.toast(evt, self.tr()("TOAST_BUSY"), alert=True)
            return
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        if text.strip().startswith("/"):
            await self.on_command(evt)
            return
        if self.quiet("home:%d" % chat_id, HOME_QUIET):
            await self.send(chat_id, screens.home(self.view(notice=self.tr()("HOME_NOTICE_PICK"))))

    async def on_command(self, evt: object) -> None:
        if not await self.guard_admin(evt):
            return
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        cmd = str(getattr(evt, "cmd", "") or "").lower()
        text = str(getattr(evt, "text", "") or "")
        if not cmd and text.startswith("/"):
            cmd = text.split()[0][1:].split("@")[0].lower()
        t = self.tr()
        found = commands.known(cmd)
        if found is not None:
            await self.command_screen(chat_id, found, t)
            return
        if cmd == "id":
            who = int(getattr(evt, "from_id", 0) or 0)
            rich = screen(
                t("ID_TITLE"),
                t("ID_SUBTITLE"),
                [f"<p>{code(who)}</p>", quote(muted(t("ID_NOTE")))],
                [row(button(t("UI_HOME"), "nav:home", icon="home"))],
            )
            await self.send(chat_id, rich)
            return
        if cmd == "help":
            await self.send(chat_id, screens.help_screen(self.view()))
            return
        if cmd == "language":
            await self.send(chat_id, screens.language_screen(self.view()))
            return
        await self.send(chat_id, screens.home(self.view()))

    async def command_screen(self, chat_id: int, found: commands.Command, t: i18n.Translator) -> None:
        cards = cores.snapshot(self.state, dict(self.xray.core), len(self.freeturn.clients))
        if found.name == "start":
            await self.send(chat_id, commands.start_screen(t, cards, self.language))
            return
        if found.name == "whitelist_bypass_wg_vk_call_raskur":
            await self.send(chat_id, commands.whitelist_screen(t, cards))
            return
        await self.send(chat_id, commands.vless_screen(t, cards))

    async def register_commands(self) -> bool:
        if self.app is None:
            return False
        payload = commands.menu(self.tr())
        for item in payload:
            if not commands.MENU_RE.match(item["command"]):
                return False
        try:
            await self.app.set_my_commands(commands=payload)
        except Exception as exc:
            log.warning("the command menu was not set: %s", exc)
            return False
        return True

    async def on_marker(self, evt: object, text: str) -> None:
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        msg_id = int(getattr(evt, "msg_id", 0) or 0)
        token, kind, index, body = inline.parse_payload(text)
        await self.drop_marker(chat_id, msg_id)
        if not token:
            return
        if self.is_busy():
            await self.send(chat_id, screens.error_screen(self.view(), self.tr()("ERR_INPUT_TITLE"), self.tr()("TOAST_BUSY")))
            return
        try:
            value = inline.value_from_payload(token, kind, index, body, self.language)
        except inline.InlineError as exc:
            await self.send(chat_id, screens.error_screen(self.view(), self.tr()("ERR_INPUT_TITLE"), str(exc)))
            return
        await self.apply_inline_value(token, kind, value, index, "marker")

    async def dispatch_input(self, chat_id: int, ident: str, ctx: str, value: str) -> None:
        if not chat_id:
            return
        actor = self.admin_id
        try:
            if ident.startswith("ssh_"):
                await self.ssh_input(chat_id, ident, value)
                self.audit.note(actor, "input:%s" % ident, "ok")
                return
            if ident.startswith("ft_"):
                await self.freeturn.apply_input(chat_id, ident, ctx, value)
                self.audit.note(actor, "input:%s" % ident, "ok")
                return
            if ident.startswith("dbg_"):
                await self.debug.apply_input(chat_id, ident, ctx, value)
                self.audit.note(actor, "input:%s" % ident, "ok")
                return
            await self.xray.apply_input(chat_id, ident, ctx, value)
            self.audit.note(actor, "input:%s" % ident, "ok")
        except (PanelError, ModelError, ConfigError, RpcError, ShellError, FtError) as exc:
            self.audit.note(actor, "input:%s" % ident, "failed")
            message = getattr(exc, "message", str(exc))
            await self.send(chat_id, screens.error_screen(self.view(), self.tr()("ERR_INPUT_TITLE"), message))

    async def drop_marker(self, chat_id: int, msg_id: int) -> None:
        if not msg_id or self.app is None:
            return
        delete = getattr(self.app, "delete_msg", None) or getattr(self.app, "delete", None)
        if delete is None:
            return
        try:
            await delete(chat_id, msg_id)
        except Exception as exc:
            log.debug("marker delete failed: %s", exc)

    async def ssh_input(self, chat_id: int, ident: str, value: str) -> None:
        text = (value or "").strip()
        if ident == "ssh_new_port":
            port = valid_port(text)
            await self.harden(chat_id, port=port)
            return
        elif ident == "ssh_pubkey":
            await self.add_key(chat_id, text)
            return
        else:
            raise ConfigError(f"unknown ssh field: {ident}")

    async def on_callback(self, evt: object) -> None:
        if not await self.guard_admin(evt):
            return
        if not self.allowed(int(getattr(evt, "from_id", 0) or 0), "callback", self.callback_limit, 60.0):
            if self.quiet("rate:%d" % int(getattr(evt, "from_id", 0) or 0), RATE_QUIET):
                await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
            return
        data = str(getattr(evt, "data", "") or "")
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        msg_id = int(getattr(evt, "msg_id", 0) or 0)
        who = int(getattr(evt, "from_id", 0) or 0)
        if self.is_busy() and not data.startswith("nav:"):
            if self.quiet("busy", BUSY_QUIET):
                await self.toast(evt, self.tr()("TOAST_BUSY"), alert=True)
            return
        if data.startswith(("nav:", "lang:")) and not self.allowed(who, "nav", NAVIGATE_LIMIT, 60.0):
            if self.quiet("nav", BUSY_QUIET):
                await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
            return
        if not data.startswith("nav:") and not data.startswith("lang:"):
            if not self.audit.first_time(int(getattr(evt, "from_id", 0) or 0), data, time.monotonic()):
                await self.toast(evt, self.tr()("TOAST_REPEAT"), alert=True)
                return
            if not self.allowed(int(getattr(evt, "from_id", 0) or 0), "expensive", self.expensive_limit, 300.0):
                self.audit.note(int(getattr(evt, "from_id", 0) or 0), data, "throttled")
                if self.quiet("rate:%d" % int(getattr(evt, "from_id", 0) or 0), RATE_QUIET):
                    await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
                return
        busy = False
        if not data.startswith(("nav:", "lang:")):
            busy = self.busy_begin()
            if not busy:
                if self.quiet("busy", BUSY_QUIET):
                    await self.toast(evt, self.tr()("TOAST_BUSY"), alert=True)
                return
        if self.slow_action(data):
            try:
                await self.render(chat_id, msg_id, screens.busy_screen(self.tr()("LOADING_BODY"), self.language, [self.tr()("LOADING_STEP")]))
            except Exception as exc:
                log.debug("the loading screen failed: %s", exc)
        try:
            await self.route(chat_id, msg_id, data)
            if data.startswith("xr:") and not data.startswith(("xr:home", "xr:in:nav")):
                try:
                    await self.subs_sync()
                except Exception as exc:
                    log.debug("the subscription refresh was skipped: %s", exc)
        except (PanelError, ModelError, ConfigError, RpcError, ShellError, FtError) as exc:
            message = getattr(exc, "message", str(exc))
            await self.render(chat_id, msg_id, screens.error_screen(self.view(), self.tr()("ERR_TITLE"), message))
        except Exception as exc:
            log.exception("callback failed: %s", data)
            await self.render(chat_id, msg_id, screens.error_screen(self.view(), self.tr()("ERR_CRASH_TITLE"), f"{type(exc).__name__}: {exc}"))
        finally:
            if busy:
                self.busy_end()

    def slow_action(self, data: str) -> bool:
        text = str(data or "")
        if not text.startswith(LOADING_MARKS):
            return False
        return text not in LOADING_SKIP

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        parts = data.split(":")
        head = parts[0] if parts else ""
        if head == "nav":
            await self.navigate(chat_id, msg_id, parts[1] if len(parts) > 1 else "home")
            return
        if head == "lang":
            await self.language_action(chat_id, msg_id, parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "")
            return
        if head == "set":
            await self.setting_action(chat_id, msg_id, parts[1] if len(parts) > 1 else "")
            return
        if head == "ssh":
            await self.ssh_action(chat_id, msg_id, parts[1] if len(parts) > 1 else "")
            return
        if head == "fb":
            await self.ban_action(chat_id, msg_id, parts[1] if len(parts) > 1 else "")
            return
        if head == "sshd":
            await self.sshd_action(chat_id, msg_id, parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "")
            return
        if head == "xr":
            await self.xray.route(chat_id, msg_id, data)
            return
        if head == "ft":
            await self.freeturn.route(chat_id, msg_id, data)
            return
        if head == "upd":
            await self.update_action(chat_id, msg_id, parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "")
            return
        if head == "core":
            await self.core_action(chat_id, msg_id, parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "")
            return
        if head == "dbg":
            await self.debug.route(chat_id, msg_id, data)
            return
        await self.render(chat_id, msg_id, screens.home(self.view(notice=self.tr()("HOME_NOTICE_UNKNOWN"))))

    async def setting_action(self, chat_id: int, msg_id: int, name: str) -> None:
        t = self.tr()
        if name != "emoji":
            await self.render(chat_id, msg_id, screens.settings(self.view()))
            return
        enabled = not self.emoji_enabled
        self.state.emoji = enabled
        self.save()
        ui.use_icons(enabled)
        self.audit.note(self.admin_id, "set:emoji", "on" if enabled else "off")
        notice = t("TOAST_EMOJI_ON") if enabled else t("TOAST_EMOJI_OFF")
        await self.render(chat_id, msg_id, screens.settings(self.view(notice=notice)))
        return

    async def language_action(self, chat_id: int, msg_id: int, action: str, code_value: str) -> None:
        choice = code_value or action
        if action == "set" and choice in i18n.LANGUAGES:
            self.state.language = i18n.normalize(choice)
            self.save()
            notice = i18n.t("LANG_CHANGED", self.language, name=i18n.t("LANG_NAME", self.language))
            await self.render(chat_id, msg_id, screens.language_screen(self.view(notice=notice)))
            return
        await self.render(chat_id, msg_id, screens.language_screen(self.view()))

    async def navigate(self, chat_id: int, msg_id: int, page: str) -> None:
        if page == "server" or page == "home":
            await self.render(chat_id, msg_id, screens.home(self.view()))
            return
        if page == "ssh":
            await self.render(chat_id, msg_id, screens.ssh_settings(self.view()))
            return
        if page == "settings":
            await self.render(chat_id, msg_id, screens.settings(self.view()))
            return
        if page == "ban":
            await self.render(chat_id, msg_id, screens.ban_screen(self.view()))
            return
        if page == "sshd":
            await self.render(chat_id, msg_id, screens.sshd_screen(self.view()))
            return
        if page == "help":
            await self.render(chat_id, msg_id, screens.help_screen(self.view()))
            return
        if page == "lang":
            await self.render(chat_id, msg_id, screens.language_screen(self.view()))
            return
        if page == "xray":
            await self.render(chat_id, msg_id, xscreens.home(self.xray.view()))
            return
        if page == "freeturn":
            await self.render(chat_id, msg_id, ftscreens.home(self.freeturn.view()))
            return
        if page == "core":
            await self.render(chat_id, msg_id, ftscreens.core_screen(self.freeturn.view()))
            return
        if page == "update":
            await self.update_action(chat_id, msg_id, "show", "")
            return
        await self.render(chat_id, msg_id, screens.home(self.view()))

    async def update_action(self, chat_id: int, msg_id: int, action: str, stage: str) -> None:
        t = self.tr()
        if action in {"", "show", "refresh"}:
            steps = [t("UPD_STEP_FETCH"), t("UPD_STEP_RESET"), t("UPD_STEP_CHECK"), t("UPD_STEP_DEPS"), t("UPD_STEP_RESTART")]
            await self.render(chat_id, msg_id, screens.busy_screen(t("UPD_BUSY"), self.language, steps))
            await self.refresh_update()
            await self.render(chat_id, msg_id, screens.update_screen(self.view(error=self.update_error), self.update_info))
            return
        if action in {"commit", "release"} and stage != "go":
            await self.refresh_update()
            preview: dict[str, object] = {}
            try:
                preview = await self.updater.preview(action)
            except UpdateError as exc:
                self.update_error = exc.message
            branch = str(self.update_info.get("branch") or "")
            if action == "commit":
                commit = str(self.update_info.get("remote") or t("UI_NOT_SET"))
                body = t("UPD_CONFIRM_COMMIT", branch=branch, commit=code(commit))
                target = "upd:commit:go"
            else:
                tag = str(self.update_info.get("release") or "")
                if not tag:
                    reason = str(self.update_info.get("release_error") or t("UI_NONE"))
                    await self.render(
                        chat_id,
                        msg_id,
                        screens.update_screen(self.view(error=t("UPD_NO_RELEASE", reason=reason)), self.update_info),
                    )
                    return
                body = t("UPD_CONFIRM_RELEASE", tag=code(tag))
                target = "upd:release:go"
            await self.render(
                chat_id,
                msg_id,
                screens.update_confirm_screen(self.view(), self.update_info, preview, body, target),
            )
            return
        if action in {"commit", "release"} and stage == "go":
            await self.run_update(chat_id, msg_id, action)
            return
        await self.render(chat_id, msg_id, screens.update_screen(self.view(), self.update_info))

    async def refresh_update(self) -> None:
        if self.update_info and not self.quiet("upd:check", UPDATE_QUIET):
            return
        self.update_error = ""
        try:
            found = await self.updater.check_all()
            self.update_info = found.to_dict()
        except UpdateError as exc:
            self.update_error = exc.message
        except (ShellError, OSError) as exc:
            self.update_error = str(exc)

    async def run_update(self, chat_id: int, msg_id: int, mode: str) -> None:
        t = self.tr()
        steps = [t("UPD_STEP_FETCH"), t("UPD_STEP_RESET"), t("UPD_STEP_CHECK"), t("UPD_STEP_DEPS"), t("UPD_STEP_RESTART")]
        await self.render(chat_id, msg_id, screens.busy_screen(t("UPD_BUSY"), self.language, steps))
        self.audit.note(self.admin_id, "upd:%s" % mode, "start")
        try:
            result = await self.updater.apply(mode)
        except UpdateError as exc:
            self.audit.note(self.admin_id, "upd:%s" % mode, "failed")
            self.update_error = exc.message
            await self.render(chat_id, msg_id, screens.update_screen(self.view(error=exc.message), self.update_info))
            return
        except (ShellError, OSError) as exc:
            self.audit.note(self.admin_id, "upd:%s" % mode, "failed")
            self.update_error = str(exc)
            await self.render(chat_id, msg_id, screens.update_screen(self.view(error=self.update_error), self.update_info))
            return
        self.audit.note(self.admin_id, "upd:%s" % mode, "ok" if result.ok else "failed")
        self.update_result = result.to_dict()
        self.update_error = ""
        await self.render(chat_id, msg_id, screens.update_result_screen(self.view(), self.update_info, self.update_result))

    async def ssh_action(self, chat_id: int, msg_id: int, action: str) -> None:
        await self.render(chat_id, msg_id, screens.ssh_settings(self.view()))

    async def core_action(self, chat_id: int, msg_id: int, action: str, name: str) -> None:
        t = self.tr()
        if action == "set" and name in {"xray", "freeturn"}:
            self.freeturn.set_core(name)
            label = t("CORE_BTN_FREETURN") if name == "freeturn" else t("CORE_BTN_XRAY")
            self.audit.note(self.admin_id, "core:set", "ok", name)
            await self.render(chat_id, msg_id, ftscreens.core_screen(self.freeturn.view(notice=t("CORE_SWITCHED", name=label))))
            return
        await self.render(chat_id, msg_id, ftscreens.core_screen(self.freeturn.view()))

    async def ban_action(self, chat_id: int, msg_id: int, action: str) -> None:
        t = self.tr()
        port = int(self.state.xray.sub_port)
        self.audit.note(self.admin_id, "ban:%s" % action, "start")
        if action == "install":
            await self.render(
                chat_id,
                msg_id,
                screens.busy_screen(t("BUSY_FB_ENABLE"), self.language, [t("BUSY_STEP_JAIL"), t("BUSY_STEP_CHECK"), t("BUSY_STEP_RESTART")]),
            )
            try:
                self.ban = await self.guard.install(
                    self.state.ssh,
                    port=port,
                    bantime=int(self.state.xray.fail2ban_bantime or DEFAULT_BANTIME),
                    ssh_bantime=self.state.xray.fail2ban_ssh_bantime,
                    ssh_maxretry=int(self.state.xray.fail2ban_ssh_maxretry),
                    ignoreip=self.state.xray.fail2ban_ignoreip,
                )
            except RpcError as exc:
                await self.render(chat_id, msg_id, screens.ban_screen(self.view(error=exc.message)))
                return
            self.state.xray.fail2ban_enabled = True
            self.save()
            await self.render(chat_id, msg_id, screens.ban_screen(self.view(notice=t("FB_NOTICE_ON"))))
            return
        if action == "remove":
            try:
                self.ban = await self.guard.remove(self.state.ssh, port=port)
            except RpcError as exc:
                await self.render(chat_id, msg_id, screens.ban_screen(self.view(error=exc.message)))
                return
            self.state.xray.fail2ban_enabled = False
            self.save()
            await self.render(chat_id, msg_id, screens.ban_screen(self.view(notice=t("FB_NOTICE_OFF"))))
            return
        if action == "reset":
            try:
                self.ban = await self.guard.remove(self.state.ssh, port=port)
                self.ban = await self.guard.install(
                    self.state.ssh,
                    port=port,
                    bantime=int(self.state.xray.fail2ban_bantime or DEFAULT_BANTIME),
                    ssh_bantime=self.state.xray.fail2ban_ssh_bantime,
                    ssh_maxretry=int(self.state.xray.fail2ban_ssh_maxretry),
                    ignoreip=self.state.xray.fail2ban_ignoreip,
                )
            except RpcError as exc:
                await self.render(chat_id, msg_id, screens.ban_screen(self.view(error=exc.message)))
                return
            await self.render(chat_id, msg_id, screens.ban_screen(self.view(notice=t("FB_NOTICE_RESET"))))
            return
        if action == "status":
            try:
                self.ban = await self.guard.status(self.state.ssh, port=port)
            except RpcError as exc:
                await self.render(chat_id, msg_id, screens.ban_screen(self.view(error=exc.message)))
                return
            self.state.xray.fail2ban_enabled = self.ban.active
            self.save()
            await self.render(chat_id, msg_id, screens.ban_screen(self.view(notice=t("FB_NOTICE_STATUS"))))
            return
        await self.render(chat_id, msg_id, screens.ban_screen(self.view()))

    async def sshd_action(self, chat_id: int, msg_id: int, action: str, value: str) -> None:
        t = self.tr()
        if action == "status":
            try:
                self.sshd = await self.guard.ssh_status(self.state.ssh)
            except RpcError as exc:
                await self.render(chat_id, msg_id, screens.sshd_screen(self.view(error=exc.message)))
                return
            await self.render(chat_id, msg_id, screens.sshd_screen(self.view(notice=t("SSHD_NOTICE_STATUS"))))
            return
        if action == "remove":
            try:
                self.sshd = await self.guard.ssh_remove(self.state.ssh)
            except RpcError as exc:
                await self.render(chat_id, msg_id, screens.sshd_screen(self.view(error=exc.message)))
                return
            await self.render(chat_id, msg_id, screens.sshd_screen(self.view(notice=t("SSHD_NOTICE_REMOVE"))))
            return
        if action == "auth":
            await self.harden(chat_id, password=value)
            return
        if action == "root":
            await self.harden(chat_id, root=value)
            return
        await self.render(chat_id, msg_id, screens.sshd_screen(self.view()))

    async def harden(self, chat_id: int, port: int = 0, password: str = "", root: str = "") -> None:
        actor = self.admin_id
        detail = "port=%d password=%s root=%s" % (int(port or 0), "set" if password else "-", "set" if root else "-")
        if password == "no":
            try:
                self.sshd = await self.guard.ssh_status(self.state.ssh)
            except RpcError as exc:
                self.audit.note(actor, "sshd:harden", "failed", detail)
                await self.send(chat_id, screens.sshd_screen(self.view(error=exc.message)))
                return
            keys = self.sshd.key_list
            if not keys and not self.sshd.keys:
                self.audit.note(actor, "sshd:harden", "blocked", "no public key in %s" % (self.sshd.key_path or "authorized_keys"))
                await self.send(
                    chat_id,
                    screens.sshd_screen(
                        self.view(
                            error=self.tr()("SSHD_PW_BLOCKED", user=self.sshd.key_user or "root", path=self.sshd.key_path or "~/.ssh/authorized_keys"),
                            notice=self.tr()("SSHD_NOTICE_PW_BLOCKED"),
                        )
                    ),
                )
                return
        try:
            self.sshd = await self.guard.ssh_apply(self.state.ssh, port=port, password=password, root=root)
        except RpcError as exc:
            self.audit.note(actor, "sshd:harden", "failed", detail)
            await self.send(chat_id, screens.sshd_screen(self.view(error=exc.message)))
            return
        self.audit.note(actor, "sshd:harden", "ok", detail)
        if port:
            self.save()
        await self.send(chat_id, screens.sshd_screen(self.view(notice=self.tr()("SSHD_NOTICE_APPLIED"))))

    async def add_key(self, chat_id: int, public_key: str) -> None:
        actor = self.admin_id
        try:
            self.sshd = await self.guard.ssh_add_key(self.state.ssh, public_key)
        except RpcError as exc:
            self.audit.note(actor, "sshd:add-key", "failed")
            await self.send(chat_id, screens.sshd_screen(self.view(error=exc.message)))
            return
        self.audit.note(actor, "sshd:add-key", "ok")
        await self.send(chat_id, screens.sshd_screen(self.view(notice=self.tr()("SSHD_NOTICE_KEY"))))
