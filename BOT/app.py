from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
from typing import Any

from goygram import GoyGram

from . import antiddos, commands, cores, dscreens, ftscreens, i18n, inline, ipscan, notify, screens, tools, ui, xscreens
from .config import Config, ConfigError
from .dbg import DebugPanel
from .freeturn import FtControl, FtError
from .ftpanel import FtPanel
from .guard import DEFAULT_BANTIME, BanState, GuardClient, SshState, ddos_call, ddos_argv, honey_events
from .models import ModelError, valid_port
from .panel import PanelError, XrayPanel, state_report
from .audit import Audit
from .seclog import SecurityLog
from .ratelimit import CALLBACK_LIMIT, CLAIM_LIMIT, EXPENSIVE_LIMIT, INLINE_LIMIT, MESSAGE_LIMIT, Limiter
from .shell import LocalShell, ShellError
from .store import State, Store
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
LOADING_MARKS = ("xr:", "ft:", "dbg:", "upd:", "fb:", "sshd:", "ssh:", "tools:")
LOADING_SKIP = ("nav:", "lang:", "set:", "dbg:home", "dbg:emoji", "dbg:info", "ft:home", "xr:home", "tools:home", "tools:fortress", "tools:pentest")
RENDER_CACHE = 64
DENY_LIMIT = 1
DENY_WINDOW = 60.0
NAVIGATE_LIMIT = 40
NAV_QUIET = 60.0
HOME_QUIET = 3.0
RATE_QUIET = 10.0
UPDATE_QUIET = 10.0
TOAST_TIMEOUT = 6.0
ACTION_TIMEOUT = 240.0
JOB_CACHE = 64
CLICK_QUIET = 2.0
ACTION_LOCK_QUIET = 5.0

NAV_PREFIXES = ("nav:", "lang:", "set:")
NAV_ROUTES = ("dbg:home", "dbg:scan", "dbg:trace", "dbg:vk", "dbg:scr", "dbg:ports", "dbg:chk", "dbg:dpi", "dbg:ntf", "dbg:hp", "dbg:dd", "dbg:info", "core:show", "ft:home", "xr:home", "xr:scan", "xr:subs", "xr:core")

def is_navigation(data: str) -> bool:
    if data.startswith(NAV_PREFIXES):
        return True
    if data in NAV_ROUTES:
        return True
    return False

CONFIRM_STEPS = re.compile(r"^(upd:(commit|release)|fb:(install|reset)|xr:(core|subs:rebuild)|ft:(apply|restart))")

def is_expensive(data: str) -> bool:
    if data.startswith(("nav:", "lang:")):
        return False
    if is_navigation(data):
        return False
    return True


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


def _extract_event_lang(evt: object, app: Any = None) -> str:
    for attr in ("lang_code", "language_code"):
        val = getattr(evt, attr, None)
        if isinstance(val, str) and val.strip():
            return val.strip()
    raw = getattr(evt, "raw", None)
    if isinstance(raw, dict):
        nested_raw = raw.get("raw") if isinstance(raw.get("raw"), dict) else {}
        nested_upd = raw.get("raw_update") if isinstance(raw.get("raw_update"), dict) else {}
        for obj in (
            raw.get("from"),
            raw.get("user"),
            nested_raw.get("from"),
            nested_upd.get("from"),
        ):
            if isinstance(obj, dict):
                code = obj.get("language_code") or obj.get("lang_code")
                if isinstance(code, str) and code.strip():
                    return code.strip()
    getter = getattr(evt, "get", None)
    if callable(getter):
        try:
            sender = getter("from")
        except Exception:
            sender = None
        if isinstance(sender, dict):
            code = sender.get("language_code") or sender.get("lang_code")
            if isinstance(code, str) and code.strip():
                return code.strip()
    who = int(getattr(evt, "from_id", 0) or 0)
    if who > 0 and app is not None:
        mt = getattr(app, "mt", None)
        entities = getattr(mt, "entities", None)
        if isinstance(entities, dict):
            ent = entities.get(("user", who))
            if isinstance(ent, dict):
                code = ent.get("lang_code") or ent.get("language_code")
                if isinstance(code, str) and code.strip():
                    return code.strip()
        users = getattr(app, "_users", None)
        if isinstance(users, dict):
            cached = users.get(who)
            if isinstance(cached, dict):
                code = cached.get("lang_code") or cached.get("language_code")
                if isinstance(code, str) and code.strip():
                    return code.strip()
    return ""


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
        self.update_system: dict[str, Any] = {}
        self.app: GoyGram | None = None
        self.ban: BanState | None = None
        self.sshd: SshState | None = None
        self.busy = False
        self.busy_until = 0.0
        self.render_seen: dict[tuple[int, int], tuple[str, float]] = {}
        self.quiet_marks: dict[str, float] = {}
        self.jobs: dict[Any, Any] = {}
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
        self.ddos_state: Any = None
        self.ddos_reported = 0.0
        self.cores_warmed = False
        self.lang_probed = False
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
        if getattr(self.state, "emoji", None):
            return True
        return bool(getattr(self.cfg, "emoji_default", False))

    def apply_emoji(self) -> bool:
        ui.use_icons(self.emoji_enabled)
        return self.emoji_enabled

    def toggle_emoji(self) -> bool:
        self.state.emoji = not self.emoji_enabled
        self.save()
        ui.use_icons(self.state.emoji)
        self.audit.note(self.admin_id, "emoji", "on" if self.state.emoji else "off")
        return bool(self.state.emoji)

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
        return self.state.xray.sub_registry(self.address(), [])

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
        try:
            status = await ddos_call(self.guard, cfg, ddos_argv("status"), 90)
        except Exception as exc:
            self.notify_poll_error = type(exc).__name__
            status = None
        self.ddos_state = status
        if status is not None and status.under_attack():
            raised.extend(self.notify.force(notify.KIND_DDOS, (status.offenders() or ["0.0.0.0"])[0], status.headline()))
        self.notify_poll_at = time.time()
        for event in raised:
            await self.notify_send(event)
        self.notify.drain()
        return raised

    async def freeturn_warmup(self) -> None:
        probe_fn = getattr(self.freeturn.control, "probe", None)
        if asyncio.iscoroutine(probe_fn):
            probe_fn.close()
            return
        if not callable(probe_fn):
            return
        try:
            state = await probe_fn()
        except Exception as exc:
            log.debug("freeturn warmup skipped: %s", exc)
            return
        saved_transport = self.freeturn.draft.transport
        self.freeturn.state = state
        self.freeturn.state.config.transport = saved_transport
        self.freeturn.draft = state.config.from_dict(state.config.to_dict())
        self.freeturn.draft.transport = saved_transport
        if "owner" in state.links:
            self.freeturn.link = state.links["owner"]
            self.freeturn.name = "owner"
        if state.installed and (not isinstance(self.freeturn.control, FtControl) or os.path.isfile("/opt/free-turn-proxy/clients.list")):
            self.freeturn.clients, self.freeturn.share = await self.freeturn._safe_list()
        if state.installed and state.running:
            await self.freeturn._auto_guard_vk(int(state.config.listen_port or 0))
        self.freeturn.save()

    async def auto_protect(self) -> dict[str, str]:
        outcomes: dict[str, str] = {}
        detected_ip = public_address()
        if detected_ip:
            changed_addr = False
            if not self.state.xray.sub_address:
                self.state.xray.sub_address = detected_ip
                changed_addr = True
            if not self.freeturn.draft.host:
                self.freeturn.draft.host = detected_ip
                self.freeturn.state.config.host = detected_ip
                changed_addr = True
            if changed_addr:
                self.save()
        ft_state = getattr(self.freeturn, "state", None)
        if ft_state is not None and ft_state.installed and ft_state.running:
            await self.freeturn._auto_guard_vk(int(ft_state.config.listen_port or 0))
            outcomes["vk_fw"] = str(self.freeturn.guard.get("mode") or "skip")
        try:
            status = await ddos_call(self.guard, self.state.ssh, ddos_argv("status"), 60)
            if not status.enabled:
                policy = antiddos.Policy.from_dict(self.state.ddos)
                status = await ddos_call(self.guard, self.state.ssh, ddos_argv("install", policy), 180)
            self.ddos_state = status
            self.debug.ddos = status
            outcomes["ddos"] = "on" if status.enabled else "off"
        except Exception as exc:
            log.debug("auto ddos skipped: %s", exc)
            outcomes["ddos"] = "skip"
        try:
            sub_port = int(getattr(self.state.xray, "sub_port", 0) or 0)
            ban = await self.guard.status(self.state.ssh, port=sub_port)
            if not ban.active:
                ban = await self.guard.install(
                    self.state.ssh,
                    port=sub_port,
                    bantime=int(self.state.xray.fail2ban_bantime or DEFAULT_BANTIME),
                    ssh_bantime=self.state.xray.fail2ban_ssh_bantime,
                    ssh_maxretry=int(self.state.xray.fail2ban_ssh_maxretry),
                    ignoreip=self.state.xray.fail2ban_ignoreip,
                )
            self.ban = ban
            self.state.xray.fail2ban_enabled = bool(ban.active)
            self.save()
            outcomes["fail2ban"] = "on" if ban.active else "off"
        except Exception as exc:
            log.debug("auto fail2ban skipped: %s", exc)
            outcomes["fail2ban"] = "skip"
        return outcomes

    async def check_inline_mode(self) -> bool:
        if self.app is None:
            return True
        get_me = getattr(self.app, "get_me", None)
        if not callable(get_me):
            return True
        try:
            me = await get_me(refresh=True)
        except TypeError:
            try:
                me = await get_me()
            except Exception:
                return True
        except Exception:
            return True
        if not isinstance(me, dict):
            return True
        supports = me.get("supports_inline_queries")
        if supports is None and "bot_inline_placeholder" in me:
            supports = me.get("bot_inline_placeholder") is not None
        if supports is False:
            banner = i18n.t("TUI_INLINE_WARN", "en")
            print("\033[1;31m%s\033[0m" % banner, file=sys.stderr, flush=True)
            log.warning("%s", banner)
            self.inline_enabled = False
            return False
        self.inline_enabled = True
        return True

    async def ensure_cores_warm(self) -> None:
        if self.cores_warmed:
            return
        self.cores_warmed = True
        if not self.xray.core and (not isinstance(self.xray.control, XrayControl) or os.geteuid() == 0):
            try:
                probed = await self.xray.control.probe(self.state.ssh)
                self.xray.core = state_report(probed)
                self.state.last_probe = dict(self.xray.core)
                self.save()
            except Exception as exc:
                log.debug("xray warmup skipped: %s", exc)
        if not self.freeturn.state.installed and (
            not isinstance(self.freeturn.control, FtControl)
            or self.state.freeturn.configured
            or os.path.isfile("/opt/free-turn-proxy/install.conf")
            or os.path.isfile("/etc/systemd/system/free-turn-proxy.service")
        ):
            await self.freeturn_warmup()

    async def run(self) -> None:
        app = await self.boot()
        await self.check_inline_mode()
        await self.verify_update()
        try:
            await self.register_commands()
        except Exception as exc:
            log.warning("the command menu was skipped: %s", exc)
        try:
            await self.notify_start()
        except Exception as exc:
            log.warning("the notification poller was skipped: %s", exc)
        if os.geteuid() == 0:
            try:
                await self.track(self.ensure_cores_warm(), "cores_warmup")
                await self.track(self.auto_protect(), "auto_protect")
            except Exception as exc:
                log.debug("cores warmup not scheduled: %s", exc)
        await app.run()

    async def verify_update(self) -> None:
        try:
            found = await self.updater.verify()
        except (UpdateError, ShellError) as exc:
            log.warning("the update check failed: %s", getattr(exc, "message", exc))
            found = {}
        except Exception as exc:
            log.debug("the update check was skipped: %s", exc)
            found = {}
        self.update_notice = found
        if found:
            await self.report_update(found)

    async def report_update(self, notice: dict[str, object]) -> None:
        owner = int(getattr(self, "admin_id", 0) or 0)
        if not owner or self.app is None:
            return
        saved = dict(self.update_notice)
        text = self.update_notice_html()
        if not text:
            return
        try:
            await self.app.send_msg(owner, text, via="mt", parse_mode="html")
        except Exception as exc:
            self.update_notice = saved
            log.debug("the update notice did not reach the owner: %s", exc)

    def update_notice_html(self) -> str:
        from .ui import esc, ref_link

        data = self.update_notice
        if not data:
            return ""
        self.update_notice = {}
        t = self.tr()
        commit = str(data.get("commit") or data.get("to") or "")[:12]
        linked = ref_link(commit)
        if data.get("healthy"):
            return t("UPD_NOTICE_VERIFIED", commit=linked, state=esc(str(data.get("state") or "active")))
        return t("UPD_NOTICE_BROKEN", commit=linked)

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
        if msg_id:
            try:
                await self.app.edit_rich(chat_id, msg_id, rich, via="mt")
                self.remember_render(key, digest, now)
                return
            except Exception as exc:
                log.warning("edit failed: %s", exc)
        if not msg_id or self.quiet("send:%d" % key[0], RENDER_QUIET):
            try:
                await self.send(chat_id, rich)
                self.remember_render(key, digest, now)
            except Exception as exc:
                log.warning("send failed: %s", exc)

    def remember_render(self, key: tuple[int, int], digest: str, now: float) -> None:
        self.render_seen[key] = (digest, now)
        if len(self.render_seen) > RENDER_CACHE:
            extra = len(self.render_seen) - RENDER_CACHE
            for item in sorted(self.render_seen.items(), key=lambda pair: pair[1][1])[:extra]:
                self.render_seen.pop(item[0], None)

    def answered(self, evt: object) -> bool:
        return bool(getattr(evt, "_obhod_answered", False))

    async def toast(self, evt: object, text: str = "", alert: bool = False) -> None:
        if self.answered(evt):
            return
        try:
            setattr(evt, "_obhod_answered", True)
        except (AttributeError, TypeError):
            pass
        try:
            await asyncio.wait_for(evt.answer(text or self.tr()("TOAST_DONE"), alert=alert), TOAST_TIMEOUT)
        except asyncio.TimeoutError:
            log.debug("the toast answer timed out")
        except Exception as exc:
            log.debug("answer failed: %s", exc)

    async def answer_click(self, evt: object) -> None:
        if not self.quiet("click", CLICK_QUIET):
            return
        await self.toast(evt, "")

    def private_chat(self, evt: object) -> bool:
        who = int(getattr(evt, "from_id", 0) or 0)
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        return who > 0 and chat_id == who

    def allowed(self, who: int, scope: str = "any", limit: int = 0, window: float = 0.0) -> bool:
        return self.limiter.allow(str(who), scope=scope, limit=limit, window=window)

    async def sync_user_language(self, evt: object) -> None:
        if getattr(self.state, "language_set", False):
            return
        code = _extract_event_lang(evt, self.app)
        if not code:
            return
        detected = i18n.detect_user_language(code)
        changed = self.state.language != detected
        self.state.language = detected
        self.state.language_set = True
        self.save()
        if (
            changed
            and self.app is not None
            and callable(getattr(self.app, "set_my_commands", None))
            and (not isinstance(self.app, GoyGram) or getattr(getattr(self.app, "api", None), "_session", None) is not None)
        ):
            try:
                await self.register_commands()
            except Exception:
                pass

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
                await self.sync_user_language(evt)
                return True
        elif who == self.admin_id:
            await self.sync_user_language(evt)
            return True
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        log.warning("blocked non-admin: who=%s, chat_id=%s", who, chat_id)
        if self.allowed(str(chat_id or who), "deny", DENY_LIMIT, DENY_WINDOW):
            await self.send(chat_id, screens.denied(self.language))
        return False

    def input_values(self) -> dict[str, str]:
        state = self.state
        xr = state.xray
        ft_cfg = getattr(self.freeturn, "draft", None) or state.freeturn.config
        dbg = getattr(self, "debug", None)
        values = {
            "ssh_new_port": str(self.sshd.ports[0] if self.sshd and self.sshd.ports else state.ssh.port),
            "ssh_pubkey": "",
            "xr_remark": "",
            "xr_port": "443",
            "xr_sni": "",
            "xr_dest": "",
            "xr_short_id": "",
            "xr_spider_x": "/",
            "xr_fingerprint": "chrome",
            "xr_alpn": "",
            "xr_cert_file": "",
            "xr_key_file": "",
            "xr_path": "",
            "xr_host_header": "",
            "xr_service": "",
            "xr_padding": "",
            "xr_mldsa65_seed": "",
            "xr_mldsa65_verify": "",
            "xr_client_email": "",
            "xr_client_flow": "",
            "xr_client_limit": "0",
            "dbg_target": str(getattr(dbg, "scan_target", "") or ""),
            "dbg_ports": str(getattr(dbg, "scan_ports", "") or ""),
            "dbg_chk_target": str(getattr(dbg, "chk_target", "") or ""),
            "dbg_hops": str(getattr(dbg, "chk_hops", 12) or 12),
            "xr_log_level": xr.log_level,
            "xr_scan_targets": ", ".join(xr.scan_targets),
            "xr_scan_manual": "",
            "xr_scan_sni": xr.scan_sni,
            "xr_scan_xver": str(xr.scan_xver),
            "xr_scan_candidates": ", ".join(xr.candidates()),
            "xr_sub_port": str(xr.sub_port),
            "xr_sub_address": xr.sub_address,
            "xr_sub_support": xr.sub_support_url,
            "xr_sub_announce": xr.sub_announce,
            "xr_sub_refresh": str(xr.sub_refresh),
            "xr_bantime": str(xr.fail2ban_bantime),
            "xr_ssh_bantime": xr.fail2ban_ssh_bantime,
            "xr_ssh_maxretry": str(xr.fail2ban_ssh_maxretry),
            "xr_ignoreip": xr.fail2ban_ignoreip,
            "xr_ban_ip": "",
            "xr_dns_servers": xr.dns_csv(),
            "xr_api_port": str(xr.api_port),
            "xr_access_log": xr.access_log,
            "xr_tunnel_host": xr.tunnel_host,
            "xr_tunnel_key": "",
            "ft_port": str(ft_cfg.listen_port),
            "ft_wg_port": str(ft_cfg.wg_port),
            "ft_wg_net": ft_cfg.wg_net,
            "ft_host": ft_cfg.host or xr.sub_address,
            "ft_connect": ft_cfg.connect,
            "ft_key": "",
            "ft_client": "",
        }
        if xr.inbounds:
            inbound = xr.inbounds[0]
            values["xr_remark"] = inbound.remark
            values["xr_port"] = str(inbound.port)
            values["xr_sni"] = inbound.sni
            values["xr_dest"] = inbound.dest
            values["xr_short_id"] = ", ".join(inbound.short_ids)
            values["xr_spider_x"] = inbound.spider_x
            values["xr_fingerprint"] = inbound.fingerprint
            values["xr_alpn"] = ", ".join(inbound.alpn)
            values["xr_cert_file"] = inbound.cert_file
            values["xr_key_file"] = inbound.key_file
            values["xr_path"] = inbound.path
            values["xr_host_header"] = inbound.host_header
            values["xr_service"] = inbound.service_name
            values["xr_padding"] = inbound.encryption.padding
            values["xr_mldsa65_verify"] = inbound.mldsa65_verify
            if inbound.clients:
                first_client = inbound.clients[0]
                values["xr_client_flow"] = first_client.flow
                values["xr_client_limit"] = str(first_client.limit_ip)
        return values

    async def on_inline(self, evt: object) -> None:
        await self.track(self.handle_inline(evt), "inline")

    async def handle_inline(self, evt: object) -> None:
        query = str(getattr(evt, "query", "") or "")
        src = str(getattr(evt, "src", "mt") or "mt")
        who = int(getattr(evt, "from_id", 0) or 0)
        results: list[dict] = []
        allowed = who > 0 and who == self.admin_id and self.allowed(who, "inline", self.inline_limit, 60.0)
        if allowed:
            stripped = query.strip()
            if not stripped:
                hint_cards = await ipscan.inline_results("ip", src=src, lang=self.language)
                field_cards = inline.results_for(query, src=src, current=self.input_values(), lang=self.language)
                results = (hint_cards + field_cards)[: inline.MAX_RESULTS]
            else:
                token, _rest = inline.parse_query(stripped)
                if token:
                    results = inline.results_for(query, src=src, current=self.input_values(), lang=self.language)
                else:
                    results = await ipscan.inline_results(stripped, src=src, lang=self.language)
        try:
            await evt.answer(results=results, cache_time=0, is_personal=True)
        except Exception as exc:
            log.warning("inline answer failed: %s", exc)

    async def on_chosen(self, evt: object) -> None:
        utype = str(getattr(evt, "update_type", "") or "")
        if utype not in ("chosen_inline_result", "updateBotInlineSend"):
            return
        raw = getattr(evt, "raw", None)
        raw_dict = raw if isinstance(raw, dict) else {}
        payload = raw_dict.get("chosen_inline_result")
        payload = payload if isinstance(payload, dict) else raw_dict
        raw_upd = raw_dict.get("raw_update")
        raw_upd = raw_upd if isinstance(raw_upd, dict) else {}
        who = int(
            ((payload.get("from") or {}).get("id") if isinstance(payload.get("from"), dict) else 0)
            or payload.get("from_id")
            or raw_upd.get("user_id")
            or getattr(evt, "from_id", 0)
            or 0
        )
        if not self.admin_id or who != self.admin_id:
            log.warning("a foreign user picked an inline result: %s", who)
            return
        if not self.allowed(who, "inline", self.inline_limit, 60.0):
            return
        rid = str(payload.get("result_id") or raw_upd.get("id") or "")
        if rid.startswith("ipscan:"):
            return
        query = str(payload.get("query") or raw_upd.get("query") or "")
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
        inline.consume_pending()
        done = asyncio.Event()
        self._marker_event = done
        try:
            await self.apply_inline_value(token, kind, value, index, "chosen")
        finally:
            done.set()

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
        await self.track(self.handle_message(evt), "msg")

    async def handle_message(self, evt: object) -> None:
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
        if text.strip().startswith("/"):
            await self.on_command(evt)
            return
        return

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
        return

    async def command_screen(self, chat_id: int, found: commands.Command, t: i18n.Translator) -> None:
        await self.ensure_cores_warm()
        cards = cores.snapshot(self.state, dict(self.xray.core), len(self.freeturn.clients))
        if found.name == "start":
            await self.send(chat_id, commands.start_screen(t, cards, self.language))
            return
        if found.name in ("wg", "wireguard_whitelist_bypass_raskur"):
            await self.send(chat_id, commands.whitelist_screen(t, cards))
            return
        if found.name in ("vless", "vless_raw_xhttp_reality_raskur"):
            await self.send(chat_id, commands.vless_screen(t, cards))
            return
        await self.send(chat_id, commands.whitelist_screen(t, cards))

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
        msg_id = int(getattr(evt, "msg_id", 0) or getattr(evt, "id", 0) or 0)
        has_legacy = inline.SEPARATOR in str(text or "")
        token, kind, index, body = inline.parse_payload(text) if has_legacy else ("", "", -1, "")
        pending_evt = getattr(self, "_marker_event", None)
        if not has_legacy and isinstance(pending_evt, asyncio.Event):
            try:
                await asyncio.wait_for(pending_evt.wait(), 0.4)
            except asyncio.TimeoutError:
                pass
        await self.drop_marker(chat_id, msg_id)
        if not has_legacy:
            token, kind, index, body = inline.consume_pending()
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
        deleted = False
        if delete is not None:
            try:
                await delete(chat_id, msg_id)
                deleted = True
            except Exception as exc:
                log.debug("marker delete failed: %s", exc)
        bot_req = getattr(self.app, "bot_req", None)
        if not deleted and callable(bot_req) and getattr(self.app, "bot", None) is not None:
            try:
                await bot_req("deleteMessage", chat_id=chat_id, message_id=int(msg_id))
            except Exception as exc:
                log.debug("bot api marker delete failed: %s", exc)

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
            if self.quiet("rate:%d" % int(getattr(evt, "from_id", 0) or 0), NAV_QUIET):
                await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
            return
        data = str(getattr(evt, "data", "") or "")
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        msg_id = int(getattr(evt, "msg_id", 0) or 0)
        who = int(getattr(evt, "from_id", 0) or 0)
        if self.is_busy() and not is_navigation(data) and not CONFIRM_STEPS.match(data):
            if self.quiet("busy", BUSY_QUIET):
                await self.toast(evt, self.tr()("TOAST_BUSY"), alert=True)
            return
        if is_navigation(data) or data.startswith(("nav:", "lang:")):
            if not self.allowed(who, "nav", NAVIGATE_LIMIT, 60.0):
                if self.quiet("rate:%d" % who, NAV_QUIET):
                    await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
                return
        if is_expensive(data):
            if data != "dbg:chk:net" and not self.audit.first_time(int(getattr(evt, "from_id", 0) or 0), data, time.monotonic()):
                await self.toast(evt, self.tr()("TOAST_REPEAT"), alert=True)
                return
            if not self.allowed(int(getattr(evt, "from_id", 0) or 0), "expensive", self.expensive_limit, 120.0):
                self.audit.note(int(getattr(evt, "from_id", 0) or 0), data, "throttled")
                if self.quiet("rate:%d" % int(getattr(evt, "from_id", 0) or 0), RATE_QUIET):
                    await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
                return
        if self.busy and not is_expensive(data) and not is_navigation(data) and not CONFIRM_STEPS.match(data):
            if self.quiet("busy", BUSY_QUIET):
                await self.toast(evt, self.tr()("TOAST_BUSY"), alert=True)
            return
        busy = False
        if is_expensive(data) or CONFIRM_STEPS.match(data):
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
        await self.answer_click(evt)
        await self.track(self.finish(self.handle_callback(chat_id, msg_id, data), busy), data)

    async def finish(self, job: Any, busy: bool) -> None:
        try:
            await job
        finally:
            if busy:
                self.busy_end()

    async def busy_wait(self) -> None:
        await self.idle()
        self.busy_end()

    async def idle(self, limit: float = ACTION_TIMEOUT) -> None:
        deadline = time.monotonic() + limit
        while self.jobs and time.monotonic() < deadline:
            await asyncio.gather(*list(self.jobs), return_exceptions=True)

    async def track(self, job: Any, label: str) -> None:
        task = asyncio.create_task(job) if asyncio.iscoroutine(job) else job
        self.jobs[task] = label
        task.add_done_callback(self.job_done)
        if len(self.jobs) > JOB_CACHE:
            extra = len(self.jobs) - JOB_CACHE
            for item in sorted(self.jobs, key=lambda task_item: self.jobs[task_item])[:extra]:
                self.jobs.pop(item, None)

    def job_done(self, task: Any) -> None:
        self.jobs.pop(task, None)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            log.warning("a background job failed: %s", error)

    async def handle_callback(self, chat_id: int, msg_id: int, data: str) -> None:
        lock = self.action_lock()
        if lock.locked() and not self.quiet("action", ACTION_LOCK_QUIET):
            return
        async with lock:
            await self.run_callback(chat_id, msg_id, data)

    def action_lock(self) -> "asyncio.Lock":
        loop = asyncio.get_running_loop()
        lock = getattr(self, "_action_lock", None)
        if lock is None or getattr(lock, "_loop", loop) is not loop:
            lock = asyncio.Lock()
            self._action_lock = lock
        return lock

    async def run_callback(self, chat_id: int, msg_id: int, data: str) -> None:
        try:
            await asyncio.wait_for(self.route(chat_id, msg_id, data), ACTION_TIMEOUT)
        except asyncio.TimeoutError:
            await self.stuck(chat_id, msg_id, data)
            return
        except (PanelError, ModelError, ConfigError, RpcError, ShellError, FtError) as exc:
            message = getattr(exc, "message", str(exc))
            await self.render(chat_id, msg_id, screens.error_screen(self.view(), self.tr()("ERR_TITLE"), message))
            return
        except Exception as exc:
            log.exception("callback failed: %s", data)
            await self.render(chat_id, msg_id, screens.error_screen(self.view(), self.tr()("ERR_CRASH_TITLE"), f"{type(exc).__name__}: {exc}"))
            return
        if data.startswith("xr:") and not data.startswith(("xr:home", "xr:in:nav")):
            try:
                await self.subs_sync()
            except Exception as exc:
                log.debug("the subscription refresh was skipped: %s", exc)

    async def stuck(self, chat_id: int, msg_id: int, data: str) -> None:
        self.busy_end()
        self.audit.note(self.admin_id, data[:32], "timeout")
        try:
            await self.render(chat_id, msg_id, screens.stuck_screen(self.view(), data))
        except Exception as exc:
            log.warning("the stuck screen did not render: %s", exc)

    def slow_action(self, data: str) -> bool:
        text = str(data or "")
        if not text.startswith(LOADING_MARKS):
            return False
        return text not in LOADING_SKIP

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        try:
            await self.dispatch(chat_id, msg_id, data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("the route %s failed", str(data)[:40])
            self.audit.note(self.admin_id, str(data)[:32], "crash")
            try:
                await self.render(
                    chat_id,
                    msg_id,
                    screens.error_screen(self.view(), self.tr()("ERR_CRASH_TITLE"), f"{type(exc).__name__}: {exc}"),
                )
            except Exception as finer:
                log.warning("the crash screen was not shown: %s", finer)

    async def dispatch(self, chat_id: int, msg_id: int, data: str) -> None:
        parts = data.split(":")
        head = parts[0] if parts else ""
        if data.startswith("tools:"):
            await self.tools_action(chat_id, msg_id, data)
            return
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
        if name == "emoji":
            value = self.toggle_emoji()
            notice = self.tr()("NAV_EMOJI_ON" if value else "NAV_EMOJI_OFF")
            await self.render(chat_id, msg_id, screens.settings(self.view(notice=notice)))
            return
        await self.render(chat_id, msg_id, screens.settings(self.view()))

    async def language_action(self, chat_id: int, msg_id: int, action: str, code_value: str) -> None:
        choice = code_value or action
        if action == "set" and choice in i18n.LANGUAGES:
            self.state.language = i18n.normalize(choice)
            self.state.language_set = True
            self.save()
            if (
                self.app is not None
                and callable(getattr(self.app, "set_my_commands", None))
                and (not isinstance(self.app, GoyGram) or getattr(getattr(self.app, "api", None), "_session", None) is not None)
            ):
                try:
                    await self.register_commands()
                except Exception:
                    pass
            notice = i18n.t("LANG_CHANGED", self.language, name=i18n.t("LANG_NAME", self.language))
            await self.render(chat_id, msg_id, screens.language_screen(self.view(notice=notice)))
            return
        await self.render(chat_id, msg_id, screens.language_screen(self.view()))

    async def navigate(self, chat_id: int, msg_id: int, page: str) -> None:
        if page == "server" or page == "home":
            await self.ensure_cores_warm()
            await self.render(chat_id, msg_id, screens.home(self.view()))
            return
        if page == "ssh":
            await self.render(chat_id, msg_id, screens.sshd_screen(self.view()))
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
        if page == "emoji":
            value = self.toggle_emoji()
            notice = self.tr()("NAV_EMOJI_ON" if value else "NAV_EMOJI_OFF")
            await self.render(chat_id, msg_id, screens.settings(self.view(notice=notice)))
            return
        if page == "quick":
            await self.render(chat_id, msg_id, screens.settings(self.view()))
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
        if page == "tools":
            await self.debug.route(chat_id, msg_id, "dbg:home")
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
            await self.render(chat_id, msg_id, screens.update_screen(self.view(error=self.update_error), self.update_doc()))
            return
        if action in {"commit", "release"} and stage != "go":
            await self.refresh_update()
            preview: dict[str, object] = {}
            try:
                preview = await self.updater.preview(action)
            except UpdateError as exc:
                self.update_error = exc.message
            repo = str(self.update_info.get("repo") or "i-execute/OBHOD")
            branch = str(self.update_info.get("branch") or "")
            if action == "commit":
                from .ui import esc, ref_link

                commit = str(self.update_info.get("remote") or t("UI_NOT_SET"))
                body = t("UPD_CONFIRM_COMMIT", branch=esc(branch), commit=ref_link(commit, repo))
                target = "upd:commit:go"
            else:
                from .ui import ref_link

                tag = str(self.update_info.get("release") or "")
                if not tag:
                    reason = str(self.update_info.get("release_error") or t("UI_NONE"))
                    await self.render(
                        chat_id,
                        msg_id,
                        screens.update_screen(self.view(error=t("UPD_NO_RELEASE", reason=reason)), self.update_info),
                    )
                    return
                body = t("UPD_CONFIRM_RELEASE", tag=ref_link(tag, repo))
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
        if action == "reinstall":
            if stage != "go":
                await self.render(chat_id, msg_id, screens.update_confirm_screen(self.view(), self.update_info, {}, t("UPD_CONFIRM_REINSTALL"), "upd:reinstall:go"))
                return
            await self.run_update(chat_id, msg_id, "reinstall")
            return
        await self.render(chat_id, msg_id, screens.update_screen(self.view(), self.update_info))

    def update_doc(self) -> dict[str, Any]:
        doc = dict(self.update_info)
        doc["system"] = dict(getattr(self, "update_system", {}) or {})
        return doc

    async def refresh_system(self) -> None:
        try:
            self.update_system = await self.updater.describe()
            self.update_system["can_update"], self.update_system["why_not"] = await self.updater.can_update()
        except Exception as exc:
            log.debug("the system probe failed: %s", exc)
            self.update_system = {}

    async def refresh_update(self) -> None:
        if not self.update_system:
            await self.refresh_system()
        if self.update_info and not self.quiet("upd:check", UPDATE_QUIET):
            return
        self.update_error = ""
        try:
            found = await self.updater.check_all()
            self.update_info = found.to_dict()
        except UpdateError as exc:
            if "not a git checkout" in exc.message:
                self.update_info = {"git": False, "root": str(self.updater.root)}
                self.update_error = ""
            else:
                self.update_error = exc.message
        except (ShellError, OSError) as exc:
            self.update_error = str(exc)

    async def run_update(self, chat_id: int, msg_id: int, mode: str) -> None:
        t = self.tr()
        steps = [t("UPD_STEP_FETCH"), t("UPD_STEP_RESET"), t("UPD_STEP_CHECK"), t("UPD_STEP_DEPS"), t("UPD_STEP_RESTART")]
        await self.render(chat_id, msg_id, screens.busy_screen(t("UPD_BUSY"), self.language, steps))
        self.audit.note(self.admin_id, "upd:%s" % mode, "start")
        try:
            if mode == "reinstall":
                await self.refresh_system()
                probe_ok, probe_reason = True, ""
                try:
                    probe_ok, probe_reason = await self.updater.probe_reinstall()
                except UpdateError as exc:
                    probe_ok, probe_reason = False, exc.message
                if not probe_ok:
                    raise UpdateError(probe_reason or "the reinstall cannot start", "blocked")
                tail = await self.updater.reinstall()
                self.update_info = {"git": False}
                self.update_error = ""
                self.update_result = {"ok": True, "mode": "reinstall", "message": tail.splitlines()[-1] if tail.strip() else "", "log": tail.splitlines()[-12:]}
                self.audit.note(self.admin_id, "upd:reinstall", "ok")
                await self.render(chat_id, msg_id, screens.update_result_screen(self.view(), self.update_info, self.update_result))
                return
            result = await self.updater.apply(mode)
        except UpdateError as exc:
            self.audit.note(self.admin_id, "upd:%s" % mode, "failed")
            self.update_error = exc.message
            if mode == "reinstall":
                await self.refresh_system()
                hint = self.updater.reinstall_command(str(self.updater.env_file()) if self.updater.env_file().is_file() else "")
                code_value = getattr(exc, "code", "") or "failed"
                await self.render(
                    chat_id,
                    msg_id,
                    screens.update_result_screen(
                        self.view(),
                        self.update_info,
                        {
                            "ok": False,
                            "mode": mode,
                            "message": exc.message,
                            "hint": hint,
                            "readonly": code_value in {"readonly", "blocked"},
                            "failure": exc.to_dict() if hasattr(exc, "to_dict") else {"message": exc.message, "code": code_value},
                            "system": dict(self.update_system),
                        },
                    ),
                )
                return
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

    async def tools_action(self, chat_id: int, msg_id: int, data: str) -> None:
        parts = data.split(":")
        action = parts[1] if len(parts) > 1 else "home"
        sub = parts[2] if len(parts) > 2 else ""
        if action == "scan":
            await self.debug.route(chat_id, msg_id, "dbg:scan:go" if sub == "go" else "dbg:scan")
            return
        if action in ("chebur", "chk"):
            await self.debug.route(chat_id, msg_id, "dbg:chk:probe" if sub == "probe" else "dbg:chk")
            return
        if action == "dpi":
            await self.debug.route(chat_id, msg_id, "dbg:dpi:scan" if sub == "scan" else "dbg:dpi")
            return
        if action == "ddos":
            await self.debug.route(chat_id, msg_id, "dbg:dd:probe" if sub == "probe" else "dbg:dd")
            return
        if action == "fw":
            await self.freeturn.route(chat_id, msg_id, "ft:fw")
            return
        if action in ("fortress", "pentest"):
            await self.render(chat_id, msg_id, tools.fortress_screen(self.debug.view()))
            return
        await self.debug.route(chat_id, msg_id, "dbg:home")

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
