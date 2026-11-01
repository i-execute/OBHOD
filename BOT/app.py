from __future__ import annotations

import ipaddress
import logging
import socket
import time

from goygram import GoyGram

from . import ftscreens, i18n, inline, screens, xscreens
from .config import Config, ConfigError
from .freeturn import FtControl, FtError
from .ftpanel import FtPanel
from .guard import DEFAULT_BANTIME, BanState, GuardClient, SshState
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

log = logging.getLogger("obhod.app")

DRAFT_ID = 1
CLAIM_WINDOW = 900.0
INLINE_DUPLICATE_WINDOW = 8.0


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
        self.updater = updater or Updater(shell=shell, state_dir=cfg.state_dir)
        self.update_info: dict[str, object] = {}
        self.update_result: dict[str, object] = {}
        self.update_notice: dict[str, object] = {}
        self.update_error = ""
        self.app: GoyGram | None = None
        self.ban: BanState | None = None
        self.sshd: SshState | None = None
        self.busy = False
        self.started_at = time.monotonic()
        self.limiter = Limiter()
        self.audit = Audit(sink=SecurityLog())
        self.message_limit = MESSAGE_LIMIT
        self.callback_limit = CALLBACK_LIMIT
        self.expensive_limit = EXPENSIVE_LIMIT
        self.inline_limit = INLINE_LIMIT
        self.inline_seen: dict[tuple[str, str, str], float] = {}

    @property
    def admin_id(self) -> int:
        return int(self.cfg.admin_id or self.state.admin_id or 0)

    @property
    def language(self) -> str:
        return i18n.normalize(self.state.language)

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
        return self.state.xray.sub_address or public_address() or "127.0.0.1"

    def save(self) -> None:
        self.store.save(self.state)

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

    async def run(self) -> None:
        await self.verify_update()
        app = await self.boot()
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
        if msg_id:
            try:
                await self.app.edit_rich(chat_id, msg_id, rich, via="mt")
                return
            except Exception as exc:
                log.warning("edit failed: %s", exc)
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
        if not self.allowed(int(getattr(evt, "from_id", 0) or 0), "message", self.message_limit, 60.0):
            await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
            return
        text = str(getattr(evt, "text", "") or "")
        if text.startswith(inline.marker_text()):
            await self.on_marker(evt, text)
            return
        if self.busy:
            await self.toast(evt, self.tr()("TOAST_BUSY"), alert=True)
            return
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        if text.strip().startswith("/"):
            await self.on_command(evt)
            return
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
        if cmd == "id":
            who = int(getattr(evt, "from_id", 0) or 0)
            rich = screen(
                t("ID_TITLE"),
                t("ID_SUBTITLE"),
                [f"<p>{code(who)}</p>", quote(muted(t("ID_NOTE")))],
                [row(button(t("UI_HOME"), "nav:home"))],
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

    async def on_marker(self, evt: object, text: str) -> None:
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        msg_id = int(getattr(evt, "msg_id", 0) or 0)
        token, kind, index, body = inline.parse_payload(text)
        await self.drop_marker(chat_id, msg_id)
        if not token:
            return
        if self.busy:
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
            await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
            return
        data = str(getattr(evt, "data", "") or "")
        chat_id = int(getattr(evt, "chat_id", 0) or 0)
        msg_id = int(getattr(evt, "msg_id", 0) or 0)
        if self.busy and not data.startswith("nav:"):
            await self.toast(evt, self.tr()("TOAST_BUSY"), alert=True)
            return
        if not data.startswith("nav:") and not data.startswith("lang:"):
            if not self.audit.first_time(int(getattr(evt, "from_id", 0) or 0), data, time.monotonic()):
                await self.toast(evt, self.tr()("TOAST_REPEAT"), alert=True)
                return
            if not self.allowed(int(getattr(evt, "from_id", 0) or 0), "expensive", self.expensive_limit, 300.0):
                self.audit.note(int(getattr(evt, "from_id", 0) or 0), data, "throttled")
                await self.toast(evt, self.tr()("TOAST_RATE"), alert=True)
                return
        try:
            await self.route(chat_id, msg_id, data)
        except (PanelError, ModelError, ConfigError, RpcError, ShellError, FtError) as exc:
            message = getattr(exc, "message", str(exc))
            await self.render(chat_id, msg_id, screens.error_screen(self.view(), self.tr()("ERR_TITLE"), message))
        except Exception as exc:
            log.exception("callback failed: %s", data)
            await self.render(chat_id, msg_id, screens.error_screen(self.view(), self.tr()("ERR_CRASH_TITLE"), f"{type(exc).__name__}: {exc}"))

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        parts = data.split(":")
        head = parts[0] if parts else ""
        if head == "nav":
            await self.navigate(chat_id, msg_id, parts[1] if len(parts) > 1 else "home")
            return
        if head == "lang":
            await self.language_action(chat_id, msg_id, parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "")
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
        await self.render(chat_id, msg_id, screens.home(self.view(notice=self.tr()("HOME_NOTICE_UNKNOWN"))))

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
