from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from typing import Any

from . import antiddos, cores, dpi, dscreens, fwguard, guard, i18n, ipscan, net, notify, portguard, rkn_live, scripts
from .freeturn import FtError

SCAN_COOLDOWN = 3.0
TRACE_COOLDOWN = 3.0
VK_COOLDOWN = 10.0
SCRIPTS_COOLDOWN = 5.0
DPI_COOLDOWN = 8.0
DDOS_COOLDOWN = 15.0
NTF_COOLDOWN = 2.0
HP_COOLDOWN = 5.0
MAX_LOG = 12
DPI_LIMIT = 20.0
VK_LIMIT = 40.0
NET_LIMIT = 120.0
RKN_LIVE_INTERVAL = 10.0
RKN_LIVE_DURATION = 300.0


OFFLINE_CODES = {"network", "timeout", "unreachable", "rate_limited", "http_000"}


def offline(error: BaseException) -> bool:
    code = str(getattr(error, "code", "") or "")
    if code in OFFLINE_CODES:
        return True
    text = str(getattr(error, "message", "") or error or "").lower()
    return any(word in text for word in ("network is unreachable", "unreachable", "timed out", "timeout", "temporary failure", "connection refused"))


class DebugPanel:
    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.target = "1.1.1.1"
        self.ports = net.DEFAULT_PORTS
        self.hops = net.DEFAULT_HOPS
        self.scan: net.Answer | None = None
        self.trace: net.Answer | None = None
        self.vk: dict[str, Any] = {}
        self.report: scripts.Report = scripts.Report()
        self.owners: list[portguard.Owner] = []
        self.tag = ""
        self.notice = ""
        self.error = ""
        self.trace_text = ""
        self.events: list[str] = []
        self.marks: dict[str, float] = {}
        self.dpi: Any = None
        self.notify: Any = self.make_centre()
        self.honeypot: Any = None
        self.honey_busy = False
        self.ddos: Any = None
        self.ddos_exposure: Any = None
        self.ddos_busy = False
        self.ddos_page = 0
        self.ddos_in_ips = False
        self.rkn_sync_errors: list[str] = []
        self.rkn_live_tasks: dict[tuple[int, int], asyncio.Task[Any]] = {}
        self.ddos_reconcile_confirm: dict[tuple[int, int], tuple[str, str, float]] = {}
        self.ddos_wal_confirm: dict[tuple[int, int], tuple[str, str, float]] = {}
        self.ddos_adopt_confirm: dict[tuple[int, int], tuple[str, str, str, float]] = {}

    def make_centre(self) -> Any:
        centre = getattr(self.bot, "notify", None)
        if centre is not None:
            return centre
        return notify.Centre(notify.Settings.from_dict(getattr(self.bot.state, "notify", {})))

    def tr(self) -> i18n.Translator:
        return i18n.translator(getattr(self.bot.state, "language", i18n.DEFAULT_LANGUAGE))

    def view(self, notice: str = "", error: str = "") -> dscreens.DbgView:
        return dscreens.DbgView(
            scan=self.scan,
            trace=self.trace,
            vk=dict(self.vk),
            report=self.report,
            owners=list(self.owners),
            target=self.target,
            ports=self.ports,
            hops=self.hops,
            notice=notice or self.notice,
            error=error or self.error,
            trace_text=self.trace_text,
            dpi=self.dpi,
            notify=self.notify,
            honeypot=self.honeypot,
            honey_busy=self.honey_busy,
            ddos=self.ddos,
            ddos_exposure=self.ddos_exposure,
            ddos_busy=self.ddos_busy,
            ddos_page=self.ddos_page,
            ddos_alerts=bool(self.notify.settings.on(notify.KIND_DDOS)),
            ddos_bot_mismatch=bool(self.ddos is not None and self.ddos.installed and antiddos.firewall_policy_differs(antiddos.Policy.from_dict(getattr(self.bot.state, "ddos", {})), self.ddos.policy)),
            emoji=self.bot.emoji_enabled,
            lang=self.tr().language,
        )

    async def render(self, chat_id: int, msg_id: int, rich: Any) -> None:
        await self.bot.render(chat_id, msg_id, rich)

    def note(self, action: str, outcome: str, detail: str = "") -> None:
        try:
            self.bot.audit.note(int(self.bot.admin_id), "debug:%s" % action, outcome, detail[:64])
        except Exception:
            pass

    def remember(self, line: str) -> None:
        self.events.append("%s %s" % (time.strftime("%H:%M:%S", time.gmtime()), line[:80]))
        self.events = self.events[-MAX_LOG:]

    def cooled(self, name: str, span: float) -> bool:
        now = time.monotonic()
        last = self.marks.get(name, 0.0)
        if last and now - last < span:
            return False
        self.marks[name] = now
        return True

    def reset(self) -> None:
        self.notice = ""
        self.error = ""
        self.trace_text = ""

    def stop_rkn_live(self, chat_id: int, msg_id: int) -> None:
        task = self.rkn_live_tasks.pop((chat_id, msg_id), None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def render_rkn_live(self, chat_id: int, msg_id: int, rich: Any) -> None:
        app = getattr(self.bot, "app", None)
        if app is None:
            raise RuntimeError("Telegram session unavailable")
        try:
            await app.edit_rich(chat_id, msg_id, rich, via="mt")
        except Exception as exc:
            if "message is not modified" not in str(exc).lower():
                raise

    async def rkn_live(self, chat_id: int, msg_id: int, kind: str, initial: str) -> None:
        key = (chat_id, msg_id)
        text = initial
        deadline = time.monotonic() + RKN_LIVE_DURATION
        try:
            while time.monotonic() < deadline:
                await asyncio.sleep(min(RKN_LIVE_INTERVAL, max(0.0, deadline - time.monotonic())))
                if time.monotonic() >= deadline:
                    break
                client = guard.GuardClient(self.bot.control)
                response = await client._call(getattr(self.bot.state, "ssh", None), guard.DDOS_SCRIPT, "ddos script", ["logs", "--kind=" + kind], 30)
                text = str(response.data.get("text", ""))
                enabled = antiddos.Policy.from_dict(self.bot.state.ddos).rkn_logging
                await self.render_rkn_live(chat_id, msg_id, dscreens.ddos_logs_screen(self.view(), text, kind, enabled, live=True))
            enabled = antiddos.Policy.from_dict(self.bot.state.ddos).rkn_logging
            await self.render_rkn_live(chat_id, msg_id, dscreens.ddos_logs_screen(self.view(), text, kind, enabled))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            enabled = antiddos.Policy.from_dict(self.bot.state.ddos).rkn_logging
            error = str(getattr(exc, "message", exc))[:160]
            try:
                await self.render_rkn_live(chat_id, msg_id, dscreens.ddos_logs_screen(self.view(error=error), text, kind, enabled))
            except Exception:
                pass
        finally:
            if self.rkn_live_tasks.get(key) is asyncio.current_task():
                self.rkn_live_tasks.pop(key, None)

    async def rkn_live_stream(self, chat_id: int, msg_id: int, kind: str, initial: str, cursor: str, started_at: int) -> None:
        key = (chat_id, msg_id)
        lines = initial.splitlines()[-40:] if initial != "No journal entries" else []
        deadline = time.monotonic() + RKN_LIVE_DURATION
        next_update = time.monotonic() + RKN_LIVE_INTERVAL
        stream = rkn_live.journal_stream(self.bot.control.shell, kind, cursor, started_at)
        reader = asyncio.create_task(anext(stream))
        dirty = False
        try:
            while time.monotonic() < deadline:
                timeout = max(0.0, min(deadline, next_update) - time.monotonic())
                completed, _pending = await asyncio.wait({reader}, timeout=timeout)
                if completed:
                    line = reader.result()
                    lines.append(line)
                    lines = lines[-40:]
                    dirty = True
                    reader = asyncio.create_task(anext(stream))
                now = time.monotonic()
                if now >= next_update:
                    if dirty:
                        enabled = antiddos.Policy.from_dict(self.bot.state.ddos).rkn_logging
                        await self.render_rkn_live(chat_id, msg_id, dscreens.ddos_logs_screen(self.view(), "\n".join(lines), kind, enabled, live=True, stream=True))
                        dirty = False
                    next_update = now + RKN_LIVE_INTERVAL
            enabled = antiddos.Policy.from_dict(self.bot.state.ddos).rkn_logging
            await self.render_rkn_live(chat_id, msg_id, dscreens.ddos_logs_screen(self.view(), "\n".join(lines), kind, enabled))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            enabled = antiddos.Policy.from_dict(self.bot.state.ddos).rkn_logging
            error = str(getattr(exc, "message", exc))[:160]
            try:
                await self.render_rkn_live(chat_id, msg_id, dscreens.ddos_logs_screen(self.view(error=error), "\n".join(lines), kind, enabled))
            except Exception:
                pass
        finally:
            if not reader.done():
                reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
            await stream.aclose()
            if self.rkn_live_tasks.get(key) is asyncio.current_task():
                self.rkn_live_tasks.pop(key, None)

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        self.stop_rkn_live(chat_id, msg_id)
        parts = data.split(":")
        head = parts[1] if len(parts) > 1 else "home"
        arg1 = parts[2] if len(parts) > 2 else ""
        self.reset()
        try:
            if head in {"", "home"}:
                await self.render(chat_id, msg_id, dscreens.home(self.view()))
                return
            if head == "network":
                await self.render(chat_id, msg_id, dscreens.network_screen(self.view()))
                return
            if head == "diagnostics":
                await self.render(chat_id, msg_id, dscreens.diagnostics_screen(self.view()))
                return
            if head == "protect":
                await self.render(chat_id, msg_id, dscreens.protection_screen(self.view()))
                return
            if head == "scan":
                await self.scan_action(chat_id, msg_id, arg1)
                return
            if head == "trace":
                await self.trace_action(chat_id, msg_id, arg1)
                return
            if head == "vk":
                await self.vk_action(chat_id, msg_id, arg1)
                return
            if head == "scr":
                await self.scripts_action(chat_id, msg_id, arg1)
                return
            if head == "ports":
                await self.ports_action(chat_id, msg_id, arg1)
                return
            if head == "dpi":
                await self.dpi_action(chat_id, msg_id, arg1)
                return
            if head == "ntf":
                await self.notify_action(chat_id, msg_id, arg1)
                return
            if head == "dd":
                tail = data.split(":", 2)[2] if data.count(":") >= 2 else ""
                await self.ddos_action(chat_id, msg_id, tail)
                return
            if head == "hp":
                await self.honeypot_action(chat_id, msg_id, arg1)
                return
            if head == "info":
                await self.render(chat_id, msg_id, dscreens.info_screen(self.view(), self.clock()))
                return
            await self.render(chat_id, msg_id, dscreens.home(self.view(notice=self.tr()("HOME_NOTICE_UNKNOWN"))))
        except Exception as exc:
            self.note("route", "crash", type(exc).__name__)
            await self.crash(chat_id, msg_id, "dbg:%s" % head, exc)

    async def crash(self, chat_id: int, msg_id: int, route: str, exc: BaseException) -> None:
        self.error = "%s: %s" % (type(exc).__name__, str(exc)[:160])
        self.trace_text = net.trace_text(exc)
        payload = dscreens.crash_screen(self.view(), route, self.trace_text)
        await self.render(chat_id, msg_id, payload)

    def clock(self) -> dict[str, Any]:
        return {
            "pid": getattr(self.bot, "started_at", 0.0),
            "uptime": time.monotonic() - float(getattr(self.bot, "started_at", time.monotonic())),
            "address": self.bot.address() if hasattr(self.bot, "address") else "",
            "cores": cores.snapshot(getattr(self.bot, "state", None), dict(getattr(getattr(self.bot, "xray", None), "core", {}) or {}), 0),
        }

    async def scan_action(self, chat_id: int, msg_id: int, stage: str) -> None:
        if stage not in {"go", "again"}:
            await self.render(chat_id, msg_id, dscreens.scan_screen(self.view()))
            return
        if not self.cooled("scan", SCAN_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.scan_screen(self.view(notice=self.tr()("DBG_LIMIT"))))
            return
        t = self.tr()
        try:
            target = net.parse(self.target)
        except net.NetError as exc:
            await self.render(chat_id, msg_id, dscreens.scan_screen(self.view(error=t("DBG_BAD_TARGET") if exc.code == "bad_arg" else t("DBG_TOO_BIG"))))
            return
        try:
            ports = net.parse_ports(self.ports)
        except net.NetError as exc:
            await self.render(chat_id, msg_id, dscreens.scan_screen(self.view(error=exc.message)))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("DBG_SCAN_RUNNING", target=target.text)))
        started = time.monotonic()
        try:
            raw = await asyncio.wait_for(self.bot.freeturn.control.net_scan(target.text, ports), NET_LIMIT)
        except asyncio.TimeoutError:
            self.scan = net.Answer(kind="scan", target=target.text, error=t("STUCK_TITLE"))
            await self.render(chat_id, msg_id, dscreens.scan_screen(self.view()))
            return
        except FtError as exc:
            self.scan = net.Answer(kind="scan", target=target.text, error=self.describe(exc))
            await self.render(chat_id, msg_id, dscreens.scan_screen(self.view()))
            return
        self.scan = net.scan_raw(raw, target.text, time.monotonic() - started)
        self.scan.hosts = self.scan.hosts or target.count
        self.note("scan", "ok", "%s %d" % (target.text, len(self.scan.open_ports)))
        self.remember("scan %s" % target.text)
        await self.render(chat_id, msg_id, dscreens.scan_screen(self.view(notice=t("DBG_SCAN_DONE"))))

    async def trace_action(self, chat_id: int, msg_id: int, stage: str) -> None:
        if stage not in {"go", "again"}:
            await self.render(chat_id, msg_id, dscreens.trace_screen_view(self.view()))
            return
        if not self.cooled("trace", TRACE_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.trace_screen_view(self.view(notice=self.tr()("DBG_LIMIT"))))
            return
        t = self.tr()
        try:
            target = net.parse(self.target)
        except net.NetError:
            await self.render(chat_id, msg_id, dscreens.trace_screen_view(self.view(error=t("DBG_BAD_TARGET"))))
            return
        try:
            hops = net.parse_hops(self.hops)
        except net.NetError as exc:
            await self.render(chat_id, msg_id, dscreens.trace_screen_view(self.view(error=exc.message)))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("DBG_TRACE_RUNNING", target=target.text)))
        started = time.monotonic()
        try:
            raw = await asyncio.wait_for(self.bot.freeturn.control.net_trace(target.text, hops), NET_LIMIT)
        except asyncio.TimeoutError:
            self.trace = net.Answer(kind="trace", target=target.text, error=t("STUCK_TITLE"))
            await self.render(chat_id, msg_id, dscreens.trace_screen_view(self.view()))
            return
        except FtError as exc:
            self.trace = net.Answer(kind="trace", target=target.text, error=self.describe(exc))
            await self.render(chat_id, msg_id, dscreens.trace_screen_view(self.view()))
            return
        self.trace = net.trace_raw(raw, target.text, time.monotonic() - started)
        self.note("trace", "ok", target.text)
        self.remember("trace %s" % target.text)
        await self.render(chat_id, msg_id, dscreens.trace_screen_view(self.view(notice=t("DBG_SCAN_DONE"))))

    async def vk_action(self, chat_id: int, msg_id: int, stage: str) -> None:
        if stage == "apply":
            await self.vk_apply(chat_id, msg_id)
            return
        if stage not in {"go", "again"}:
            await self.render(chat_id, msg_id, dscreens.vk_screen(self.view()))
            return
        if not self.cooled("vk", VK_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.vk_screen(self.view(notice=self.tr()("DBG_LIMIT"))))
            return
        t = self.tr()
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("DBG_VK_RUNNING")))
        fwguard.clear()
        try:
            cidrs, reason = await asyncio.wait_for(asyncio.to_thread(fwguard.vk_cidrs), VK_LIMIT)
        except (OSError, asyncio.TimeoutError):
            cidrs, reason = [], "unreachable"
        old = {str(item) for item in (self.vk.get("applied") or [])}
        fresh = set(cidrs)
        self.vk = {
            "cidrs": cidrs,
            "reason": reason,
            "domains": [holder for _asn, holder in fwguard.ASNS],
            "asns": fwguard.holders(),
            "added": sorted(fresh - old)[:64] if old else list(cidrs)[:64],
            "removed": sorted(old - fresh)[:32],
            "changed": bool(old) and fresh != old,
            "checked_at": time.time(),
        }
        self.note("vk", "ok" if cidrs else "fail", str(len(cidrs)))
        self.remember("vk %d" % len(cidrs))
        await self.render(chat_id, msg_id, dscreens.vk_screen(self.view(notice=t("DBG_VK_CHANGED") if self.vk["changed"] else t("DBG_VK_SAME"))))

    async def vk_apply(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        cidrs = self.vk.get("cidrs") or []
        if not cidrs:
            await self.render(chat_id, msg_id, dscreens.vk_screen(self.view(error=t("DBG_VK_SAME"))))
            return
        port = int(getattr(getattr(self.bot.state, "freeturn", None), "config", None).listen_port or 0) if getattr(self.bot.state, "freeturn", None) else 0
        if not port:
            await self.render(chat_id, msg_id, dscreens.vk_screen(self.view(error=t("FT_ERR_NOT_INSTALLED"))))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("DBG_VK_RUNNING")))
        try:
            keep = self.keep_ports()
            try:
                portguard.check(port, keep, "vk")
            except portguard.PortError:
                await self.render(chat_id, msg_id, dscreens.vk_screen(self.view(error=t("FT_CODE_PORT_PROTECTED"))))
                return
            guard = await self.bot.freeturn.control.firewall("vk", port, fwguard.join_cidrs(cidrs), keep=portguard.join(keep))
        except FtError as exc:
            await self.render(chat_id, msg_id, dscreens.vk_screen(self.view(error=self.describe(exc))))
            return
        self.vk["applied"] = list(cidrs)
        self.vk["guard"] = guard.to_dict() if hasattr(guard, "to_dict") else {}
        if hasattr(self.bot, "freeturn"):
            self.bot.freeturn.guard = dict(self.vk["guard"])
        self.note("vk", "applied", str(len(cidrs)))
        await self.render(chat_id, msg_id, dscreens.vk_screen(self.view(notice=t("DBG_VK_CHANGED"))))

    def dpi_inputs(self) -> tuple[list[str], list[str], str]:
        xray = getattr(self.bot.state, "xray", None)
        book = dict(getattr(xray, "last_core", {}) or {})
        return dpi.collect(getattr(xray, "inbounds", []), book)

    async def dpi_geo(self) -> dict[str, str]:
        address = ""
        try:
            address = str(self.bot.address() or "")
        except Exception:
            address = ""
        if not address:
            return {}
        try:
            metadata = await asyncio.to_thread(ipscan.fetch_ip_api, address)
        except Exception:
            return {}
        return {"asn": str(metadata.get("as") or ""), "organisation": str(metadata.get("org") or ""), "country": str(metadata.get("country") or "")}

    async def dpi_action(self, chat_id: int, msg_id: int, stage: str) -> None:
        t = self.tr()
        if stage not in {"scan", "again"}:
            await self.render(chat_id, msg_id, dscreens.dpi_screen(self.view()))
            return
        if not self.cooled("dpi", DPI_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.dpi_screen(self.view(notice=t("DBG_LIMIT"))))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view()))
        marks, networks, version = self.dpi_inputs()
        try:
            state = await asyncio.wait_for(asyncio.to_thread(dpi.kernel_state), DPI_LIMIT)
        except (OSError, asyncio.TimeoutError, ValueError):
            state = {}
        try:
            geo = await asyncio.wait_for(self.dpi_geo(), DPI_LIMIT)
        except (OSError, asyncio.TimeoutError):
            geo = {}
        self.dpi = dpi.assess(
            fingerprints=marks,
            networks=networks,
            core=version,
            asn=geo.get("asn", ""),
            organisation=geo.get("organisation", ""),
            country=geo.get("country", ""),
            kernel=state,
        )
        self.note("dpi", self.dpi.level(), dpi.quote_summary(self.dpi)[:64])
        self.remember("dpi %s" % dpi.quote_summary(self.dpi))
        await self.render(chat_id, msg_id, dscreens.dpi_screen(self.view()))

    def save_notify(self) -> None:
        try:
            self.bot.state.notify = self.notify.settings.to_dict()
            self.bot.save()
        except Exception:
            pass

    async def notify_action(self, chat_id: int, msg_id: int, action: str) -> None:
        t = self.tr()
        self.honey_busy = False
        if action in ("", "open"):
            await self.render(chat_id, msg_id, dscreens.notify_screen(self.view()))
            return
        if action == "test":
            if not self.cooled("ntf:test", NTF_COOLDOWN):
                await self.render(chat_id, msg_id, dscreens.notify_screen(self.view(notice=t("DBG_LIMIT"))))
                return
            event = notify.Event(notify.KIND_CORE, address="0.0.0.0", detail=t("NTF_TEST_TITLE"), at=0.0)
            sent = await self.bot.notify_send(event, test=True)
            self.note("ntf", "test", "sent" if sent else "no-owner")
            await self.render(chat_id, msg_id, dscreens.notify_screen(self.view(notice=t("NTF_TEST_LINE") if sent else t("NTF_OWNER_RULE"))))
            return
        if action in ("on", "off"):
            for kind in notify.KINDS:
                self.notify.settings.enabled[kind] = action == "on"
            self.notify.settings.mute_until = 0.0
            self.save_notify()
            self.note("ntf", action, "all")
            await self.render(chat_id, msg_id, dscreens.notify_screen(self.view()))
            return
        if action in notify.KINDS:
            value = self.notify.toggle(action)
            self.save_notify()
            key = "NTF_TOAST_ON" if value else "NTF_TOAST_OFF"
            self.note("ntf", action, "on" if value else "off")
            await self.render(chat_id, msg_id, dscreens.notify_screen(self.view(notice=t(key, value=dscreens.notify_kind_label(t, action)))))
            return
        await self.render(chat_id, msg_id, dscreens.notify_screen(self.view(error=t("HOME_NOTICE_UNKNOWN"))))

    async def honey_refresh(self) -> None:
        cfg = getattr(self.bot.state, "ssh", None)
        client = guard.GuardClient(self.bot.control)
        try:
            self.honeypot = await guard.honey_call(client, cfg, guard.honey_argv("status"), 120)
        except Exception as exc:
            self.honeypot = None
            self.error = str(getattr(exc, "message", exc))[:160]

    async def honeypot_action(self, chat_id: int, msg_id: int, action: str) -> None:
        t = self.tr()
        self.honey_busy = False
        if action in ("", "open", "refresh"):
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            await self.honey_refresh()
            await self.render(chat_id, msg_id, dscreens.honeypot_screen(self.view()))
            return
        mapping = {"install": "install", "start": "start", "stop": "stop", "remove": "remove", "check": "selfcheck"}
        if action not in mapping:
            await self.render(chat_id, msg_id, dscreens.honeypot_screen(self.view(error=t("HOME_NOTICE_UNKNOWN"))))
            return
        if not self.cooled("hp:" + action, HP_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.honeypot_screen(self.view(notice=t("DBG_LIMIT"))))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view()))
        client = guard.GuardClient(self.bot.control)
        cfg = getattr(self.bot.state, "ssh", None)
        try:
            await guard.honey_call(client, cfg, guard.honey_argv(mapping[action]), 300)
        except Exception as exc:
            message = str(getattr(exc, "message", exc))
            self.honey_busy = "busy" in message or getattr(exc, "code", "") == "port_busy"
            self.note("hp", action, "fail")
            self.error = message[:160]
            await self.render(chat_id, msg_id, dscreens.honeypot_screen(self.view()))
            return
        self.error = ""
        self.note("hp", action, "ok")
        await self.honey_refresh()
        await self.render(chat_id, msg_id, dscreens.honeypot_screen(self.view(notice=self.tr()("HP_TITLE"))))

    async def ddos_refresh(self, probe: bool = False) -> None:
        client = guard.GuardClient(self.bot.control)
        cfg = getattr(self.bot.state, "ssh", None)
        try:
            self.ddos = await guard.ddos_call(client, cfg, guard.ddos_argv("status"), 120)
        except Exception as exc:
            self.ddos = None
            self.error = str(getattr(exc, "message", exc))[:160]
        if probe:
            try:
                allow = portguard.protected_ports(self.bot.state) + [int(getattr(self.bot.state.xray, "api_port", 0) or 0)]
                self.ddos_exposure = await guard.ddos_exposure(client, cfg, allow)
            except Exception as exc:
                self.ddos_exposure = []
                self.error = str(getattr(exc, "message", exc))[:160]

    def _protected_rkn_ips(self) -> list[str]:
        protected: list[str] = []
        state = getattr(self.bot, "state", None)
        if state is None:
            return protected
        candidates = (
            getattr(getattr(state, "ssh", None), "host", ""),
            getattr(getattr(state, "xray", None), "sub_address", ""),
            getattr(getattr(getattr(state, "freeturn", None), "config", None), "host", ""),
        )
        for item in candidates:
            cleaned = antiddos.clean_entry(str(item or ""), allow_private=True)
            if cleaned and cleaned not in protected:
                protected.append(cleaned)
        return protected

    def rkn_source_cache(self) -> dict[str, Any]:
        path = getattr(getattr(self.bot, "store", None), "path", None)
        if not path:
            return {}
        target = path.parent / "rkn_sources_cache.json"
        try:
            if target.is_symlink() or target.stat().st_size > 32 * antiddos.MAX_RKN_BYTES:
                return {}
            data = json.loads(target.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    async def auto_sync_rkn(self) -> tuple[int, int, int]:
        policy = antiddos.Policy.from_dict(getattr(self.bot.state, "ddos", {}))
        client = guard.GuardClient(self.bot.control)
        cfg = getattr(self.bot.state, "ssh", None)
        observed = await guard.ddos_call(client, cfg, ["status"], 60)
        if observed.transaction_state != "none" or observed.table_inspection == "unknown" or (observed.table and not observed.installed) or (observed.installed and antiddos.firewall_policy_differs(policy, observed.policy)) or observed.saved_policy_consistency in ("mismatch", "unknown") or observed.live_rate_consistency in ("mismatch", "unknown"):
            raise antiddos.DDoSerror("firewall policy needs review before source update")
        digest = observed.policy_sha256
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise antiddos.DDoSerror("firewall policy digest is unavailable; source update cancelled")
        extra = [*self._protected_rkn_ips(), *policy.rkn_allow]
        v4, v6, ok_sources, errors = await asyncio.to_thread(
            antiddos.fetch_rkn_subnets,
            custom_sources=policy.custom_sources,
            extra_protected=extra,
            timeout=10.0,
            cache_path=getattr(getattr(self.bot, "store", None), "path", None).parent / "rkn_sources_cache.json" if getattr(getattr(self.bot, "store", None), "path", None) else None,
            disabled_sources=policy.disabled_sources,
        )
        current = antiddos.Policy.from_dict(getattr(self.bot.state, "ddos", {}))
        if antiddos.firewall_policy_differs(current, policy) or (current.custom_sources, current.disabled_sources) != (policy.custom_sources, policy.disabled_sources):
            raise antiddos.DDoSerror("RKN policy changed during update; retry")
        zhex = antiddos.encode_rkn_zhex(v4, v6)
        args = ["rkn-sync", "--rkn_zhex=-", "--expected_policy_sha=" + digest]
        if any("(no cache)" in err or "(cached)" not in err for err in errors):
            args.append("--preserve_existing=1")
        status = await guard.ddos_call(
            client,
            cfg,
            args,
            240,
            stdin=zhex.encode("ascii"),
        )
        self.rkn_sync_errors = list(errors)
        self.ddos = status
        if hasattr(self.bot, "ddos_state"):
            self.bot.ddos_state = status
        self.note("dd", "rkn_sync", "%d+%d" % (len(v4), len(v6)))
        return len(v4), len(v6), ok_sources

    async def _mutate_ddos_entries(self, chat_id: int, field_name: str, raw_value: str, *, allow_private: bool) -> None:
        t = self.tr()
        token = str(raw_value or "").strip()
        policy = antiddos.Policy.from_dict(self.bot.state.ddos)
        items = list(getattr(policy, field_name) or [])
        target_screen = dscreens.ddos_ips_screen if self.ddos_in_ips else dscreens.ddos_screen
        if token.lower() in {"clear", "none", "reset"}:
            items = []
            notice = "%s: 0" % field_name
        else:
            remove_explicit = token.startswith("-")
            if token[:1] in {"+", "-"}:
                token = token[1:].strip()
            cleaned = antiddos.clean_entry(token, allow_private=allow_private)
            if not cleaned or (not allow_private and cleaned in self._protected_rkn_ips()):
                await self.bot.send(chat_id, target_screen(self.view(error=t("DDOS_BAD_ENTRY"))))
                return
            if remove_explicit or cleaned in items:
                items = [entry for entry in items if entry != cleaned]
                notice = "-%s" % cleaned
            else:
                if len(items) >= antiddos.MAX_CUSTOM_ENTRIES:
                    await self.bot.send(chat_id, target_screen(self.view(error=t("DDOS_LIST_FULL"))))
                    return
                items.append(cleaned)
                notice = "+%s" % cleaned
                if field_name == "manual_bans":
                    policy.rkn_allow = [entry for entry in policy.rkn_allow if entry != cleaned]
                    policy.unbanned = [entry for entry in policy.unbanned if entry != cleaned]
                elif field_name == "rkn_allow":
                    policy.manual_bans = [entry for entry in policy.manual_bans if entry != cleaned]
        setattr(policy, field_name, items)
        policy.normalise()
        if self.ddos is not None and self.ddos.installed:
            client = guard.GuardClient(self.bot.control)
            cfg = getattr(self.bot.state, "ssh", None)
            try:
                self.ddos = await guard.ddos_call(client, cfg, guard.ddos_argv("install", policy), 240)
                if hasattr(self.bot, "ddos_state"):
                    self.bot.ddos_state = self.ddos
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                self.note("dd", field_name, "fail")
                await self.bot.send(chat_id, target_screen(self.view()))
                return
        elif self.ddos is not None:
            self.ddos.policy = policy
        self.bot.state.ddos = policy.to_dict()
        if hasattr(self.bot, "save"):
            self.bot.save()
        self.note("dd", field_name, notice)
        await self.bot.send(chat_id, target_screen(self.view(notice=notice)))

    def _resolve_ddos_token(self, token: str) -> str:
        raw = str(token or "").strip()
        return "" if raw.startswith("@") else raw

    async def _toggle_ddos_ip(self, chat_id: int, msg_id: int, mode: str, page_str: str, token: str) -> None:
        t = self.tr()
        try:
            self.ddos_page = max(0, int(page_str or "0"))
        except ValueError:
            self.ddos_page = 0
        self.ddos_in_ips = True
        target = self._resolve_ddos_token(token)
        allow_priv = mode == "ub"
        cleaned = antiddos.clean_entry(target, allow_private=allow_priv)
        if not cleaned or (mode == "rb" and cleaned in self._protected_rkn_ips()):
            await self.render(chat_id, msg_id, dscreens.ddos_ips_screen(self.view(error=t("DDOS_BAD_ENTRY"))))
            return
        records = self.ddos.ip_records() if self.ddos is not None else []
        if not any(item.address == cleaned and item.blocked == (mode == "ub") for item in records):
            await self.render(chat_id, msg_id, dscreens.ddos_ips_screen(self.view(error=t("DDOS_IP_STALE"))))
            return
        policy = antiddos.Policy.from_dict(self.bot.state.ddos)
        if mode == "ub":
            policy.manual_bans = [item for item in policy.manual_bans if item != cleaned]
            if cleaned not in policy.rkn_allow:
                if len(policy.rkn_allow) >= antiddos.MAX_CUSTOM_ENTRIES:
                    await self.render(chat_id, msg_id, dscreens.ddos_ips_screen(self.view(error=t("DDOS_LIST_FULL"))))
                    return
                policy.rkn_allow.append(cleaned)
            policy.unbanned = [cleaned, *[item for item in policy.unbanned if item != cleaned]][:64]
            cmd_name = "unban"
            toast = t("DDOS_TOAST_UNBANNED", ip=cleaned)
        else:
            policy.rkn_allow = [item for item in policy.rkn_allow if item != cleaned]
            policy.unbanned = [item for item in policy.unbanned if item != cleaned]
            if cleaned not in policy.manual_bans:
                if len(policy.manual_bans) >= antiddos.MAX_CUSTOM_ENTRIES:
                    await self.render(chat_id, msg_id, dscreens.ddos_ips_screen(self.view(error=t("DDOS_LIST_FULL"))))
                    return
                policy.manual_bans.append(cleaned)
            cmd_name = "reban"
            toast = t("DDOS_TOAST_REBANNED", ip=cleaned)
        policy.normalise()
        if self.ddos is not None and self.ddos.installed:
            client = guard.GuardClient(self.bot.control)
            cfg = getattr(self.bot.state, "ssh", None)
            try:
                self.ddos = await guard.ddos_call(client, cfg, [cmd_name, "--ip=" + cleaned], 120)
                if hasattr(self.bot, "ddos_state"):
                    self.bot.ddos_state = self.ddos
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                self.note("dd", cmd_name, "fail")
                await self.render(chat_id, msg_id, dscreens.ddos_ips_screen(self.view()))
                return
        elif self.ddos is not None:
            if mode == "ub":
                for bucket in ("syn_flood", "conn_flood", "udp_flood", "icmp_flood", "scan"):
                    cur = list(getattr(self.ddos, bucket, []) or [])
                    if cleaned in cur:
                        setattr(self.ddos, bucket, [item for item in cur if item != cleaned])
            self.ddos.policy = policy
        self.bot.state.ddos = policy.to_dict()
        if hasattr(self.bot, "save"):
            self.bot.save()
        self.note("dd", cmd_name, cleaned)
        await self.render(chat_id, msg_id, dscreens.ddos_ips_screen(self.view(notice=toast)))

    async def _scan_ddos_ip(self, chat_id: int, msg_id: int, page_str: str, raw_target: str) -> None:
        t = self.tr()
        try:
            self.ddos_page = max(0, int(page_str or "0"))
        except ValueError:
            self.ddos_page = 0
        self.ddos_in_ips = True
        target = ipscan.scan_ip(raw_target)
        records = self.ddos.ip_records() if self.ddos is not None else []
        if not target or target not in {ipscan.ip_target(item.address) for item in records}:
            await self.render(chat_id, msg_id, dscreens.ddos_ips_screen(self.view(error=t("IPSCAN_ERR_BAD"))))
            return
        repeat = f"dbg:dd:ipscan:{self.ddos_page}:{target}"
        await self.bot.run_callback_ipscan(
            None,
            chat_id,
            msg_id,
            target,
            back=f"dbg:dd:ips:{self.ddos_page}",
            retry=repeat,
        )

    async def ddos_action(self, chat_id: int, msg_id: int, action: str) -> None:
        t = self.tr()
        self.ddos_busy = False
        key = (chat_id, msg_id)
        if action != "adopt_policy" and not action.startswith("adopt_do:"):
            self.ddos_adopt_confirm.pop(key, None)
        if action != "wal_recover" and not action.startswith("wal_do:"):
            self.ddos_wal_confirm.pop(key, None)
        if action != "reconcile" and not action.startswith("reconcile_do:"):
            self.ddos_reconcile_confirm.pop(key, None)
        if action == "adopt_policy":
            self.ddos_adopt_confirm.pop(key, None)
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                client = guard.GuardClient(self.bot.control)
                current = await guard.ddos_call(client, getattr(self.bot.state, "ssh", None), ["status"], 60)
                digest = current.policy_sha256
                if not current.installed or current.transaction_state != "none" or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    raise ValueError(t("DDOS_ADOPT_UNAVAILABLE"))
                local = antiddos.Policy.from_dict(self.bot.state.ddos)
                if not antiddos.firewall_policy_differs(local, current.policy):
                    raise ValueError(t("DDOS_ADOPT_UNAVAILABLE"))
                local_sha = hashlib.sha256(json.dumps(local.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
                now = time.monotonic()
                for pending, item in list(self.ddos_adopt_confirm.items()):
                    if pending[0] == chat_id or item[3] < now:
                        self.ddos_adopt_confirm.pop(pending, None)
                if len(self.ddos_adopt_confirm) >= 64:
                    oldest = min(self.ddos_adopt_confirm, key=lambda item: self.ddos_adopt_confirm[item][3])
                    self.ddos_adopt_confirm.pop(oldest, None)
                token = secrets.token_hex(8)
                self.ddos_adopt_confirm[key] = (token, digest, local_sha, now + 120.0)
                self.ddos = current
                self.error = ""
                await self.render(chat_id, msg_id, dscreens.ddos_adopt_screen(self.view(), current, token))
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if action.startswith("adopt_do:"):
            confirm = self.ddos_adopt_confirm.pop(key, None)
            token = action.split(":", 1)[1]
            if not confirm or not secrets.compare_digest(token, confirm[0]) or time.monotonic() > confirm[3]:
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(error=t("DDOS_RECONCILE_STALE"))))
                return
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                client = guard.GuardClient(self.bot.control)
                current = await guard.ddos_call(client, getattr(self.bot.state, "ssh", None), ["status"], 60)
                local = antiddos.Policy.from_dict(self.bot.state.ddos)
                local_sha = hashlib.sha256(json.dumps(local.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
                if not current.installed or current.transaction_state != "none" or current.policy_sha256 != confirm[1] or local_sha != confirm[2]:
                    raise ValueError(t("DDOS_RECONCILE_STALE"))
                merged = current.policy.to_dict()
                merged["custom_sources"] = local.custom_sources
                merged["disabled_sources"] = local.disabled_sources
                previous = self.bot.state.ddos
                self.bot.state.ddos = antiddos.Policy.from_dict(merged).to_dict()
                try:
                    self.bot.save()
                except Exception:
                    self.bot.state.ddos = previous
                    raise
                self.ddos = current
                if hasattr(self.bot, "ddos_state"):
                    self.bot.ddos_state = current
                self.error = ""
                self.note("dd", "adopt_policy", "ok")
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=t("DDOS_ADOPT_DONE"))))
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                self.note("dd", "adopt_policy", "fail")
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if action == "wal_recover":
            self.ddos_wal_confirm.pop(key, None)
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                client = guard.GuardClient(self.bot.control)
                current = await guard.ddos_call(client, getattr(self.bot.state, "ssh", None), ["status"], 60)
                digest = current.transaction_digest
                if current.transaction_state not in ("automatic", "manual") or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    raise ValueError(t("DDOS_WAL_UNAVAILABLE"))
                now = time.monotonic()
                for pending, item in list(self.ddos_wal_confirm.items()):
                    if pending[0] == chat_id or item[2] < now:
                        self.ddos_wal_confirm.pop(pending, None)
                if len(self.ddos_wal_confirm) >= 64:
                    oldest = min(self.ddos_wal_confirm, key=lambda item: self.ddos_wal_confirm[item][2])
                    self.ddos_wal_confirm.pop(oldest, None)
                token = secrets.token_hex(8)
                self.ddos_wal_confirm[key] = (token, digest, now + 120.0)
                self.ddos = current
                self.error = ""
                await self.render(chat_id, msg_id, dscreens.ddos_wal_screen(self.view(), current, token))
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if action.startswith("wal_do:"):
            confirm = self.ddos_wal_confirm.pop(key, None)
            token = action.split(":", 1)[1]
            if not confirm or not secrets.compare_digest(token, confirm[0]) or time.monotonic() > confirm[2]:
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(error=t("DDOS_RECONCILE_STALE"))))
                return
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                client = guard.GuardClient(self.bot.control)
                await client._call(getattr(self.bot.state, "ssh", None), guard.DDOS_SCRIPT, "ddos script", ["recover-policy", "--expected_sha=" + confirm[1]], 180)
                self.error = ""
                await self.ddos_refresh(probe=False)
                if self.ddos is None or self.error:
                    raise ValueError(t("DDOS_WAL_STATUS_FAILED"))
                if hasattr(self.bot, "ddos_state"):
                    self.bot.ddos_state = self.ddos
                self.note("dd", "wal_recover", "ok")
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=t("DDOS_WAL_DONE"))))
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                self.note("dd", "wal_recover", "fail")
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if action == "reconcile":
            self.ddos_reconcile_confirm.pop(key, None)
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                client = guard.GuardClient(self.bot.control)
                current = await guard.ddos_call(client, getattr(self.bot.state, "ssh", None), ["status"], 60)
                fingerprint = current.reconcile_fingerprint
                if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
                    raise ValueError(t("DDOS_RECONCILE_UNAVAILABLE"))
                now = time.monotonic()
                for pending, item in list(self.ddos_reconcile_confirm.items()):
                    if pending[0] == chat_id or item[2] < now:
                        self.ddos_reconcile_confirm.pop(pending, None)
                if len(self.ddos_reconcile_confirm) >= 64:
                    oldest = min(self.ddos_reconcile_confirm, key=lambda item: self.ddos_reconcile_confirm[item][2])
                    self.ddos_reconcile_confirm.pop(oldest, None)
                token = secrets.token_hex(8)
                self.ddos_reconcile_confirm[key] = (token, fingerprint, now + 120.0)
                self.ddos = current
                self.error = ""
                await self.render(chat_id, msg_id, dscreens.ddos_reconcile_screen(self.view(), current, token))
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if action.startswith("reconcile_do:"):
            confirm = self.ddos_reconcile_confirm.pop(key, None)
            token = action.split(":", 1)[1]
            if not confirm or not secrets.compare_digest(token, confirm[0]) or time.monotonic() > confirm[2]:
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(error=t("DDOS_RECONCILE_STALE"))))
                return
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                client = guard.GuardClient(self.bot.control)
                self.ddos = await guard.ddos_call(client, getattr(self.bot.state, "ssh", None), ["reconcile", "--expected_sha=" + confirm[1]], 180)
                if hasattr(self.bot, "ddos_state"):
                    self.bot.ddos_state = self.ddos
                self.error = ""
                self.note("dd", "reconcile", "ok")
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=t("DDOS_RECONCILE_DONE"))))
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                self.note("dd", "reconcile", "fail")
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if action in ("", "open", "refresh"):
            self.ddos_in_ips = False
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            await self.ddos_refresh(probe=action == "open")
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if action in ("schedule", "sched12", "sched6", "schedoff"):
            client = guard.GuardClient(self.bot.control)
            cfg = getattr(self.bot.state, "ssh", None)
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                argv = ["schedule-status"] if action == "schedule" else ["schedule-set", "--mode=" + ("off" if action == "schedoff" else ("calendar" if action == "sched6" else "hours")), "--value=" + ("06:00" if action == "sched6" else "12")]
                response = await client._call(cfg, guard.DDOS_SCRIPT, "ddos script", argv, 60)
                schedule = response.data
                for current in (self.ddos, getattr(self.bot, "ddos_state", None)):
                    if current is not None:
                        current.timer_active = bool(schedule.get("active"))
                        current.timer_configured = bool(schedule.get("configured"))
                        current.timer_mode = str(schedule.get("mode", ""))
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                schedule = {}
            await self.render(chat_id, msg_id, dscreens.ddos_schedule_screen(self.view(), schedule))
            return
        if action == "exceptions":
            await self.render(chat_id, msg_id, dscreens.ddos_exceptions_screen(self.view(), antiddos.Policy.from_dict(self.bot.state.ddos)))
            return
        if action == "src" or action.startswith("src:"):
            policy = antiddos.Policy.from_dict(self.bot.state.ddos)
            parts = action.split(":")
            page = 0
            if len(parts) == 3 and parts[1] == "p":
                try:
                    page = max(0, int(parts[2]))
                except ValueError:
                    page = 0
            elif len(parts) == 3 and parts[1] in ("t", "d"):
                entries = [url for _, url in antiddos.RKN_SOURCES] + policy.custom_sources
                matches = [url for url in entries if hashlib.sha256(url.encode("utf-8")).hexdigest()[:12] == parts[2]]
                if len(matches) != 1:
                    self.error = t("DDOS_SOURCE_STALE")
                else:
                    url = matches[0]
                    if parts[1] == "d":
                        if url not in policy.custom_sources:
                            self.error = t("DDOS_SOURCE_STALE")
                        elif url not in policy.disabled_sources and len([item for item in entries if item not in policy.disabled_sources]) <= 1:
                            self.error = t("DDOS_SOURCE_LAST")
                        else:
                            policy.custom_sources.remove(url)
                            policy.disabled_sources = [item for item in policy.disabled_sources if item != url]
                    elif url in policy.disabled_sources:
                        policy.disabled_sources.remove(url)
                    elif len([item for item in entries if item not in policy.disabled_sources]) <= 1:
                        self.error = t("DDOS_SOURCE_LAST")
                    else:
                        policy.disabled_sources.append(url)
                    if not self.error:
                        self.bot.state.ddos = policy.to_dict()
                        if hasattr(self.bot, "save"):
                            self.bot.save()
                        if self.ddos is not None and self.ddos.installed and policy.enabled and policy.rkn_enabled:
                            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
                            try:
                                await self.auto_sync_rkn()
                                if self.rkn_sync_errors:
                                    self.error = t("DDOS_RKN_PARTIAL", errors=len(self.rkn_sync_errors))
                            except Exception as exc:
                                self.error = str(getattr(exc, "message", exc))[:160]
            await self.render(chat_id, msg_id, dscreens.ddos_sources_screen(self.view(), policy, page, self.rkn_source_cache()))
            return
        if action == "log_toggle":
            policy = antiddos.Policy.from_dict(self.bot.state.ddos)
            policy.rkn_logging = not policy.rkn_logging
            try:
                if self.ddos is not None and self.ddos.installed:
                    client = guard.GuardClient(self.bot.control)
                    self.ddos = await guard.ddos_call(client, getattr(self.bot.state, "ssh", None), guard.ddos_argv("install", policy), 300)
                    if hasattr(self.bot, "ddos_state"):
                        self.bot.ddos_state = self.ddos
                self.bot.state.ddos = policy.to_dict()
                if hasattr(self.bot, "save"):
                    self.bot.save()
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
            action = "logs:v4"
        if action in ("upstream", "upstream_confirm", "upstream_install"):
            if action == "upstream_confirm":
                await self.render(chat_id, msg_id, dscreens.ddos_upstream_screen(self.view(), {}, confirm=True))
                return
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                client = guard.GuardClient(self.bot.control)
                response = await client._call(getattr(self.bot.state, "ssh", None), guard.RKN_UPSTREAM_SCRIPT, "upstream rkn-guard script", ["install" if action == "upstream_install" else "status"], 240 if action == "upstream_install" else 30)
                data = response.data
                if action == "upstream_install":
                    self.note("dd", "upstream_install", "ok")
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                data = {}
                self.note("dd", "upstream", "fail")
            await self.render(chat_id, msg_id, dscreens.ddos_upstream_screen(self.view(), data))
            return
        if action == "fwdiag":
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                client = guard.GuardClient(self.bot.control)
                response = await client._call(getattr(self.bot.state, "ssh", None), guard.DDOS_SCRIPT, "ddos script", ["firewall-diagnose"], 45)
                data = response.data
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                data = {}
            await self.render(chat_id, msg_id, dscreens.ddos_firewall_diag_screen(self.view(), data))
            return
        if action == "stats_reset":
            await self.render(chat_id, msg_id, dscreens.ddos_stats_reset_screen(self.view()))
            return
        if action == "stats_reset_confirm":
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            try:
                client = guard.GuardClient(self.bot.control)
                await client._call(getattr(self.bot.state, "ssh", None), guard.DDOS_SCRIPT, "ddos script", ["stats-reset"], 30)
                self.note("dd", "stats_reset", "ok")
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
            action = "logs:top"
        live_kinds = ("service", "update", "v4", "v6", "top")
        start_live = action.startswith("live:") and action.split(":", 1)[1] in live_kinds and bool(msg_id)
        stop_live = action.startswith("live_stop:") and action.split(":", 1)[1] in live_kinds
        if action == "logs" or action in tuple("logs:" + item for item in live_kinds) or start_live or stop_live:
            kind = action.split(":", 1)[1] if ":" in action else "v4"
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            shell = getattr(self.bot.control, "shell", None)
            streaming = bool(start_live and kind in ("v4", "v6") and isinstance(shell, rkn_live.LocalShell) and not shell.escalated)
            cursor = ""
            started_at = 0
            try:
                client = guard.GuardClient(self.bot.control)
                response = await client._call(getattr(self.bot.state, "ssh", None), guard.DDOS_SCRIPT, "ddos script", ["logs-live-snapshot" if streaming else "logs", "--kind=" + kind], 30)
                text = str(response.data.get("text", ""))
                cursor = str(response.data.get("cursor", ""))
                started_at = int(response.data.get("started_at", 0) or 0)
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                text = ""
            logging_enabled = antiddos.Policy.from_dict(self.bot.state.ddos).rkn_logging
            active = start_live and not self.error
            await self.render(chat_id, msg_id, dscreens.ddos_logs_screen(self.view(), text, kind, logging_enabled, live=active, stream=streaming and active))
            if active:
                for live_chat, live_message in list(self.rkn_live_tasks):
                    if live_chat == chat_id:
                        self.stop_rkn_live(live_chat, live_message)
                worker = self.rkn_live_stream(chat_id, msg_id, kind, text, cursor, started_at) if streaming else self.rkn_live(chat_id, msg_id, kind, text)
                self.rkn_live_tasks[(chat_id, msg_id)] = asyncio.create_task(worker)
            return
        if action.startswith("ipscan:"):
            parts = action.split(":", 2)
            await self._scan_ddos_ip(
                chat_id,
                msg_id,
                parts[1] if len(parts) > 1 else "0",
                parts[2] if len(parts) > 2 else "",
            )
            return
        if action == "ips" or action.startswith("ips:"):
            self.ddos_in_ips = True
            page_part = action.split(":", 1)[1] if ":" in action else "0"
            try:
                self.ddos_page = max(0, int(page_part))
            except ValueError:
                self.ddos_page = 0
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            await self.ddos_refresh(probe=False)
            await self.render(chat_id, msg_id, dscreens.ddos_ips_screen(self.view()))
            return
        if action.startswith("ub:") or action.startswith("rb:"):
            parts = action.split(":", 2)
            mode = parts[0]
            page_part = parts[1] if len(parts) > 1 else "0"
            token_part = parts[2] if len(parts) > 2 else ""
            await self._toggle_ddos_ip(chat_id, msg_id, mode, page_part, token_part)
            return
        if action == "ntf":
            new_val = not self.notify.settings.on(notify.KIND_DDOS)
            self.notify.settings.enabled[notify.KIND_DDOS] = new_val
            self.notify.settings.enabled[notify.KIND_PORTSCAN] = new_val
            if new_val:
                self.notify.settings.mute_until = 0.0
            self.save_notify()
            self.note("dd", "ntf", "on" if new_val else "off")
            toast = t("DDOS_BTN_NTF_ON") if new_val else t("DDOS_BTN_NTF_OFF")
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=toast)))
            return
        if action not in ("install", "remove", "probe", "rkn", "rkn_sync"):
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(error=t("HOME_NOTICE_UNKNOWN"))))
            return
        if action == "probe":
            if not self.cooled("dd:probe", DDOS_COOLDOWN):
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=t("DBG_LIMIT"))))
                return
            await self.render(chat_id, msg_id, dscreens.busy(self.view()))
            await self.ddos_refresh(probe=True)
            self.note("dd", "probe", "ok")
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if action != "rkn" and not self.cooled("dd:" + action, DDOS_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=t("DBG_LIMIT"))))
            return
        if action == "rkn":
            policy = antiddos.Policy.from_dict(self.bot.state.ddos)
            policy.rkn_enabled = not policy.rkn_enabled
            if self.ddos is not None and self.ddos.installed:
                await self.render(chat_id, msg_id, dscreens.busy(self.view()))
                client = guard.GuardClient(self.bot.control)
                cfg = getattr(self.bot.state, "ssh", None)
                try:
                    self.ddos = await guard.ddos_call(client, cfg, guard.ddos_argv("install", policy), 300)
                    if hasattr(self.bot, "ddos_state"):
                        self.bot.ddos_state = self.ddos
                except Exception as exc:
                    self.error = str(getattr(exc, "message", exc))[:160]
                    self.note("dd", "rkn", "fail")
                    await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
                    return
            self.bot.state.ddos = policy.to_dict()
            if hasattr(self.bot, "save"):
                self.bot.save()
            self.error = ""
            self.note("dd", "rkn", "on" if policy.rkn_enabled else "off")
            label = t("DDOS_BTN_RKN_ON") if policy.rkn_enabled else t("DDOS_BTN_RKN_OFF")
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=label)))
            return
        if action == "rkn_sync":
            await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("DDOS_RKN_SYNCING")))
            try:
                v4_len, v6_len, ok_sources = await self.auto_sync_rkn()
            except Exception as exc:
                self.error = str(getattr(exc, "message", exc))[:160]
                self.note("dd", "rkn_sync", "fail")
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
                return
            self.error = ""
            msg = t("DDOS_RKN_SYNCED", v4=v4_len, v6=v6_len, sources=ok_sources)
            if self.rkn_sync_errors:
                msg += "\n" + t("DDOS_RKN_PARTIAL", errors=len(self.rkn_sync_errors))
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=msg)))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view()))
        client = guard.GuardClient(self.bot.control)
        cfg = getattr(self.bot.state, "ssh", None)
        policy = antiddos.Policy.from_dict(self.bot.state.ddos)
        if action == "install":
            policy.enabled = True
        try:
            argv = guard.ddos_argv(action, policy) if action == "install" else guard.ddos_argv(action)
            await guard.ddos_call(client, cfg, argv, 300)
            if action in ("install", "remove"):
                policy.enabled = action == "install"
                self.bot.state.ddos = policy.to_dict()
                if hasattr(self.bot, "save"):
                    self.bot.save()
        except Exception as exc:
            message = str(getattr(exc, "message", exc))
            self.ddos_busy = "busy" in message or getattr(exc, "code", "") == "port_busy"
            self.note("dd", action, "fail")
            self.error = message[:160]
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        self.error = ""
        self.note("dd", action, "ok")
        await self.ddos_refresh(probe=True)
        await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=t("DDOS_TITLE"))))

    async def scripts_action(self, chat_id: int, msg_id: int, stage: str) -> None:
        if stage == "fetch":
            await self.scripts_fetch(chat_id, msg_id)
            return
        if stage == "keep":
            self.notice = self.tr()("SCR_KEEP")
            await self.render(chat_id, msg_id, dscreens.scripts_screen(self.view()))
            return
        if not self.cooled("scripts", SCRIPTS_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.scripts_screen(self.view(notice=self.tr()("DBG_LIMIT"))))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view()))
        await self.scripts_check()
        await self.render(chat_id, msg_id, dscreens.scripts_screen(self.view()))

    async def scripts_check(self) -> None:
        control = self.bot.freeturn.control
        items = scripts.targets()

        async def load_cached() -> list[dict[str, Any]]:
            try:
                return await control.scripts_list()
            except FtError:
                return []

        async def run_probe(item: scripts.Target) -> tuple[str, dict[str, Any]]:
            try:
                return item.key, await control.scripts_probe(item.url(self.tag))
            except FtError:
                return item.key, {}

        cached, *pairs = await asyncio.gather(load_cached(), *(run_probe(item) for item in items))
        probes = dict(pairs)
        self.report = scripts.merge(scripts.parse_cache(cached), probes, self.tag)
        self.remember("scripts %d" % len(self.report.pending()))

    async def scripts_fetch(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        pending = self.report.pending()
        if not pending:
            await self.render(chat_id, msg_id, dscreens.scripts_screen(self.view(notice=t("SCR_FETCHED"))))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view()))
        failed = ""
        for item in pending:
            try:
                await self.bot.freeturn.control.scripts_fetch(item.url, item.remote_digest)
            except FtError as exc:
                failed = self.describe(exc)
                break
        await self.scripts_check()
        self.note("scripts", "fetch" if not failed else "fail", failed)
        await self.render(chat_id, msg_id, dscreens.scripts_screen(self.view(notice=t("SCR_FETCHED") if not failed else "", error=failed)))

    def keep_ports(self) -> list[int]:
        extra = [int(getattr(getattr(self.bot.state, "panel", None), "port", 0) or 0)]
        return portguard.protected_ports(self.bot.state, extra)

    async def ports_action(self, chat_id: int, msg_id: int, stage: str) -> None:
        if stage != "go":
            await self.render(chat_id, msg_id, dscreens.ports_screen(self.view()))
            return
        t = self.tr()
        keep = self.keep_ports()
        await self.render(chat_id, msg_id, dscreens.busy(self.view()))
        try:
            raw = await self.bot.freeturn.control.net_ports(portguard.join(keep))
        except FtError as exc:
            await self.render(chat_id, msg_id, dscreens.ports_screen(self.view(error=self.describe(exc))))
            return
        rows = [owner for owner in (portguard.Owner.from_dict(item) for item in raw.get("ports") or [])]
        for owner in rows:
            if portguard.is_protected(owner.port, keep):
                owner.protected = True
                owner.reason = owner.reason or "module"
        self.owners = rows
        self.note("ports", "ok", str(len(rows)))
        await self.render(chat_id, msg_id, dscreens.ports_screen(self.view(notice=t("DBG_PORTS_NOTE"))))

    def describe(self, error: FtError) -> str:
        key = "FT_CODE_%s" % str(error.code or "").upper()
        t = self.tr()
        if i18n.has_key(key, t.language):
            return t(key)
        return error.message

    async def apply_input(self, chat_id: int, ident: str, ctx: str, value: str) -> None:
        text = str(value or "").strip()
        try:
            if ident == "dbg_target":
                target = net.parse(text)
                self.target = target.text
                await self.bot.send(chat_id, dscreens.scan_screen(self.view(notice=target.text)))
                return
            if ident == "dbg_ports":
                ports = net.parse_ports(text)
                self.ports = ",".join(str(item) for item in ports)
                await self.bot.send(chat_id, dscreens.scan_screen(self.view(notice=self.ports)))
                return
            if ident == "dbg_hops":
                self.hops = net.parse_hops(text)
                await self.bot.send(chat_id, dscreens.trace_screen_view(self.view(notice=str(self.hops))))
                return
            if ident == "dbg_rkn_schedule":
                mode = "off" if text.lower() == "off" else ("hours" if text.isascii() and text.isdigit() else "calendar")
                client = guard.GuardClient(self.bot.control)
                try:
                    response = await client._call(getattr(self.bot.state, "ssh", None), guard.DDOS_SCRIPT, "ddos script", ["schedule-set", "--mode=" + mode, "--value=" + text], 60)
                    schedule = response.data
                    for current in (self.ddos, getattr(self.bot, "ddos_state", None)):
                        if current is not None:
                            current.timer_active = bool(schedule.get("active"))
                            current.timer_configured = bool(schedule.get("configured"))
                            current.timer_mode = str(schedule.get("mode", ""))
                    self.error = ""
                except Exception as exc:
                    self.error = str(getattr(exc, "message", exc))[:160]
                    schedule = {}
                await self.bot.send(chat_id, dscreens.ddos_schedule_screen(self.view(), schedule))
                return
            if ident == "dbg_rkn_exception":
                policy = antiddos.Policy.from_dict(self.bot.state.ddos)
                remove = text.startswith("-")
                parsed = antiddos.parse_rkn_exceptions(text[1:].strip() if text[:1] in ("+", "-") else text)
                if len(parsed) != 1:
                    await self.bot.send(chat_id, dscreens.ddos_exceptions_screen(self.view(error=self.tr()("DDOS_EXCEPTION_BAD")), policy))
                    return
                entry = parsed[0]
                if remove:
                    policy.rkn_exceptions = [item for item in policy.rkn_exceptions if item != entry]
                elif entry not in policy.rkn_exceptions:
                    if len(policy.rkn_exceptions) >= 128:
                        await self.bot.send(chat_id, dscreens.ddos_exceptions_screen(self.view(error=self.tr()("DDOS_EXCEPTION_BAD")), policy))
                        return
                    policy.rkn_exceptions.append(entry)
                try:
                    if self.ddos is not None and self.ddos.installed:
                        client = guard.GuardClient(self.bot.control)
                        self.ddos = await guard.ddos_call(client, getattr(self.bot.state, "ssh", None), guard.ddos_argv("install", policy), 300)
                        if hasattr(self.bot, "ddos_state"):
                            self.bot.ddos_state = self.ddos
                    self.bot.state.ddos = policy.to_dict()
                    if hasattr(self.bot, "save"):
                        self.bot.save()
                    self.error = ""
                except Exception as exc:
                    self.error = str(getattr(exc, "message", exc))[:160]
                    policy = antiddos.Policy.from_dict(self.bot.state.ddos)
                await self.bot.send(chat_id, dscreens.ddos_exceptions_screen(self.view(), policy))
                return
            if ident == "dbg_rkn_source":
                policy = antiddos.Policy.from_dict(self.bot.state.ddos)
                url = antiddos.normalize_source_url(text)
                known = [item for _, item in antiddos.RKN_SOURCES] + policy.custom_sources
                if not url or url in known or len(policy.custom_sources) >= antiddos.MAX_CUSTOM_SOURCES:
                    await self.bot.send(chat_id, dscreens.ddos_sources_screen(self.view(error=self.tr()("DDOS_SOURCE_BAD")), policy))
                    return
                try:
                    lines = await asyncio.to_thread(antiddos._download_source_lines, url, 10.0)
                    antiddos.validate_custom_source(lines)
                    v4, v6 = antiddos.sanitize_rkn_networks(lines)
                    if not v4 and not v6:
                        raise ValueError("empty list")
                except Exception as exc:
                    await self.bot.send(chat_id, dscreens.ddos_sources_screen(self.view(error=self.tr()("DDOS_SOURCE_CHECK_FAILED", reason=type(exc).__name__)), policy))
                    return
                policy.custom_sources.append(url)
                policy.disabled_sources.append(url)
                self.bot.state.ddos = policy.to_dict()
                if hasattr(self.bot, "save"):
                    self.bot.save()
                await self.bot.send(chat_id, dscreens.ddos_sources_screen(self.view(notice=self.tr()("DDOS_SOURCE_ADDED")), policy, (len(known)) // 3, self.rkn_source_cache()))
                return
            if ident == "dbg_ddos_ban":
                await self._mutate_ddos_entries(chat_id, "manual_bans", text, allow_private=False)
                return
            if ident == "dbg_ddos_allow":
                await self._mutate_ddos_entries(chat_id, "rkn_allow", text, allow_private=True)
                return
        except net.NetError as exc:
            await self.bot.send(chat_id, dscreens.crash_screen(self.view(error=exc.message), ident, net.trace_text(exc)))
            return
        await self.bot.send(chat_id, dscreens.home(self.view()))
