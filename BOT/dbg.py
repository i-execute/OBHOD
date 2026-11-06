from __future__ import annotations

import asyncio
import time
from typing import Any

from . import antiddos, chebur, cores, dpi, dscreens, fwguard, guard, i18n, net, notify, portguard, scripts
from .freeturn import FtError

SCAN_COOLDOWN = 3.0
TRACE_COOLDOWN = 3.0
VK_COOLDOWN = 10.0
SCRIPTS_COOLDOWN = 5.0
CHK_COOLDOWN = 4.0
DPI_COOLDOWN = 8.0
DDOS_COOLDOWN = 15.0
NTF_COOLDOWN = 2.0
HP_COOLDOWN = 5.0
MAX_LOG = 12
CHEBUR_LIMIT = 45.0
REACH_LIMIT = 12.0
DPI_LIMIT = 20.0
VK_LIMIT = 40.0
NET_LIMIT = 120.0


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
        self.chebur: chebur.Answer | None = None
        self.chebur_target = ""
        self.dpi: Any = None
        self.notify: Any = self.make_centre()
        self.honeypot: Any = None
        self.honey_busy = False
        self.ddos: Any = None
        self.ddos_exposure: Any = None
        self.ddos_busy = False

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
            chebur=self.chebur,
            chebur_target=self.chebur_target,
            dpi=self.dpi,
            notify=self.notify,
            honeypot=self.honeypot,
            honey_busy=self.honey_busy,
            ddos=self.ddos,
            ddos_exposure=self.ddos_exposure,
            ddos_busy=self.ddos_busy,
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

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        parts = data.split(":")
        head = parts[1] if len(parts) > 1 else "home"
        arg1 = parts[2] if len(parts) > 2 else ""
        self.reset()
        try:
            if head in {"", "home"}:
                await self.render(chat_id, msg_id, dscreens.home(self.view()))
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
            if head == "chk":
                await self.chebur_action(chat_id, msg_id, arg1)
                return
            if head == "dpi":
                await self.dpi_action(chat_id, msg_id, arg1)
                return
            if head == "ntf":
                await self.notify_action(chat_id, msg_id, arg1)
                return
            if head == "dd":
                await self.ddos_action(chat_id, msg_id, arg1)
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
        try:
            await self.bot.send(chat_id, dscreens.trace_screen(self.view(), route, self.trace_text))
        except Exception:
            pass

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
            registry = await asyncio.to_thread(chebur.check, address)
        except Exception:
            return {}
        geo = registry.geo
        return {"asn": geo.asn, "organisation": geo.organisation, "country": geo.country}

    async def dpi_action(self, chat_id: int, msg_id: int, stage: str) -> None:
        t = self.tr()
        if stage not in {"scan", "again"}:
            await self.render(chat_id, msg_id, dscreens.dpi_screen(self.view()))
            return
        if not self.cooled("dpi", DPI_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.dpi_screen(self.view(notice=t("DBG_LIMIT"))))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("LOADING_STEP")))
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
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("LOADING_STEP")))
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

    async def ddos_action(self, chat_id: int, msg_id: int, action: str) -> None:
        t = self.tr()
        self.ddos_busy = False
        if action in ("", "open", "refresh"):
            await self.ddos_refresh(probe=action == "open")
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if action not in ("install", "remove", "probe"):
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(error=t("HOME_NOTICE_UNKNOWN"))))
            return
        if action == "probe":
            if not self.cooled("dd:probe", DDOS_COOLDOWN):
                await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=t("DBG_LIMIT"))))
                return
            await self.ddos_refresh(probe=True)
            self.note("dd", "probe", "ok")
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view()))
            return
        if not self.cooled("dd:" + action, DDOS_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.ddos_screen(self.view(notice=t("DBG_LIMIT"))))
            return
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("LOADING_STEP")))
        client = guard.GuardClient(self.bot.control)
        cfg = getattr(self.bot.state, "ssh", None)
        policy = antiddos.Policy.from_dict(self.bot.state.ddos)
        try:
            argv = guard.ddos_argv(action, policy) if action == "install" else guard.ddos_argv(action)
            await guard.ddos_call(client, cfg, argv, 300)
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
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), self.tr()("LOADING_STEP")))
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
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("LOADING_STEP")))
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
        await self.render(chat_id, msg_id, dscreens.busy(self.view(), t("LOADING_STEP")))
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

    async def chebur_action(self, chat_id: int, msg_id: int, action: str) -> None:
        t = self.tr()
        target = self.chebur_target or self.target
        if action in ("", "open"):
            await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view()))
            return
        if action not in ("check", "probe", "both", "net"):
            await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view(error=t("HOME_NOTICE_UNKNOWN"))))
            return
        if not self.cooled("chk:" + action, CHK_COOLDOWN):
            await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view(error=t("CHK_TOO_FAST"))))
            return
        if action == "net":
            await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view(notice=t("CHK_RUNNING_NET"))))
            probe = await asyncio.to_thread(chebur.reach)
            answer = self.chebur if self.chebur is not None else chebur.Answer(target=target, at=0.0)
            answer.reach = probe
            if not probe.reachable():
                answer.error = probe.error or t("CHK_NET_TCP_FAIL")
                answer.code = "network"
            elif answer.error and answer.code in ("network", "timeout"):
                answer.error = ""
                answer.code = ""
            self.chebur = answer
            self.note("chk", "reach", probe.state())
            await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view()))
            return
        try:
            host, _kind = chebur.clean_target(target)
        except chebur.CheburError as exc:
            self.note("chk", "bad_arg", exc.code)
            await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view(error=t("CHK_BAD_TARGET"))))
            return
        self.chebur_target = host
        if _kind in ("ip", "subnet"):
            self.target = host
        wants_live = action in ("probe", "both")
        answer = chebur.Answer(target=host, at=0.0)
        try:
            answer.registry = await asyncio.to_thread(chebur.check, host)
        except chebur.CheburError as exc:
            self.note("chk", "check_failed", exc.code)
            answer.error = exc.message
            answer.code = exc.code
            try:
                answer.reach = await asyncio.wait_for(asyncio.to_thread(chebur.reach), REACH_LIMIT)
            except (chebur.CheburError, OSError, asyncio.TimeoutError):
                answer.reach = None
            self.chebur = answer
            self.remember("chk %s %s" % (host, exc.code))
            await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view()))
            return
        self.chebur = answer
        if wants_live and not chebur.probe_supported(_kind):
            self.chebur = answer
            self.note("chk", "registry_only", _kind)
            self.remember("chk %s %s" % (host, answer.verdict()))
            await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view(notice=t("CHK_PROBE_WIDE"))))
            return
        if not wants_live or not answer.registry.context:
            self.note("chk", "registry", "blocked" if answer.blocked() else "clean")
            self.remember("chk %s %s" % (host, answer.verdict()))
            await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view()))
            return
        await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view(notice=t("CHK_RUNNING", value=answer.registry.geo.label()))))
        try:
            live = await asyncio.wait_for(asyncio.to_thread(chebur.probe, answer.registry.context, chebur.PROBE_DEADLINE, None), CHEBUR_LIMIT)
        except (chebur.CheburError, OSError, asyncio.TimeoutError) as exc:
            reason = getattr(exc, "message", None) or "the live probe did not answer in %d seconds" % int(CHEBUR_LIMIT)
            self.note("chk", "probe_failed", str(getattr(exc, "code", "timeout")))
            self.remember("chk %s probe_failed" % host)
            await self.render(chat_id, msg_id, dscreens.stub_screen(self.view(), t("CHK_BTN_PROBE"), reason, chebur.HOST, "dbg:chk:probe"))
            return
        answer.live = live
        self.chebur = answer
        self.remember("chk %s %s" % (host, answer.verdict()))
        self.note("chk", answer.verdict(), host)
        await self.render(chat_id, msg_id, dscreens.chebur_screen(self.view()))

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
            if ident == "dbg_chk_target":
                host, _kind = chebur.clean_target(text)
                if host != self.chebur_target:
                    self.chebur = None
                self.chebur_target = host
                await self.bot.send(chat_id, dscreens.chebur_screen(self.view(notice=host)))
                return
            if ident == "dbg_hops":
                self.hops = net.parse_hops(text)
                await self.bot.send(chat_id, dscreens.trace_screen_view(self.view(notice=str(self.hops))))
                return
        except chebur.CheburError as exc:
            self.note("chk", "bad_arg", exc.code)
            await self.bot.send(chat_id, dscreens.chebur_screen(self.view(error=self.tr()("CHK_BAD_TARGET"))))
            return
        except net.NetError as exc:
            await self.bot.send(chat_id, dscreens.crash_screen(self.view(error=exc.message), ident, net.trace_text(exc)))
            return
        await self.bot.send(chat_id, dscreens.home(self.view()))
