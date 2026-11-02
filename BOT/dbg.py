from __future__ import annotations

import time
from typing import Any

from . import cores, dscreens, fwguard, i18n, net, portguard, scripts, ui
from .freeturn import FtError

SCAN_COOLDOWN = 3.0
TRACE_COOLDOWN = 3.0
VK_COOLDOWN = 10.0
SCRIPTS_COOLDOWN = 5.0
MAX_LOG = 12


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
            if head == "emoji":
                await self.emoji_action(chat_id, msg_id)
                return
            if head == "ports":
                await self.ports_action(chat_id, msg_id, arg1)
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
            raw = await self.bot.freeturn.control.net_scan(target.text, ports)
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
            raw = await self.bot.freeturn.control.net_trace(target.text, hops)
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
        cidrs, reason = fwguard.vk_cidrs()
        old = {str(item) for item in (self.vk.get("applied") or [])}
        fresh = set(cidrs)
        self.vk = {
            "cidrs": cidrs,
            "reason": reason,
            "domains": [holder for _asn, holder in fwguard.ASNS],
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
        port = int(getattr(getattr(self.bot.state, "freeturn", None), "config", None).port or 0) if getattr(self.bot.state, "freeturn", None) else 0
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
        cached: list[dict[str, Any]] = []
        probes: dict[str, dict[str, Any]] = {}
        try:
            cached = await control.scripts_list()
        except FtError:
            cached = []
        for item in scripts.targets():
            try:
                probes[item.key] = await control.scripts_probe(item.url(self.tag))
            except FtError:
                probes[item.key] = {}
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

    async def emoji_action(self, chat_id: int, msg_id: int) -> None:
        enabled = not self.bot.emoji_enabled
        self.bot.state.emoji = enabled
        self.bot.save()
        ui.use_icons(enabled)
        self.note("emoji", "on" if enabled else "off")
        notice = self.tr()("TOAST_EMOJI_ON") if enabled else self.tr()("TOAST_EMOJI_OFF")
        await self.render(chat_id, msg_id, dscreens.emoji_screen(self.view(notice=notice)))

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
        except net.NetError as exc:
            await self.bot.send(chat_id, dscreens.crash_screen(self.view(error=exc.message), ident, net.trace_text(exc)))
            return
        await self.bot.send(chat_id, dscreens.home(self.view()))
