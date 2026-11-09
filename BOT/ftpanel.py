from __future__ import annotations

import asyncio
from typing import Any

from . import ftscreens, fwguard, i18n, traffic
from .freeturn import (
    BACKENDS,
    DEFAULT_LISTEN_PORT,
    METHODS,
    PINNED_SCRIPT_SHA256,
    TRANSPORTS,
    VERSION_CHOICES,
    is_port,
    MODES,
    OBF_PROFILES,
    FtClient,
    FtConfig,
    FtControl,
    FtError,
    FtShare,
    FtState,
    complete_link,
    normalize_conf,
    random_listen_port,
    rewrite_link_transport,
    valid_cidr,
    valid_hex64,
    valid_host,
    valid_hostport,
    valid_name,
)
from .models import ModelError


class FtPanel:
    def __init__(self, bot: Any, control: FtControl | None = None) -> None:
        self.bot = bot
        self.control = control or FtControl()
        self.state: FtState = bot.state.freeturn
        self.draft: FtConfig = FtConfig.from_dict(bot.state.freeturn.config.to_dict())
        if not self.state.installed and not self.state.configured and self.draft.listen_port == DEFAULT_LISTEN_PORT:
            self.draft.listen_port = random_listen_port()
        self.clients: list[FtClient] = []
        self.share: FtShare | None = None
        self.logs: list[str] = []
        self.link = ""
        self.conf = ""
        self.name = ""
        self.key_once = ""
        self.guard: dict[str, Any] = {}
        self.error = ""
        self.traffic = traffic.Traffic()
        self.usage: list[traffic.Usage] = []
        self.page = 0
        self.traffic_error = ""
        self.pending = ""

    def tr(self) -> i18n.Translator:
        return i18n.translator(getattr(self.bot.state, "language", i18n.DEFAULT_LANGUAGE))

    def save(self) -> None:
        self.state.config = FtConfig.from_dict(self.draft.to_dict())
        self.bot.state.freeturn = self.state
        self.bot.save()

    def view(self, notice: str = "", error: str = "") -> ftscreens.FtView:
        return ftscreens.FtView(
            state=self.state,
            draft=self.draft,
            clients=list(self.clients),
            share=self.share,
            notice=notice,
            error=error or self.error,
            logs=list(self.logs),
            link=self.link,
            conf=self.conf,
            name=self.name,
            guard=dict(self.guard),
            core=str(getattr(self.bot.state, "core", "xray")),
            lang=self.tr().language,
            usage=list(self.usage),
            totals=self.traffic.totals(self.usage) if self.usage else {},
            page=self.page,
            pages=pages_of(len(self.clients)),
            traffic_error=self.traffic_error,
        )

    async def render(self, chat_id: int, msg_id: int, rich: Any) -> None:
        await self.bot.render(chat_id, msg_id, rich)

    async def send(self, chat_id: int, rich: Any) -> None:
        await self.bot.send(chat_id, rich)

    async def busy(self, chat_id: int, msg_id: int, notice: str) -> None:
        await self.render(chat_id, msg_id, ftscreens.busy_screen(notice, self.tr().language))

    def describe(self, error: FtError) -> str:
        key = "FT_CODE_%s" % str(error.code or "").upper()
        t = self.tr()
        if i18n.has_key(key, t.language):
            return t(key)
        return error.message

    def note(self, action: str, outcome: str, detail: str = "") -> None:
        try:
            self.bot.audit.note(int(self.bot.admin_id), "freeturn:%s" % action, outcome, detail)
        except Exception:
            pass

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        parts = data.split(":")
        head = parts[1] if len(parts) > 1 else "home"
        arg1 = parts[2] if len(parts) > 2 else ""
        arg2 = parts[3] if len(parts) > 3 else ""
        self.error = ""
        if head in {"", "home"}:
            await self.render(chat_id, msg_id, ftscreens.home(self.view()))
            return
        if head == "check":
            await self.check(chat_id, msg_id)
            return
        if head == "plan":
            await self.render(chat_id, msg_id, ftscreens.plan_screen(self.view()))
            return
        if head == "cyc":
            self.cycle(arg1)
            self.save()
            await self.render(chat_id, msg_id, ftscreens.plan_screen(self.view()))
            return
        if head == "apply":
            await self.apply(chat_id, msg_id)
            return
        if head == "stop":
            await self.simple(chat_id, msg_id, "stop")
            return
        if head == "restart":
            await self.simple(chat_id, msg_id, "restart")
            return
        if head == "logs":
            await self.read_logs(chat_id, msg_id)
            return
        if head == "clients":
            self.page = _page(arg1)
            await self.read_clients(chat_id, msg_id)
            return
        if head == "cl":
            await self.open_client(chat_id, msg_id, arg1, arg2)
            return
        if head == "tr":
            self.page = _page(arg1)
            await self.read_traffic(chat_id, msg_id)
            return
        if head == "rm":
            if not valid_name(arg1):
                await self.render(chat_id, msg_id, ftscreens.home(self.view(error=self.tr()("FT_ERR_BAD_NAME"))))
                return
            if arg2 != "yes":
                self.pending = arg1
                t = self.tr()
                await self.render(
                    chat_id,
                    msg_id,
                    ftscreens.confirm_screen(
                        self.view(),
                        t("FT_CONFIRM_REMOVE_TITLE", name=arg1),
                        t("FT_CONFIRM_REMOVE_BODY", name=arg1),
                        "ft:rm:%s:yes" % arg1,
                        "ft:cl:%s" % arg1,
                    ),
                )
                return
            if self.pending != arg1:
                self.pending = ""
                await self.render(chat_id, msg_id, ftscreens.clients_screen(self.view()))
                return
            self.pending = ""
            await self.remove_client(chat_id, msg_id, arg1)
            return
        if head == "share":
            await self.owner_share(chat_id, msg_id)
            return
        if head == "un":
            if arg1 == "yes":
                await self.uninstall(chat_id, msg_id)
                return
            t = self.tr()
            await self.render(
                chat_id,
                msg_id,
                ftscreens.confirm_screen(self.view(), t("FT_CONFIRM_UNINSTALL_TITLE"), t("FT_CONFIRM_UNINSTALL_BODY"), "ft:un:yes", "ft:home"),
            )
            return
        if head == "uninstall":
            await self.uninstall(chat_id, msg_id)
            return
        if head == "fw":
            await self.firewall(chat_id, msg_id, arg1, arg2)
            return
        if head == "rport":
            self.draft.listen_port = random_listen_port({int(self.draft.listen_port or 0), int(self.draft.wg_port or 0)})
            self.save()
            await self.render(chat_id, msg_id, ftscreens.plan_screen(self.view()))
            return
        if head == "port":
            await self.apply_input(chat_id, "ft_port", arg1, arg2)
            return
        await self.render(chat_id, msg_id, ftscreens.home(self.view()))

    def cycle(self, field: str) -> None:
        if field == "method":
            self.draft.method = _next(METHODS, self.draft.method)
            return
        if field == "backend":
            self.draft.backend = _next(BACKENDS, self.draft.backend)
            if self.draft.backend == "new":
                self.draft.mode = "udp"
            return
        if field == "mode":
            self.draft.mode = _next(MODES, self.draft.mode)
            if self.draft.mode == "tcp" and self.draft.backend == "new":
                self.draft.backend = "external"
            return
        if field == "transport":
            self.draft.transport = _next(TRANSPORTS, self.draft.transport)
            self.state.config.transport = self.draft.transport
            if self.state.links:
                self.state.links = {
                    name: rewrite_link_transport(val, self.draft.transport)
                    for name, val in self.state.links.items()
                }
            if self.link:
                self.link = rewrite_link_transport(self.link, self.draft.transport)
            return
        if field == "obf_profile":
            self.draft.obf_profile = _next(OBF_PROFILES, self.draft.obf_profile)
            return
        if field == "version":
            self.draft.version = _next(VERSION_CHOICES, self.draft.version)
            return
        raise ModelError("unknown plan field: %s" % field[:24])

    def guard_proto(self) -> str:
        return "udp"

    def guard_port(self) -> int:
        try:
            port = int(self.state.config.listen_port or self.draft.listen_port or 0)
        except (TypeError, ValueError):
            port = 0
        return port if 1 <= port <= 65535 else 0

    async def firewall(self, chat_id: int, msg_id: int, action: str, confirmed: str = "") -> None:
        t = self.tr()
        port = self.guard_port()
        proto = self.guard_proto()
        if not port:
            await self.render(chat_id, msg_id, ftscreens.fw_screen(self.view(error=t("FT_FW_NO_RANGES", reason="no port"))))
            return
        if action in {"", "status"}:
            try:
                found = await self.control.firewall("status", port, proto=proto)
            except FtError as exc:
                self.note("fw", "failed", exc.code)
                await self.render(chat_id, msg_id, ftscreens.fw_screen(self.view(error=self.describe(exc))))
                return
            self.guard = {"port": found.port, "proto": found.proto, "backend": found.backend, "mode": found.mode, "rules": found.rules, "cidrs": found.cidrs}
            await self.render(chat_id, msg_id, ftscreens.fw_screen(self.view()))
            return
        if action not in {"vk", "open", "closed"}:
            await self.render(chat_id, msg_id, ftscreens.fw_screen(self.view()))
            return
        if action in {"vk", "closed"} and not confirmed:
            await self.render(
                chat_id,
                msg_id,
                ftscreens.confirm_screen(
                    self.view(),
                    t("FT_FW_CONFIRM_TITLE"),
                    t("FT_FW_CONFIRM_BODY", mode=t("FT_FW_MODE_%s" % action.upper()), port=str(port)),
                    "ft:fw:%s:yes" % action,
                    "ft:fw",
                ),
            )
            return
        await self.busy(chat_id, msg_id, t("FT_FW_BUSY"))
        cidrs = ""
        if action == "vk":
            try:
                found, reason = await asyncio.to_thread(fwguard.vk_cidrs)
            except fwguard.GuardError as exc:
                await self.render(chat_id, msg_id, ftscreens.fw_screen(self.view(error=t("FT_FW_NO_RANGES", reason=exc.message))))
                return
            if not found:
                self.note("fw", "failed", reason or "no_prefixes")
                await self.render(chat_id, msg_id, ftscreens.fw_screen(self.view(error=t("FT_FW_NO_RANGES", reason=reason or "no_prefixes"))))
                return
            cidrs = fwguard.join_cidrs(found)
        try:
            result = await self.control.firewall(action, port, cidrs, proto=proto)
        except FtError as exc:
            self.note("fw", "failed", exc.code)
            await self.render(chat_id, msg_id, ftscreens.fw_screen(self.view(error=self.describe(exc))))
            return
        self.guard = {"port": result.port, "proto": result.proto, "backend": result.backend, "mode": result.mode, "rules": result.rules, "cidrs": result.cidrs}
        self.note("fw", "ok", "%s %s" % (result.mode, result.backend))
        if action == "vk":
            notice = t("FT_FW_NOTICE_VK", count=result.cidrs or len(cidrs.split(",")))
        elif action == "open":
            notice = t("FT_FW_NOTICE_OPEN")
        else:
            notice = t("FT_FW_NOTICE_CLOSED")
        await self.render(chat_id, msg_id, ftscreens.fw_screen(self.view(notice=notice)))

    async def check(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        await self.busy(chat_id, msg_id, t("FT_BUSY_CHECK"))
        try:
            state = await self.control.probe()
        except FtError as exc:
            self.note("probe", "failed", exc.code)
            await self.render(chat_id, msg_id, ftscreens.home(self.view(error=self.describe(exc))))
            return
        saved_links = dict(self.state.links)
        saved_transport = self.draft.transport if self.draft.transport in TRANSPORTS else "auto"
        self.state = state
        self.state.config.transport = saved_transport
        draft = FtConfig.from_dict(state.config.to_dict())
        draft.transport = saved_transport
        if not state.installed and not state.configured and draft.listen_port == DEFAULT_LISTEN_PORT:
            draft.listen_port = self.draft.listen_port if self.draft.listen_port != DEFAULT_LISTEN_PORT else random_listen_port()
        ver = str(draft.version or "").strip()
        if ver and ver.lower() not in {"latest", "local", "auto", "default"}:
            tag = ver if ver.startswith("v") else "v" + ver
            if tag not in PINNED_SCRIPT_SHA256:
                draft.version = "latest"
        self.draft = draft
        if self.state.links:
            self.state.links = {
                name: self._finish_link(val) or rewrite_link_transport(val, saved_transport)
                for name, val in self.state.links.items()
            }
        elif saved_links and self.state.installed:
            self.state.links = {
                name: rewrite_link_transport(val, saved_transport)
                for name, val in saved_links.items()
            }
        if "owner" in self.state.links:
            self.link = self.state.links["owner"]
            self.name = "owner"
        self.save()
        await self.render(chat_id, msg_id, ftscreens.home(self.view(notice=t("FT_NOTICE_CHECKED"))))

    async def apply(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        try:
            self.draft.check()
        except FtError as exc:
            await self.render(chat_id, msg_id, ftscreens.plan_screen(self.view(error=self.describe(exc))))
            return
        await self.busy(chat_id, msg_id, t("FT_BUSY_APPLY"))
        key_rotated = bool(self.key_once)
        try:
            state = await self.control.apply(self.draft, obf_key=self.key_once)
            self.key_once = ""
        except FtError as exc:
            self.note("apply", "failed", exc.code)
            msg = self.describe(exc)
            if exc.code == "internal" and "systemd" in msg.lower():
                msg = msg + "  -  " + t("FT_HINT_METHOD")
            if exc.code in {"needs_root", "no_systemd"}:
                msg = self.describe(exc) + "  -  " + t("FT_HINT_METHOD")
            await self.render(chat_id, msg_id, ftscreens.plan_screen(self.view(error=msg)))
            return
        prev_cfg = FtConfig.from_dict(self.state.config.to_dict())
        saved_links = dict(self.state.links)
        saved_transport = self.draft.transport if self.draft.transport in TRANSPORTS else "auto"
        share_changed = bool(
            key_rotated
            or int(prev_cfg.listen_port) != int(self.draft.listen_port)
            or str(prev_cfg.host or "") != str(self.draft.host or "")
            or str(prev_cfg.mode or "") != str(self.draft.mode or "")
            or str(prev_cfg.obf_profile or "") != str(self.draft.obf_profile or "")
            or str(prev_cfg.backend or "") != str(self.draft.backend or "")
        )
        self.state = state
        self.state.config.transport = saved_transport
        applied_draft = FtConfig.from_dict(state.config.to_dict())
        applied_draft.transport = saved_transport
        ver = str(applied_draft.version or "").strip()
        if ver and ver.lower() not in {"latest", "local", "auto", "default"}:
            tag = ver if ver.startswith("v") else "v" + ver
            if tag not in PINNED_SCRIPT_SHA256:
                applied_draft.version = "latest"
        self.draft = applied_draft
        if self.state.links:
            self.state.links = {
                name: self._finish_link(val) or rewrite_link_transport(val, saved_transport)
                for name, val in self.state.links.items()
            }
        elif saved_links and not share_changed:
            self.state.links = {
                name: rewrite_link_transport(val, saved_transport)
                for name, val in saved_links.items()
            }
        if "owner" in self.state.links:
            self.link = self.state.links["owner"]
            self.name = "owner"
        self.save()
        self.note("apply", "ok", "port=%d" % int(self.draft.listen_port))
        await self.render(chat_id, msg_id, ftscreens.home(self.view(notice=t("FT_NOTICE_APPLIED"))))

    async def simple(self, chat_id: int, msg_id: int, action: str) -> None:
        t = self.tr()
        await self.busy(chat_id, msg_id, t("FT_BUSY_ACTION"))
        try:
            if action == "stop":
                await self.control.stop()
                notice = t("FT_NOTICE_STOPPED")
                self.state.running = False
            else:
                await self.control.restart()
                notice = t("FT_NOTICE_RESTARTED")
                self.state.running = True
        except FtError as exc:
            self.note(action, "failed", exc.code)
            await self.render(chat_id, msg_id, ftscreens.home(self.view(error=self.describe(exc))))
            return
        self.save()
        self.note(action, "ok")
        await self.render(chat_id, msg_id, ftscreens.home(self.view(notice=notice)))

    async def read_logs(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        await self.busy(chat_id, msg_id, t("FT_BUSY_ACTION"))
        try:
            self.logs = await self.control.logs(tail=int(self.bot.state.log_tail))
        except FtError as exc:
            await self.render(chat_id, msg_id, ftscreens.home(self.view(error=self.describe(exc))))
            return
        await self.render(chat_id, msg_id, ftscreens.logs_screen(self.view()))

    async def read_clients(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        await self.busy(chat_id, msg_id, t("FT_BUSY_ACTION"))
        try:
            self.clients, self.share = await self.control.client_list()
        except FtError as exc:
            await self.render(chat_id, msg_id, ftscreens.home(self.view(error=self.describe(exc))))
            return
        self.clients = [item for item in self.clients if valid_name(item.name)]
        self.state.installed = True
        self.state.key_present = bool(self.share and self.share.key_present)
        self.save()
        await self.refresh_traffic()
        await self.render(chat_id, msg_id, ftscreens.clients_screen(self.view()))

    async def read_traffic(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        if not self.clients:
            try:
                self.clients, self.share = await self.control.client_list()
            except FtError as exc:
                await self.render(chat_id, msg_id, ftscreens.home(self.view(error=self.describe(exc))))
                return
        await self.busy(chat_id, msg_id, t("FT_BUSY_TRAFFIC"))
        await self.refresh_traffic()
        await self.render(chat_id, msg_id, ftscreens.traffic_screen(self.view()))

    async def refresh_traffic(self) -> None:
        try:
            rows, names = await self.control.wg_peers()
        except FtError as exc:
            self.traffic_error = self.describe(exc)
            self.usage = []
            return
        self.traffic_error = ""
        self.traffic.load(rows, names)
        self.usage = self.traffic.usage(self.clients, self.history())
        self.store_history()

    def history(self) -> dict[str, Any]:
        raw = getattr(self.bot.state, "traffic", {})
        return dict(raw) if isinstance(raw, dict) else {}

    def store_history(self) -> None:
        try:
            self.bot.state.traffic = traffic.history_from(self.usage)
            self.bot.save()
        except Exception:
            pass

    async def add_client(self, chat_id: int, name: str) -> None:
        t = self.tr()
        clean = (name or "").strip()
        if not valid_name(clean):
            await self.send(chat_id, ftscreens.clients_screen(self.view(error=t("FT_CLIENT_INPUT"))))
            return
        await self.send(chat_id, ftscreens.busy_screen(t("FT_BUSY_ACTION"), self.tr().language))
        try:
            client, link, conf = await self.control.client_add(clean)
        except FtError as exc:
            self.note("client-add", "failed", exc.code)
            await self.send(chat_id, ftscreens.clients_screen(self.view(error=self.describe(exc))))
            return
        self.note("client-add", "ok", clean[:32])
        self.clients, self.share = await self._safe_list()
        self.link = self._finish_link(link)
        self.remember_link(clean, self.link)
        self.conf = normalize_conf(_conf_text(conf))
        self.name = clean
        if not any(item.name == clean for item in self.clients):
            self.clients.append(client)
        await self.send(chat_id, ftscreens.client_screen(self.view(notice=t("FT_NOTICE_ADDED", name=clean)), clean))

    async def open_client(self, chat_id: int, msg_id: int, name: str, action: str = "") -> None:
        t = self.tr()
        clean = (name or "").strip()
        if not valid_name(clean):
            await self.render(chat_id, msg_id, ftscreens.clients_screen(self.view()))
            return
        await self.busy(chat_id, msg_id, t("FT_BUSY_ACTION"))
        if action != "t":
            try:
                client, link, conf = await self.control.client_conf(clean)
            except FtError as exc:
                await self.render(chat_id, msg_id, ftscreens.clients_screen(self.view(error=self.describe(exc))))
                return
            if not any(item.name == clean for item in self.clients):
                self.clients.append(client)
            self.link = self._finish_link(link)
            self.remember_link(clean, self.link)
            self.conf = normalize_conf(_conf_text(conf))
            self.name = clean
        elif not self.clients:
            try:
                self.clients, self.share = await self.control.client_list()
            except FtError as exc:
                await self.render(chat_id, msg_id, ftscreens.clients_screen(self.view(error=self.describe(exc))))
                return
        await self.refresh_traffic()
        await self.render(chat_id, msg_id, ftscreens.client_screen(self.view(), clean))

    async def remove_client(self, chat_id: int, msg_id: int, name: str) -> None:
        t = self.tr()
        clean = (name or "").strip()
        if not valid_name(clean):
            await self.render(chat_id, msg_id, ftscreens.clients_screen(self.view()))
            return
        await self.busy(chat_id, msg_id, t("FT_BUSY_ACTION"))
        try:
            await self.control.client_remove(clean)
        except FtError as exc:
            self.note("client-remove", "failed", exc.code)
            await self.render(chat_id, msg_id, ftscreens.clients_screen(self.view(error=self.describe(exc))))
            return
        self.note("client-remove", "ok", clean[:32])
        self.clients = [item for item in self.clients if item.name != clean]
        if self.name == clean:
            self.link = ""
            self.conf = ""
            self.name = ""
        self.clients, self.share = await self._safe_list()
        await self.render(chat_id, msg_id, ftscreens.clients_screen(self.view(notice=t("FT_NOTICE_REMOVED", name=clean))))

    async def owner_share(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        await self.busy(chat_id, msg_id, t("FT_BUSY_ACTION"))
        try:
            _client, link, conf = await self.control.client_conf("owner")
            if not link:
                self.clients, self.share = await self.control.client_list()
        except FtError as exc:
            await self.render(chat_id, msg_id, ftscreens.home(self.view(error=self.describe(exc))))
            return
        self.link = self._finish_link(link)
        self.remember_link("owner", self.link)
        self.conf = normalize_conf(_conf_text(conf))
        self.name = "owner"
        if self.share is None:
            self.share = await self._safe_share()
        await self.render(chat_id, msg_id, ftscreens.share_screen(self.view()))

    async def uninstall(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        await self.busy(chat_id, msg_id, t("FT_BUSY_ACTION"))
        try:
            await self.control.uninstall("all", True)
        except FtError as exc:
            self.note("uninstall", "failed", exc.code)
            await self.render(chat_id, msg_id, ftscreens.home(self.view(error=self.describe(exc))))
            return
        self.state = FtState(config=self.draft)
        self.clients = []
        self.share = None
        self.link = ""
        self.conf = ""
        self.name = ""
        self.save()
        self.note("uninstall", "ok")
        await self.render(chat_id, msg_id, ftscreens.home(self.view(notice=t("FT_UNINSTALL_DONE"))))

    async def _safe_list(self) -> tuple[list[FtClient], FtShare | None]:
        try:
            clients, share = await self.control.client_list()
        except FtError:
            return self.clients, self.share
        self.share = share
        return clients, share

    async def _safe_share(self) -> FtShare | None:
        try:
            _clients, share = await self.control.client_list()
        except FtError:
            return self.share
        return share

    def _finish_link(self, link: str) -> str:
        text = str(link or "").strip()
        if not text:
            return ""
        try:
            done = complete_link(text, self.draft, transport=self.draft.transport)
        except FtError:
            return ""
        return done

    def remember_link(self, name: str, link: str) -> None:
        if not link:
            return
        before = dict(self.state.links)
        self.state.links = before
        self.state.remember(name, link)
        if self.state.links != before:
            self.save()

    async def apply_input(self, chat_id: int, ident: str, ctx: str, value: str) -> None:
        text = (value or "").strip()
        t = self.tr()
        if ident == "ft_port":
            if not is_port(text):
                await self.send(chat_id, ftscreens.plan_screen(self.view(error=t("FT_PORT_INPUT"))))
                return
            self.draft.listen_port = int(text)
        elif ident == "ft_wg_port":
            if not is_port(text):
                await self.send(chat_id, ftscreens.plan_screen(self.view(error=t("FT_WG_PORT_INPUT"))))
                return
            self.draft.wg_port = int(text)
        elif ident == "ft_wg_net":
            if not valid_cidr(text):
                await self.send(chat_id, ftscreens.plan_screen(self.view(error=t("FT_WG_NET_INPUT"))))
                return
            self.draft.wg_net = text
        elif ident == "ft_host":
            if text and not valid_host(text):
                await self.send(chat_id, ftscreens.plan_screen(self.view(error=t("FT_HOST_INPUT"))))
                return
            self.draft.host = text
        elif ident == "ft_key":
            if not valid_hex64(text):
                await self.send(chat_id, ftscreens.plan_screen(self.view(error=t("FT_KEY_INPUT"))))
                return
            self.key_once = text
        elif ident == "ft_connect":
            if not valid_hostport(text):
                await self.send(chat_id, ftscreens.plan_screen(self.view(error=t("FT_CONNECT_INPUT"))))
                return
            self.draft.connect = text
        elif ident == "ft_client":
            await self.add_client(chat_id, text)
            return
        else:
            raise ModelError("unknown freeturn field: %s" % str(ident)[:24])
        self.save()
        await self.send(chat_id, ftscreens.plan_screen(self.view(notice=t("FT_NOTICE_CHECKED"))))

    def set_core(self, name: str) -> bool:
        if name not in {"xray", "freeturn"}:
            return False
        self.bot.state.core = name
        self.bot.save()
        return True


def pages_of(count: int, size: int = ftscreens.MAX_CLIENT_BUTTONS) -> int:
    if count <= 0:
        return 1
    return max((int(count) + size - 1) // size, 1)


def _page(raw: str) -> int:
    text = str(raw or "").strip()
    if not text.isdigit():
        return 0
    return max(int(text) - 1, 0)


def _next(options: tuple[str, ...], current: str) -> str:
    try:
        index = options.index(current)
    except ValueError:
        return options[0]
    return options[(index + 1) % len(options)]


def _conf_text(conf_b64: str) -> str:
    import base64

    token = str(conf_b64 or "").strip()
    if not token:
        return ""
    try:
        return base64.b64decode(token + "=" * (-len(token) % 4), validate=False).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return ""
