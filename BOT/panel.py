from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

from . import i18n, inline, screens, xscreens
from .inline import InlineError
from .models import ModelError
from .scan import CONCURRENCY, ScanResult, best_candidate, parse_candidates, scan_targets
from .ui import button, code, copy_row, muted, pre, quote, row, screen
from .xray import (
    DEFAULT_IGNOREIP,
    FINGERPRINTS,
    LOG_LEVELS,
    NETWORKS,
    SECURITIES,
    SUB_SEGMENT_LEN,
    VERSION_CHOICES,
    XRAY_VERSION,
    XrayError,
    XrayInbound,
    XrayState,
    gen_short_id,
    link_for,
    new_inbound,
    sanitize_remark,
    valid_alpn,
    valid_cert_path,
    valid_dest,
    valid_email,
    valid_host_name,
    valid_padding,
    valid_request_path,
    valid_short_id,
    valid_token,
    x25519_keypair,
)
from .xrayrpc import DEFAULT_VERSION, CoreState, SubState, XrayControl, XrayError as RpcError

log = logging.getLogger("obhod.panel")

DURATION = re.compile(r"^[1-9][0-9]{0,4}[smhdw]$")
SCAN_LIMIT = 24
CANDIDATE_LIMIT = 512
FIELDS = frozenset(inline.FIELDS)
GLOBAL_FIELDS = frozenset(
    {
        "xr_scan_targets",
        "xr_scan_manual",
        "xr_log_level",
        "xr_sub_port",
        "xr_sub_address",
        "xr_sub_refresh",
        "xr_ban_ip",
        "xr_bantime",
        "xr_ssh_bantime",
        "xr_ssh_maxretry",
        "xr_ignoreip",
        "xr_scan_candidates",
        "xr_scan_sni",
        "xr_scan_xver",
        "xr_dns_servers",
        "xr_api_port",
        "xr_access_log",
        "ssh_new_port",
        "ssh_pubkey",
    }
)


class PanelError(Exception):
    pass


class XrayPanel:
    def __init__(self, bot: Any, control: XrayControl | None = None) -> None:
        self.bot = bot
        self.control = control or XrayControl()
        self.core: dict[str, Any] = dict(bot.state.xray.last_core)
        self.draft: dict[str, str] = {}
        self.results: list[ScanResult] = [ScanResult.from_dict(item) for item in bot.state.xray.scan_results]
        self.sub_state: dict[str, Any] = {}

    @property
    def state(self) -> XrayState:
        return self.bot.state.xray

    def tr(self) -> i18n.Translator:
        return i18n.translator(self.bot.state.language)

    def save(self) -> None:
        self.state.last_core = dict(self.core)
        self.state.scan_results = [item.to_dict() for item in self.results]
        self.state.sub_port = int(self.bot.state.sub_port)
        self.bot.save()

    def view(self, notice: str = "", error: str = "") -> xscreens.XrayView:
        item = xscreens.XrayView(state=self.state, core=dict(self.core), notice=notice, error=error, lang=self.bot.state.language)
        item.draft = dict(self.draft)
        return item

    async def render(self, chat_id: int, msg_id: int, rich: Any) -> None:
        await self.bot.render(chat_id, msg_id, rich)

    async def send(self, chat_id: int, rich: Any) -> None:
        await self.bot.send(chat_id, rich)

    def address(self) -> str:
        return self.bot.address()

    def links_of(self, inbound: XrayInbound) -> list[tuple[str, str]]:
        host = self.address()
        out: list[tuple[str, str]] = []
        for client in inbound.clients:
            try:
                out.append((client.email, link_for(inbound, client, host, inbound.port)))
            except XrayError as exc:
                log.warning("link failed: %s", exc)
        return out

    def link_of(self, inbound: XrayInbound, email: str) -> str:
        client = inbound.client(email)
        if client is None:
            return ""
        try:
            return link_for(inbound, client, self.address(), inbound.port)
        except XrayError:
            return ""

    def sub_url(self, email: str) -> tuple[str, str]:
        sub = self.state.subscription_of(email)
        if sub is None:
            return "", ""
        host = self.state.address(self.address())
        return sub.path(), sub.url(host, self.state.sub_port)

    def next_port(self) -> int:
        used = set(self.state.ports())
        for port in (443, 8443, 2053, 2083, 2087, 2096, 24443, 30443):
            if port not in used:
                return port
        port = 30000
        while port in used:
            port += 1
        return port

    async def route(self, chat_id: int, msg_id: int, data: str) -> None:
        parts = data.split(":")
        head = parts[1] if len(parts) > 1 else "home"
        arg1 = parts[2] if len(parts) > 2 else ""
        arg2 = parts[3] if len(parts) > 3 else ""
        if head == "home":
            await self.render(chat_id, msg_id, xscreens.home(self.view()))
            return
        if head == "check":
            await self.check(chat_id, msg_id)
            return
        if head == "new":
            if not arg1:
                await self.render(chat_id, msg_id, xscreens.new_menu(self.view()))
                return
            await self.create_quick(chat_id, msg_id, arg2 or "reality", arg1, parts[4] if len(parts) > 4 else "")
            return
        if head == "custom":
            self.draft = {"network": "raw", "security": "reality", "port": str(self.next_port())}
            await self.render(chat_id, msg_id, xscreens.custom_menu(self.view()))
            return
        if head == "cyc":
            self.cycle(arg1)
            await self.render(chat_id, msg_id, xscreens.custom_menu(self.view()))
            return
        if head == "create":
            await self.create_custom(chat_id, msg_id)
            return
        if head == "in":
            await self.open_inbound(chat_id, msg_id, arg1)
            return
        if head == "edit":
            await self.render(chat_id, msg_id, xscreens.input_screen(self.view(), arg2, arg1, f"xr:in:{arg1}"))
            return
        if head == "toggle":
            await self.toggle(chat_id, msg_id, arg1)
            return
        if head == "keys":
            await self.regen_keys(chat_id, msg_id, arg1)
            return
        if head == "mldsa":
            await self.mldsa_action(chat_id, msg_id, arg1, arg2)
            return
        if head == "del":
            t = self.tr()
            await self.render(
                chat_id,
                msg_id,
                xscreens.confirm_screen(
                    self.view(),
                    t("CONFIRM_INBOUND_TITLE"),
                    t("CONFIRM_INBOUND_BODY", ident=arg1),
                    f"xr:del2:{arg1}",
                ),
            )
            return
        if head == "del2":
            await self.delete_inbound(chat_id, msg_id, arg1)
            return
        if head == "cladd":
            await self.render(chat_id, msg_id, xscreens.input_screen(self.view(), "xr_client_email", arg1, f"xr:in:{arg1}"))
            return
        if head == "cl":
            await self.open_client(chat_id, msg_id, arg1, arg2)
            return
        if head == "cldel":
            await self.delete_client(chat_id, msg_id, arg1, arg2)
            return
        if head == "clflow":
            await self.render(chat_id, msg_id, xscreens.input_screen(self.view(), "xr_client_flow", f"{arg1}:{arg2}", f"xr:cl:{arg1}:{arg2}"))
            return
        if head == "cllimit":
            await self.render(chat_id, msg_id, xscreens.input_screen(self.view(), "xr_client_limit", f"{arg1}:{arg2}", f"xr:cl:{arg1}:{arg2}"))
            return
        if head == "link":
            await self.show_links(chat_id, msg_id, arg1)
            return
        if head == "sub":
            await self.show_subscription(chat_id, msg_id, arg1, arg2)
            return
        if head == "subrot":
            await self.rotate_subscription(chat_id, msg_id, arg1, arg2)
            return
        if head == "subs":
            await self.subs_action(chat_id, msg_id, arg1)
            return
        if head == "core":
            await self.core_action(chat_id, msg_id, arg1, arg2)
            return
        if head == "logs":
            await self.logs(chat_id, msg_id, arg1)
            return
        if head == "scan":
            await self.scan_action(chat_id, msg_id, arg1, arg2)
            return
        await self.render(chat_id, msg_id, xscreens.home(self.view(notice=self.tr()("XR_HOME_NOTICE_UNKNOWN"))))

    def cycle(self, key: str) -> None:
        options = {"network": NETWORKS, "security": SECURITIES}
        values = options.get(key)
        if not values:
            return
        current = self.draft.get(key, values[0])
        index = values.index(current) if current in values else 0
        self.draft[key] = values[(index + 1) % len(values)]

    async def create_quick(self, chat_id: int, msg_id: int, security: str, network: str, port: str = "") -> None:
        if network not in NETWORKS:
            raise PanelError(f"the network {network} is not supported")
        if security not in SECURITIES:
            raise PanelError(f"the security {security} is not supported")
        number = int(port) if port.isdigit() else self.next_port()
        try:
            inbound = new_inbound("vless", number, network, security)
        except (XrayError, ValueError) as exc:
            raise PanelError(str(exc)) from None
        inbound.remark = f"{security}-{number}"
        self.state.add(inbound)
        inbound.make_client("owner")
        self.save()
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice=self.tr()("NOTICE_INBOUND_CREATED")), inbound))

    async def create_custom(self, chat_id: int, msg_id: int) -> None:
        draft = dict(self.draft)
        network = draft.get("network", "raw")
        security = draft.get("security", "reality")
        port = int(draft.get("port") or self.next_port())
        try:
            inbound = new_inbound("vless", port, network, security)
        except (XrayError, ValueError) as exc:
            raise PanelError(str(exc)) from None
        inbound.remark = f"{security}-{port}"
        self.state.add(inbound)
        inbound.make_client("owner")
        self.draft = {}
        self.save()
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice=self.tr()("NOTICE_INBOUND_CREATED")), inbound))

    def get(self, ident: str) -> XrayInbound:
        item = self.state.inbound(ident)
        if item is None:
            raise PanelError(f"inbound {ident} was not found")
        return item

    async def open_inbound(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(), inbound))

    async def toggle(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        inbound.enable = not inbound.enable
        self.save()
        t = self.tr()
        notice = t("NOTICE_INBOUND_ON") if inbound.enable else t("NOTICE_INBOUND_OFF")
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice=notice), inbound))

    async def regen_keys(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        if inbound.security != "reality":
            await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(error="reality keys need the reality security"), inbound))
            return
        private = ""
        public = ""
        if self.core.get("installed"):
            try:
                private, public = await self.control.x25519(self.bot.state.ssh)
            except RpcError as exc:
                log.warning("remote x25519 failed: %s", exc.message)
        if not private or not public:
            private, public = x25519_keypair()
        self.state.set_reality_keys(inbound.id, private, public)
        inbound.short_ids = [gen_short_id()]
        self.save()
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice=self.tr()("NOTICE_KEYS_REGEN")), inbound))

    async def mldsa_action(self, chat_id: int, msg_id: int, ident: str, action: str) -> None:
        inbound = self.get(ident)
        if inbound.security != "reality":
            await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(error="ml-dsa-65 needs the reality security"), inbound))
            return
        if action == "gen":
            seed = ""
            verify = ""
            try:
                seed, verify = await self.control.mldsa65(self.bot.state.ssh)
            except RpcError as exc:
                await self.render(chat_id, msg_id, xscreens.mldsa_screen(self.view(error=exc.message), inbound))
                return
            self.state.set_mldsa65(inbound.id, seed, verify)
            self.save()
            await self.render(chat_id, msg_id, xscreens.mldsa_screen(self.view(notice=self.tr()("NOTICE_MI_MLDSA_GENERATED")), inbound))
            return
        if action == "clear":
            self.state.clear_mldsa65(inbound.id)
            self.save()
            await self.render(chat_id, msg_id, xscreens.mldsa_screen(self.view(notice=self.tr()("NOTICE_MLDSA_REMOVED")), inbound))
            return
        await self.render(chat_id, msg_id, xscreens.mldsa_screen(self.view(), inbound))

    async def delete_inbound(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        remark = inbound.remark
        self.state.remove(ident)
        self.save()
        await self.render(chat_id, msg_id, xscreens.home(self.view(notice=self.tr()("NOTICE_INBOUND_DELETED", remark=remark))))

    async def open_client(self, chat_id: int, msg_id: int, ident: str, email: str) -> None:
        inbound = self.get(ident)
        link = self.link_of(inbound, email)
        path, url = self.sub_url(email)
        await self.render(chat_id, msg_id, xscreens.client_screen(self.view(), inbound, email, link, url, path))

    async def delete_client(self, chat_id: int, msg_id: int, ident: str, email: str) -> None:
        inbound = self.get(ident)
        if not inbound.remove_client(email):
            raise PanelError(f"the client {email} was not found")
        self.save()
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice=self.tr()("NOTICE_CLIENT_DELETED", email=email)), inbound))

    async def show_links(self, chat_id: int, msg_id: int, ident: str) -> None:
        inbound = self.get(ident)
        links = self.links_of(inbound)
        await self.render(chat_id, msg_id, xscreens.links_screen(self.view(), inbound, self.address(), links))

    async def show_subscription(self, chat_id: int, msg_id: int, ident: str, email: str) -> None:
        inbound = self.get(ident)
        path, url = self.sub_url(email)
        if not path:
            await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(error="the client has no subscription path"), inbound))
            return
        t = self.tr()
        blocks = [
            f"<p>{t('XR_CLIENT_NAME')} {code(email)}</p>",
            f"<p>{t('SUB_LABEL_PATH', path=code(path))}</p>",
            pre(url),
            quote(muted(t("XR_SUBS_NOTE", length=SUB_SEGMENT_LEN))),
        ]
        buttons = [
            copy_row(t("SUB_COPY"), url) or "",
            row(button(t("XR_CLIENT_NEW_PATH"), f"xr:subrot:{ident}:{email}"), button(t("XR_CLIENT_SUB"), f"xr:cl:{ident}:{email}")),
            xscreens.back_row(self.bot.state.language, "xr:home"),
        ]
        await self.render(chat_id, msg_id, screen(t("SUB_TITLE"), email, blocks, buttons))

    async def rotate_subscription(self, chat_id: int, msg_id: int, ident: str, email: str) -> None:
        if self.state.rotate_subscription(email) is None:
            raise PanelError(f"the client {email} was not found")
        self.save()
        await self.show_subscription(chat_id, msg_id, ident, email)

    def sub_rows(self) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        host = self.state.address(self.address())
        for item in self.state.subscriptions(host):
            out.append((item.email, item.path(), item.url(host, self.state.sub_port)))
        return out

    async def subs_action(self, chat_id: int, msg_id: int, action: str) -> None:
        if action == "apply":
            await self.subs_apply(chat_id, msg_id)
            return
        if action == "status":
            await self.subs_status(chat_id, msg_id)
            return
        if action == "stop":
            await self.subs_stop(chat_id, msg_id)
            return
        if action == "rotate":
            for inbound in self.state.inbounds:
                for client in inbound.clients:
                    client.ensure_subscription()
                    client.sub_id = client.sub_key = ""
                    client.ensure_subscription()
            self.save()
            await self.render(chat_id, msg_id, xscreens.subs_screen(self.view(notice=self.tr()("NOTICE_SUBS_ROTATED")), self.sub_rows()))
            return
        await self.render(chat_id, msg_id, xscreens.subs_screen(self.view(), self.sub_rows()))

    async def subs_apply(self, chat_id: int, msg_id: int) -> None:
        state = self.state
        t = self.tr()
        await self.render(
            chat_id,
            msg_id,
            xscreens.busy_screen(t("BUSY_SUBS_WRITE"), self.bot.state.language, [t("BUSY_STEP_FILE"), t("BUSY_STEP_REGISTRY"), t("BUSY_STEP_SERVICE")]),
        )
        try:
            self.bot.state.sub_port = int(state.sub_port)
            state.sub_port = int(state.sub_port)
            await self.control.sub_install(self.bot.state.ssh, state.sub_port)
            registry = state.sub_registry(state.address(self.address()))
            await self.control.sub_sync(self.bot.state.ssh, registry, state.sub_port)
        except (RpcError, OSError) as exc:
            message = getattr(exc, "message", str(exc))
            await self.render(chat_id, msg_id, xscreens.subs_screen(self.view(error=str(message)), self.sub_rows()))
            return
        state.sub_enabled = True
        self.save()
        await self.render(chat_id, msg_id, xscreens.subs_screen(self.view(notice=t("NOTICE_SUBS_APPLIED")), self.sub_rows()))

    async def subs_status(self, chat_id: int, msg_id: int) -> None:
        try:
            state: SubState = await self.control.sub_status(self.bot.state.ssh, self.state.sub_port)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.subs_screen(self.view(error=exc.message), self.sub_rows()))
            return
        t = self.tr()
        notice = t("NOTICE_SUBS_PORT", port=state.port) if state.listening else t("NOTICE_SUBS_NO_PORT")
        self.state.sub_enabled = bool(state.listening)
        self.save()
        await self.render(chat_id, msg_id, xscreens.subs_screen(self.view(notice=notice), self.sub_rows()))

    async def subs_stop(self, chat_id: int, msg_id: int) -> None:
        try:
            await self.control.sub_stop(self.bot.state.ssh, self.state.sub_port)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.subs_screen(self.view(error=exc.message), self.sub_rows()))
            return
        self.state.sub_enabled = False
        self.save()
        await self.render(chat_id, msg_id, xscreens.subs_screen(self.view(notice=self.tr()("NOTICE_SUBS_STOPPED")), self.sub_rows()))

    async def check(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        await self.render(chat_id, msg_id, xscreens.busy_screen(t("BUSY_CORE_READ"), self.bot.state.language))
        try:
            state = await self.control.probe(self.bot.state.ssh)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message)))
            return
        self.core = state_report(state)
        self.save()
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice=t("NOTICE_CORE_READ"))))

    async def core_action(self, chat_id: int, msg_id: int, action: str, extra: str) -> None:
        if action in {"", "open"}:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view()))
            return
        if action == "ver":
            await self.set_version(chat_id, msg_id, extra)
            return
        t = self.tr()
        if action == "purge":
            await self.render(
                chat_id,
                msg_id,
                xscreens.confirm_screen(self.view(), t("CONFIRM_PURGE_TITLE"), t("CONFIRM_PURGE_BODY"), "xr:core:purge2"),
            )
            return
        if action == "purge2":
            await self.purge(chat_id, msg_id)
            return
        if action == "install":
            await self.install_core(chat_id, msg_id)
            return
        if action == "apply":
            await self.apply(chat_id, msg_id)
            return
        if action == "restart":
            await self.run_core(chat_id, msg_id, t("BUSY_CORE_RESTART"), self.control.restart)
            return
        if action == "stop":
            await self.run_core(chat_id, msg_id, t("BUSY_CORE_STOP"), self.control.stop)
            return
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view()))

    async def set_version(self, chat_id: int, msg_id: int, choice: str) -> None:
        value = XRAY_VERSION if choice == "pin" else "latest"
        t = self.tr()
        if value not in VERSION_CHOICES:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=t("NOTICE_CORE_UNKNOWN_VERSION"))))
            return
        self.state.version = value
        self.save()
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice=t("NOTICE_VERSION_SELECTED", value=value))))

    async def install_core(self, chat_id: int, msg_id: int) -> None:
        version = self.state.install_version()
        t = self.tr()
        await self.render(
            chat_id,
            msg_id,
            xscreens.busy_screen(
                t("BUSY_CORE_INSTALL", version=version),
                self.bot.state.language,
                [t("BUSY_STEP_DOWNLOAD"), t("BUSY_STEP_HASH"), t("BUSY_STEP_UNPACK")],
            ),
        )
        try:
            response = await self.control.install_core(self.bot.state.ssh, version, force=True)
            state = CoreState.from_dict(response.data)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message)))
            return
        self.core = state_report(state)
        self.save()
        installed = str(self.core.get("version", version))
        if state.fallback:
            notice = t("NOTICE_CORE_FALLBACK", version=installed, fallback=state.fallback_version or DEFAULT_VERSION)
        else:
            notice = t("NOTICE_CORE_INSTALLED", version=installed)
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice=notice)))

    async def apply(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        if not self.state.inbounds:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error="there are no inbounds to apply")))
            return
        try:
            config = self.state.to_config()
        except XrayError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=str(exc))))
            return
        version = self.state.install_version()
        await self.render(
            chat_id,
            msg_id,
            xscreens.busy_screen(t("BUSY_CONFIG_WRITE"), self.bot.state.language, [t("BUSY_STEP_VALIDATE"), t("BUSY_STEP_RESTART")]),
        )
        try:
            state = await self.control.apply(self.bot.state.ssh, config, version=version)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message)))
            return
        self.core = state_report(state)
        self.save()
        ports = ", ".join(str(item) for item in self.core.get("listening") or [])
        notice = t("NOTICE_CORE_APPLIED_PORTS", ports=ports) if ports else t("NOTICE_CORE_APPLIED")
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice=notice)))

    async def run_core(self, chat_id: int, msg_id: int, title: str, action: Any) -> None:
        await self.render(chat_id, msg_id, xscreens.busy_screen(title, self.bot.state.language))
        try:
            state = await action(self.bot.state.ssh)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message)))
            return
        self.core = state_report(state)
        self.save()
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice=self.tr()("NOTICE_CORE_DONE", action=title))))

    async def purge(self, chat_id: int, msg_id: int) -> None:
        t = self.tr()
        await self.render(chat_id, msg_id, xscreens.busy_screen(t("BUSY_CORE_PURGE"), self.bot.state.language))
        try:
            await self.control.uninstall(self.bot.state.ssh)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.core_screen(self.view(error=exc.message)))
            return
        self.core = {}
        self.save()
        await self.render(chat_id, msg_id, xscreens.core_screen(self.view(notice=t("NOTICE_CORE_PURGED"))))

    async def logs(self, chat_id: int, msg_id: int, tail: str) -> None:
        size = 200
        if tail:
            try:
                size = max(20, min(2000, int(tail)))
            except ValueError:
                size = 200
        try:
            lines = await self.control.logs(self.bot.state.ssh, size)
        except RpcError as exc:
            await self.render(chat_id, msg_id, xscreens.logs_screen(self.view(error=exc.message), [], size))
            return
        await self.render(chat_id, msg_id, xscreens.logs_screen(self.view(), lines, size))

    async def scan_action(self, chat_id: int, msg_id: int, action: str, extra: str) -> None:
        if not action:
            await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(), self.results))
            return
        if action == "targets":
            await self.render(chat_id, msg_id, xscreens.scan_targets_screen(self.view()))
            return
        if action == "reset":
            self.state.scan_targets = self.state.candidates()
            self.save()
            await self.render(chat_id, msg_id, xscreens.scan_targets_screen(self.view(notice=self.tr()("NOTICE_TARGETS_RESET"))))
            return
        if action == "run":
            await self.run_scan(chat_id, msg_id, self.state.scan_targets)
            return
        if action == "use":
            await self.use_target(chat_id, msg_id, extra)
            return
        await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(), self.results))

    async def run_scan(self, chat_id: int, msg_id: int, targets: list[str]) -> None:
        clean = [item for item in targets if item.strip()][:SCAN_LIMIT]
        t = self.tr()
        if not clean:
            await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(error="the scan list is empty"), self.results))
            return
        await self.render(
            chat_id,
            msg_id,
            xscreens.busy_screen(
                t("BUSY_SCAN"),
                self.bot.state.language,
                [t("BUSY_SCAN_STEP_COUNT", count=len(clean)), t("BUSY_SCAN_STEP_CHECKS")],
            ),
        )
        try:
            results = await scan_targets(
                clean,
                sni=self.state.scan_sni,
                xver=int(self.state.scan_xver or 0),
                candidates=self.state.candidates(),
                concurrency=CONCURRENCY,
            )
        except (OSError, ValueError) as exc:
            await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(error=str(exc)), self.results))
            return
        self.results = results
        self.save()
        good = sum(1 for item in results if item.feasible)
        await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(notice=t("NOTICE_SCAN_DONE", good=good, total=len(results))), results))

    async def use_target(self, chat_id: int, msg_id: int, index: str) -> None:
        if not index.isdigit():
            raise PanelError("the target number must be a number")
        position = int(index)
        if position < 0 or position >= len(self.results):
            raise PanelError("the target was not found")
        result = self.results[position]
        inbound = next((item for item in self.state.inbounds if item.security == "reality"), None)
        if inbound is None:
            await self.render(chat_id, msg_id, xscreens.scan_screen(self.view(error="create a reality inbound first"), self.results))
            return
        sni = (result.server_names[0] if result.server_names else "") or result.host or result.target
        self.state.adopt_scan(inbound.id, result.host or result.target, sni, result.port)
        self.save()
        notice = self.tr()("NOTICE_TARGET_APPLIED", target=result.target, remark=inbound.remark)
        await self.render(chat_id, msg_id, xscreens.inbound_screen(self.view(notice=notice), inbound))

    def inbound_of_ctx(self, ctx: str) -> XrayInbound | None:
        ident = ctx.split(":", 1)[0]
        return self.state.inbound(ident) if ident.isdigit() else None

    def client_of_ctx(self, ctx: str, ident: str) -> Any:
        inbound = self.inbound_of_ctx(ctx)
        if inbound is None:
            raise PanelError("the inbound was not found")
        client = inbound.client(ctx.split(":", 1)[1])
        if client is None:
            raise PanelError("the client was not found")
        return client

    def set_field(self, ident: str, ctx: str, value: str) -> str:
        t = self.tr()
        if ident not in FIELDS:
            raise PanelError(f"the field {ident} is not supported")
        if ident in GLOBAL_FIELDS:
            return self.set_global(ident, ctx, value)
        inbound = self.inbound_of_ctx(ctx)
        if inbound is None:
            raise PanelError("the inbound for the input was not found")
        text = (value or "").strip()
        if ident == "xr_port":
            port = parse_port(text)
            for item in self.state.inbounds:
                if item.port == port and item.id != inbound.id:
                    raise PanelError(f"the port {port} is used by the inbound {item.remark}")
            inbound.port = port
            return t("NOTICE_PORT", port=port)
        if ident == "xr_remark":
            inbound.remark = checked(sanitize_remark, text, 40)
            return t("NOTICE_NAME")
        if ident == "xr_sni":
            host = checked(valid_host_name, text, "the server name")
            inbound.sni = host
            inbound.dest = f"{host}:443"
            return t("NOTICE_SNI", value=host)
        if ident == "xr_dest":
            inbound.dest = checked(valid_dest, text)
            if not inbound.sni:
                inbound.sni = inbound.dest.rsplit(":", 1)[0]
            return t("NOTICE_DEST", value=inbound.dest)
        if ident == "xr_short_id":
            inbound.short_ids = [valid_short_id(text or gen_short_id())]
            return t("NOTICE_SHORT_ID")
        if ident == "xr_spider_x":
            inbound.spider_x = checked(valid_request_path, text, "the spider path")
            return t("NOTICE_SPIDER")
        if ident == "xr_fingerprint":
            if text not in FINGERPRINTS:
                raise PanelError("the fingerprint is not supported")
            inbound.fingerprint = text
            return t("NOTICE_FINGERPRINT", value=text)
        if ident == "xr_alpn":
            inbound.alpn = checked(valid_alpn, text)
            return t("NOTICE_ALPN")
        if ident == "xr_cert_file":
            inbound.cert_file = checked(valid_cert_path, text, "the certificate path")
            return t("NOTICE_CERT")
        if ident == "xr_key_file":
            inbound.key_file = checked(valid_cert_path, text, "the key path")
            return t("NOTICE_KEY")
        if ident == "xr_path":
            inbound.path = checked(valid_request_path, text, "the path")
            return t("NOTICE_PATH", value=inbound.path)
        if ident == "xr_host_header":
            inbound.host_header = checked(valid_host_name, text, "the host header")
            return t("NOTICE_HOST_HEADER")
        if ident == "xr_service":
            inbound.service_name = checked(valid_token, text, "the service name")
            return t("NOTICE_SERVICE")
        if ident == "xr_padding":
            inbound.encryption.padding = valid_padding(text) if text else ""
            return t("NOTICE_PADDING")
        if ident == "xr_mldsa65_seed":
            if inbound.security != "reality":
                raise PanelError("ml-dsa-65 needs the reality security")
            if text:
                inbound.mldsa65_seed = text
                return t("NOTICE_MLDSA_SEED")
            inbound.mldsa65_seed = ""
            inbound.mldsa65_verify = ""
            return t("NOTICE_MLDSA_REMOVED")
        if ident == "xr_mldsa65_verify":
            if inbound.security != "reality":
                raise PanelError("ml-dsa-65 needs the reality security")
            inbound.mldsa65_verify = text
            return t("NOTICE_MLDSA_VERIFY")
        if ident == "xr_client_email":
            email = valid_email(text)
            if inbound.client(email) is not None:
                raise PanelError(f"the client {email} already exists")
            client = inbound.make_client(email)
            shared = self.state.canonical_subscription(email, skip=client)
            if shared is not None:
                client.sub_id, client.sub_key = shared
            return t("NOTICE_CLIENT_ADDED", email=email)
        if ident == "xr_client_flow":
            client = self.client_of_ctx(ctx, ident)
            if text not in {"", "xtls-rprx-vision"}:
                raise PanelError("the flow is not supported")
            if text and not (inbound.network == "raw" and inbound.security in {"reality", "tls"}):
                raise PanelError("the flow needs the raw network with reality or tls")
            client.flow = text
            return t("NOTICE_FLOW")
        if ident == "xr_client_limit":
            client = self.client_of_ctx(ctx, ident)
            if not text.isdigit():
                raise PanelError("the ip limit must be a number")
            client.limit_ip = int(text)
            return t("NOTICE_LIMIT_IP", value=client.limit_ip)
        raise PanelError(f"the field {ident} is not supported")

    def set_global(self, ident: str, ctx: str, value: str) -> str:
        t = self.tr()
        text = (value or "").strip()
        if ident == "xr_scan_targets":
            targets = [item.strip() for item in text.replace(";", ",").split(",") if item.strip()]
            if not targets:
                raise PanelError("the scan list is empty")
            if len(targets) > SCAN_LIMIT:
                raise PanelError(f"no more than {SCAN_LIMIT} targets are allowed")
            self.state.scan_targets = targets
            return t("NOTICE_TARGETS_COUNT", count=len(targets))
        if ident == "xr_scan_manual":
            target = manual_target(text)
            if target not in self.state.scan_targets:
                self.state.scan_targets.append(target)
            return t("NOTICE_TARGET_ADDED", target=target)
        if ident == "xr_log_level":
            level = text.lower()
            if level not in LOG_LEVELS:
                raise PanelError("the log level must be debug, info, warning or error")
            self.state.log_level = level
            return t("NOTICE_LOG_LEVEL", value=level)
        if ident == "xr_sub_port":
            port = parse_port(text)
            for inbound in self.state.inbounds:
                if inbound.port == port:
                    raise PanelError(f"the port {port} is used by the inbound {inbound.remark}")
            self.state.sub_port = port
            self.bot.state.sub_port = port
            return t("NOTICE_SUB_PORT", port=port)
        if ident == "xr_sub_address":
            self.state.sub_address = text
            return t("NOTICE_SUB_ADDRESS", value=text) if text else t("NOTICE_SUB_ADDRESS_RESET")
        if ident == "xr_bantime":
            if not text.isdigit() or int(text) < 1:
                raise PanelError("the ban time must be a positive number of minutes")
            self.bot.state.xray.fail2ban_bantime = int(text)
            return t("NOTICE_BANTIME", value=text)
        if ident == "xr_ssh_bantime":
            value = parse_duration(text)
            self.bot.state.xray.fail2ban_ssh_bantime = value
            return t("NOTICE_SSH_BANTIME", value=value)
        if ident == "xr_ssh_maxretry":
            if not text.isdigit() or not 1 <= int(text) <= 50:
                raise PanelError("the ssh retry count must be between 1 and 50")
            self.bot.state.xray.fail2ban_ssh_maxretry = int(text)
            return t("NOTICE_SSH_MAXRETRY", value=text)
        if ident == "xr_ignoreip":
            values = parse_addresses(text)
            self.bot.state.xray.fail2ban_ignoreip = " ".join(values)
            return t("NOTICE_IGNOREIP", value=", ".join(values) or DEFAULT_IGNOREIP)
        if ident == "xr_sub_refresh":
            if not text.isdigit() or not 1 <= int(text) <= 168:
                raise PanelError("the refresh interval must be between 1 and 168 hours")
            self.state.sub_refresh = int(text)
            return t("NOTICE_SUB_REFRESH", value=self.state.sub_refresh)
        if ident == "xr_ban_ip":
            if not text:
                raise PanelError("the ip address must not be empty")
            return t("NOTICE_ADDRESS", value=text)
        if ident == "xr_scan_candidates":
            values = parse_candidates(text)
            if len(values) > CANDIDATE_LIMIT:
                raise PanelError(f"no more than {CANDIDATE_LIMIT} candidates are allowed")
            self.state.scan_candidates = values
            return t("NOTICE_CANDIDATES", count=len(values))
        if ident == "xr_scan_sni":
            self.state.scan_sni = text
            return t("NOTICE_SCAN_SNI", value=text) if text else t("NOTICE_SCAN_SNI", value=t("UI_NONE"))
        if ident == "xr_scan_xver":
            if not text.isdigit() or int(text) not in (0, 1, 2):
                raise PanelError("the proxy protocol version must be 0, 1 or 2")
            self.state.scan_xver = int(text)
            return t("NOTICE_SCAN_XVER", value=self.state.scan_xver)
        if ident == "xr_dns_servers":
            servers = parse_dns(text)
            self.state.dns_servers = servers
            return t("NOTICE_DNS", value=", ".join(servers) or t("UI_NONE"))
        if ident == "xr_api_port":
            port = parse_port(text)
            for inbound in self.state.inbounds:
                if inbound.port == port:
                    raise PanelError(f"the port {port} is used by the inbound {inbound.remark}")
            self.state.api_port = port
            return t("NOTICE_API_PORT", port=port)
        if ident == "xr_access_log":
            if not text.startswith("/") or "\n" in text or "\r" in text:
                raise PanelError("the access log path must be an absolute path without newlines")
            self.state.access_log = text
            return t("NOTICE_ACCESS_LOG", value=text)
        if ident == "ssh_new_port":
            port = parse_port(text)
            return t("NOTICE_SSH_PORT", port=port)
        if ident == "ssh_pubkey":
            if not text.startswith(("ssh-", "ecdsa-", "sk-")):
                raise PanelError("the value is not a public key")
            return t("NOTICE_PUBKEY")
        raise PanelError(f"the field {ident} is not supported")

    async def apply_input(self, chat_id: int, ident: str, ctx: str, value: str) -> None:
        try:
            notice = self.set_field(ident, ctx, value)
        except (PanelError, XrayError, InlineError, ModelError, ValueError) as exc:
            await self.send(chat_id, self.error_screen(ident, ctx, str(exc)))
            return
        self.save()
        await self.send(chat_id, await self.screen_for(ident, ctx, notice))

    def error_screen(self, ident: str, ctx: str, message: str) -> Any:
        try:
            return xscreens.input_screen(self.view(error=message), ident, ctx, self.back_target(ctx))
        except InlineError:
            return xscreens.home(self.view(error=message))

    def back_target(self, ctx: str) -> str:
        parts = ctx.split(":", 1)
        return f"xr:in:{parts[0]}" if parts[0].isdigit() else "xr:home"

    async def screen_for(self, ident: str, ctx: str, notice: str) -> Any:
        parts = ctx.split(":", 1)
        inbound = self.inbound_of_ctx(ctx)
        if inbound is not None and len(parts) > 1:
            client = inbound.client(parts[1])
            if client is not None:
                link = self.link_of(inbound, client.email)
                path, url = self.sub_url(client.email)
                return xscreens.client_screen(self.view(notice=notice), inbound, client.email, link, url, path)
        if inbound is not None:
            return xscreens.inbound_screen(self.view(notice=notice), inbound)
        if ident in {"xr_scan_targets", "xr_scan_manual", "xr_scan_candidates", "xr_scan_sni", "xr_scan_xver"}:
            return xscreens.scan_targets_screen(self.view(notice=notice))
        if ident in {"xr_dns_servers", "xr_api_port", "xr_access_log", "xr_ignoreip"}:
            return screens.settings(self.view(notice=notice))
        if ident == "xr_log_level":
            return xscreens.core_screen(self.view(notice=notice))
        if ident in {"xr_sub_port", "xr_sub_address", "xr_sub_refresh"}:
            return xscreens.subs_screen(self.view(notice=notice), self.sub_rows())
        if ident in {"xr_ban_ip", "xr_bantime", "xr_ssh_bantime", "xr_ssh_maxretry"}:
            return self.bot.ban_view(notice=notice)
        if ident in {"ssh_new_port", "ssh_pubkey"}:
            return self.bot.sshd_view(notice=notice)
        return xscreens.home(self.view(notice=notice))


def manual_target(text: str) -> str:
    body = (text or "").strip()
    if "/" in body:
        return body
    host, port = host_port(body)
    return f"{host}:{port}"


def checked(func, *args):
    try:
        return func(*args)
    except XrayError as exc:
        raise PanelError(str(exc)) from None


def host_port(value: object) -> tuple[str, int]:
    text = str(value or "").strip()
    if not text:
        raise PanelError("a host:port value is required")
    host = text
    port = 443
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        rest = rest.lstrip(":")
        if rest:
            port = parse_port(rest)
    elif text.count(":") == 1:
        host, raw_port = text.split(":", 1)
        port = parse_port(raw_port)
    host = host.strip()
    if not host or any(char.isspace() for char in host):
        raise PanelError("the address must not contain spaces")
    return host, port


DNS_ENTRY = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


def parse_dns(value: object) -> list[str]:
    text = str(value or "").replace(";", ",").replace(" ", ",")
    out: list[str] = []
    for item in text.split(","):
        token = item.strip()
        if not token:
            continue
        if token.startswith(("https://", "tls://", "quic://", "h2c://")):
            if any(char.isspace() for char in token) or len(token) > 300:
                raise PanelError("the dns server looks wrong")
            if token not in out:
                out.append(token)
            continue
        body = token.split(":", 1)[0] if token.count(":") == 1 else token
        if not DNS_ENTRY.match(token) or not body:
            raise PanelError(f"{token} is not a dns server")
        if token not in out:
            out.append(token)
    return out[:8]


def parse_duration(value: object) -> str:
    text = str(value or "").strip().lower()
    if not DURATION.match(text):
        raise PanelError("the duration must be a number with s, m, h, d or w, for example 3d")
    return text


def parse_addresses(value: object) -> list[str]:
    text = str(value or "").replace(";", ",").replace(" ", ",")
    out: list[str] = []
    for item in text.split(","):
        token = item.strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            raise PanelError(f"{token} is not an address or a network") from None
        rendered = str(network.network_address) + ("/" + str(network.prefixlen) if network.prefixlen != network.max_prefixlen else "")
        if rendered not in out:
            out.append(rendered)
    if not out:
        raise PanelError("at least one address is required")
    return out


def parse_port(value: object) -> int:
    text = str(value or "").strip()
    if not text.isdigit():
        raise PanelError("the port must be a number")
    port = int(text)
    if port < 1 or port > 65535:
        raise PanelError("the port must be between 1 and 65535")
    return port


def ensure_slash(value: str) -> str:
    text = (value or "/").strip() or "/"
    return text if text.startswith("/") else "/" + text


def state_report(state: CoreState) -> dict[str, Any]:
    return {
        "installed": state.installed,
        "version": state.version,
        "pinned": state.pinned,
        "core_path": state.core_path,
        "config_path": state.config_path,
        "config_exists": state.config_exists,
        "config_digest": state.config_digest,
        "inbounds": state.inbounds,
        "port": state.port,
        "ports": state.ports,
        "listening": state.listening,
        "service": state.service,
        "unit": state.unit,
        "systemd": state.systemd,
        "arch": state.arch,
    }


def best_of(results: list[ScanResult]) -> ScanResult | None:
    if not results:
        return None
    return best_candidate(results)
