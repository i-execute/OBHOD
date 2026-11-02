from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import cores, i18n, xscreens
from .guard import BanState, SshState
from .store import State
from .ui import (

    bold,
    bullet_list,
    button,
    code,
    input_row,
    fitted,
    details,

    heading,
    inline_button,
    muted,
    pre,
    quote,
    row,
    screen,
    table,
)


@dataclass
class View:
    state: State
    core: dict[str, Any] = field(default_factory=dict)
    ban: BanState | None = None
    sshd: SshState | None = None
    notice: str = ""
    error: str = ""
    busy: str = ""
    lang: str = i18n.DEFAULT_LANGUAGE
    emoji_default: bool = False
    ft_clients: int = 0

    @property
    def emoji_on(self) -> bool:
        if self.state.emoji is None:
            return bool(self.emoji_default)
        return bool(self.state.emoji)

    @property
    def ssh_ready(self) -> bool:
        return self.state.ssh.is_ready()

    @property
    def running(self) -> bool:
        return str(self.core.get("service", "")) == "active"

    @property
    def installed(self) -> bool:
        return bool(self.core.get("installed", False))

    @property
    def clients(self) -> int:
        return sum(len(item.clients) for item in self.state.xray.inbounds)

    def tr(self) -> i18n.Translator:
        return i18n.translator(self.lang)


def yes_no(lang: str, value: bool) -> str:
    return i18n.t("UI_YES" if value else "UI_NO", lang)


def banner(view: View, t: i18n.Translator) -> list[str]:
    out: list[str] = []
    if view.notice:
        out.append(quote(muted(view.notice)))
    if view.error:
        out.append(quote(bold(view.error)))
    if view.busy:
        out.append(quote(muted(view.busy)))
    return out


def ssh_line(view: View, t: i18n.Translator) -> str:
    cfg = view.state.ssh
    mark = t("HOME_SSH_READY") if cfg.is_ready() else t("HOME_SSH_NOT_READY")
    return bold(t("HOME_SSH_LOCAL", port=cfg.port)) + " " + muted(mark)


def core_line(view: View, t: i18n.Translator) -> str:
    if not view.core:
        return muted(t("HOME_CORE_UNKNOWN"))
    if not view.installed:
        return bold(t("HOME_CORE_MISSING"))
    state = t("HOME_CORE_RUNNING") if view.running else t("HOME_CORE_STOPPED")
    ports = ", ".join(str(item) for item in view.core.get("listening") or []) or t("UI_NONE")
    version = str(view.core.get("version", "") or "")
    return bold(t("HOME_CORE_STATE", version=version, state=state)) + " " + muted(t("HOME_CORE_PORTS", ports=ports))


def core_rows(view: View, t: i18n.Translator) -> list[tuple[str, str, str]]:
    cards = cores.snapshot(view.state, view.core, view.ft_clients)
    rows: list[tuple[str, str, str]] = []
    for card in cards:
        rows.append((card.icon, card.label(t), card.detail(t)))
    return rows


def home(view: View) -> Any:
    t = view.tr()
    state = view.state
    xray = state.xray
    cards = cores.snapshot(state, view.core, view.ft_clients)
    blocks = banner(view, t)
    blocks.append(f"<p>{ssh_line(view, t)}</p>")
    summary = [
        ("module", t("HOME_SUMMARY_ACTIVE"), code(t("CORE_NAME_%s" % cores.normalize(state.core).upper()))),
        ("ok", t("HOME_SUMMARY_RUNNING"), code(cores.running_count(cards))),
        ("save", t("HOME_SUMMARY_INSTALLED"), code(cores.installed_count(cards))),
        ("info", t("HOME_LABEL_INBOUNDS"), code(len(xray.inbounds))),
        ("users", t("HOME_LABEL_CLIENTS"), code(view.clients)),
        ("link", t("HOME_LABEL_SUBS"), code(t("UI_ON") if xray.sub_enabled else t("UI_OFF"))),
        ("shield", t("HOME_LABEL_FAIL2BAN"), code(t("UI_ON") if xray.fail2ban_enabled else t("UI_OFF"))),
    ]
    blocks.append(table(summary, (t("HOME_SUMMARY_TITLE"), t("UI_VALUE"))))
    blocks.append(table(core_rows(view, t), (t("HOME_CORE_TABLE"), t("HOME_CORE_TABLE2"))))
    blocks.append(f"<p>{muted(t('HOME_CORE_HINT'))}</p>")
    pairs = [
        ("info", t("HOME_LABEL_INBOUNDS"), code(len(xray.inbounds))),
        ("users", t("HOME_LABEL_CLIENTS"), code(view.clients)),
        ("link", t("HOME_LABEL_SUBS"), code(t("UI_ON") if xray.sub_enabled else t("UI_OFF"))),
        ("shield", t("HOME_LABEL_FAIL2BAN"), code(t("UI_ON") if xray.fail2ban_enabled else t("UI_OFF"))),
        ("settings", t("HOME_LABEL_PROTOCOL"), code(xray.protocol_label())),
        ("settings", t("HOME_LABEL_ENCRYPTION"), code(xray.encryption_label())),
    ]
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    if xray.inbounds:
        rows = [
            ("xray", f"{item.id} {item.remark}", f"{item.port} {item.network} {item.security}") for item in xray.inbounds
        ]
        blocks.append(table(rows, (t("HOME_TABLE_HEADER"), t("HOME_TABLE_HEADER2"))))
    core_buttons = [row(button(card.label(t), card.route, icon=card.icon)) for card in cards]
    buttons = core_buttons + [
        row(button(t("NAV_SCANNER"), "xr:scan", icon="scan"), button(t("NAV_SUBS"), "xr:subs", icon="link")),
        row(button(t("CORE_NAV"), "core:show", icon="module"), button(t("NAV_DEBUG"), "dbg:home", icon="bug")),
        row(button(t("NAV_FAIL2BAN"), "nav:ban", icon="shield"), button(t("NAV_SSHD"), "nav:sshd", icon="lock")),
        row(button(t("NAV_SSH"), "nav:ssh", icon="key"), button(t("NAV_SETTINGS"), "nav:settings", icon="settings")),
        row(button(t("NAV_UPDATE"), "upd:show", icon="update"), button(t("NAV_LANGUAGE"), "nav:lang", icon="language")),
        row(button(t("NAV_HELP"), "nav:help", icon="docs")),
    ]
    return screen(t("HOME_TITLE"), t("HOME_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"), icon="home")


def language_screen(view: View) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(table([("language", t("LANG_CURRENT"), code(t("LANG_NAME")))], (t("UI_PARAM"), t("UI_VALUE"))))
    blocks.append(quote(muted(t("LANG_NOTE"))))
    buttons = [row(*[button(i18n.t("LANG_NAME", item), f"lang:set:{item}", icon="language") for item in i18n.LANGUAGES])]
    buttons.append(row(button(t("UI_HOME"), "nav:home", icon="home")))
    return screen(t("LANG_TITLE"), t("LANG_SUBTITLE"), blocks, buttons, icon="language")


def ssh_settings(view: View) -> Any:
    t = view.tr()
    cfg = view.state.ssh
    blocks = banner(view, t)
    pairs = [
        ("lock", t("SSH_LABEL_MODE"), code(t("SSH_LOCAL_MODE"))),
        ("lock", t("SSH_LABEL_PORT"), code(cfg.port)),
    ]
    if view.sshd is not None:
        pairs.extend(
            [
                ("logs", t("SSHD_PASSWORD_LOGIN"), code(view.sshd.password_authentication)),
                ("lock", t("SSHD_ROOT"), code(view.sshd.permit_root_login)),
                ("key", t("SSHD_KEYS"), code(t("SSHD_KEYS_VALUE", count=view.sshd.keys, user=view.sshd.key_user or "root"))),
            ]
        )
    blocks.append(table(pairs, (t("UI_FIELD"), t("UI_VALUE"))))
    blocks.append(quote(muted(t("SSH_NO_PASSWORD"))))
    buttons = [
        input_row(t("SSH_LABEL_PORT"), "ssh_new_port", "-", view.lang),
        input_row(t("SSHD_NOTICE_KEY"), "ssh_pubkey", "-", view.lang),
        row(button(t("SSHD_BTN_CHECK"), "sshd:status", icon="info"), button(t("SSHD_PW_OFF"), "sshd:auth:no", icon="lock")),
        row(button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("SSH_TITLE"), t("SSH_SUBTITLE"), blocks, buttons, icon="key")


def settings(view: View) -> Any:
    t = view.tr()
    xray = view.state.xray
    blocks = banner(view, t)
    pairs = [
        ("tag", t("SET_CORE_VERSION"), code(xray.version)),
        ("logs", t("SET_LOG_LEVEL"), code(xray.log_level)),
        ("link", t("SET_SUB_PORT"), code(view.state.sub_port)),
        ("link", t("SET_SUB_ADDRESS"), code(xray.sub_address or t("UI_NOT_SET"))),
        ("target", t("SET_TARGETS"), code(len(xray.scan_targets))),
        ("link", t("SET_SUB_PATH"), code(xray.sub_path_pattern())),
    ]
    pairs.extend(
        [
            ("info", t("SET_CANDIDATES"), code(len(xray.candidates()))),
            ("scan", t("SET_SCAN_SNI"), code(xray.scan_sni or t("UI_NONE"))),
            ("scan", t("SET_SCAN_XVER"), code(xray.scan_xver)),
            ("world", t("SET_API_PORT"), code(xray.api_port)),
            ("logs", t("SET_ACCESS_LOG"), code(xray.access_log)),
            ("world", t("SET_DNS"), code(xray.dns_csv() or t("UI_NONE"))),
            ("clock", t("SET_SSH_BANTIME"), code(xray.fail2ban_ssh_bantime)),
            ("clock", t("SET_SSH_MAXRETRY"), code(str(xray.fail2ban_ssh_maxretry))),
            ("world", t("SET_IGNOREIP"), code(xray.fail2ban_ignoreip)),
            ("clock", t("SET_SUB_REFRESH"), code(xray.sub_refresh)),
            ("star", t("SET_EMOJI"), code(t("SET_EMOJI_ON") if view.emoji_on else t("SET_EMOJI_OFF"))),
        ]
    )
    blocks.append(table(pairs, (t("UI_FIELD"), t("UI_VALUE"))))
    target = next((item for item in xray.inbounds if item.security in {"reality", "tls"}), None)
    blocks.append(
        table(
            [
                ("target", t("SET_CHECK_TARGET"), code(target.dest if target else t("UI_NOT_SET"))),
                ("shield", t("XR_SEC_CURRENT"), code(xscreens.security_label(target.security_kind(), view.lang) if target else t("UI_NONE"))),
            ],
            (t("UI_FIELD"), t("UI_VALUE")),
        )
    )
    blocks.append(quote(muted(t("XR_CHECK_NOTE"))))
    blocks.append(quote(muted(t("SET_NOTE_SUB_PATH"))))
    blocks.append(quote(muted(t("SET_EMOJI_NOTE"))))
    buttons = [
        row(button(t("SET_VERSION_PINNED", version=xray.pinned()), "xr:core:ver:pin", icon="pin"), button(t("SET_VERSION_LATEST"), "xr:core:ver:latest", icon="update")),
        input_row(t("SET_LOG_LEVEL"), "xr_log_level", "-", view.lang),
        input_row(t("SET_SUB_PORT"), "xr_sub_port", "-", view.lang),
        input_row(t("SET_SUB_ADDRESS"), "xr_sub_address", "-", view.lang),
        input_row(t("SET_CANDIDATES"), "xr_scan_candidates", "-", view.lang),
        row(button(t("XR_CHECK_BTN"), "xr:fit:" + str(target.id if target else ""), icon="scan")),
        input_row(t("SET_API_PORT"), "xr_api_port", "-", view.lang),
        input_row(t("SET_ACCESS_LOG"), "xr_access_log", "-", view.lang),
        input_row(t("SET_DNS"), "xr_dns_servers", "-", view.lang),
        row(
            button(t("SET_EMOJI_BTN_OFF" if view.emoji_on else "SET_EMOJI_BTN_ON"), "set:emoji", icon="star"),
        ),
        row(button(t("NAV_LANGUAGE"), "nav:lang", icon="language")),
        row(button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("SET_TITLE"), t("SET_SUBTITLE"), blocks, buttons, icon="settings")


def ban_screen(view: View) -> Any:
    t = view.tr()
    xray = view.state.xray
    blocks = banner(view, t)
    ban = view.ban
    pairs = [
        ("shield", t("FB_ENABLED_BOT"), code(yes_no(view.lang, xray.fail2ban_enabled))),
        ("shield", t("FB_JAIL"), code(xray.fail2ban_jail)),
        ("clock", t("FB_BANTIME"), code(t("FB_MINUTES", value=xray.fail2ban_bantime))),
        ("clock", t("FB_SSH_BANTIME"), code(xray.fail2ban_ssh_bantime)),
        ("clock", t("FB_SSH_MAXRETRY"), code(str(xray.fail2ban_ssh_maxretry))),
        ("shield", t("FB_IGNOREIP"), code(xray.fail2ban_ignoreip)),
    ]
    if ban is not None:
        pairs.extend(
            [
                ("shield", t("FB_SERVER"), code(yes_no(view.lang, ban.installed))),
                ("shield", t("FB_JAIL_ACTIVE"), code(yes_no(view.lang, ban.active))),
                ("shield", t("FB_JAILS"), code(", ".join(ban.jails) or t("UI_NONE"))),
                ("shield", t("FB_SUB_JAIL"), code(ban.sub_jail)),
                ("shield", t("FB_CHAIN"), code(ban.chain)),
                ("shield", t("FB_RULES"), code(len(ban.chain_rules))),
            ]
        )
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    if ban is not None:
        blocks.append(f"<p>{t('FB_BANNED', ips=code(', '.join(ban.banned) or t('UI_NONE')))}</p>")
        blocks.append(f"<p>{t('FB_BANNED_SSH', ips=code(', '.join(ban.ssh_banned) or t('UI_NONE')))}</p>")
        blocks.append(f"<p>{t('FB_BANNED_SUB', ips=code(', '.join(ban.sub_banned) or t('UI_NONE')))}</p>")
        if ban.chain_rules:
            blocks.append(pre("\n".join(ban.chain_rules[:12])))
    blocks.append(
        details(
            t("FB_HOW_TITLE"),
            bullet_list(
                [
                    t("FB_HOW_LOG", path=code(xray.access_log)),
                    t("FB_HOW_LINE", line=code("[LIMIT_IP] Email = ... || Disconnecting OLD IP = ... || Timestamp = ...")),
                    t("FB_HOW_LIMITS"),
                    t("FB_HOW_PORTS"),
                ]
            ),
        )
    )
    buttons = [
        row(button(t("FB_BTN_ENABLE"), "fb:install", icon="shield"), button(t("FB_BTN_CHECK"), "fb:status", icon="info")),
        input_row(t("FB_BANTIME"), "xr_bantime", "-", view.lang),
        input_row(t("FB_IP_FIELD"), "xr_ban_ip", "-", view.lang),
        input_row(t("SET_SSH_BANTIME"), "xr_ssh_bantime", "-", view.lang),
        input_row(t("SET_SSH_MAXRETRY"), "xr_ssh_maxretry", "-", view.lang),
        input_row(t("SET_IGNOREIP"), "xr_ignoreip", "-", view.lang),
        row(button(t("FB_BTN_RESET"), "fb:reset", icon="restart"), button(t("FB_BTN_DISABLE"), "fb:remove", icon="delete")),
        row(button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("FB_TITLE"), t("FB_SUBTITLE"), blocks, buttons, icon="shield")


def sshd_screen(view: View) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    item = view.sshd
    if item is None:
        blocks.append(quote(muted(t("SSHD_NOT_READ"))))
    else:
        pairs = [
            ("lock", t("SSHD_PORTS"), code(", ".join(str(port) for port in item.ports))),
            ("lock", t("SSHD_ROOT"), code(item.permit_root_login)),
            ("logs", t("SSHD_PASSWORD_LOGIN"), code(item.password_authentication)),
            ("shield", t("FB_JAIL"), code(t("SSHD_RISK_OFF") if item.password_authentication == "no" else t("SSHD_RISK_ON"))),
            ("key", t("SSHD_KEY_LOGIN"), code(item.pubkey_authentication)),
            ("lock", t("SSHD_SERVICE"), code(item.service)),
            ("lock", t("SSHD_BINARY"), code(yes_no(view.lang, item.sshd))),
            ("lock", t("SSHD_CONFIG"), code(item.config)),
            ("key", t("SSHD_KEYS"), code(t("SSHD_KEYS_VALUE", count=item.keys, user=item.key_user or "root"))),
        ]
        blocks.append(table(pairs, (t("UI_FIELD"), t("UI_VALUE"))))
        state = t("SSHD_CREATED") if item.dropin_exists else t("SSHD_NOT_CREATED")
        blocks.append(f"<p>{t('SSHD_DROPIN', path=code(item.dropin), state=muted(state))}</p>")
        blocks.append(heading(t("SSHD_KEYS_TITLE"), 3))
        if item.key_list:
            rows = []
            for index, key in enumerate(item.key_list, 1):
                name = key.get("comment") or t("UI_NONE")
                rows.append((t("SSHD_KEY_ROW", count=index, kind=key.get("type", ""), comment=name), key.get("fingerprint") or t("SSHD_KEY_BYTES", bytes=int(key.get("bytes", 0)))))
            blocks.append(table(rows, (t("SSHD_KEYS"), t("UI_VALUE"))))
            blocks.append(f"<p>{muted(t('SSHD_PW_READY', count=len(item.key_list)))}</p>")
        else:
            blocks.append(quote(bold(t("SSHD_KEYS_EMPTY", path=item.key_path or "~/.ssh/authorized_keys", user=item.key_user or "root"))))
            blocks.append(f"<p>{muted(t('SSHD_KEYS_HINT'))}</p>")
            blocks.append(f"<p>{muted(t('SSHD_PW_BLOCKED', user=item.key_user or 'root', path=item.key_path or '~/.ssh/authorized_keys'))}</p>")
        blocks.append(f"<p>{muted(t('SSHD_KEYS_ONLY'))}</p>")
    buttons = [
        row(button(t("SSHD_BTN_CHECK"), "sshd:status", icon="info")),
        input_row(t("SSHD_NEW_PORT"), "ssh_new_port", "-", view.lang),
        input_row(t("SSHD_PUBKEY"), "ssh_pubkey", "-", view.lang),
        row(button(t("SSHD_PW_OFF"), "sshd:auth:no", icon="lock"), button(t("SSHD_PW_ON"), "sshd:auth:yes", icon="unlock")),
        row(button(t("SSHD_ROOT_KEY"), "sshd:root:prohibit-password", icon="key"), button(t("SSHD_ROOT_OFF"), "sshd:root:no", icon="lock")),
        row(button(t("SSHD_REMOVE"), "sshd:remove", icon="delete"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("SSHD_TITLE"), t("SSHD_SUBTITLE"), blocks, buttons, footer=t("SSHD_FOOTER"), icon="lock")


def update_screen(view: View, info: dict[str, Any]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if not info.get("git"):
        blocks.append(quote(bold(t("UPD_NO_GIT"))))
        buttons = [row(button(t("UI_REFRESH"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home"))]
        return screen(t("UPD_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"), icon="update")
    branch = str(info.get("branch") or "")
    behind = int(info.get("behind", 0) or 0)
    behind_text = t("UPD_BEHIND", count=code(behind), branch=branch) if behind else t("UPD_UP_TO_DATE", branch=branch)
    release = str(info.get("release") or "")
    release_text = release or t("UPD_NO_RELEASE", reason=str(info.get("release_error") or t("UI_NONE")))
    pairs = [
        ("info", t("UPD_LABEL_SOURCE"), code(info.get("root") or t("UI_NOT_SET"))),
        ("info", t("UPD_LABEL_BRANCH"), code(branch or t("UI_NOT_SET"))),
        ("info", t("UPD_LABEL_COMMIT"), code("%s %s" % (info.get("commit") or t("UI_NOT_SET"), info.get("subject") or ""))),
        ("tag", t("UPD_LABEL_TAG"), code(info.get("tag") or t("UI_NOT_SET"))),
        ("info", t("UPD_LABEL_CHANGES"), code(info.get("dirty", 0))),
        ("info", t("UPD_LABEL_BEHIND"), behind_text),
        ("info", t("UPD_LABEL_RELEASE"), code(release_text)),
        ("info", t("UPD_LABEL_SERVICE"), code(info.get("unit_state") or t("UI_NONE"))),
    ]
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    buttons = [
        row(button(t("UPD_BTN_COMMIT"), "upd:commit", icon="update"), button(t("UPD_BTN_RELEASE"), "upd:release", icon="tag")),
        row(button(t("UI_REFRESH"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("UPD_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"), icon="update")


def update_confirm_screen(view: View, info: dict[str, Any], preview: dict[str, Any], body: str, action: str) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(body)))
    commits = int(preview.get("commits", 0) or 0)
    if commits:
        blocks.append(f"<p>{t('UPD_PREVIEW_COUNT', count=code(commits), files=code(preview.get('total', 0)))}</p>")
        files = [code(str(item)) for item in preview.get("files") or []]
        if files:
            blocks.append(bullet_list(files))
        extra = int(preview.get("total", 0) or 0) - len(files)
        if extra > 0:
            blocks.append(quote(muted(t("UPD_PREVIEW_MORE", count=extra))))
    buttons = [
        row(button(t("UI_CONFIRM"), action, icon="ok"), button(t("UI_CANCEL"), "upd:show", icon="update")),
    ]
    return screen(t("UPD_CONFIRM_TITLE"), t("UI_ACTION_IRREVERSIBLE"), blocks, buttons, footer=t("HOME_FOOTER"), icon="warn")


def update_result_screen(view: View, info: dict[str, Any], result: dict[str, Any]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    ok = bool(result.get("ok"))
    commit = str(result.get("target") or "")
    subject = str(result.get("subject") or "")
    body = t("UPD_DONE", commit=code(commit), subject=subject) if ok else t("UPD_FAILED", error=body_text(result.get("message")))
    blocks.append(quote(bold(body)))
    steps = [muted(str(item)) for item in result.get("steps") or []]
    if steps:
        blocks.append(f"<p>{bold(t('UPD_STEPS_DONE'))}</p>")
        blocks.append(bullet_list(steps))
    if ok and result.get("message") == "already up to date":
        blocks.append(quote(muted(t("UPD_ALREADY", commit=code(commit)))))
    if result.get("rollback"):
        blocks.append(quote(muted(t("UPD_ROLLBACK", commit=code(str(result.get("source") or ""))))))
    if ok and result.get("restarted"):
        blocks.append(quote(muted(t("UPD_RESTART"))))
    buttons = [
        row(button(t("UI_REFRESH"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("UPD_DONE_TITLE") if ok else t("UPD_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"), icon="ok")


def body_text(value: object) -> str:
    return code(str(value or ""))


def help_screen(view: View) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(heading(t("HELP_WHAT_TITLE"), 3))
    blocks.append(
        bullet_list(
            [
                t("HELP_WHAT_1", protocol=code("vless"), networks=" ".join(code(item) for item in ("raw", "grpc", "xhttp"))),
                t("HELP_WHAT_2", security=" ".join(code(item) for item in ("reality", "tls", "none"))),
                t("HELP_WHAT_3", encryption=code("mlkem768x25519plus"), signature=code("ml-dsa-65")),
                t("HELP_WHAT_4"),
                t("HELP_WHAT_5", path=code("/<64>/<64>")),
                t("HELP_WHAT_6"),
            ]
        )
    )
    blocks.append(heading(t("HELP_FLOW_TITLE"), 3))
    blocks.append(bullet_list([t("HELP_FLOW_1"), t("HELP_FLOW_2"), t("HELP_FLOW_3"), t("HELP_FLOW_4")]))
    blocks.append(heading(t("INL_HINT_TITLE"), 3))
    blocks.append(bullet_list([t("INL_HINT_1"), t("INL_HINT_2"), t("INL_HINT_3"), t("INL_HINT_4")]))
    blocks.append(f"<p>{muted(t('INL_STATUS_ON'))} {muted(t('INL_STATUS_OWNER'))}</p>")
    buttons = [row(button(t("UI_HOME"), "nav:home", icon="home"), button(t("NAV_XRAY"), "xr:home", icon="xray"))]
    return screen(t("HELP_TITLE"), t("HELP_SUBTITLE"), blocks, buttons, icon="docs")


def denied(lang: str = i18n.DEFAULT_LANGUAGE) -> Any:
    t = i18n.translator(lang)
    return screen(t("DENIED_TITLE"), "", [quote(bold(t("DENIED_BODY")))], [], icon="stop")


def error_screen(view: View, title: str, message: str) -> Any:
    t = view.tr()
    blocks = [quote(bold(message))]
    buttons = [row(button(t("UI_HOME"), "nav:home", icon="home"), button(t("NAV_XRAY"), "xr:home", icon="xray"))]
    return screen(title, t("UI_ACTION_FAILED"), blocks, buttons, icon="fail")


def busy_screen(title: str, lang: str = i18n.DEFAULT_LANGUAGE, steps: list[str] | None = None) -> Any:
    t = i18n.translator(lang)
    blocks = [quote(muted(title))]
    if steps:
        blocks.append(bullet_list([muted(item) for item in steps]))
    return screen(t("BUSY_TITLE"), t("BUSY_SUBTITLE"), blocks, [], icon="clock")


def prompt(ident: str, lang: str = i18n.DEFAULT_LANGUAGE, error: str = "") -> Any:
    from . import inline

    t = i18n.translator(lang)
    item = inline.field(ident)
    blocks: list[str] = []
    if error:
        blocks.append(quote(bold(error)))
    blocks.append(
        table(
            [
                ("tag", t("UI_FIELD"), code(item.label(lang))),
                ("info", t("UI_HINT"), muted(item.hint(lang))),
            ],
            (t("UI_FIELD"), t("UI_VALUE")),
        )
    )
    if item.example:
        blocks.append(f"<p>{t('PROMPT_EXAMPLE', example=code(item.example))}</p>")
    buttons = [row(inline_button(t("PROMPT_INPUT"), inline.prefill(ident), icon="tag"), button(t("UI_CANCEL"), "nav:home", icon="home"))]
    return screen(t("PROMPT_TITLE"), item.label(lang), blocks, buttons, icon="file")


def confirm(title: str, body: str, action: str, lang: str = i18n.DEFAULT_LANGUAGE, back: str = "nav:home") -> Any:
    t = i18n.translator(lang)
    blocks = [quote(bold(body))]
    buttons = [row(button(t("UI_CONFIRM"), action, icon="ok"), button(t("UI_CANCEL"), back, icon="back"))]
    return screen(title, t("UI_ACTION_IRREVERSIBLE"), blocks, buttons, icon="warn")


def logs_screen(view: View, lines: list[str], tail: int) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(f"<p>{t('LOGS_LAST', count=code(tail))}</p>")
    blocks.append(pre("\n".join(lines) or t("UI_EMPTY")))
    buttons = [
        row(button("50", "xr:logs:50", icon="logs"), button("200", "xr:logs:200", icon="logs"), button("500", "xr:logs:500", icon="logs")),
        row(button(t("UI_REFRESH"), f"xr:logs:{tail}", icon="refresh"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("LOGS_TITLE"), t("LOGS_SUBTITLE"), blocks, buttons, icon="logs")


def subscription_hint(path: str, url: str, lang: str = i18n.DEFAULT_LANGUAGE) -> Any:
    t = i18n.translator(lang)
    copy_html, long_html = fitted(t("SUB_COPY"), url, lang)
    blocks = [f"<p>{t('SUB_LABEL_PATH', path=code(path))}</p>"]
    blocks.append(copy_html and pre(url) or long_html)
    blocks.append(quote(muted(t("SUB_NOTE"))))
    buttons = [copy_html, row(button(t("UI_HOME"), "nav:home", icon="home"))]
    return screen(t("SUB_TITLE"), t("SUB_SUBTITLE"), blocks, buttons, icon="link")
