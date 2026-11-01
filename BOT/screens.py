from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import i18n
from .guard import BanState, SshState
from .store import State
from .ui import (
    big,
    bold,
    bullet_list,
    button,
    code,
    input_row,
    fitted,
    details,
    divider,
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


def home(view: View) -> Any:
    t = view.tr()
    state = view.state
    xray = state.xray
    blocks = banner(view, t)
    blocks.append(f"<p>{ssh_line(view, t)}</p>")
    blocks.append(f"<p>{core_line(view, t)}</p>")
    pairs = [
        (t("HOME_LABEL_INBOUNDS"), code(len(xray.inbounds))),
        (t("HOME_LABEL_CLIENTS"), code(view.clients)),
        (t("HOME_LABEL_SUBS"), code(t("UI_ON") if xray.sub_enabled else t("UI_OFF"))),
        (t("HOME_LABEL_FAIL2BAN"), code(t("UI_ON") if xray.fail2ban_enabled else t("UI_OFF"))),
        (t("HOME_LABEL_PROTOCOL"), code(xray.protocol_label())),
        (t("HOME_LABEL_ENCRYPTION"), code(xray.encryption_label())),
    ]
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    if xray.inbounds:
        rows = [(f"{item.id} {item.remark}", f"{item.port} {item.network} {item.security}") for item in xray.inbounds]
        blocks.append(table(rows, (t("HOME_TABLE_HEADER"), t("HOME_TABLE_HEADER2"))))
    buttons = [
        row(button(t("NAV_XRAY"), "xr:home"), button(t("NAV_FREETURN"), "ft:home")),
        row(button(t("NAV_SCANNER"), "xr:scan"), button(t("NAV_SUBS"), "xr:subs")),
        row(button(t("NAV_CORE"), "xr:core"), button(t("CORE_NAV"), "core:show")),
        row(button(t("NAV_FAIL2BAN"), "nav:ban"), button(t("NAV_SSHD"), "nav:sshd")),
        row(button(t("NAV_SSH"), "nav:ssh"), button(t("NAV_SETTINGS"), "nav:settings")),
        row(button(t("NAV_UPDATE"), "upd:show"), button(t("NAV_LANGUAGE"), "nav:lang")),
        row(button(t("NAV_HELP"), "nav:help")),
    ]
    return screen(t("HOME_TITLE"), t("HOME_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"))


def language_screen(view: View) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(table([(t("LANG_CURRENT"), code(t("LANG_NAME")))], (t("UI_PARAM"), t("UI_VALUE"))))
    blocks.append(quote(muted(t("LANG_NOTE"))))
    buttons = [row(*[button(i18n.t("LANG_NAME", item), f"lang:set:{item}") for item in i18n.LANGUAGES])]
    buttons.append(row(button(t("UI_HOME"), "nav:home")))
    return screen(t("LANG_TITLE"), t("LANG_SUBTITLE"), blocks, buttons)


def ssh_settings(view: View) -> Any:
    t = view.tr()
    cfg = view.state.ssh
    blocks = banner(view, t)
    pairs = [
        (t("SSH_LABEL_MODE"), code(t("SSH_LOCAL_MODE"))),
        (t("SSH_LABEL_PORT"), code(cfg.port)),
    ]
    if view.sshd is not None:
        pairs.extend(
            [
                (t("SSHD_PASSWORD_LOGIN"), code(view.sshd.password_authentication)),
                (t("SSHD_ROOT"), code(view.sshd.permit_root_login)),
                (t("SSHD_KEYS"), code(t("SSHD_KEYS_VALUE", count=view.sshd.keys, user=view.sshd.key_user or "root"))),
            ]
        )
    blocks.append(table(pairs, (t("UI_FIELD"), t("UI_VALUE"))))
    blocks.append(quote(muted(t("SSH_NO_PASSWORD"))))
    buttons = [
        input_row(t("SSH_LABEL_PORT"), "ssh_new_port", "-", view.lang),
        input_row(t("SSHD_NOTICE_KEY"), "ssh_pubkey", "-", view.lang),
        row(button(t("SSHD_BTN_CHECK"), "sshd:status"), button(t("SSHD_PW_OFF"), "sshd:auth:no")),
        row(button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("SSH_TITLE"), t("SSH_SUBTITLE"), blocks, buttons)


def settings(view: View) -> Any:
    t = view.tr()
    xray = view.state.xray
    blocks = banner(view, t)
    pairs = [
        (t("SET_CORE_VERSION"), code(xray.version)),
        (t("SET_LOG_LEVEL"), code(xray.log_level)),
        (t("SET_SUB_PORT"), code(view.state.sub_port)),
        (t("SET_SUB_ADDRESS"), code(xray.sub_address or t("UI_NOT_SET"))),
        (t("SET_TARGETS"), code(len(xray.scan_targets))),
        (t("SET_SUB_PATH"), code(xray.sub_path_pattern())),
    ]
    pairs.extend(
        [
            (t("SET_CANDIDATES"), code(len(xray.candidates()))),
            (t("SET_SCAN_SNI"), code(xray.scan_sni or t("UI_NONE"))),
            (t("SET_SCAN_XVER"), code(xray.scan_xver)),
            (t("SET_API_PORT"), code(xray.api_port)),
            (t("SET_ACCESS_LOG"), code(xray.access_log)),
            (t("SET_DNS"), code(xray.dns_csv() or t("UI_NONE"))),
            (t("SET_SSH_BANTIME"), code(xray.fail2ban_ssh_bantime)),
            (t("SET_SSH_MAXRETRY"), code(str(xray.fail2ban_ssh_maxretry))),
            (t("SET_IGNOREIP"), code(xray.fail2ban_ignoreip)),
            (t("SET_SUB_REFRESH"), code(xray.sub_refresh)),
        ]
    )
    blocks.append(table(pairs, (t("UI_FIELD"), t("UI_VALUE"))))
    blocks.append(quote(muted(t("SET_NOTE_SUB_PATH"))))
    buttons = [
        row(button(t("SET_VERSION_PINNED", version=xray.pinned()), "xr:core:ver:pin"), button(t("SET_VERSION_LATEST"), "xr:core:ver:latest")),
        input_row(t("SET_LOG_LEVEL"), "xr_log_level", "-", view.lang),
        input_row(t("SET_SUB_PORT"), "xr_sub_port", "-", view.lang),
        input_row(t("SET_SUB_ADDRESS"), "xr_sub_address", "-", view.lang),
        input_row(t("SET_CANDIDATES"), "xr_scan_candidates", "-", view.lang),
        input_row(t("SET_API_PORT"), "xr_api_port", "-", view.lang),
        input_row(t("SET_ACCESS_LOG"), "xr_access_log", "-", view.lang),
        input_row(t("SET_DNS"), "xr_dns_servers", "-", view.lang),
        row(button(t("NAV_LANGUAGE"), "nav:lang")),
        row(button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("SET_TITLE"), t("SET_SUBTITLE"), blocks, buttons)


def ban_screen(view: View) -> Any:
    t = view.tr()
    xray = view.state.xray
    blocks = banner(view, t)
    ban = view.ban
    pairs = [
        (t("FB_ENABLED_BOT"), code(yes_no(view.lang, xray.fail2ban_enabled))),
        (t("FB_JAIL"), code(xray.fail2ban_jail)),
        (t("FB_BANTIME"), code(t("FB_MINUTES", value=xray.fail2ban_bantime))),
        (t("FB_SSH_BANTIME"), code(xray.fail2ban_ssh_bantime)),
        (t("FB_SSH_MAXRETRY"), code(str(xray.fail2ban_ssh_maxretry))),
        (t("FB_IGNOREIP"), code(xray.fail2ban_ignoreip)),
    ]
    if ban is not None:
        pairs.extend(
            [
                (t("FB_SERVER"), code(yes_no(view.lang, ban.installed))),
                (t("FB_JAIL_ACTIVE"), code(yes_no(view.lang, ban.active))),
                (t("FB_JAILS"), code(", ".join(ban.jails) or t("UI_NONE"))),
                (t("FB_SUB_JAIL"), code(ban.sub_jail)),
                (t("FB_CHAIN"), code(ban.chain)),
                (t("FB_RULES"), code(len(ban.chain_rules))),
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
        row(button(t("FB_BTN_ENABLE"), "fb:install"), button(t("FB_BTN_CHECK"), "fb:status")),
        input_row(t("FB_BANTIME"), "xr_bantime", "-", view.lang),
        input_row(t("FB_IP_FIELD"), "xr_ban_ip", "-", view.lang),
        input_row(t("SET_SSH_BANTIME"), "xr_ssh_bantime", "-", view.lang),
        input_row(t("SET_SSH_MAXRETRY"), "xr_ssh_maxretry", "-", view.lang),
        input_row(t("SET_IGNOREIP"), "xr_ignoreip", "-", view.lang),
        row(button(t("FB_BTN_RESET"), "fb:reset"), button(t("FB_BTN_DISABLE"), "fb:remove")),
        row(button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("FB_TITLE"), t("FB_SUBTITLE"), blocks, buttons)


def sshd_screen(view: View) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    item = view.sshd
    if item is None:
        blocks.append(quote(muted(t("SSHD_NOT_READ"))))
    else:
        pairs = [
            (t("SSHD_PORTS"), code(", ".join(str(port) for port in item.ports))),
            (t("SSHD_ROOT"), code(item.permit_root_login)),
            (t("SSHD_PASSWORD_LOGIN"), code(item.password_authentication)),
            (t("FB_JAIL"), code(t("SSHD_RISK_OFF") if item.password_authentication == "no" else t("SSHD_RISK_ON"))),
            (t("SSHD_KEY_LOGIN"), code(item.pubkey_authentication)),
            (t("SSHD_SERVICE"), code(item.service)),
            (t("SSHD_BINARY"), code(yes_no(view.lang, item.sshd))),
            (t("SSHD_CONFIG"), code(item.config)),
            (t("SSHD_KEYS"), code(t("SSHD_KEYS_VALUE", count=item.keys, user=item.key_user or "root"))),
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
        row(button(t("SSHD_BTN_CHECK"), "sshd:status")),
        input_row(t("SSHD_NEW_PORT"), "ssh_new_port", "-", view.lang),
        input_row(t("SSHD_PUBKEY"), "ssh_pubkey", "-", view.lang),
        row(button(t("SSHD_PW_OFF"), "sshd:auth:no"), button(t("SSHD_PW_ON"), "sshd:auth:yes")),
        row(button(t("SSHD_ROOT_KEY"), "sshd:root:prohibit-password"), button(t("SSHD_ROOT_OFF"), "sshd:root:no")),
        row(button(t("SSHD_REMOVE"), "sshd:remove"), button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("SSHD_TITLE"), t("SSHD_SUBTITLE"), blocks, buttons, footer=t("SSHD_FOOTER"))


def update_screen(view: View, info: dict[str, Any]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    if not info.get("git"):
        blocks.append(quote(bold(t("UPD_NO_GIT"))))
        buttons = [row(button(t("UI_REFRESH"), "upd:show"), button(t("UI_HOME"), "nav:home"))]
        return screen(t("UPD_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"))
    branch = str(info.get("branch") or "")
    behind = int(info.get("behind", 0) or 0)
    behind_text = t("UPD_BEHIND", count=code(behind), branch=branch) if behind else t("UPD_UP_TO_DATE", branch=branch)
    release = str(info.get("release") or "")
    release_text = release or t("UPD_NO_RELEASE", reason=str(info.get("release_error") or t("UI_NONE")))
    pairs = [
        (t("UPD_LABEL_SOURCE"), code(info.get("root") or t("UI_NOT_SET"))),
        (t("UPD_LABEL_BRANCH"), code(branch or t("UI_NOT_SET"))),
        (t("UPD_LABEL_COMMIT"), code("%s %s" % (info.get("commit") or t("UI_NOT_SET"), info.get("subject") or ""))),
        (t("UPD_LABEL_TAG"), code(info.get("tag") or t("UI_NOT_SET"))),
        (t("UPD_LABEL_CHANGES"), code(info.get("dirty", 0))),
        (t("UPD_LABEL_BEHIND"), behind_text),
        (t("UPD_LABEL_RELEASE"), code(release_text)),
        (t("UPD_LABEL_SERVICE"), code(info.get("unit_state") or t("UI_NONE"))),
    ]
    blocks.append(table(pairs, (t("UI_PARAM"), t("UI_VALUE"))))
    buttons = [
        row(button(t("UPD_BTN_COMMIT"), "upd:commit"), button(t("UPD_BTN_RELEASE"), "upd:release")),
        row(button(t("UI_REFRESH"), "upd:show"), button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("UPD_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"))


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
        row(button(t("UI_CONFIRM"), action), button(t("UI_CANCEL"), "upd:show")),
    ]
    return screen(t("UPD_CONFIRM_TITLE"), t("UI_ACTION_IRREVERSIBLE"), blocks, buttons, footer=t("HOME_FOOTER"))


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
        row(button(t("UI_REFRESH"), "upd:show"), button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("UPD_DONE_TITLE") if ok else t("UPD_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"))


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
    buttons = [row(button(t("UI_HOME"), "nav:home"), button(t("NAV_XRAY"), "xr:home"))]
    return screen(t("HELP_TITLE"), t("HELP_SUBTITLE"), blocks, buttons)


def denied(lang: str = i18n.DEFAULT_LANGUAGE) -> Any:
    t = i18n.translator(lang)
    return screen(t("DENIED_TITLE"), "", [quote(bold(t("DENIED_BODY")))], [])


def error_screen(view: View, title: str, message: str) -> Any:
    t = view.tr()
    blocks = [quote(bold(message))]
    buttons = [row(button(t("UI_HOME"), "nav:home"), button(t("NAV_XRAY"), "xr:home"))]
    return screen(title, t("UI_ACTION_FAILED"), blocks, buttons)


def busy_screen(title: str, lang: str = i18n.DEFAULT_LANGUAGE, steps: list[str] | None = None) -> Any:
    t = i18n.translator(lang)
    blocks = [quote(muted(title))]
    if steps:
        blocks.append(bullet_list([muted(item) for item in steps]))
    return screen(t("BUSY_TITLE"), t("BUSY_SUBTITLE"), blocks, [])


def prompt(ident: str, lang: str = i18n.DEFAULT_LANGUAGE, error: str = "") -> Any:
    from . import inline

    t = i18n.translator(lang)
    item = inline.field(ident)
    blocks: list[str] = []
    if error:
        blocks.append(quote(bold(error)))
    blocks.append(
        table(
            [(t("UI_FIELD"), code(item.label(lang))), (t("UI_HINT"), muted(item.hint(lang)))],
            (t("UI_FIELD"), t("UI_VALUE")),
        )
    )
    if item.example:
        blocks.append(f"<p>{t('PROMPT_EXAMPLE', example=code(item.example))}</p>")
    buttons = [row(inline_button(t("PROMPT_INPUT"), inline.prefill(ident)), button(t("UI_CANCEL"), "nav:home"))]
    return screen(t("PROMPT_TITLE"), item.label(lang), blocks, buttons)


def confirm(title: str, body: str, action: str, lang: str = i18n.DEFAULT_LANGUAGE, back: str = "nav:home") -> Any:
    t = i18n.translator(lang)
    blocks = [quote(bold(body))]
    buttons = [row(button(t("UI_CONFIRM"), action), button(t("UI_CANCEL"), back))]
    return screen(title, t("UI_ACTION_IRREVERSIBLE"), blocks, buttons)


def logs_screen(view: View, lines: list[str], tail: int) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(f"<p>{t('LOGS_LAST', count=code(tail))}</p>")
    blocks.append(pre("\n".join(lines) or t("UI_EMPTY")))
    buttons = [
        row(button("50", "xr:logs:50"), button("200", "xr:logs:200"), button("500", "xr:logs:500")),
        row(button(t("UI_REFRESH"), f"xr:logs:{tail}"), button(t("UI_HOME"), "nav:home")),
    ]
    return screen(t("LOGS_TITLE"), t("LOGS_SUBTITLE"), blocks, buttons)


def guard_rows(view: View) -> str:
    t = view.tr()
    return divider() + row(big(t("NAV_FAIL2BAN"), "nav:ban"), big(t("NAV_SSHD"), "nav:sshd"))


def subscription_hint(path: str, url: str, lang: str = i18n.DEFAULT_LANGUAGE) -> Any:
    t = i18n.translator(lang)
    copy_html, long_html = fitted(t("SUB_COPY"), url, lang)
    blocks = [f"<p>{t('SUB_LABEL_PATH', path=code(path))}</p>"]
    blocks.append(copy_html and pre(url) or long_html)
    blocks.append(quote(muted(t("SUB_NOTE"))))
    buttons = [copy_html, row(button(t("UI_HOME"), "nav:home"))]
    return screen(t("SUB_TITLE"), t("SUB_SUBTITLE"), blocks, buttons)
