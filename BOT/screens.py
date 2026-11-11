from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import cores, i18n, xscreens
from .guard import BanState, SshState
from .store import State
from .ui import (
    DEFAULT_REPO,
    bold,
    bold_html,
    bullet_list,
    button,
    code,
    esc,
    input_row,
    fitted,
    details,
    heading,
    ico,
    inline_button,
    muted,
    muted_html,
    pre,
    quote,
    ref_link,
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
        return ui_icons_on()

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
        return muted(t("HOME_CORE_MISSING"))
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
    blocks = banner(view, t)
    blocks.append(table(core_rows(view, t), (t("HOME_SUMMARY_TITLE"), t("HOME_CORE_TABLE2"))))
    facts = [
        ("info", t("HOME_LABEL_INBOUNDS"), code(len(xray.inbounds))),
        ("users", t("HOME_LABEL_CLIENTS"), code(view.clients)),
        ("link", t("HOME_LABEL_SUBS"), code(t("UI_ON") if xray.sub_enabled else t("UI_OFF"))),
        ("shield", t("HOME_LABEL_FAIL2BAN"), code(t("UI_ON") if xray.fail2ban_enabled else t("UI_OFF"))),
    ]
    if xray.inbounds:
        facts.extend(("xray", f"{item.id} {item.remark}", code(f"{item.port} {item.network} {item.security}")) for item in xray.inbounds)
    blocks.append(details(t("HOME_DETAILS"), table(facts, (t("UI_PARAM"), t("UI_VALUE")))))
    buttons = [row(button(card.label(t), card.route, icon=card.icon)) for card in cores.snapshot(state, view.core, view.ft_clients)]
    buttons.append(row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("NAV_SETTINGS"), "nav:settings", icon="settings")))
    buttons.append(row(button(t("NAV_UPDATE"), "upd:show", icon="update"), button(t("NAV_HELP"), "nav:help", icon="docs")))
    buttons.append(row(button(t("UI_REFRESH"), "nav:home", icon="refresh")))
    return screen(t("HOME_TITLE"), t("HOME_SUBTITLE"), blocks, buttons, icon="home")


def emoji_button(t: i18n.Translator, view: View) -> Any:
    label = t("NAV_EMOJI_ON") if view.emoji_on else t("NAV_EMOJI_OFF")
    return button(label, "nav:emoji", icon="star")


def home_line(view: View, t: i18n.Translator) -> str:
    cards = cores.snapshot(view.state, view.core, view.ft_clients)
    running = cores.running_count(cards)
    installed = cores.installed_count(cards)
    return bold(t("HOME_SUMMARY_RUNNING")) + " " + code(running) + " " + muted(t("HOME_SUMMARY_INSTALLED") + " " + str(installed))


def ui_icons_on() -> bool:
    from . import ui

    return bool(ui.icons_on())


def stuck_screen(view: View, route: str, seconds: int = 240) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(quote(bold(t("STUCK_TITLE"))))
    blocks.append(f"<p>{t('STUCK_BODY', seconds=code(seconds), route=code(route[:48]))}</p>")
    blocks.append(quote(muted(t("STUCK_HINT"))))
    buttons = [row(button(t("STUCK_DONE"), "nav:home", icon="home"), button(t("UI_REFRESH"), route, icon="refresh"))]
    return screen(t("STUCK_TITLE"), t("HOME_SUBTITLE"), blocks, buttons, icon="warn")


def quick_screen(view: View) -> Any:
    t = view.tr()
    xray = view.state.xray
    blocks = banner(view, t)
    blocks.append(quote(muted(t("HOME_SUMMARY_ACTIVE"))))
    facts = [
        ("xray", t("HOME_LABEL_INBOUNDS"), code(len(xray.inbounds))),
        ("users", t("HOME_LABEL_CLIENTS"), code(view.clients)),
        ("link", t("HOME_LABEL_SUBS"), code(t("UI_ON") if xray.sub_enabled else t("UI_OFF"))),
        ("shield", t("HOME_LABEL_FAIL2BAN"), code(t("UI_ON") if xray.fail2ban_enabled else t("UI_OFF"))),
        ("info", t("HOME_LABEL_PROTOCOL"), code(xray.protocol_label())),
    ]
    blocks.append(table(facts, (t("UI_PARAM"), t("UI_VALUE"))))
    blocks.append(quote(muted(t("HOME_EMOJI_NOTE"))))
    buttons = [
        row(button(t("NAV_UPDATE"), "upd:show", icon="update"), button(t("NAV_FAIL2BAN"), "nav:ban", icon="shield")),
        row(button(t("NAV_SSHD"), "nav:sshd", icon="lock"), button(t("NAV_LANGUAGE"), "nav:lang", icon="language")),
        row(emoji_button(t, view), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("NAV_QUICK"), t("HOME_SUBTITLE"), blocks, buttons, icon="star")


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
        ("star", t("SET_EMOJI"), code(t("SET_EMOJI_ON") if view.emoji_on else t("SET_EMOJI_OFF"))),
        ("link", t("SET_SUB_PATH"), code(xray.sub_path_pattern())),
        ("tag", t("SET_CORE_VERSION"), code(xray.version)),
    ]
    blocks.append(table(pairs, (t("UI_FIELD"), t("UI_VALUE"))))
    target = next((item for item in xray.inbounds if item.security in {"reality", "tls"}), None)
    extra_pairs = [
        ("logs", t("SET_LOG_LEVEL"), code(xray.log_level)),
        ("world", t("SET_API_PORT"), code(xray.api_port)),
        ("world", t("SET_DNS"), code(xray.dns_csv() or t("UI_NONE"))),
        ("target", t("SET_CHECK_TARGET"), code(target.dest if target else t("UI_NOT_SET"))),
        ("shield", t("XR_SEC_CURRENT"), code(xscreens.security_label(target.security_kind(), view.lang) if target else t("UI_NONE"))),
    ]
    blocks.append(details(t("HOME_DETAILS"), table(extra_pairs, (t("UI_FIELD"), t("UI_VALUE")))))
    buttons = []
    if target is not None:
        buttons.append(row(button(t("XR_CHECK_BTN"), "xr:fit:" + str(target.id), icon="scan")))
    buttons.extend(
        [
            row(button(t("NAV_LANGUAGE"), "nav:lang", icon="language"), emoji_button(t, view)),
            input_row(t("SET_API_PORT"), "xr_api_port", "-", view.lang),
            input_row(t("SET_DNS"), "xr_dns_servers", "-", view.lang),
            row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
        ]
    )
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
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
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
    buttons = [
        row(button(t("SSHD_BTN_CHECK"), "sshd:status", icon="info"), button(t("SSHD_REMOVE"), "sshd:remove", icon="delete")),
        input_row(t("SSHD_NEW_PORT"), "ssh_new_port", "-", view.lang),
        input_row(t("SSHD_PUBKEY"), "ssh_pubkey", "-", view.lang),
        row(button(t("SSHD_PW_OFF"), "sshd:auth:no", icon="lock"), button(t("SSHD_PW_ON"), "sshd:auth:yes", icon="unlock")),
        row(button(t("SSHD_ROOT_KEY"), "sshd:root:prohibit-password", icon="key"), button(t("SSHD_ROOT_OFF"), "sshd:root:no", icon="lock")),
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("SSHD_TITLE"), t("SSHD_SUBTITLE"), blocks, buttons, icon="lock")


def update_screen(view: View, info: dict[str, Any]) -> Any:
    t = view.tr()
    facts = dict(info.get("system") or {})
    if not info.get("git") and view.error and "not a git checkout" in view.error:
        view = View(state=view.state, core=view.core, ban=view.ban, sshd=view.sshd, notice=view.notice, error="", busy=view.busy, lang=view.lang, emoji_default=view.emoji_default, ft_clients=view.ft_clients)
    blocks = banner(view, t)
    if not info.get("git"):
        blocks.append(quote(bold(t("UPD_NO_GIT"))))
        blocks.append(
            table(
                [
                    ("info", t("UPD_LABEL_INSTALL"), code(info.get("root") or t("UI_NOT_SET"))),
                    ("info", t("UPD_LABEL_SERVICE"), code(info.get("unit_state") or t("UI_NONE"))),
                ],
                (t("UI_PARAM"), t("UI_VALUE")),
            )
        )
        writable = facts.get("dest_write")
        protected = dict(facts.get("protected") or {})
        flags = dict(facts.get("root_flags") or {})
        blocks.append(
            table(
                [
                    ("folder", t("UPD_LABEL_DEST"), code(facts.get("dest") or t("UI_NOT_SET"))),
                    ("key", t("UPD_LABEL_WRITE"), code(t("UPD_WRITE_OK") if writable else t("UPD_WRITE_BLOCKED", reason=str(facts.get("dest_reason") or t("UI_NONE"))))),
                    ("shield", t("UPD_LABEL_HELPER"), code(t("UPD_WRITE_OK") if facts.get("helper_write") else t("UI_OFF"))),
                ],
                (t("UI_PARAM"), t("UI_VALUE")),
            )
        )
        blocks.append(f"<p>{muted(t('UPD_NO_GIT_HINT'))}</p>")
        if flags.get("path"):
            blocks.append(quote(muted(t("UPD_RO_MOUNT", path=str(flags.get("path")), fstype=str(flags.get("fstype") or t("UI_NONE")), options=str(flags.get("options") or "")))))
        if protected.get("inside") == "yes":
            blocks.append(quote(muted_html(t("UPD_PROTECTED", unit=bold("obhod.service")))))
        if facts.get("can_update"):
            blocks.append(quote(muted(t("UPD_RETRY_HINT"))))
        else:
            blocks.append(quote(muted(t("UPD_NOT_IN_PLACE", reason=str(facts.get("why_not") or t("UI_NONE"))))))
            blocks.append(quote(muted(t("UPD_RUN_AS_ROOT"))))
            blocks.append(pre(str(facts.get("command") or "")))
        buttons = [
            row(button(t("UPD_REINSTALL_BTN"), "upd:reinstall", icon="update")),
            row(button(t("UI_HOME"), "nav:home", icon="home")),
        ]
        return screen(t("UPD_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"), icon="update")
    repo = str(info.get("repo") or DEFAULT_REPO)
    branch = str(info.get("branch") or "")
    behind = int(info.get("behind", 0) or 0)
    behind_text = t("UPD_BEHIND", count=code(behind), branch=esc(branch)) if behind else esc(t("UPD_UP_TO_DATE", branch=branch))
    release = str(info.get("release") or "")
    release_text = release or t("UPD_NO_RELEASE", reason=str(info.get("release_error") or t("UI_NONE")))
    local_commit = str(info.get("commit") or "")
    local_subj = str(info.get("subject") or "")
    commit_cell = (ref_link(local_commit, repo) + (" " + esc(local_subj) if local_subj else "")) if local_commit else code(t("UI_NOT_SET"))
    local_tag = str(info.get("tag") or "")
    tag_cell = ref_link(local_tag, repo) if local_tag else code(t("UI_NOT_SET"))
    release_cell = ref_link(release, repo) if release else code(release_text)
    pairs = [
        ("info", t("UPD_LABEL_SOURCE"), code(info.get("root") or t("UI_NOT_SET"))),
        ("info", t("UPD_LABEL_BRANCH"), code(branch or t("UI_NOT_SET"))),
        ("info", t("UPD_LABEL_COMMIT"), commit_cell),
        ("tag", t("UPD_LABEL_TAG"), tag_cell),
        ("info", t("UPD_LABEL_CHANGES"), code(info.get("dirty", 0))),
        ("info", t("UPD_LABEL_BEHIND"), behind_text),
        ("info", t("UPD_LABEL_RELEASE"), release_cell),
        ("info", t("UPD_LABEL_SERVICE"), code(service_state_label(info.get("unit_state"), view.lang))),
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
    blocks.append(quote(bold_html(body) if "<a " in body else bold(body)))
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
    repo = str(info.get("repo") or DEFAULT_REPO)
    ok = bool(result.get("ok"))
    commit = str(result.get("target") or "")
    subject = str(result.get("subject") or "")
    message = str(result.get("message") or "")
    if ok and not message:
        message = t("UPD_DONE_PLAIN")
    if ok:
        body = t("UPD_DONE", commit=ref_link(commit, repo), subject=esc(subject or message))
        blocks.append(quote(bold_html(body)))
    else:
        prefix = esc(str(t("UPD_FAILED", error="")).rstrip(": ").strip())
        blocks.append(quote(bold_html(f"{prefix} {esc(message or t('UPD_NOTHING_DONE'))}")))
    failure = dict(result.get("failure") or {})
    if not ok and failure.get("copy_ok"):
        blocks.append(quote(bold(t("UPD_COPY_DONE"))))
    steps = [muted(str(item)) for item in result.get("steps") or []]
    if steps:
        blocks.append(f"<p>{bold(t('UPD_STEPS_DONE'))}</p>")
        blocks.append(bullet_list(steps))
    if ok and message == "already up to date":
        blocks.append(quote(muted_html(t("UPD_ALREADY", commit=ref_link(commit, repo)))))
    if result.get("rollback"):
        blocks.append(quote(muted_html(t("UPD_ROLLBACK", commit=ref_link(str(result.get("source") or ""), repo)))))
    if ok and result.get("restarted"):
        blocks.append(quote(muted(t("UPD_RESTART"))))
    if result.get("log"):
        blocks.append(pre("\n".join(str(item) for item in result["log"])))
    if not ok and failure:
        rows = []
        if failure.get("step"):
            rows.append(("route", t("UPD_FAIL_STEP"), code(str(failure.get("step")))))
        if failure.get("path"):
            rows.append(("folder", t("UPD_FAIL_PATH"), code(str(failure.get("path")))))
        rows.append(("warn", t("UPD_FAIL_WHY"), code(str(failure.get("detail") or failure.get("message") or t("UI_NONE")))))
        blocks.append(table(rows, (t("UI_PARAM"), t("UI_VALUE"))))
        if failure.get("log"):
            blocks.append(pre("\n".join(str(item) for item in failure.get("log") or [])))
    if not ok and result.get("readonly") and (result.get("system") or {}).get("root"):
        system = dict(result.get("system") or {})
        blocks.append(quote(muted(t("UPD_READONLY_WHY", dir=str(system.get("root") or t("UI_NOT_SET")), reason=str(system.get("root_reason") or t("UI_NONE"))))))
        blocks.append(f"<p>{muted(t('UPD_RUN_AS_ROOT'))}</p>")
        if result.get("hint"):
            blocks.append(pre(str(result.get("hint"))))
    elif not ok and result.get("hint"):
        blocks.append(f"<p>{muted(t('UPD_ACTION_NEEDED'))}</p>")
        blocks.append(pre(str(result.get("hint"))))
    buttons = [
        row(button(t("UI_REFRESH"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("UPD_DONE_TITLE") if ok else t("UPD_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, footer=t("HOME_FOOTER"), icon="ok")


def service_state_label(raw_state: object, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    value = str(raw_state or "").strip().lower()
    if value in {"active", "running", "activating"}:
        return i18n.t("SVC_STATE_ACTIVE", lang)
    if value in {"failed", "error"}:
        return i18n.t("SVC_STATE_FAILED", lang)
    if value in {"inactive", "stopped", "dead", "deactivating"}:
        return i18n.t("SVC_STATE_INACTIVE", lang)
    if value == "expired":
        return i18n.t("SVC_STATE_EXPIRED", lang)
    if value in {"missing", "not_installed"}:
        return i18n.t("SVC_STATE_MISSING", lang)
    return i18n.t("UI_NONE", lang)


def _update_stage_catalog(t: i18n.Translator, include_deps: bool = False) -> list[dict[str, str]]:
    items = [
        {"key": "fetch", "run": t("UPD_STAGE_FETCH_RUN"), "done": t("UPD_STAGE_FETCH_DONE")},
        {"key": "compare", "run": t("UPD_STAGE_COMPARE_RUN"), "done": t("UPD_STAGE_COMPARE_DONE")},
        {"key": "apply", "run": t("UPD_STAGE_APPLY_RUN"), "done": t("UPD_STAGE_APPLY_DONE")},
        {"key": "verify", "run": t("UPD_STAGE_VERIFY_RUN"), "done": t("UPD_STAGE_VERIFY_DONE")},
    ]
    if include_deps:
        items.append({"key": "deps", "run": t("UPD_STAGE_DEPS_RUN"), "done": t("UPD_STAGE_DEPS_DONE")})
    return items


def update_step_block(view: View, info: dict[str, Any], stage: str, meta: dict[str, Any] | None = None) -> str:
    t = view.tr()
    data = dict(meta or {})
    repo = str(info.get("repo") or DEFAULT_REPO)
    target = str(data.get("target") or "")[:12]
    linked = ref_link(target, repo) if target else code(t("UI_NOT_SET"))
    subject = str(data.get("subject") or "").strip()
    if stage == "fetch":
        return f"<p>{ico('loading')}{bold(t('UPD_STAGE_FETCH_RUN'))}</p>"
    if stage == "compare":
        return f"<p>{ico('ok')}{esc(t('UPD_STAGE_FETCH_DONE'))} · {ico('loading')}{bold(t('UPD_STAGE_COMPARE_RUN'))}</p>"
    if stage == "apply":
        tail = f" ({linked})" if target else ""
        return f"<p>{ico('ok')}{esc(t('UPD_STAGE_COMPARE_DONE'))} · {ico('loading')}{bold(t('UPD_STAGE_APPLY_RUN'))}{tail}</p>"
    if stage == "verify":
        return f"<p>{ico('ok')}{esc(t('UPD_STAGE_APPLY_DONE'))} · {ico('loading')}{bold(t('UPD_STAGE_VERIFY_RUN'))}</p>"
    if stage == "deps":
        return f"<p>{ico('ok')}{esc(t('UPD_STAGE_VERIFY_DONE'))} · {ico('loading')}{bold(t('UPD_STAGE_DEPS_RUN'))}</p>"
    if stage == "restarting":
        prev_done = t("UPD_STAGE_DEPS_DONE") if data.get("deps") else t("UPD_STAGE_VERIFY_DONE")
        parts = [
            f"<p>{ico('ok')}{esc(prev_done)}</p>",
            quote(ico("restart") + bold(t("UPD_RESTARTING_TITLE")) + " · " + bold_html(t("UPD_RESTARTING_BODY", commit=linked))),
        ]
        if subject:
            parts.append(quote(muted(subject)))
        return "\n".join(parts)
    return f"<p>{ico('loading')}{bold(stage)}</p>"


def update_final_block(view: View, info: dict[str, Any], kind: str, payload: dict[str, Any] | None = None) -> tuple[str, list[str]]:
    t = view.tr()
    data = dict(payload or {})
    repo = str(info.get("repo") or data.get("repo") or DEFAULT_REPO)
    commit = str(data.get("commit") or data.get("target") or data.get("to") or data.get("source") or info.get("commit") or "")[:12]
    linked = ref_link(commit, repo) if commit else code(t("UI_NOT_SET"))
    subject = str(data.get("subject") or info.get("subject") or "").strip()
    if kind == "already":
        parts = [
            f"<p>{ico('ok')}{esc(t('UPD_STAGE_COMPARE_DONE'))}</p>",
            quote(ico("ok") + bold(t("UPD_ALREADY_TITLE")) + " · " + bold_html(t("UPD_ALREADY", commit=linked))),
        ]
        if subject:
            parts.append(quote(muted(subject)))
        btns = [row(button(t("UI_REFRESH"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home"))]
        return "\n".join(parts), btns
    if kind == "failed":
        message = str(data.get("message") or t("UPD_NOTHING_DONE")).strip()
        prefix = esc(str(t("UPD_FAILED", error="")).rstrip(": ").strip())
        parts = [quote(ico("warn") + bold_html(f"{prefix}: {esc(message)}"))]
        if data.get("rollback"):
            source = str(data.get("source") or "")[:12]
            if source:
                parts.append(quote(muted_html(t("UPD_ROLLBACK", commit=ref_link(source, repo)))))
        btns = [row(button(t("UI_REFRESH"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home"))]
        return "\n".join(parts), btns
    if kind == "manual":
        prev_done = t("UPD_STAGE_DEPS_DONE") if data.get("deps") else t("UPD_STAGE_VERIFY_DONE")
        parts = [
            f"<p>{ico('ok')}{esc(prev_done)}</p>",
            quote(ico("info") + bold(t("UPD_RESTART_MANUAL_TITLE")) + " · " + bold_html(t("UPD_RESTART_MANUAL_BODY", commit=linked))),
        ]
        if subject:
            parts.append(quote(muted(subject)))
        btns = [row(button(t("NAV_UPDATE"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home"))]
        return "\n".join(parts), btns
    parts = [quote(ico("ok") + bold_html(t("UPD_APPLIED_FINAL", commit=linked)))]
    btns = [row(button(t("NAV_UPDATE"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home"))]
    return "\n".join(parts), btns


def update_cumulative_screen(view: View, log_blocks: list[str], buttons: list[str] | None = None) -> Any:
    t = view.tr()
    return screen(t("UPD_PROGRESS_TITLE"), "", list(log_blocks), list(buttons or []), icon="update")


def update_progress_screen(view: View, info: dict[str, Any], stage: str, meta: dict[str, Any] | None = None) -> Any:
    t = view.tr()
    data = dict(meta or {})
    repo = str(info.get("repo") or DEFAULT_REPO)
    include_deps = bool(data.get("deps")) or stage == "deps"
    catalog = _update_stage_catalog(t, include_deps=include_deps)
    keys = [item["key"] for item in catalog]
    active_idx = keys.index(stage) if stage in keys else 0
    active_label = catalog[active_idx]["run"]
    blocks = banner(view, t)
    blocks.append(quote(ico("loading") + bold(active_label)))
    rows = []
    for idx, entry in enumerate(catalog):
        if idx < active_idx:
            rows.append(("ok", entry["done"], code(t("UPD_STATE_DONE"))))
        elif idx == active_idx:
            rows.append(("loading", entry["run"], bold(t("UPD_STATE_RUNNING"))))
        else:
            rows.append(("clock", entry["run"], muted(t("UPD_STATE_WAIT"))))
    blocks.append(table(rows, (t("UPD_COL_STAGE"), t("UPD_COL_STATE"))))
    target = str(data.get("target") or "")[:12]
    subject = str(data.get("subject") or "").strip()
    if target:
        tail = f" {esc(subject)}" if subject else ""
        blocks.append(quote(muted_html(f"{ref_link(target, repo)}{tail}")))
    subtitle = t("UPD_PROGRESS_SUBTITLE", step=active_idx + 1, total=len(catalog))
    return screen(t("UPD_PROGRESS_TITLE"), subtitle, blocks, [], icon="update")


def update_already_screen(view: View, info: dict[str, Any], result: dict[str, Any]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    repo = str(info.get("repo") or DEFAULT_REPO)
    commit = str(result.get("target") or result.get("source") or info.get("commit") or "")[:12]
    linked = ref_link(commit, repo) if commit else code(t("UI_NOT_SET"))
    blocks.append(quote(bold_html(t("UPD_ALREADY", commit=linked))))
    rows = [("info", t("UPD_LABEL_COMMIT"), linked)]
    branch = str(info.get("branch") or "").strip()
    if branch:
        rows.append(("tag", t("UPD_LABEL_BRANCH"), code(branch)))
    blocks.append(table(rows, (t("UI_PARAM"), t("UI_VALUE"))))
    subject = str(result.get("subject") or info.get("subject") or "").strip()
    if subject:
        blocks.append(quote(muted(subject)))
    buttons = [
        row(button(t("UI_REFRESH"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("UPD_ALREADY_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, icon="ok")


def update_handoff_screen(view: View, info: dict[str, Any], meta: dict[str, Any] | None = None, restarted: bool = True) -> Any:
    t = view.tr()
    data = dict(meta or {})
    repo = str(info.get("repo") or DEFAULT_REPO)
    commit = str(data.get("target") or "")[:12]
    linked = ref_link(commit, repo) if commit else code(t("UI_NOT_SET"))
    catalog = _update_stage_catalog(t, include_deps=bool(data.get("deps")))
    blocks = banner(view, t)
    if restarted:
        blocks.append(quote(bold_html(t("UPD_RESTARTING_BODY", commit=linked))))
    else:
        blocks.append(quote(bold_html(t("UPD_RESTART_MANUAL_BODY", commit=linked))))
    rows = [("ok", entry["done"], code(t("UPD_STATE_DONE"))) for entry in catalog]
    blocks.append(table(rows, (t("UPD_COL_STAGE"), t("UPD_COL_STATE"))))
    subject = str(data.get("subject") or "").strip()
    if subject:
        blocks.append(quote(muted(subject)))
    if restarted:
        return screen(t("UPD_RESTARTING_TITLE"), t("UPD_RESTARTING_SUBTITLE"), blocks, [], icon="restart")
    buttons = [
        row(button(t("NAV_UPDATE"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("UPD_RESTART_MANUAL_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, icon="info")


def update_failed_screen(view: View, info: dict[str, Any], result: dict[str, Any]) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    repo = str(info.get("repo") or DEFAULT_REPO)
    message = str(result.get("message") or t("UPD_NOTHING_DONE")).strip()
    prefix = esc(str(t("UPD_FAILED", error="")).rstrip(": ").strip())
    blocks.append(quote(bold_html(f"{prefix}: {esc(message)}")))
    if result.get("rollback"):
        source = str(result.get("source") or "")[:12]
        if source:
            blocks.append(quote(muted_html(t("UPD_ROLLBACK", commit=ref_link(source, repo)))))
    buttons = [
        row(button(t("UI_REFRESH"), "upd:show", icon="update"), button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("UPD_TITLE"), t("UPD_SUBTITLE"), blocks, buttons, icon="warn")


def _daemon_label(t: i18n.Translator, key: str) -> str:
    mapping = {
        "bot": "UPD_DAEMON_BOT",
        "xray": "UPD_DAEMON_XRAY",
        "freeturn": "UPD_DAEMON_FREETURN",
        "sub": "UPD_DAEMON_SUB",
        "tailnet": "UPD_DAEMON_TAILNET",
        "fail2ban": "UPD_DAEMON_FAIL2BAN",
    }
    token = mapping.get(str(key or "").strip().lower(), "")
    return t(token) if token else str(key or "")


def update_verified_screen(view: View, notice: dict[str, Any]) -> Any:
    t = view.tr()
    blocks: list[str] = []
    repo = str(notice.get("repo") or DEFAULT_REPO)
    healthy = bool(notice.get("healthy", True))
    commit = str(notice.get("commit") or notice.get("to") or "")[:12]
    linked = ref_link(commit, repo) if commit else code(t("UI_NOT_SET"))
    raw_daemons = list(notice.get("daemons") or [])
    if not raw_daemons:
        raw_daemons = [
            {
                "id": "bot",
                "icon": "bot",
                "state": str(notice.get("state") or ("active" if healthy else "failed")),
                "detail": "",
            }
        ]
    ok_count = sum(1 for item in raw_daemons if str(item.get("state") or "").strip().lower() in {"active", "running", "activating"})
    total_count = len(raw_daemons)
    all_ok = healthy and ok_count == total_count
    if not healthy:
        blocks.append(quote(bold_html(t("UPD_NOTICE_BROKEN", commit=linked))))
    elif all_ok:
        blocks.append(quote(bold_html(t("UPD_BOOTED_ALL_OK", commit=linked, ok=ok_count, total=total_count))))
    else:
        blocks.append(quote(bold_html(t("UPD_BOOTED_PARTIAL", commit=linked, ok=ok_count, total=total_count))))
    summary_parts: list[str] = []
    cores_info = list(notice.get("cores_info") or [])
    if cores_info:
        core_rows = []
        for entry in cores_info:
            cid = str(entry.get("id") or "").strip().lower()
            configured = bool(entry.get("configured", False))
            raw_state = str(entry.get("state") or "missing").strip().lower()
            cfg_text = t("UPD_CORE_CONFIGURED") if configured else t("UPD_CORE_UNCONFIGURED")
            state_text = service_state_label(raw_state, view.lang)
            ver = str(entry.get("detail") or "").strip()
            parts_cell = [cfg_text, state_text]
            if ver:
                parts_cell.append(ver)
            c_icon = "ok" if raw_state in {"active", "running", "activating"} else ("warn" if configured else "info")
            core_rows.append((c_icon, _daemon_label(t, cid), code(" / ".join(parts_cell))))
        summary_parts.append(table(core_rows, (t("NAV_CORE"), t("UPD_COL_STATE"))))
    daemon_rows = []
    for item in raw_daemons:
        raw_state = str(item.get("state") or "inactive").strip().lower()
        state_text = service_state_label(raw_state, view.lang)
        detail = str(item.get("detail") or "").strip()
        cell = code(f"{state_text} / {detail}") if detail else code(state_text)
        if raw_state in {"active", "running", "activating"}:
            row_icon = "ok"
        elif raw_state in {"failed", "error", "expired"}:
            row_icon = "fail"
        else:
            row_icon = "warn"
        daemon_rows.append((row_icon, _daemon_label(t, str(item.get("id") or "")), cell))
    summary_parts.append(table(daemon_rows, (t("UPD_COL_DAEMON"), t("UPD_COL_STATE"))))
    branch = str(notice.get("branch") or "").strip()
    subject = str(notice.get("subject") or "").strip()
    if branch or subject:
        tail_bits = [code(branch)] if branch else []
        if subject:
            tail_bits.append(esc(subject))
        summary_parts.append(quote(muted_html(" · ".join(tail_bits))))
    blocks.append(details(t("UPD_BOOTED_SUMMARY", ok=ok_count, total=total_count), "\n".join(summary_parts)))
    output = str(notice.get("output") or "").strip()
    if not healthy and output:
        blocks.append(pre(output[:1200]))
    buttons = [
        row(button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    title = t("UPD_BOOTED_TITLE") if healthy else t("UPD_TITLE")
    return screen(title, "", blocks, buttons, icon="ok" if all_ok else "warn")


def body_text(value: object) -> str:
    return code(str(value or ""))


def help_screen(view: View) -> Any:
    t = view.tr()
    blocks = banner(view, t)
    blocks.append(heading(t("HELP_FLOW_TITLE"), 3))
    blocks.append(bullet_list([t("HELP_FLOW_1"), t("HELP_FLOW_2"), t("HELP_FLOW_3"), t("HELP_FLOW_4"), t("HELP_FLOW_5"), t("HELP_FLOW_6")]))
    blocks.append(
        details(
            t("HELP_WHAT_TITLE"),
            bullet_list(
                [
                    t("HELP_WHAT_1", protocol=code("vless"), networks=" ".join(code(item) for item in ("raw", "grpc", "xhttp"))),
                    t("HELP_WHAT_2", security=" ".join(code(item) for item in ("reality", "tls", "none"))),
                    t("HELP_WHAT_3", encryption=code("mlkem768x25519plus"), signature=code("ml-dsa-65")),
                    t("HELP_WHAT_4"),
                    t("HELP_WHAT_5", path=code("/<64>/<64>")),
                    t("HELP_WHAT_6"),
                    t("HELP_WHAT_7"),
                    t("HELP_WHAT_8"),
                    t("HELP_WHAT_9"),
                    t("HELP_WHAT_10"),
                ]
            ),
        )
    )
    blocks.append(details(t("INL_HINT_TITLE"), bullet_list([t("INL_HINT_1"), t("INL_HINT_2"), t("INL_HINT_3"), t("INL_HINT_4")])))
    blocks.append(f"<p>{muted(t('INL_STATUS_ON'))} {muted(t('INL_STATUS_OWNER'))}</p>")
    buttons = [
        row(button(t("NAV_XRAY"), "xr:home", icon="xray"), button(t("NAV_FREETURN"), "ft:home", icon="tunnel")),
        row(button(t("TOOLS_TITLE"), "dbg:home", icon="tools"), button(t("DDOS_BTN_OPEN"), "dbg:dd", icon="shield")),
        row(button(t("UI_HOME"), "nav:home", icon="home")),
    ]
    return screen(t("HELP_TITLE"), t("HELP_SUBTITLE"), blocks, buttons, icon="docs")


def denied(lang: str = i18n.DEFAULT_LANGUAGE) -> Any:
    t = i18n.translator(lang)
    return screen(t("DENIED_TITLE"), "", [quote(bold(t("DENIED_BODY")))], [], icon="stop")


def error_screen(view: View, title: str, message: str) -> Any:
    t = view.tr()
    blocks = [quote(bold(message))]
    buttons = [row(button(t("UI_HOME"), "nav:home", icon="home"))]
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