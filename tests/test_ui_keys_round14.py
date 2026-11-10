from __future__ import annotations

import ast
import asyncio
import builtins
import re
import symtable
from pathlib import Path

import pytest

from BOT import dscreens, ftscreens, i18n, inline, screens, strings, tools, xscreens
from BOT.freeturn import FtConfig, FtState
from tests.fakes import make_bot

PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")
CALLBACK_RE = re.compile(r'type="callback_data" data="([^"]+)"')
BUILTIN_NAMES = set(dir(builtins)) | {"__file__", "__name__", "__package__", "__doc__", "__spec__", "__annotations__"}


def _undefined_globals(tbl: symtable.SymbolTable, mod_globals: set[str]) -> list[tuple[int, str, str]]:
    missing: list[tuple[int, str, str]] = []
    if tbl.get_type() == "module":
        mod_globals = {sym.get_name() for sym in tbl.get_symbols() if sym.is_assigned() or sym.is_imported()}
    for sym in tbl.get_symbols():
        name = sym.get_name()
        if sym.is_referenced() and sym.is_global() and not sym.is_declared_global():
            if name not in mod_globals and name not in BUILTIN_NAMES:
                missing.append((tbl.get_lineno(), tbl.get_name(), name))
    for child in tbl.get_children():
        missing.extend(_undefined_globals(child, mod_globals))
    return missing


def test_no_undefined_globals_or_missing_imports_anywhere_in_repo() -> None:
    root = Path(__file__).resolve().parent.parent
    offenders: list[str] = []
    for folder in ("BOT", "Storage", "tools", "tests"):
        for py_file in sorted((root / folder).rglob("*.py")):
            source = py_file.read_text(encoding="utf-8")
            table = symtable.symtable(source, str(py_file), "exec")
            for lineno, scope, name in _undefined_globals(table, set()):
                offenders.append(f"{py_file.relative_to(root)}:{lineno}:{scope}:{name}")
    assert offenders == []


def test_bot_run_executes_root_freeturn_warmup_without_import_or_runtime_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import BOT.app as app_mod

    bot = make_bot(tmp_path)
    ran_app = False

    class _DummyApp:
        async def run(self) -> None:
            nonlocal ran_app
            ran_app = True

    probed_state = FtState(installed=True, running=True, config=FtConfig(listen_port=56000, host="203.0.113.10"))

    async def _fake_probe() -> FtState:
        return probed_state

    async def _fake_boot() -> _DummyApp:
        bot.app = _DummyApp()
        return bot.app

    async def _noop() -> bool:
        return True

    async def _noop_none() -> None:
        return None

    monkeypatch.setattr(bot, "boot", _fake_boot)
    monkeypatch.setattr(bot, "verify_update", _noop_none)
    monkeypatch.setattr(bot, "register_commands", _noop)
    monkeypatch.setattr(bot, "notify_start", _noop_none)
    monkeypatch.setattr(bot.freeturn.control, "probe", _fake_probe)
    monkeypatch.setattr(app_mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(app_mod.os.path, "isfile", lambda path: path == "/opt/free-turn-proxy/install.conf")

    async def _exercise() -> None:
        await bot.run()
        await bot.idle()

    asyncio.run(_exercise())
    assert ran_app is True
    assert bot.freeturn.state.installed is True
    assert bot.freeturn.state.config.listen_port == 56000


def test_every_registered_inline_field_is_covered_in_bot_input_values(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    values = bot.input_values()
    assert set(values.keys()) == set(inline.FIELDS.keys())
    for ident, field in inline.FIELDS.items():
        if field.secret:
            assert values[ident] == ""


def test_settings_ban_sshd_and_ft_connect_inputs_render_rich_screens_without_crash(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    cases = [
        ("xr_dns_servers", "-", "1.1.1.1, 8.8.8.8"),
        ("xr_api_port", "-", "62790"),
        ("xr_access_log", "-", "/var/log/xray/access.log"),
        ("xr_ignoreip", "-", "127.0.0.1/8"),
        ("xr_bantime", "-", "45"),
        ("xr_ssh_bantime", "-", "7d"),
        ("xr_ssh_maxretry", "-", "5"),
        ("ft_connect", "-", "127.0.0.1:51820"),
    ]
    for ident, ctx, value in cases:
        asyncio.run(bot.dispatch_input(bot.admin_id, ident, ctx, value))
    assert bot.state.freeturn.config.connect == "127.0.0.1:51820"
    assert bot.freeturn.draft.connect == "127.0.0.1:51820"

    for ident in (
        "xr_dns_servers",
        "xr_api_port",
        "xr_access_log",
        "xr_ignoreip",
        "xr_ban_ip",
        "xr_bantime",
        "xr_ssh_bantime",
        "xr_ssh_maxretry",
        "ssh_new_port",
        "ssh_pubkey",
    ):
        rich = asyncio.run(bot.xray.screen_for(ident, "-", "saved"))
        html = rich.to_html()
        assert "saved" in html


def test_ftscreens_plan_adapts_to_backend_and_obfuscation_profile(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.freeturn.draft.backend = "new"
    bot.freeturn.draft.obf_profile = "rtpopus3"
    html_new = ftscreens.plan_screen(bot.freeturn.view()).to_html()
    assert i18n.t("FT_WG_PORT_INPUT", bot.language) in html_new
    assert i18n.t("FT_CONNECT_INPUT", bot.language) not in html_new
    assert i18n.t("FT_KEY_INPUT", bot.language) in html_new

    bot.freeturn.draft.backend = "external"
    bot.freeturn.draft.obf_profile = "none"
    html_ext = ftscreens.plan_screen(bot.freeturn.view()).to_html()
    assert i18n.t("FT_CONNECT_INPUT", bot.language) in html_ext
    assert i18n.t("FT_WG_PORT_INPUT", bot.language) not in html_ext
    assert i18n.t("FT_KEY_INPUT", bot.language) not in html_ext


@pytest.mark.parametrize("lang", i18n.LANGUAGES)
def test_string_catalog_keys_and_placeholders_match_across_languages_and_ast(lang: str) -> None:
    en_keys = {k for k in dir(strings.EN) if k.isupper()}
    cat_obj = {"en": strings.EN, "ru": strings.RU, "zh": strings.ZH}[lang]
    cat_keys = {k for k in dir(cat_obj) if k.isupper()}
    assert cat_keys == en_keys
    for key in en_keys:
        en_val = str(getattr(strings.EN, key))
        cat_val = str(getattr(cat_obj, key))
        assert PLACEHOLDER_RE.findall(en_val) == PLACEHOLDER_RE.findall(cat_val) or set(PLACEHOLDER_RE.findall(en_val)) == set(
            PLACEHOLDER_RE.findall(cat_val)
        ), key

    bot_dir = Path(__file__).resolve().parent.parent / "BOT"
    for py_file in sorted(bot_dir.glob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if func_name == "t" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    literal = node.args[0].value
                    if literal.isupper():
                        assert literal in i18n.RESERVED or i18n.has_key(literal, lang), f"{py_file.name}:{literal}"


def test_simplified_navigation_eliminates_duplicate_hub_and_unknown_routes(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    home_html = screens.home(bot.view()).to_html()
    assert 'data="dbg:home"' in home_html
    assert 'data="tools:home"' not in home_html

    settings_html = screens.settings(bot.view()).to_html()
    assert 'data="nav:quick"' not in settings_html
    assert 'data="xr:fit:"' not in settings_html
    assert 'data="nav:sshd"' not in settings_html
    assert 'data="nav:ban"' not in settings_html

    tools_html = dscreens.home(bot.debug.view()).to_html()
    for tool_cb in (
        "ft:fw",
        "dbg:dd",
        "nav:ban",
        "nav:sshd",
        "dbg:hp",
        "dbg:ntf",
        "dbg:chk",
        "dbg:dpi",
        "dbg:vk",
        "dbg:scan",
        "dbg:trace",
        "dbg:ports",
        "dbg:scr",
        "dbg:info",
    ):
        assert f'data="{tool_cb}"' in tools_html, tool_cb

    fw_html = tools.fw_screen(dscreens.DbgView(lang="en")).to_html()
    assert 'data="ft:fw"' in fw_html
    assert 'data="tools:fw:status"' not in fw_html

    pages = [
        screens.home(bot.view()),
        screens.settings(bot.view()),
        screens.quick_screen(bot.view()),
        screens.language_screen(bot.view()),
        screens.help_screen(bot.view()),
        ftscreens.home(bot.freeturn.view()),
        ftscreens.plan_screen(bot.freeturn.view()),
        dscreens.home(bot.debug.view()),
        xscreens.home(bot.xray.view()),
    ]
    unknown_notice = i18n.t("HOME_NOTICE_UNKNOWN", bot.language)
    seen: set[str] = set()
    for page in pages:
        for cb in CALLBACK_RE.findall(page.to_html()):
            seen.add(cb)
    assert seen
    for cb in sorted(seen):
        if cb.startswith(("upd:", "fb:", "sshd:", "ft:apply", "ft:un", "ft:restart", "ft:stop", "ft:check", "ft:fw")):
            continue
        asyncio.run(bot.dispatch(bot.admin_id, 1, cb))
        if bot.sent:
            last_html = bot.sent[-1][1]
            assert unknown_notice not in last_html, cb


def test_start_screen_warms_cores_and_removes_redundant_text_and_home_btn(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from tests.fakes import FakeFtControl

    bot = make_bot(tmp_path)
    bot.freeturn.control = FakeFtControl()

    evt = SimpleNamespace(
        from_id=bot.admin_id,
        chat_id=bot.admin_id,
        text="/start",
        is_private=True,
        raw={"from": {"id": bot.admin_id, "language_code": "ru"}},
    )
    asyncio.run(bot.on_command(evt))

    assert bot.language == "ru"
    assert bot.state.language_set is True
    assert bot.sent, "expected /start screen"
    html = bot.sent[-1].to_html()
    assert 'data="nav:home"' not in html
    assert 'data="xr:home"' in html
    assert 'data="ft:home"' in html
    assert 'data="dbg:home"' in html
    assert 'data="nav:settings"' in html
    assert i18n.t("CORE_STATE_MISSING", "ru").lower() not in html.lower()
    assert i18n.t("CORE_STATE_RUNNING", "ru").lower() in html.lower()
    assert html.lower().count(i18n.t("CMD_START_DESC", "ru").lower()) == 1


def test_language_autodetect_respects_fallback_and_manual_override(tmp_path: Path) -> None:
    from types import SimpleNamespace

    bot_de = make_bot(tmp_path / "de")
    evt_de = SimpleNamespace(
        from_id=bot_de.admin_id,
        chat_id=bot_de.admin_id,
        text="/start",
        is_private=True,
        raw={"from": {"id": bot_de.admin_id, "language_code": "de-DE"}},
    )
    asyncio.run(bot_de.on_command(evt_de))
    assert bot_de.language == "en"
    assert bot_de.state.language_set is True

    bot_mt = make_bot(tmp_path / "mt")
    bot_mt.app = SimpleNamespace(mt=SimpleNamespace(entities={("user", bot_mt.admin_id): {"lang_code": "ru-RU"}}))
    evt_mt = SimpleNamespace(from_id=bot_mt.admin_id, chat_id=bot_mt.admin_id, text="/start", is_private=True, raw={})
    asyncio.run(bot_mt.on_command(evt_mt))
    assert bot_mt.language == "ru"

    asyncio.run(bot_mt.language_action(bot_mt.admin_id, 1, "set", "en"))
    assert bot_mt.language == "en"
    asyncio.run(bot_mt.on_command(evt_mt))
    assert bot_mt.language == "en"


def test_ftscreens_shows_install_button_until_installed(tmp_path: Path) -> None:
    bot = make_bot(tmp_path)
    bot.state.language = "ru"
    bot.freeturn.state = FtState(installed=False)
    uninstalled_html = ftscreens.home(bot.freeturn.view()).to_html()
    plan_uninstalled = ftscreens.plan_screen(bot.freeturn.view()).to_html()
    assert i18n.t("FT_BTN_INSTALL", "ru") in uninstalled_html
    assert i18n.t("FT_BTN_INSTALL", "ru") in plan_uninstalled
    assert 56000 <= bot.freeturn.draft.listen_port <= 56999

    bot.freeturn.state = FtState(installed=True, running=True)
    installed_html = ftscreens.home(bot.freeturn.view()).to_html()
    plan_installed = ftscreens.plan_screen(bot.freeturn.view()).to_html()
    assert i18n.t("FT_BTN_INSTALL", "ru") not in installed_html
    assert i18n.t("FT_BTN_APPLY", "ru") in plan_installed


def test_xscreens_back_rows_and_scan_buttons_stay_in_footer_and_localized() -> None:
    from BOT.scan import ScanResult
    from BOT.xray import XrayState, new_inbound

    state = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    inbound.reality_private = "k" * 43
    inbound.mldsa65_seed = "s" * 32
    inbound.mldsa65_verify = "v" * 32
    state.add(inbound)
    short = ScanResult(
        target="short.example:443",
        host="short.example",
        port=443,
        feasible=True,
        tls13=True,
        h2=True,
        x25519=True,
        pq_hybrid=True,
        cert_valid=True,
        days_left=30,
        cert_chain_bytes=1800,
        ml_dsa_ready=False,
    )
    view_ru = xscreens.XrayView(state=state, lang="ru")
    home_ru = xscreens.home(view_ru).to_html()
    assert i18n.t("UI_HOME", "ru") in home_ru
    assert 'data="xr:home"' not in home_ru

    scan_ru = xscreens.scan_screen(view_ru, [short]).to_html()
    body_part, buttons_part = scan_ru.split("<hr/>", 1)
    assert "<tg-button-row>" not in body_part
    assert 'data="xr:scan:fit:0"' in buttons_part
    assert buttons_part.count('data="xr:home"') == 1
    assert "3500" in body_part


def test_freeturn_agent_locale_env_nft_accept_policy_drop_and_iptables_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import importlib.util
    import subprocess as sp

    spec = importlib.util.spec_from_file_location(
        "freeturn_agent_r15",
        Path(__file__).resolve().parent.parent / "Storage" / "remote" / "freeturn_agent.py",
    )
    assert spec and spec.loader
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)

    captured_env: dict[str, str] = {}

    def _fake_subproc_run(cmd: list[str], **kwargs: object) -> object:
        nonlocal captured_env
        env_arg = kwargs.get("env")
        if isinstance(env_arg, dict):
            captured_env = dict(env_arg)
        return sp.CompletedProcess(cmd, 0, stdout=b"Status: active\n")

    monkeypatch.setattr(agent, "sandboxed_host", lambda: False)
    monkeypatch.setattr(agent.subprocess, "run", _fake_subproc_run)
    code, out = agent.run_tool(["ufw", "status"])
    assert code == 0
    assert "Status: active" in out
    assert captured_env.get("LANG") == "C.UTF-8"
    assert captured_env.get("LC_ALL") == "C.UTF-8"

    nft_ruleset = (
        "table inet hostfw {\n"
        "\tchain input {\n"
        "\t\ttype filter hook input priority filter; policy accept;\n"
        "\t\tct state established,related accept\n"
        "\t\tcounter drop\n"
        "\t}\n"
        "}\n"
    )
    nft_cmds: list[list[str]] = []

    def _fake_nft_run(argv: list[str], timeout: float = 15.0) -> tuple[int, str]:
        nft_cmds.append(list(argv))
        if argv[:3] == ["nft", "list", "ruleset"]:
            return 0, nft_ruleset
        return 0, ""

    monkeypatch.setattr(agent.shutil, "which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(agent, "run_tool", _fake_nft_run)
    monkeypatch.setattr(agent, "tool_text", lambda argv, timeout=15.0: nft_ruleset if argv[:3] == ["nft", "list", "ruleset"] else "")
    agent.nft_open_port(56432, ["udp"])
    assert ["nft", "insert", "rule", "inet", "hostfw", "input", "udp", "dport", "56432", "accept"] in nft_cmds

    ipt_cmds: list[list[str]] = []
    ipt_listing = (
        "-P INPUT ACCEPT\n"
        "-A INPUT -j DROP\n"
        "-A INPUT -p udp -m udp --dport 56432 -j ACCEPT\n"
    )
    checks_left = [0, 1]

    def _fake_ipt_run(argv: list[str], timeout: float = 15.0) -> tuple[int, str]:
        ipt_cmds.append(list(argv))
        if "-C" in argv:
            return (checks_left.pop(0) if checks_left else 1), ""
        return 0, ""

    monkeypatch.setattr(agent, "run_tool", _fake_ipt_run)
    monkeypatch.setattr(agent, "tool_text", lambda argv, timeout=15.0: ipt_listing)
    agent._iptables_accept_above_drop("iptables", "udp", 56432)
    assert ["iptables", "-D", "INPUT", "-p", "udp", "--dport", "56432", "-j", "ACCEPT"] in ipt_cmds
    assert ["iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", "56432", "-j", "ACCEPT"] in ipt_cmds

    real_service = (Path(__file__).resolve().parent.parent / "Storage" / "obhod.service").read_text(encoding="utf-8")
    assert "ProtectSystem=strict" in real_service

