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
    assert 'data="nav:sshd"' in settings_html
    assert 'data="nav:ban"' in settings_html

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
