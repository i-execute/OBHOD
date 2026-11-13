from __future__ import annotations

import asyncio
import importlib.util
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from BOT import antiddos, dscreens, guard, i18n, notify, screens, ui
from BOT.app import Bot
from BOT.config import Config
from BOT.xray import new_inbound

ROOT = Path(__file__).resolve().parents[1]


def _load_ddos_agent() -> Any:
    spec = importlib.util.spec_from_file_location("ddos_agent_r32", ROOT / "Storage" / "remote" / "ddos_agent.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_bot(tmp_path: Path) -> Bot:
    cfg = Config(bot_token="123456:ABCDEF", api_id=1, api_hash="0" * 32, admin_id=7, state_dir=tmp_path / "data")
    bot = Bot(cfg)
    bot.state.admin_id = 7
    bot.state.ssh.host = "198.51.100.10"
    bot.state.ssh.port = 2222
    bot.state.xray.sub_port = 8443
    bot.state.xray.inbounds.append(new_inbound("vless", 9443, "raw", "reality"))
    return bot


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_home_screen_has_direct_ddos_button_within_budget(tmp_path: Path, lang: str) -> None:
    bot = _make_bot(tmp_path)
    bot.state.language = lang
    rendered = screens.home(bot.view())
    html = rendered.to_html()
    assert 'data="dbg:dd"' in html
    assert i18n.t("DDOS_BTN_OPEN", lang) in html
    assert ui.count_buttons(html) <= ui.MAX_BUTTONS


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_clean_ddos_and_ip_table_screens_render_all_languages(lang: str) -> None:
    pol = antiddos.Policy(
        rkn_enabled=True,
        manual_bans=["203.0.113.99"],
        unbanned=["198.51.100.55"],
        rkn_allow=["198.51.100.55"],
    )
    st = antiddos.Status(
        installed=True,
        enabled=True,
        table=True,
        pps=120,
        connections=14,
        syn_flood=["203.0.113.7", "203.0.113.8"],
        udp_flood=["203.0.113.11"],
        scan=["203.0.113.44"],
        policy=pol,
        rkn_enabled=True,
        rkn_v4_count=2594,
        rkn_v6_count=40,
        counters={"rkn_drop": 380, "syn_drop": 32},
    )
    main_doc = dscreens.ddos_screen(dscreens.DbgView(lang=lang, ddos=st))
    main_html = main_doc.to_html()
    assert "{" not in main_html
    assert 'data="dbg:dd:ips"' in main_html
    assert 'data="dbg:dd:ntf"' in main_html
    assert "203.0.113.7" in main_html
    assert "2594 IPv4, 40 IPv6" in main_html
    assert ui.count_buttons(main_html) <= ui.MAX_BUTTONS

    many_syn = [f"203.0.113.{idx}" for idx in range(1, 13)]
    pol_many = antiddos.Policy(
        manual_bans=["2001:db8:85a3::8a2e:370:7334/128"],
        unbanned=["198.51.100.77"],
        rkn_allow=["198.51.100.77"],
    )
    st_many = antiddos.Status(installed=True, enabled=True, table=True, syn_flood=many_syn, policy=pol_many)
    ips_doc_p0 = dscreens.ddos_ips_screen(dscreens.DbgView(lang=lang, ddos=st_many, ddos_page=0))
    ips_html_p0 = ips_doc_p0.to_html()
    assert "{" not in ips_html_p0
    assert 'data="dbg:dd:ub:0:203.0.113.1"' in ips_html_p0
    assert 'data="dbg:dd:ips:1"' in ips_html_p0
    assert ui.count_buttons(ips_html_p0) <= ui.MAX_BUTTONS

    ips_doc_p2 = dscreens.ddos_ips_screen(dscreens.DbgView(lang=lang, ddos=st_many, ddos_page=2))
    ips_html_p2 = ips_doc_p2.to_html()
    assert 'data="dbg:dd:rb:2:198.51.100.77"' in ips_html_p2
    assert ui.count_buttons(ips_html_p2) <= ui.MAX_BUTTONS

    for cb in re.findall(r'data="([^"]+)"', ips_html_p0 + ips_html_p2):
        assert len(cb.encode("utf-8")) <= 64, cb


def test_ddos_agent_unban_deletes_from_kernel_sets_and_reban_restores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agent = _load_ddos_agent()
    bins = tmp_path / "bins"
    bins.mkdir()
    nft_bin = bins / "nft"
    nft_bin.write_text("exit 0\n", encoding="utf-8")
    nft_bin.chmod(0o755)
    sctl_bin = bins / "systemctl"
    sctl_bin.write_text("exit 0\n", encoding="utf-8")
    sctl_bin.chmod(0o755)
    sys_bin = bins / "sysctl"
    sys_bin.write_text("exit 0\n", encoding="utf-8")
    sys_bin.chmod(0o755)

    recorded_cmds: list[list[str]] = []

    def fake_run(cmd: list[str], timeout: int = 15, stdin_text: str | None = None) -> tuple[int, str, str]:
        recorded_cmds.append(list(cmd))
        return 0, "", ""

    monkeypatch.setattr(agent, "run", fake_run)
    work_dir = tmp_path / "ddos_etc"
    base_flags = [
        f"--dir={work_dir}",
        f"--nft={nft_bin}",
        f"--systemctl={sctl_bin}",
        f"--sysctl={sys_bin}",
    ]

    rc = agent.main(["install", *base_flags, "--manual_bans=203.0.113.50"])
    assert rc == 0
    assert "203.0.113.50" in (work_dir / "ddos.nft").read_text(encoding="utf-8")

    recorded_cmds.clear()
    rc = agent.main(["unban", *base_flags, "--ip=203.0.113.50"])
    assert rc == 0
    delete_calls = [cmd for cmd in recorded_cmds if len(cmd) >= 3 and cmd[1:3] == ["delete", "element"]]
    assert len(delete_calls) == len(agent.SETS)
    saved = agent.read_json(str(work_dir / "ddos.json"))
    assert "203.0.113.50" not in saved["manual_bans"]
    assert "203.0.113.50" in saved["rkn_allow"]
    assert saved["unbanned"][0] == "203.0.113.50"

    rc = agent.main(["reban", *base_flags, "--ip=203.0.113.50"])
    assert rc == 0
    saved2 = agent.read_json(str(work_dir / "ddos.json"))
    assert "203.0.113.50" in saved2["manual_bans"]
    assert "203.0.113.50" not in saved2["rkn_allow"]
    assert "203.0.113.50" not in saved2["unbanned"]


def test_bot_interactive_unban_and_reban_cycle_without_repeat_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = _make_bot(tmp_path)
    rendered_html: list[str] = []
    toasts: list[str] = []
    agent_calls: list[list[str]] = []

    async def fake_render(_chat: int, _msg: int, payload: Any) -> int:
        rendered_html.append(payload.to_html() if hasattr(payload, "to_html") else str(payload))
        return 1

    async def fake_toast(_evt: Any, text: str = "", alert: bool = False) -> None:
        if text:
            toasts.append(text)

    async def fake_answer_click(_evt: Any) -> None:
        return None

    live_syn = ["203.0.113.7"]

    async def fake_ddos_call(_client: Any, _cfg: Any, argv: list[str], timeout: float = 180.0, stdin: bytes | None = None) -> antiddos.Status:
        agent_calls.append(list(argv))
        pol = antiddos.Policy.from_dict(bot.state.ddos)
        if argv[0] == "unban":
            ip = argv[1].split("=", 1)[1]
            if ip in live_syn:
                live_syn.remove(ip)
        return antiddos.Status(installed=True, enabled=True, table=True, syn_flood=list(live_syn), policy=pol)

    monkeypatch.setattr(bot, "render", fake_render)
    monkeypatch.setattr(bot, "toast", fake_toast)
    monkeypatch.setattr(bot, "answer_click", fake_answer_click)
    monkeypatch.setattr(guard, "ddos_call", fake_ddos_call)

    def make_cb(data: str) -> Any:
        return SimpleNamespace(from_id=7, chat_id=7, msg_id=10, data=data, id="cb1")

    asyncio.run(bot.on_callback(make_cb("dbg:dd:ips")))
    asyncio.run(bot.idle())
    assert 'data="dbg:dd:ub:0:203.0.113.7"' in rendered_html[-1]

    asyncio.run(bot.on_callback(make_cb("dbg:dd:ub:0:203.0.113.7")))
    asyncio.run(bot.idle())
    assert ["unban", "--ip=203.0.113.7"] in agent_calls
    assert 'data="dbg:dd:rb:0:203.0.113.7"' in rendered_html[-1]
    assert "203.0.113.7" in bot.state.ddos["unbanned"]

    asyncio.run(bot.on_callback(make_cb("dbg:dd:rb:0:203.0.113.7")))
    asyncio.run(bot.idle())
    assert ["reban", "--ip=203.0.113.7"] in agent_calls
    assert 'data="dbg:dd:ub:0:203.0.113.7"' in rendered_html[-1]
    assert "203.0.113.7" in bot.state.ddos["manual_bans"]

    asyncio.run(bot.on_callback(make_cb("dbg:dd:ub:0:203.0.113.7")))
    asyncio.run(bot.idle())
    assert toasts == []
    assert 'data="dbg:dd:rb:0:203.0.113.7"' in rendered_html[-1]

    asyncio.run(bot.debug.route(7, 10, "dbg:dd:rb:0:198.51.100.10"))
    assert "198.51.100.10" not in bot.state.ddos.get("manual_bans", [])


def test_attack_and_portscan_notifications_fire_out_of_the_box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = _make_bot(tmp_path)
    delivered: list[str] = []

    async def fake_send(_target: int, payload: Any) -> int:
        delivered.append(payload.to_html() if hasattr(payload, "to_html") else str(payload))
        return len(delivered)

    async def fake_honey(_guard: Any, _cfg: Any, _limit: int) -> dict[str, Any]:
        return {}

    async def fake_ban_status(_cfg: Any, _port: int = 0) -> Any:
        return None

    async def fake_ddos_status(_guard: Any, _cfg: Any, _argv: list[str], _timeout: float = 90.0) -> antiddos.Status:
        return antiddos.Status(
            installed=True,
            enabled=True,
            table=True,
            pps=480,
            syn_flood=["203.0.113.77", "203.0.113.78"],
            scan=["198.51.100.88"],
        )

    import BOT.app as app_mod

    monkeypatch.setattr(bot, "send", fake_send)
    monkeypatch.setattr(app_mod, "honey_events", fake_honey)
    monkeypatch.setattr(bot.guard, "status", fake_ban_status)
    monkeypatch.setattr(app_mod, "ddos_call", fake_ddos_status)

    events = asyncio.run(bot.notify_poll())
    kinds = [evt.kind for evt in events]
    assert notify.KIND_DDOS in kinds
    assert notify.KIND_PORTSCAN in kinds
    assert len(delivered) == 2
    assert 'data="dbg:dd:ips"' in delivered[0]
    assert "SYN:2" in delivered[0]


def test_auto_protect_syncs_all_live_ports_and_enables_out_of_the_box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = _make_bot(tmp_path)
    calls: list[list[str]] = []

    async def fake_ddos_call(_guard: Any, _cfg: Any, argv: list[str], _timeout: float = 90.0) -> antiddos.Status:
        calls.append(list(argv))
        if argv[0] == "status":
            return antiddos.Status(installed=False, enabled=False, table=False)
        pol = antiddos.Policy.from_dict(bot.state.ddos)
        return antiddos.Status(installed=True, enabled=True, table=True, policy=pol, rkn_enabled=True)

    async def fake_ban_status(_cfg: Any, port: int = 0) -> Any:
        return SimpleNamespace(active=True, installed=True, banned=[], ssh_banned=[], honey_banned=[], sub_banned=[], jails=[], chain_rules=[])

    import BOT.app as app_mod

    monkeypatch.setattr(app_mod, "public_address", lambda: "198.51.100.10")
    monkeypatch.setattr(app_mod, "ddos_call", fake_ddos_call)
    monkeypatch.setattr(bot.guard, "status", fake_ban_status)

    outcomes = asyncio.run(bot.auto_protect())
    assert outcomes["ddos"] == "on"
    install_calls = [c for c in calls if c[0] == "install"]
    assert len(install_calls) == 1
    ports_arg = next(arg for arg in install_calls[0] if arg.startswith("--ports="))
    for expected_port in ("22", "443", "2222", "8443", "9443"):
        assert expected_port in ports_arg.split("=", 1)[1].split(",")

    installer_text = (ROOT / "Storage" / "obhod_install.sh").read_text(encoding="utf-8")
    assert "nftables" in installer_text
    assert "ddos_agent.py" in installer_text
