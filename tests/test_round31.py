from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from BOT import antiddos, dscreens, guard, i18n, ui
from BOT.app import Bot
from BOT.config import Config

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "Storage" / "remote" / "ddos_agent.py"


def _make_bot(tmp_path: Path) -> Bot:
    cfg = Config(
        bot_token="123456:ABCDEF",
        api_id=1,
        api_hash="0" * 32,
        state_dir=tmp_path / "data",
        admin_id=7,
    )
    bot = Bot(cfg)
    bot.state.admin_id = 7
    bot.state.ssh.host = "198.51.100.42"
    return bot


def _script(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def test_rkn_seed_integrity_and_non_overlapping_intervals() -> None:
    assert antiddos.RKN_GUARD_AUTHOR == "Flecksis"
    assert antiddos.RKN_GUARD_REPO == "https://github.com/Flecksis/rkn-guard"
    assert len(antiddos.RKN_SOURCES) == 5
    v4, v6 = antiddos.seed_rkn_subnets()
    assert len(v4) >= 2500
    assert len(v6) >= 30
    nets_v4 = [ipaddress.ip_network(item) for item in v4]
    nets_v6 = [ipaddress.ip_network(item) for item in v6]
    assert [str(n) for n in ipaddress.collapse_addresses(nets_v4)] == v4
    assert [str(n) for n in ipaddress.collapse_addresses(nets_v6)] == v6
    probe_skipa = ipaddress.ip_address("37.9.13.54")
    assert any(probe_skipa in net for net in nets_v4)


def test_sanitize_rkn_networks_blocks_poisoned_and_protected_ranges() -> None:
    raw = [
        "37.9.13.0/24",
        "37.9.13.54/32",
        "0.0.0.0/0",
        "::/0",
        "8.0.0.0/8",
        "10.0.0.0/8",
        "192.168.1.0/24",
        "127.0.0.1/32",
        "100.100.100.100/32",
        "fd7a:115c:a1e0::1/128",
        "149.154.167.50/32",
        "91.108.56.100/32",
        "1.1.1.1/32",
        "8.8.8.8/32",
        "9.9.9.9/32",
        "198.51.100.42/32",
        "2a00:1fa0::/29",
        "2a00:1fa0:1::/48",
    ]
    v4, v6 = antiddos.sanitize_rkn_networks(raw, extra_protected=["198.51.100.42"])
    assert v4 == ["37.9.13.0/24"]
    assert v6 == ["2a00:1fa0::/29"]


def test_normalize_source_url_enforces_https_and_rewrites_github_blob() -> None:
    blob_url = "https://github.com/shadow-netlab/traffic-guard-lists/blob/main/public/skipa.list"
    assert antiddos.normalize_source_url(blob_url) == (
        "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/skipa.list"
    )
    refs_url = "https://raw.githubusercontent.com/C24Be/AS_Network_List/refs/heads/main/blacklists/blacklist.txt"
    assert antiddos.normalize_source_url(refs_url) == (
        "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt"
    )
    for unsafe in (
        "http://raw.githubusercontent.com/a/b/main/x.txt",
        "file:///etc/passwd",
        "https://127.0.0.1/list.txt",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.1/list.txt",
        "https://localhost/list.txt",
        "https://user:pass@example.com/list.txt",
    ):
        assert antiddos.normalize_source_url(unsafe) == ""


def test_fetch_rkn_subnets_falls_back_to_seed_when_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_download(url: str, timeout: float) -> list[str]:
        raise OSError("network unreachable")

    monkeypatch.setattr(antiddos, "_download_source_lines", broken_download)
    v4, v6, ok_count, errors = antiddos.fetch_rkn_subnets(extra_protected=["198.51.100.42"])
    assert ok_count == 0
    assert len(errors) == len(antiddos.RKN_SOURCES)
    assert len(v4) >= 2500
    assert len(v6) >= 30


def test_nft_table_orders_allowlist_manual_bans_and_rkn_established_bypass() -> None:
    policy = antiddos.Policy(
        enabled=True,
        ports=[22, 443, 8443],
        rkn_enabled=True,
        rkn_allow=["198.51.100.77", "10.8.0.0/16"],
        manual_bans=["203.0.113.55", "2001:db8:bad::/48"],
    )
    table = antiddos.nft_table(policy, rkn_v4=["37.9.13.54/32"], rkn_v6=["2a00:1fa0::/29"])
    assert "set rkn_allow_v4 {" in table
    assert "set manual_ban_v4 {" in table
    assert "set rkn_v4 {" in table
    assert "set rkn_v6 {" in table
    idx_allow = table.index("ip saddr @rkn_allow_v4 accept")
    idx_ban = table.index("ip saddr @manual_ban_v4 counter drop")
    idx_est = table.index("ct state established,related ip saddr @rkn_v4 accept")
    idx_rkn = table.index("ip saddr @rkn_v4 counter drop")
    idx_syn = table.index("ip saddr @syn_flood counter drop")
    assert idx_allow < idx_ban < idx_est < idx_rkn < idx_syn

    disabled = antiddos.Policy(enabled=True, rkn_enabled=False)
    table_off = antiddos.nft_table(disabled)
    assert "@rkn_v4" not in table_off
    assert "@rkn_v6" not in table_off
    assert "@syn_flood" in table_off


def test_background_rkn_drops_do_not_trigger_false_ddos_attack_alert() -> None:
    calm_with_rkn_scans = antiddos.Status(
        installed=True,
        enabled=True,
        table=True,
        pps=120,
        conntrack=40,
        conntrack_max=65536,
        counters={"rkn_drop": 250000, "manual_drop": 9000, "syn_drop": 2},
    )
    assert calm_with_rkn_scans.rkn_dropped() == 250000
    assert calm_with_rkn_scans.manual_dropped() == 9000
    assert calm_with_rkn_scans.dropped() == 259002
    assert calm_with_rkn_scans.flood_dropped() == 2
    assert calm_with_rkn_scans.level() == "ok"
    assert calm_with_rkn_scans.under_attack() is False


def test_ddos_agent_rkn_sync_ban_allow_and_counters(tmp_path: Path) -> None:
    bins = tmp_path / "bin"
    bins.mkdir()
    loaded = tmp_path / "loaded.nft"
    nft = _script(
        bins / "nft",
        "\n".join(
            [
                "#!/bin/sh",
                'case "$1" in',
                '  list) if [ -s "$STUB_LOADED" ]; then cat "$STUB_LOADED"; exit 0; fi; exit 1 ;;',
                "  -c) exit 0 ;;",
                '  -f) cp "$2" "$STUB_LOADED"; exit 0 ;;',
                "  delete) exit 0 ;;",
                "esac",
                "exit 0",
                "",
            ]
        ),
    )
    systemctl = _script(bins / "systemctl", "#!/bin/sh\nexit 0\n")
    sysctl = _script(bins / "sysctl", "#!/bin/sh\nexit 0\n")
    env = {**os.environ, "STUB_LOADED": str(loaded)}

    def run_agent(cmd: str, *extra: str, stdin_text: str = "") -> dict[str, Any]:
        proc = subprocess.run(
            [
                sys.executable,
                str(AGENT),
                cmd,
                f"--dir={tmp_path}",
                f"--nft={nft}",
                f"--systemctl={systemctl}",
                f"--sysctl={sysctl}",
                *extra,
            ],
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = json.loads(proc.stdout)
        assert out["ok"] is True
        return out["data"]

    installed = run_agent("install", "--ports=22,443,8443")
    assert installed["rkn_enabled"] is True
    assert installed["rkn_v4_count"] >= 2500
    assert "set rkn_v4 {" in (tmp_path / "ddos.nft").read_text(encoding="utf-8")
    assert "tcp dport != { 22, 443, 8443 } tcp flags & (fin|syn|rst|ack) == syn update @port_scan" in (
        tmp_path / "ddos.nft"
    ).read_text(encoding="utf-8")

    custom_zhex = antiddos.encode_rkn_zhex(["5.143.224.100/30", "37.9.13.54/32"], ["2a00:1fa0::/29"])
    synced = run_agent("rkn-sync", "--rkn_zhex=-", stdin_text=custom_zhex)
    assert synced["rkn_v4_count"] == 2
    assert synced["rkn_v6_count"] == 1
    assert (tmp_path / "rkn_subnets.json").is_file()

    after_ban = run_agent("ban-add", "--ip=203.0.113.88")
    assert "203.0.113.88" in after_ban["policy"]["manual_bans"]
    assert "set manual_ban_v4 {" in (tmp_path / "ddos.nft").read_text(encoding="utf-8")

    after_allow = run_agent("allow-add", "--ip=198.51.100.12")
    assert "198.51.100.12" in after_allow["policy"]["rkn_allow"]
    assert "set rkn_allow_v4 {" in (tmp_path / "ddos.nft").read_text(encoding="utf-8")

    loaded.write_text(
        "\n".join(
            [
                "table inet obhod_ddos {",
                "  chain input {",
                "    ip saddr @rkn_v4 counter packets 310 bytes 18600 drop",
                "    ip6 saddr @rkn_v6 counter packets 15 bytes 1200 drop",
                "    ip saddr @manual_ban_v4 counter packets 7 bytes 420 drop",
                "    counter packets 99 bytes 5940 accept",
                "  }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    st = run_agent("status")
    assert st["counters"]["rkn_drop"] == 325
    assert st["counters"]["manual_drop"] == 7
    assert st["counters"]["accepted"] == 99


def test_debug_panel_rkn_toggle_sync_and_inline_mutations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bot = _make_bot(tmp_path)
    sent: list[Any] = []
    calls: list[tuple[list[str], bytes | None]] = []

    async def fake_send(_chat: int, payload: Any) -> int:
        sent.append(payload)
        return len(sent)

    async def fake_edit(_chat: int, _msg: int, payload: Any) -> int:
        sent.append(payload)
        return _msg

    async def fake_ddos_call(
        _client: Any,
        _cfg: Any,
        argv: list[str],
        timeout: float = 180.0,
        stdin: bytes | None = None,
    ) -> antiddos.Status:
        calls.append((list(argv), stdin))
        pol = antiddos.Policy.from_dict(bot.state.ddos)
        return antiddos.Status(
            installed=True,
            enabled=True,
            table=True,
            policy=pol,
            rkn_enabled=pol.rkn_enabled,
            rkn_v4_count=2594 if pol.rkn_enabled else 0,
            rkn_v6_count=40 if pol.rkn_enabled else 0,
            counters={"rkn_drop": 42},
        )

    monkeypatch.setattr(bot, "send", fake_send)
    monkeypatch.setattr(bot, "render", fake_edit)
    monkeypatch.setattr(guard, "ddos_call", fake_ddos_call)
    monkeypatch.setattr(
        antiddos,
        "fetch_rkn_subnets",
        lambda **kwargs: (["5.143.224.100/30", "37.9.13.54/32"], ["2a00:1fa0::/29"], 5, []),
    )

    bot.debug.ddos = antiddos.Status(installed=True, enabled=True, table=True)
    asyncio.run(bot.debug.ddos_action(7, 1, "rkn_sync"))
    assert calls[-1][0] == ["rkn-sync", "--rkn_zhex=-"]
    assert calls[-1][1] is not None and len(calls[-1][1]) > 10

    bot.debug.marks.clear()
    asyncio.run(bot.debug.ddos_action(7, 1, "rkn"))
    assert bot.state.ddos["rkn_enabled"] is False
    assert "--rkn_enabled=0" in calls[-1][0]

    asyncio.run(bot.debug.apply_input(7, "dbg_ddos_ban", "-", "203.0.113.99"))
    assert "203.0.113.99" in bot.state.ddos["manual_bans"]

    asyncio.run(bot.debug.apply_input(7, "dbg_ddos_ban", "-", "198.51.100.42"))
    assert "198.51.100.42" not in bot.state.ddos["manual_bans"]

    asyncio.run(bot.debug.apply_input(7, "dbg_ddos_ban", "-", "203.0.113.99"))
    assert "203.0.113.99" not in bot.state.ddos["manual_bans"]

    asyncio.run(bot.debug.apply_input(7, "dbg_ddos_allow", "-", "198.51.100.55"))
    assert "198.51.100.55" in bot.state.ddos["rkn_allow"]


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_ddos_screen_renders_rkn_guard_within_button_budget(lang: str) -> None:
    pol = antiddos.Policy(rkn_enabled=True, manual_bans=["203.0.113.9"], rkn_allow=["198.51.100.5"])
    st = antiddos.Status(
        installed=True,
        enabled=True,
        table=True,
        policy=pol,
        rkn_enabled=True,
        rkn_v4_count=2594,
        rkn_v6_count=40,
        counters={"rkn_drop": 128},
    )
    rendered = dscreens.ddos_screen(dscreens.DbgView(lang=lang, ddos=st))
    html = rendered.to_html()
    assert "2594 IPv4, 40 IPv6" in html
    assert "128" in html
    assert "dbg:dd:rkn" in html
    assert "dbg:dd:rkn_sync" in html
    assert html.count("<tg-button") <= ui.MAX_BUTTONS


def test_readme_credit_flecksis() -> None:
    body = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Flecksis" in body
    assert "https://github.com/Flecksis/rkn-guard" in body
