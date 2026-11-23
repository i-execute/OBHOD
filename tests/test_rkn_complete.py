from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from BOT import antiddos, dscreens, guard, i18n, ui

ROOT = Path(__file__).resolve().parents[1]


def agent():
    spec = importlib.util.spec_from_file_location("rkn_full_agent", ROOT / "Storage/remote/ddos_agent.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_individual_source_cache_survives_partial_failure_and_disable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sources = (("first", "https://example.com/a"), ("second", "https://example.com/b"))
    monkeypatch.setattr(antiddos, "RKN_SOURCES", sources)
    cache = tmp_path / "cache.json"
    monkeypatch.setattr(antiddos, "_download_source_lines", lambda url, timeout: ["5.143.224.0/24" if url.endswith("a") else "37.9.13.0/24"])
    v4, _, ok, errors = antiddos.fetch_rkn_subnets(cache_path=cache)
    assert ok == 2 and not errors and len(v4) == 2
    assert cache.stat().st_mode & 0o777 == 0o600

    def partial(url: str, timeout: float) -> list[str]:
        if url.endswith("a"):
            raise TimeoutError()
        return ["37.9.14.0/24"]

    monkeypatch.setattr(antiddos, "_download_source_lines", partial)
    v4, _, ok, errors = antiddos.fetch_rkn_subnets(cache_path=cache)
    assert ok == 1 and len(errors) == 1 and "(cached)" in errors[0]
    assert "5.143.224.0/24" in v4 and "37.9.14.0/24" in v4 and "37.9.13.0/24" not in v4
    v4, _, _, errors = antiddos.fetch_rkn_subnets(cache_path=cache, disabled_sources=[sources[0][1]])
    assert not errors and v4 == ["37.9.14.0/24"]
    with pytest.raises(antiddos.DDoSerror):
        antiddos.fetch_rkn_subnets(cache_path=cache, disabled_sources=[item[1] for item in sources])


def test_exception_validation_and_clear_are_transmitted() -> None:
    raw = ["37.9.13.54 tcp 443", "37.9.13.54 tcp 443", "bad udp 3", "1.2.3.4 udp 0", "::1 udp 53"]
    policy = antiddos.Policy(rkn_exceptions=raw).normalise()
    assert policy.rkn_exceptions == ["37.9.13.54 tcp 443", "::1 udp 53"]
    assert "--rkn_exceptions=37.9.13.54 tcp 443;::1 udp 53" in guard.ddos_argv("install", policy)
    assert "--manual_bans=" in guard.ddos_argv("install", antiddos.Policy())
    table = antiddos.nft_table(policy, rkn_v4=["37.9.13.0/24"], rkn_v6=[])
    assert "ip saddr 37.9.13.54 tcp dport 443 return" in table
    assert "jump rkn_check" in table


def test_agent_timer_validates_and_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "systemctl": "/bin/true", "mode": "calendar", "value": "18:30,06:00,06:00"}
    (tmp_path / "obhod-rkn-update.service").write_text("[Service]\nType=oneshot\nExecStart=/bin/true\n")
    calls: list[list[str]] = []
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (calls.append(argv) or (0, "", "")))
    result = m.schedule_set(flags)
    assert result["active"] and result["value"] == "06:00,18:30"
    body = (tmp_path / "obhod-rkn-update.timer").read_text()
    assert "OnCalendar=*-*-* 06:00:00 Europe/Moscow" in body
    before = len(calls)
    m.schedule_set(flags)
    assert not any("restart" in cmd or "enable" in cmd for cmd in calls[before:])
    flags["value"] = "06:00\nExecStart=/bin/evil"
    with pytest.raises(m.DDosError):
        m.schedule_set(flags)
    assert (tmp_path / "obhod-rkn-update.timer").read_text() == body


def test_logs_are_bounded_and_selector_is_not_injectable(monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    calls = []
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/journalctl")
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (calls.append(argv) or (0, "x" * 5000, "")))
    assert len(m.service_logs({"kind": "v4"})["text"]) == 3000
    assert "--grep=OBHOD-RKN-v4:" in calls[0]
    with pytest.raises(m.DDosError):
        m.service_logs({"kind": "v4;reboot"})


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_new_screens_render_safely_and_within_budget(lang: str) -> None:
    view = dscreens.DbgView(lang=lang)
    policy = antiddos.Policy(custom_sources=["https://example.org/a?x=1&y=2"], rkn_exceptions=["37.9.13.54 tcp 443"]).normalise()
    panels = [dscreens.ddos_sources_screen(view, policy, 1), dscreens.ddos_logs_screen(view, "<script>", "v4"), dscreens.ddos_exceptions_screen(view, policy), dscreens.ddos_schedule_screen(view, {"mode": "hours", "value": "12", "active": True})]
    for panel in panels:
        html = panel.to_html()
        assert html.count("<tg-button type=") <= ui.MAX_BUTTONS
        assert "<script>" not in html


def test_timer_update_uses_cached_sources_and_refuses_stale_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace
    from BOT import rkn_update

    monkeypatch.setenv("OBHOD_STATE_DIR", str(tmp_path))
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"ddos": {"enabled": True, "rkn_enabled": True}}))
    monkeypatch.setattr(antiddos, "RKN_SOURCES", (("a", "https://example.com/a"),))
    monkeypatch.setattr(antiddos, "_download_source_lines", lambda url, timeout: ["5.143.224.0/24"])
    calls = []
    def call(args, **kwargs):
        calls.append((args, kwargs))
        if args[-1] == "status":
            data = {"installed": True, "enabled": True, "table": True, "policy": antiddos.Policy().to_dict(), "policy_sha256": "a" * 64}
            return SimpleNamespace(returncode=0, stdout=json.dumps({"ok": True, "data": data}).encode())
        return SimpleNamespace(returncode=0, stdout=b'{"ok":true}')
    monkeypatch.setattr(rkn_update.subprocess, "run", call)
    assert rkn_update.main() == 0
    assert "--rkn_zhex=-" in calls[1][0] and "--expected_policy_sha=" + "a" * 64 in calls[1][0]
    assert calls[1][1]["input"]
    assert (tmp_path / "rkn_sources_cache.json").is_file()
    state_file.write_text(json.dumps({"ddos": {"enabled": False}}))
    calls.clear()
    assert rkn_update.main() == 0 and not calls


def test_top_statistics_counts_sampled_kernel_log(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    m = agent()
    events = [
        {"__CURSOR": "s=1;i=1", "MESSAGE": "OBHOD-RKN-v4: SRC=5.143.224.2 DPT=443"},
        {"__CURSOR": "s=1;i=2", "MESSAGE": "OBHOD-RKN-v4: SRC=5.143.224.2 DPT=22"},
        {"__CURSOR": "s=1;i=3", "MESSAGE": "OBHOD-RKN-v6: SRC=2a00:1fa0::1 DPT=443"},
    ]
    calls = []
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/journalctl")

    def journal(argv, timeout=60):
        calls.append(argv)
        return ([], False) if any(arg.startswith("--after-cursor=") for arg in argv) else ([json.dumps(event) for event in events], False)

    monkeypatch.setattr(m, "journal_batch", journal)
    flags = {"kind": "top", "dir": str(tmp_path)}
    text = m.service_logs(flags)["text"]
    assert "5.143.224.2  2" in text and "2a00:1fa0::1  1" in text
    assert m.service_logs(flags)["text"] == text
    assert "--after-cursor=s=1;i=3" in calls[-1]
    assert (tmp_path / "rkn_attack_stats.json").stat().st_mode & 0o777 == 0o600


def test_ssh_safety_is_short_lived_and_scoped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    m = agent()
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (0, '0 0 5.143.224.1:2222 5.143.224.2:45454 users:(("sshd",pid=10,fd=5))\n', ""))
    peers = m.ssh_safety_entries({"dir": str(tmp_path), "ss": "/bin/true", "ssh_session": "5.143.224.3 12345 5.143.224.1 2222"})
    assert ("5.143.224.2", 2222) in peers and ("5.143.224.3", 2222) in peers
    policy = m.policy_from({}, {})
    body = m.rules_text(policy, {"dir": str(tmp_path)}, peers)
    assert "timeout 30m" in body and "ip saddr . tcp dport @safe_ssh4 accept" in body
    assert body.index("@safe_ssh4 accept") < body.index("ct state invalid counter drop")
    assert "safe_ssh" not in m.rules_text(policy, {"dir": str(tmp_path)})


def test_bad_source_urls_do_not_crash() -> None:
    assert antiddos.normalize_source_url("https://[broken") == ""
    assert antiddos.normalize_source_url("https://example.org:bad/list") == ""


def test_custom_sources_require_valid_cidr_entries() -> None:
    antiddos.validate_custom_source(["5.143.224.0/24 # example", "2a00:1fa0::/29"])
    for bad in (["5.143.224.2"], ["5.143.224.0/24", "broken"], ["0.0.0.0/0"], ["::ffff:192.0.2.1/128"], ["# empty"]):
        with pytest.raises(ValueError):
            antiddos.validate_custom_source(bad)


def test_source_ui_actions_are_bound_to_url_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import hashlib
    from tests.test_round31 import _make_bot

    bot = _make_bot(tmp_path)
    sent = []

    async def send(_chat, payload):
        sent.append(payload)
        return 1

    async def render(_chat, _msg, payload):
        sent.append(payload)
        return 1

    monkeypatch.setattr(bot, "send", send)
    monkeypatch.setattr(bot, "render", render)
    monkeypatch.setattr(antiddos, "_download_source_lines", lambda url, timeout: ["5.143.224.0/24"])
    url = "https://example.org/custom.txt"
    asyncio.run(bot.debug.apply_input(7, "dbg_rkn_source", "-", url))
    assert url in bot.state.ddos["custom_sources"] and url in bot.state.ddos["disabled_sources"]
    key = hashlib.sha256(url.encode()).hexdigest()[:12]
    asyncio.run(bot.debug.ddos_action(7, 1, "src:t:" + key))
    assert url not in bot.state.ddos["disabled_sources"]
    asyncio.run(bot.debug.ddos_action(7, 1, "src:d:" + key))
    assert url not in bot.state.ddos["custom_sources"]
    asyncio.run(bot.debug.ddos_action(7, 1, "src:t:" + key))
    assert bot.debug.error


def test_stats_read_failure_retains_prior_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    state = {"cursor": "s=1;i=1", "counts": {"5.143.224.2": 7}, "updated_at": "x"}
    file = tmp_path / "rkn_attack_stats.json"
    file.write_text(json.dumps(state))
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/journalctl")
    def failed_journal(argv, timeout=30):
        raise m.DDosError("stats_failed", "journal unavailable", "stats")

    monkeypatch.setattr(m, "journal_batch", failed_journal)
    text = m.service_logs({"kind": "top", "dir": str(tmp_path)})["text"]
    assert "journal unavailable" in text and "5.143.224.2  7" in text
    assert json.loads(file.read_text()) == state


def test_live_logs_refresh_cancel_and_report_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace
    from BOT import dbg

    async def exercise() -> None:
        renders = []
        calls = []
        refreshed = asyncio.Event()
        failed = asyncio.Event()
        state = SimpleNamespace(ddos={}, language="en", ssh=None)

        class Bot:
            control = object()
            emoji_enabled = False
            admin_id = 1

            def __init__(self) -> None:
                self.state = state
                self.app = self

            async def edit_rich(self, chat_id: int, msg_id: int, rich: object, via: str) -> None:
                await self.render(chat_id, msg_id, rich)

            async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
                html = rich.to_html()
                renders.append(html)
                if "event two" in html:
                    refreshed.set()
                if "journal unavailable" in html:
                    failed.set()

        class Client:
            def __init__(self, control: object) -> None:
                pass

            async def _call(self, cfg: object, script: object, name: str, argv: list[str], timeout: float) -> object:
                calls.append(argv)
                if len(calls) == 3:
                    raise RuntimeError("journal unavailable")
                return SimpleNamespace(data={"text": "event one" if len(calls) == 1 else "event two"})

        monkeypatch.setattr(dbg.guard, "GuardClient", Client)
        monkeypatch.setattr(dbg, "RKN_LIVE_INTERVAL", 0.01)
        monkeypatch.setattr(dbg, "RKN_LIVE_DURATION", 1.0)
        panel = dbg.DebugPanel(Bot())
        await panel.route(1, 4, "dbg:dd:live:v4")
        assert "event one" in renders[-1]
        assert (1, 4) in panel.rkn_live_tasks
        await asyncio.wait_for(refreshed.wait(), 1)
        await asyncio.wait_for(failed.wait(), 1)
        await asyncio.sleep(0)
        assert not panel.rkn_live_tasks
        assert "journal unavailable" in renders[-1]
        calls.clear()
        await panel.route(1, 4, "dbg:dd:live:v6")
        task = panel.rkn_live_tasks[(1, 4)]
        await panel.route(1, 4, "dbg:home")
        await asyncio.sleep(0)
        assert task.cancelled()
        assert not panel.rkn_live_tasks
        assert calls == [["logs", "--kind=v6"]]

    asyncio.run(exercise())


def test_live_logs_expire_and_are_limited_per_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace
    from BOT import dbg

    async def exercise() -> None:
        renders = []
        done = asyncio.Event()

        class Bot:
            state = SimpleNamespace(ddos={}, language="en", ssh=None)
            control = object()
            emoji_enabled = False
            admin_id = 1

            def __init__(self) -> None:
                self.app = self

            async def edit_rich(self, chat_id: int, msg_id: int, rich: object, via: str) -> None:
                await self.render(chat_id, msg_id, rich)

            async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
                html = rich.to_html()
                renders.append((msg_id, html))
                if msg_id == 5 and "Auto-refresh (5 min)" in html:
                    done.set()

        class Client:
            def __init__(self, control: object) -> None:
                pass

            async def _call(self, cfg: object, script: object, name: str, argv: list[str], timeout: float) -> object:
                return SimpleNamespace(data={"text": "sample"})

        monkeypatch.setattr(dbg.guard, "GuardClient", Client)
        monkeypatch.setattr(dbg, "RKN_LIVE_INTERVAL", 0.01)
        monkeypatch.setattr(dbg, "RKN_LIVE_DURATION", 0.04)
        panel = dbg.DebugPanel(Bot())
        await panel.route(1, 4, "dbg:dd:live:v4")
        old = panel.rkn_live_tasks[(1, 4)]
        await panel.route(1, 5, "dbg:dd:live:v6")
        await asyncio.sleep(0)
        assert old.cancelled()
        assert list(panel.rkn_live_tasks) == [(1, 5)]
        await asyncio.wait_for(done.wait(), 1)
        await asyncio.sleep(0)
        assert not panel.rkn_live_tasks
        assert "Stop auto-refresh" not in renders[-1][1]

    asyncio.run(exercise())


def test_live_does_not_send_replacement_when_edit_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace
    from BOT import dbg

    async def exercise() -> None:
        edits = []
        renders = []

        class App:
            async def edit_rich(self, chat_id: int, msg_id: int, rich: object, via: str) -> None:
                edits.append(msg_id)
                raise RuntimeError("message deleted")

        class Bot:
            state = SimpleNamespace(ddos={}, language="en", ssh=None)
            control = object()
            app = App()
            emoji_enabled = False
            admin_id = 1

            async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
                renders.append(msg_id)

        class Client:
            def __init__(self, control: object) -> None:
                pass

            async def _call(self, cfg: object, script: object, name: str, argv: list[str], timeout: float) -> object:
                return SimpleNamespace(data={"text": "event"})

        monkeypatch.setattr(dbg.guard, "GuardClient", Client)
        monkeypatch.setattr(dbg, "RKN_LIVE_INTERVAL", 0.01)
        panel = dbg.DebugPanel(Bot())
        await panel.route(1, 4, "dbg:dd:live:v4")
        task = panel.rkn_live_tasks[(1, 4)]
        await asyncio.wait_for(task, 1)
        assert edits == [4, 4]
        assert renders == [4, 4]
        assert not panel.rkn_live_tasks

    asyncio.run(exercise())


def test_journal_batch_bounds_preserves_oldest_and_reports_errors(tmp_path: Path) -> None:
    import sys
    m = agent()
    emitter = tmp_path / "emitter.py"
    emitter.write_text("import sys\nfor i in range(1105):\n print(i, flush=True)\n")
    rows, limited = m.journal_batch([sys.executable, str(emitter)], max_lines=1000)
    assert limited and rows == [str(i) for i in range(1000)]
    emitter.write_text("import sys\nprint('x'*1000, flush=True)\n")
    with pytest.raises(m.DDosError, match="byte limit"):
        m.journal_batch([sys.executable, str(emitter)], max_bytes=100)
    emitter.write_text("import sys\nsys.stderr.write('bad journal')\nsys.exit(2)\n")
    with pytest.raises(m.DDosError, match="bad journal"):
        m.journal_batch([sys.executable, str(emitter)])
    emitter.write_text("import time\ntime.sleep(10)\n")
    with pytest.raises(m.DDosError, match="timed out"):
        m.journal_batch([sys.executable, str(emitter)], timeout=0.1)


def test_collection_backlog_is_processed_without_duplicates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    events = [{"__CURSOR": "s=1;i=%d" % n, "MESSAGE": "OBHOD-RKN-v4: SRC=5.143.224.2"} for n in range(1, 2501)]
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/journalctl")
    commands = []

    def batch(command):
        commands.append(command)
        arg = next((item for item in command if item.startswith("--after-cursor=")), "")
        last = int(arg.rsplit("=", 1)[1]) if arg else 0
        selected = events[last:last + 1000]
        return [json.dumps(event) for event in selected], len(events) > last + 1000

    monkeypatch.setattr(m, "journal_batch", batch)
    flags = {"dir": str(tmp_path)}
    assert m.collect_stats(flags)["batch_limited"]
    assert m.collect_stats(flags)["batch_limited"]
    assert not m.collect_stats(flags)["batch_limited"]
    assert m.collect_stats(flags)["accepted"] == 0
    saved = json.loads((tmp_path / "rkn_attack_stats.json").read_text())
    assert saved["counts"]["5.143.224.2"] == 2500
    assert saved["cursor"] == "s=1;i=2500"
    assert all("-n" not in cmd and "--reverse" not in cmd for cmd in commands)


def test_collection_bad_data_never_advances_cursor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    before = {"cursor": "s=1;i=3", "counts": {"5.143.224.2": 1}, "order_version": 2}
    target = tmp_path / "rkn_attack_stats.json"
    target.write_text(json.dumps(before))
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/journalctl")
    good = json.dumps({"__CURSOR": "s=1;i=4", "MESSAGE": "OBHOD-RKN-v4: SRC=5.143.224.2"})
    monkeypatch.setattr(m, "journal_batch", lambda command: ([good, "not json"], False))
    with pytest.raises(m.DDosError):
        m.collect_stats({"dir": str(tmp_path)})
    assert json.loads(target.read_text()) == before


def test_stats_reset_preserves_cursor_and_warns_about_legacy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    target = tmp_path / "rkn_attack_stats.json"
    state = {"cursor": "s=1;i=7", "counts": {"5.143.224.2": 11}}
    target.write_text(json.dumps(state))
    assert m.stats_snapshot({"dir": str(tmp_path)})["legacy_counts"]
    result = m.reset_stats({"dir": str(tmp_path)})
    assert result == {"reset": True, "cursor_retained": True}
    reset = json.loads(target.read_text())
    assert reset["cursor"] == "s=1;i=7" and reset["counts"] == {}
    assert not reset["legacy_counts"] and reset["order_version"] == 2
    reset["cursor"] = "x\n--bad"
    target.write_text(json.dumps(reset))
    with pytest.raises(m.DDosError):
        m.reset_stats({"dir": str(tmp_path)})
    assert json.loads(target.read_text()) == reset


def test_stats_reset_requires_confirmation_in_ui(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace
    from BOT import dbg

    async def exercise() -> None:
        commands = []
        renders = []

        class Bot:
            state = SimpleNamespace(ddos={}, language="en", ssh=None)
            control = object()
            emoji_enabled = False
            admin_id = 1

            async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
                renders.append(rich.to_html())

        class Client:
            def __init__(self, control: object) -> None:
                pass

            async def _call(self, cfg: object, script: object, name: str, argv: list[str], timeout: float) -> object:
                commands.append(argv)
                return SimpleNamespace(data={"text": "No recorded events"})

        monkeypatch.setattr(dbg.guard, "GuardClient", Client)
        panel = dbg.DebugPanel(Bot())
        await panel.route(1, 4, "dbg:dd:stats_reset")
        assert not commands and "Confirm reset" in renders[-1]
        await panel.route(1, 4, "dbg:dd:stats_reset_confirm")
        assert commands == [["stats-reset"], ["logs", "--kind=top"]]

    asyncio.run(exercise())


def test_log_views_show_latest_events_in_chronological_order(monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/journalctl")
    calls = []
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (calls.append(argv) or (0, "latest\nsecond\noldest\n", "")))
    assert m.service_logs({"kind": "v4"})["text"] == "oldest\nsecond\nlatest"
    assert "--reverse" in calls[0]
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (1, "", ""))
    assert m.service_logs({"kind": "v4"})["text"] == "No journal entries"


def test_firewall_diagnose_only_uses_read_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    monkeypatch.setattr(m, "binary", lambda flags, name, fallback: "/bin/" + fallback)
    calls = []

    def fake(argv, timeout=60):
        calls.append(argv)
        if argv[-1] == "status":
            return 0, "Status: active\n", ""
        if argv[-1] == "--state":
            return 0, "running\n", ""
        return 0, "test version\n", ""

    monkeypatch.setattr(m, "run", fake)
    result = m.firewall_diagnose({})
    assert result["ufw"] == result["firewalld"] == "active" and result["conflict"]
    assert all(cmd[-1] in ("--version", "--state", "status", "tables", "-S") for cmd in calls)
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (1, "", "bus unavailable"))
    result = m.firewall_diagnose({})
    assert result["ufw"] == result["firewalld"] == "unknown" and not result["conflict"]


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_firewall_diag_and_reset_screens_are_safe(lang: str) -> None:
    view = dscreens.DbgView(lang=lang)
    panels = [dscreens.ddos_firewall_diag_screen(view, {"iptables": "<bad>", "conflict": True}), dscreens.ddos_stats_reset_screen(view), dscreens.ddos_logs_screen(view, "log", "top")]
    for panel in panels:
        html = panel.to_html()
        assert html.count("<tg-button type=") <= ui.MAX_BUTTONS
        assert "<bad>" not in html


@pytest.mark.parametrize("command", ["unban", "reban", "ban-add", "ban-del", "allow-add", "allow-del"])
def test_failed_policy_apply_restores_configuration_and_never_unbans_early(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "ip": "5.143.224.2"}
    before = '{"enabled":true,"manual_bans":["5.143.224.2"],"rkn_allow":[]}\n'
    path = Path(m.conf_path(flags))
    path.write_text(before)
    Path(m.rules_path(flags)).write_text("old nft rules\n")
    calls = []
    monkeypatch.setattr(m, "apply_rules", lambda flags, policy, **kwargs: (_ for _ in ()).throw(m.DDosError("apply", "failed", "apply")))
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (calls.append(argv) or (0, "", "")))
    functions = {
        "unban": lambda: m.unban_cmd(flags),
        "reban": lambda: m.reban_cmd(flags),
        "ban-add": lambda: m.mutate_list_cmd(flags, "manual_bans", True, False, "ban-add"),
        "ban-del": lambda: m.mutate_list_cmd(flags, "manual_bans", False, False, "ban-del"),
        "allow-add": lambda: m.mutate_list_cmd(flags, "rkn_allow", True, True, "allow-add"),
        "allow-del": lambda: m.mutate_list_cmd(flags, "rkn_allow", False, True, "allow-del"),
    }
    with pytest.raises(m.DDosError):
        functions[command]()
    assert path.read_text() == before
    assert not calls


def test_no_nft_leaves_persisted_rules_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/missing"}
    path = Path(m.rules_path(flags))
    path.write_text("old rules\n")
    with pytest.raises(m.DDosError) as error:
        m.apply_rules(flags, m.policy_from({}, {}))
    assert error.value.code == "no_nft"
    assert path.read_text() == "old rules\n"


def test_disable_refuses_to_report_success_when_table_might_remain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path)}
    monkeypatch.setattr(m, "binary", lambda flags, name, fallback: "/bin/nft")
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (1, "", "permission denied"))
    with pytest.raises(m.DDosError) as error:
        m.disable(flags)
    assert error.value.code == "backup_failed"
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: ((1, "", "No such file") if argv[1] == "delete" else (0, "table ip unrelated\n", "")))
    assert m.disable(flags) == {"disabled": True}
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: ((1, "", "denied") if argv[1] == "delete" else (0, "table inet obhod_ddos\n", "")))
    with pytest.raises(m.DDosError):
        m.disable(flags)


def test_full_allowlist_fails_without_mutating_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import ipaddress
    m = agent()
    flags = {"dir": str(tmp_path), "ip": "5.143.224.2"}
    allowed = [str(ipaddress.IPv4Address("10.1.0.1") + i) for i in range(m.MAX_CUSTOM_ENTRIES)]
    conf = Path(m.conf_path(flags))
    before = json.dumps({"enabled": True, "rkn_allow": allowed})
    conf.write_text(before)
    monkeypatch.setattr(m, "apply_rules", lambda *args: pytest.fail("should not apply"))
    with pytest.raises(m.DDosError) as error:
        m.unban_cmd(flags)
    assert error.value.code == "limit_reached"
    assert conf.read_text() == before


def test_policy_rollback_failure_is_reported_explicitly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "ip": "5.143.224.2"}
    Path(m.conf_path(flags)).write_text('{"enabled":true}\n')
    Path(m.rules_path(flags)).write_text("old\n")
    original = m.write_atomic
    writes = []

    def write(path, content, mode=0o644):
        writes.append(path)
        if len(writes) > 1:
            raise m.DDosError("fs", "injected rollback failure", "fs")
        return original(path, content, mode)

    monkeypatch.setattr(m, "write_atomic", write)
    monkeypatch.setattr(m, "apply_rules", lambda flags, policy, **kwargs: (_ for _ in ()).throw(m.DDosError("apply", "failed", "apply")))
    with pytest.raises(m.DDosError) as error:
        m.reban_cmd(flags)
    assert error.value.code == "rollback_failed"
    assert "rollback failed" in error.value.message


def test_install_disabled_does_not_reenable_boot_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "enabled": "0", "systemctl": "/bin/true", "nft": "/bin/true"}
    Path(m.unit_path(flags)).write_text("[Service]\nExecStart=/bin/true\n")
    Path(m.rules_path(flags)).write_text("old\n")
    calls = []
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (calls.append(argv) or (0, "", "")))
    monkeypatch.setattr(m, "apply_sysctl", lambda flags: {"applied": False})
    monkeypatch.setattr(m, "status", lambda flags: {"table": False, "notice": ""})
    monkeypatch.setattr(m, "apply_rules", lambda *args: pytest.fail("disabled rules must not be installed"))
    result = m.install(flags)
    assert not result["unit"]["enabled"]
    assert ["/bin/true", "disable", "obhod-ddos.service"] in calls
    assert not any("enable" in call for call in calls)
    assert not json.loads(Path(m.conf_path(flags)).read_text())["enabled"]


def test_install_disabled_retains_active_policy_if_disabling_unit_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "enabled": "0", "systemctl": "/bin/true", "nft": "/bin/true"}
    conf = Path(m.conf_path(flags))
    conf.write_text('{"enabled":true}\n')
    Path(m.unit_path(flags)).write_text("[Service]\nExecStart=/bin/true\n")
    calls = []
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (calls.append(argv) or (1, "", "denied")))
    with pytest.raises(m.DDosError) as error:
        m.install(flags)
    assert error.value.code == "unit_failed"
    assert json.loads(conf.read_text())["enabled"]
    assert all("delete" not in call for call in calls)


def test_bot_list_actions_do_not_save_or_claim_success_on_apply_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import copy
    from types import SimpleNamespace
    from BOT import dbg

    async def exercise() -> None:
        rendered = []
        saved = []

        class Bot:
            control = object()
            emoji_enabled = False
            admin_id = 1

            def __init__(self) -> None:
                self.state = SimpleNamespace(ddos=antiddos.Policy(manual_bans=["5.143.224.2"]).to_dict(), language="en", ssh=None)

            def save(self) -> None:
                saved.append(True)

            async def send(self, chat_id: int, rich: object) -> None:
                rendered.append(rich.to_html())

            async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
                rendered.append(rich.to_html())

        async def fail(*args, **kwargs):
            raise RuntimeError("firewall apply failed")

        monkeypatch.setattr(dbg.guard, "ddos_call", fail)
        bot = Bot()
        panel = dbg.DebugPanel(bot)
        panel.ddos = antiddos.Status(installed=True, enabled=True, table=True, policy=antiddos.Policy(manual_bans=["5.143.224.2"]))
        previous = copy.deepcopy(bot.state.ddos)
        original_status = panel.ddos
        await panel._mutate_ddos_entries(1, "rkn_allow", "5.143.224.2", allow_private=True)
        assert bot.state.ddos == previous and panel.ddos is original_status and not saved
        assert "firewall apply failed" in rendered[-1] and "+5.143.224.2" not in rendered[-1]
        panel.error = ""
        await panel._toggle_ddos_ip(1, 4, "ub", "0", "5.143.224.2")
        assert bot.state.ddos == previous and panel.ddos is original_status and not saved
        assert "firewall apply failed" in rendered[-1]

    asyncio.run(exercise())


def test_live_snapshot_returns_newest_cursor_and_chronological_text(monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/journalctl")
    events = [
        {"__CURSOR": "s=1;i=2", "MESSAGE": "OBHOD-RKN-v4: SRC=5.143.224.2 NEW"},
        {"__CURSOR": "s=1;i=1", "MESSAGE": "OBHOD-RKN-v4: SRC=5.143.224.2 OLD"},
    ]
    calls = []
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (calls.append(argv) or (0, "\n".join(map(json.dumps, events)), "")))
    data = m.live_log_snapshot({"kind": "v4"})
    assert data["cursor"] == "s=1;i=2"
    assert data["text"].endswith("NEW") and data["text"].startswith("OBHOD-RKN-v4: SRC=5.143.224.2 OLD")
    assert "--reverse" in calls[0]
    with pytest.raises(m.DDosError):
        m.live_log_snapshot({"kind": "v4;reboot"})


def test_live_journal_stream_terminates_process_and_validates_selector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import os
    from types import SimpleNamespace
    from BOT import rkn_live

    script = tmp_path / "journalctl"
    pidfile = tmp_path / "pid"
    event = json.dumps({"MESSAGE": "OBHOD-RKN-v4: SRC=5.143.224.2 DPT=443"})
    script.write_text("#!/usr/bin/env python3\nimport os,time\nopen(%r,'w').write(str(os.getpid()))\nprint(%r, flush=True)\ntime.sleep(60)\n" % (str(pidfile), event))
    script.chmod(0o755)
    monkeypatch.setattr(rkn_live.shutil, "which", lambda name: str(script))

    async def exercise() -> None:
        stream = rkn_live.journal_stream(SimpleNamespace(escalated=False), "v4", "s=1;i=10")
        line = await asyncio.wait_for(anext(stream), 2)
        assert "SRC=5.143.224.2" in line
        pid = int(pidfile.read_text())
        await stream.aclose()
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        invalid = rkn_live.journal_stream(SimpleNamespace(escalated=False), "v4", "s=1\n--bad")
        with pytest.raises(ValueError):
            await anext(invalid)

    asyncio.run(exercise())


def test_live_stream_ui_batches_and_stops_on_navigation(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace
    from BOT import dbg, rkn_live
    from BOT.shell import LocalShell

    async def exercise() -> None:
        finalized = asyncio.Event()
        updated = asyncio.Event()
        renders = []
        calls = []

        class RootShell(LocalShell):
            @property
            def escalated(self) -> bool:
                return False

        class Bot:
            state = SimpleNamespace(ddos={}, language="en", ssh=None)
            control = SimpleNamespace(shell=RootShell())
            emoji_enabled = False
            admin_id = 1

            def __init__(self) -> None:
                self.app = self

            async def edit_rich(self, chat_id: int, msg_id: int, rich: object, via: str) -> None:
                await self.render(chat_id, msg_id, rich)

            async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
                html = rich.to_html()
                renders.append(html)
                if "new streamed event" in html:
                    updated.set()

        class Client:
            def __init__(self, control: object) -> None:
                pass

            async def _call(self, cfg: object, script: object, name: str, argv: list[str], timeout: float) -> object:
                calls.append(argv)
                return SimpleNamespace(data={"text": "old event", "cursor": "s=1;i=2"})

        async def stream(shell, kind, cursor, started_at):
            assert kind == "v4" and cursor == "s=1;i=2"
            try:
                yield "new streamed event"
                await asyncio.sleep(10)
            finally:
                finalized.set()

        monkeypatch.setattr(dbg.guard, "GuardClient", Client)
        monkeypatch.setattr(rkn_live, "journal_stream", stream)
        monkeypatch.setattr(dbg, "RKN_LIVE_INTERVAL", 0.01)
        monkeypatch.setattr(dbg, "RKN_LIVE_DURATION", 1)
        panel = dbg.DebugPanel(Bot())
        await panel.route(1, 4, "dbg:dd:live:v4")
        assert calls == [["logs-live-snapshot", "--kind=v4"]]
        await asyncio.wait_for(updated.wait(), 1)
        assert "Live journal stream" in renders[-1]
        task = panel.rkn_live_tasks[(1, 4)]
        await panel.route(1, 4, "dbg:home")
        await asyncio.wait_for(finalized.wait(), 1)
        await asyncio.gather(task, return_exceptions=True)
        assert task.cancelled() and not panel.rkn_live_tasks

    asyncio.run(exercise())


def test_ip_buttons_embed_full_ipv6_cidr_within_callback_budget() -> None:
    address = "2001:aaaa:bbbb:cccc:dddd:eeee:ffff:eeee/127"
    state = antiddos.Status(installed=True, enabled=True, table=True, policy=antiddos.Policy(manual_bans=[address]))
    html = dscreens.ddos_ips_screen(dscreens.DbgView(lang="en", ddos=state)).to_html()
    callback = "dbg:dd:ub:0:" + address
    assert 'data="' + callback + '"' in html
    assert len(callback.encode()) <= ui.MAX_CALLBACK
    assert 'data="dbg:dd:ub:0:@0"' not in html


def test_stale_ip_buttons_never_modify_another_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace
    from BOT import dbg

    async def exercise() -> None:
        rendered = []
        calls = []

        class Bot:
            state = SimpleNamespace(ddos=antiddos.Policy(manual_bans=["5.143.224.2"]).to_dict(), language="en", ssh=None)
            control = object()
            emoji_enabled = False
            admin_id = 1

            async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
                rendered.append(rich.to_html())

        async def call(*args, **kwargs):
            calls.append(args)
            raise AssertionError("stale callback must not call the firewall")

        monkeypatch.setattr(dbg.guard, "ddos_call", call)
        panel = dbg.DebugPanel(Bot())
        panel.ddos = antiddos.Status(installed=True, table=True, policy=antiddos.Policy(manual_bans=["5.143.224.2"]))
        await panel._toggle_ddos_ip(1, 2, "rb", "0", "5.143.224.2")
        assert not calls and "outdated" in rendered[-1]
        await panel._toggle_ddos_ip(1, 2, "ub", "0", "@0")
        assert not calls

    asyncio.run(exercise())


def test_install_fails_before_nft_when_persistence_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/bin/true", "systemctl": "/bin/true"}
    conf = Path(m.conf_path(flags))
    unit = Path(m.unit_path(flags))
    rules = Path(m.rules_path(flags))
    conf.write_text('{"enabled":true,"syn_rate":60}\n')
    unit.write_text("old unit\n")
    rules.write_text("old rules\n")
    calls = []

    def fake(argv, timeout=60):
        calls.append(argv)
        if "is-enabled" in argv:
            return 1, "disabled\n", ""
        if "enable" in argv:
            return 1, "", "enable denied"
        return 0, "", ""

    monkeypatch.setattr(m, "run", fake)
    monkeypatch.setattr(m, "apply_rules", lambda *args: pytest.fail("firewall must not change"))
    with pytest.raises(m.DDosError) as error:
        m.install({**flags, "syn_rate": "120"})
    assert error.value.code == "unit_failed"
    assert conf.read_text() == '{"enabled":true,"syn_rate":60}\n'
    assert unit.read_text() == "old unit\n" and rules.read_text() == "old rules\n"
    assert any("disable" in call for call in calls)


def test_install_rolls_back_conf_and_unit_when_nft_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/bin/true", "systemctl": "/bin/true"}
    conf = Path(m.conf_path(flags))
    unit = Path(m.unit_path(flags))
    rules = Path(m.rules_path(flags))
    conf.write_text('{"enabled":true,"syn_rate":60}\n')
    unit.write_text("old unit\n")
    rules.write_text("old rules\n")
    calls = []

    def fake(argv, timeout=60):
        calls.append(argv)
        return (1, "disabled\n", "") if "is-enabled" in argv else (0, "", "")

    monkeypatch.setattr(m, "run", fake)
    monkeypatch.setattr(m, "apply_rules", lambda *args, **kwargs: (_ for _ in ()).throw(m.DDosError("apply", "injected failure", "apply")))
    with pytest.raises(m.DDosError) as error:
        m.install({**flags, "syn_rate": "120"})
    assert error.value.code == "apply"
    assert conf.read_text() == '{"enabled":true,"syn_rate":60}\n'
    assert unit.read_text() == "old unit\n" and rules.read_text() == "old rules\n"
    assert any("disable" in call for call in calls)


def test_disabled_install_restores_policy_and_unit_after_nft_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "enabled": "0", "nft": "/bin/true", "systemctl": "/bin/true"}
    conf = Path(m.conf_path(flags))
    unit = Path(m.unit_path(flags))
    conf.write_text('{"enabled":true}\n')
    unit.write_text("old unit\n")
    calls = []

    def fake(argv, timeout=60):
        calls.append(argv)
        return (0, "enabled\n", "") if "is-enabled" in argv else (0, "", "")

    monkeypatch.setattr(m, "run", fake)
    monkeypatch.setattr(m, "disable", lambda flags: (_ for _ in ()).throw(m.DDosError("disable_failed", "injected failure", "disable")))
    with pytest.raises(m.DDosError) as error:
        m.install(flags)
    assert error.value.code == "disable_failed"
    assert conf.read_text() == '{"enabled":true}\n' and unit.read_text() == "old unit\n"
    assert any("enable" in call for call in calls)


def test_install_refuses_unrecognized_unit_state_before_changing_firewall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/bin/true", "systemctl": "/bin/true"}
    unit = Path(m.unit_path(flags))
    unit.write_text("old unit\n")
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (1, "masked\n", ""))
    monkeypatch.setattr(m, "apply_rules", lambda *args: pytest.fail("firewall must not change"))
    with pytest.raises(m.DDosError) as error:
        m.install(flags)
    assert error.value.code == "unit_failed" and unit.read_text() == "old unit\n"


def upstream_agent():
    spec = importlib.util.spec_from_file_location("rkn_upstream_agent_test", ROOT / "Storage/remote/rkn_upstream_agent.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_upstream_binary_install_checks_digest_and_never_changes_firewall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib
    m = upstream_agent()
    original = b"original verified binary"
    replacement = b"new verified binary"
    root = tmp_path / "upstream-rkn-guard"
    root.mkdir(mode=0o700)
    target = root / "rkn-guard"
    target.write_bytes(original)
    target.chmod(0o700)
    monkeypatch.setattr(m.platform, "machine", lambda: "test")
    monkeypatch.setitem(m.ARCHES, "test", ("amd64", hashlib.sha256(replacement).hexdigest()))
    calls = []
    monkeypatch.setattr(m, "build_info", lambda path: (calls.append(path) or ("v3.0.0", "test")))

    class Response:
        def __init__(self, body):
            self.body = body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def geturl(self):
            return "https://release-assets.githubusercontent.com/file"
        def read(self, size):
            part, self.body = self.body[:size], self.body[size:]
            return part

    class Opener:
        def __init__(self, body):
            self.body = body
        def open(self, request, timeout):
            assert request.full_url.startswith("https://github.com/Flecksis/rkn-guard/releases/download/v3.0.0/")
            return Response(self.body)

    monkeypatch.setattr(m.urllib.request, "build_opener", lambda *args: Opener(b"untrusted contents"))
    with pytest.raises(m.UpstreamError) as error:
        m.install({"dir": str(tmp_path)})
    assert error.value.code == "digest_mismatch" and target.read_bytes() == original
    assert not calls and not list(root.glob(".rkn-download-*"))
    monkeypatch.setattr(m.urllib.request, "build_opener", lambda *args: Opener(replacement))
    result = m.install({"dir": str(tmp_path)})
    assert target.read_bytes() == replacement and result["verified"] and result["version"] == "v3.0.0"
    assert not result["managed_backend"]
    assert target.stat().st_mode & 0o777 == 0o700
    assert len(calls) == 2


def test_upstream_binary_rejects_untrusted_urls_symlinks_and_unverified_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = upstream_agent()
    assert m.safe_url("https://github.com/Flecksis/rkn-guard/a")
    assert m.safe_url("https://release-assets.githubusercontent.com/a")
    for url in ("http://github.com/a", "https://github.com.evil.example/a", "https://github.com@evil.example/a", "https://github.com:444/a", "file:///etc/passwd"):
        assert not m.safe_url(url)
    root = tmp_path / "upstream-rkn-guard"
    root.mkdir(mode=0o700)
    target = root / "rkn-guard"
    target.write_bytes(b"modified")
    target.chmod(0o700)
    monkeypatch.setattr(m, "build_info", lambda path: pytest.fail("unverified binary must never execute"))
    info = m.status({"dir": str(tmp_path)})
    assert info["installed"] and not info["verified"]
    target.unlink()
    target.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(m.UpstreamError) as error:
        m.status({"dir": str(tmp_path)})
    assert error.value.code == "unsafe_path"


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_upstream_screens_disclose_binary_does_not_switch_backend(lang: str) -> None:
    view = dscreens.DbgView(lang=lang)
    for panel in (dscreens.ddos_upstream_screen(view, {"installed": True, "verified": True, "version": "v3.0.0", "architecture": "amd64"}), dscreens.ddos_upstream_screen(view, {}, confirm=True)):
        assert panel.to_html().count("<tg-button") <= ui.MAX_BUTTONS
        assert "v3.0.0" in panel.to_html()


def test_upstream_ui_confirmation_does_not_run_program(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace
    from BOT import dbg

    async def exercise() -> None:
        calls = []
        renders = []

        class Bot:
            state = SimpleNamespace(ddos={}, language="en", ssh=None)
            control = object()
            emoji_enabled = False
            admin_id = 1

            async def render(self, chat_id: int, msg_id: int, rich: object) -> None:
                renders.append(rich.to_html())

        class Client:
            def __init__(self, control: object) -> None:
                pass

            async def _call(self, cfg: object, script: object, name: str, argv: list[str], timeout: float) -> object:
                calls.append((script, argv))
                return SimpleNamespace(data={"installed": True, "verified": True, "version": "v3.0.0", "architecture": "amd64"})

        monkeypatch.setattr(dbg.guard, "GuardClient", Client)
        panel = dbg.DebugPanel(Bot())
        await panel.route(1, 4, "dbg:dd:upstream_confirm")
        assert not calls and "Confirm download" in renders[-1]
        await panel.route(1, 4, "dbg:dd:upstream_install")
        assert calls == [(guard.RKN_UPSTREAM_SCRIPT, ["install"])]
        assert "Verified" in renders[-1]

    asyncio.run(exercise())


def test_restore_unit_uses_agent_without_deleting_table_on_stop() -> None:
    m = agent()
    unit = m.unit_text({"dir": "/tmp/with spaces%$", "agent_path": str(ROOT / "Storage/remote/ddos_agent.py"), "nft": "/bin/true"})
    assert '"--dir=/tmp/with spaces%%$$"' in unit
    assert '"restore"' in unit and '"--nft=/bin/true"' in unit
    assert "ExecStop=" not in unit
    with pytest.raises(m.DDosError):
        m.systemd_arg("bad\npath")


def test_restore_refuses_untrusted_agent_symlink_or_writable_file(tmp_path: Path) -> None:
    m = agent()
    target = tmp_path / "agent.py"
    target.write_text("pass\n")
    target.chmod(0o666)
    with pytest.raises(m.DDosError) as exc:
        m.agent_path({"agent_path": str(target)})
    assert exc.value.code == "unsafe_agent"
    target.chmod(0o600)
    link = tmp_path / "link.py"
    link.symlink_to(target)
    with pytest.raises(m.DDosError):
        m.agent_path({"agent_path": str(link)})


def test_restore_rejects_unavailable_or_ambiguous_table_listing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path)}
    policy = m.policy_from({}, {})
    (tmp_path / "ddos.json").write_text(json.dumps(policy))
    (tmp_path / "ddos.nft").write_text(m.rules_text(policy, flags))
    monkeypatch.setattr(m, "binary", lambda flags, name, fallback: "/bin/true" if name == "nft" else "")
    monkeypatch.setattr(m, "ssh_safety_entries", lambda flags: [])
    calls = []
    def failed(argv: list[str], timeout: int = 30) -> tuple[int, str, str]:
        calls.append(argv)
        return (1, "", "permission denied")
    monkeypatch.setattr(m, "run", failed)
    with pytest.raises(m.DDosError) as exc:
        m.restore_rules(flags)
    assert exc.value.code == "snapshot_failed" and calls == [["/bin/true", "list", "tables"]]
    monkeypatch.setattr(m, "run", lambda argv, timeout=30: (0, "x" * m.MAX_OUTPUT, ""))
    with pytest.raises(m.DDosError) as exc:
        m.restore_rules(flags)
    assert exc.value.code == "snapshot_failed"


def test_restore_disabled_and_corrupt_policy_never_runs_nft(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path)}
    monkeypatch.setattr(m, "binary", lambda flags, name, fallback: "/bin/true")
    monkeypatch.setattr(m, "run", lambda *args, **kwargs: pytest.fail("nft must not run"))
    (tmp_path / "ddos.json").write_text('{"enabled":false}')
    assert not m.restore_rules(flags)["restored"]
    (tmp_path / "ddos.json").write_text('{"enabled":"false"}')
    with pytest.raises(m.DDosError) as exc:
        m.restore_rules(flags)
    assert exc.value.code == "bad_policy"


def test_install_does_not_touch_unit_when_agent_path_is_unsafe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/bin/true", "systemctl": "/bin/true", "agent_path": str(tmp_path / "missing.py")}
    old = tmp_path / "obhod-ddos.service"
    old.write_text("old unit\n")
    calls = []
    monkeypatch.setattr(m, "run", lambda argv, timeout=30: (calls.append(argv) or (0, "", "")))
    with pytest.raises(m.DDosError) as exc:
        m.install(flags)
    assert exc.value.code == "unsafe_agent" and old.read_text() == "old unit\n" and not calls


def test_ddos_rpc_install_supplies_the_local_agent_path() -> None:
    import asyncio
    from types import SimpleNamespace

    async def exercise() -> None:
        calls = []
        class Client:
            async def _call(self, cfg, script, name, argv, timeout, stdin=None):
                calls.append((script, argv))
                return SimpleNamespace(data={})
        await guard.ddos_call(Client(), None, ["install", "--enabled=1"])
        assert calls[0][0] == guard.DDOS_SCRIPT
        assert calls[0][1] == ["install", "--enabled=1", "--agent_path=" + str(guard.DDOS_SCRIPT.resolve())]
        await guard.ddos_call(Client(), None, ["status"])
        assert calls[1][1] == ["status"]

    asyncio.run(exercise())


def test_timeout_after_nft_apply_restores_checkpoint_and_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/bin/true"}
    policy = m.policy_from({}, {})
    previous = "previous rules\n"
    (tmp_path / "ddos.nft").write_text(previous)
    snapshot = "table inet obhod_ddos {\n}\n"
    calls = []
    monkeypatch.setattr(m, "nft_checkpoint", lambda *args: snapshot)
    monkeypatch.setattr(m, "restore_nft_checkpoint", lambda flags, tool, body: calls.append(body))
    monkeypatch.setattr(m, "ssh_safety_entries", lambda flags: [])
    monkeypatch.setattr(m, "run", lambda argv, timeout=30: ((124, "", "timeout") if argv[1] == "-f" else (0, "", "")))
    with pytest.raises(m.DDosError) as exc:
        m.apply_rules(flags, policy)
    assert exc.value.code == "apply" and calls == [snapshot]
    assert (tmp_path / "ddos.nft").read_text() == previous


def test_timeout_rollback_failure_is_not_reported_as_normal_apply_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/bin/true"}
    policy = m.policy_from({}, {})
    (tmp_path / "ddos.nft").write_text("old\n")
    monkeypatch.setattr(m, "nft_checkpoint", lambda *args: "table inet obhod_ddos {\n}\n")
    monkeypatch.setattr(m, "ssh_safety_entries", lambda flags: [])
    def fail(*args):
        raise m.DDosError("rollback_failed", "injected rollback error", "apply")
    monkeypatch.setattr(m, "restore_nft_checkpoint", fail)
    monkeypatch.setattr(m, "run", lambda argv, timeout=30: ((124, "", "timeout") if argv[1] == "-f" else (0, "", "")))
    with pytest.raises(m.DDosError) as exc:
        m.apply_rules(flags, policy)
    assert exc.value.code == "rollback_failed"
    assert (tmp_path / "ddos.nft").read_text() == "old\n"


def test_ipv6_neighbor_discovery_allowed_with_required_hop_limit_before_bans(tmp_path: Path) -> None:
    m = agent()
    flags = {"dir": str(tmp_path)}
    (tmp_path / "rkn_subnets.json").write_text(json.dumps({"v4": [], "v6": ["2a00:1fa0::/29"]}))
    policy = m.policy_from({}, {})
    policy["manual_bans"] = ["2a00:1fa0::2"]
    body = m.rules_text(policy, flags)
    nd = "ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept"
    assert nd in body
    assert body.index(nd) < body.index("ip6 saddr @manual_ban_v6 counter drop")
    ui_body = antiddos.nft_table(antiddos.Policy(manual_bans=["2a00:1fa0::2"]), rkn_v4=[], rkn_v6=["2a00:1fa0::/29"])
    assert nd in ui_body and ui_body.index(nd) < ui_body.index("ip6 saddr @manual_ban_v6 counter drop")
    assert "nd-router-advert" not in nd


def test_restore_unit_requires_trusted_python_interpreter_when_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    python = tmp_path / "python3"
    python.write_text("unsafe")
    python.chmod(0o777)
    monkeypatch.setattr(m.sys, "executable", str(python))
    monkeypatch.setattr(m.os, "geteuid", lambda: 0)
    original = m.agent_path
    def check(flags):
        if flags.get("agent_path") == "/safe/agent.py":
            return "/safe/agent.py"
        return original(flags)
    monkeypatch.setattr(m, "agent_path", check)
    with pytest.raises(m.DDosError) as exc:
        m.unit_text({"agent_path": "/safe/agent.py"})
    assert exc.value.code == "unsafe_agent"


def test_atomic_write_syncs_file_permissions_then_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    events = []
    real_fsync = m.os.fsync
    real_fchmod = m.os.fchmod
    real_replace = m.os.replace

    def chmod(fd, mode):
        events.append("chmod")
        return real_fchmod(fd, mode)

    def sync(fd):
        import stat
        events.append("dirsync" if stat.S_ISDIR(m.os.fstat(fd).st_mode) else "filesync")
        return real_fsync(fd)

    def replace(source, target):
        events.append("replace")
        return real_replace(source, target)

    monkeypatch.setattr(m.os, "fchmod", chmod)
    monkeypatch.setattr(m.os, "fsync", sync)
    monkeypatch.setattr(m.os, "replace", replace)
    target = tmp_path / "policy.json"
    m.write_atomic(str(target), "new", 0o600)
    assert target.read_text() == "new"
    assert target.stat().st_mode & 0o777 == 0o600
    assert events == ["chmod", "filesync", "replace", "dirsync"]


def test_atomic_write_reports_ambiguous_directory_fsync_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    real_fsync = m.os.fsync

    def sync(fd):
        import stat
        if stat.S_ISDIR(m.os.fstat(fd).st_mode):
            raise OSError(5, "I/O error")
        return real_fsync(fd)

    monkeypatch.setattr(m.os, "fsync", sync)
    target = tmp_path / "policy.json"
    target.write_text("old")
    with pytest.raises(m.DDosError) as exc:
        m.write_atomic(str(target), "new")
    assert exc.value.code == "fs"
    assert "replacement may have occurred" in exc.value.message
    assert target.read_text() == "new"


@pytest.mark.parametrize("url,expected", [
    ("https://[2606:4700:4700::1111]/list", "https://[2606:4700:4700::1111]/list"),
    ("https://[2606:4700:4700::1111]:8443/list?format=cidr", "https://[2606:4700:4700::1111]:8443/list?format=cidr"),
    ("https://[2606:4700:4700::1111]:443", "https://[2606:4700:4700::1111]/"),
    ("https://[fe80::1]/list", ""),
    ("https://[2606:4700:4700::1111%25eth0]/list", ""),
    ("https://[2606:4700:4700::1111]:99999/list", ""),
])
def test_source_url_global_ipv6_literals_are_bracketed(url: str, expected: str) -> None:
    assert antiddos.normalize_source_url(url) == expected
    if expected:
        assert antiddos.normalize_source_url(expected) == expected


def test_too_many_ssh_peers_are_not_silently_discarded(monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    lines = [f'0 0 5.143.224.1:2222 8.8.8.{n}:45454 users:(("sshd",pid=10,fd=5))' for n in range(1, 34)]
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (0, "\n".join(lines), ""))
    with pytest.raises(m.DDosError) as exc:
        m.ssh_safety_entries({"ss": "/bin/true"})
    assert exc.value.code == "ssh_safety"
    assert "firewall was not changed" in exc.value.message


def test_truncated_ssh_listing_is_not_treated_as_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    monkeypatch.setattr(m, "MAX_OUTPUT", 50)
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (0, "x" * 50, ""))
    with pytest.raises(m.DDosError) as exc:
        m.ssh_safety_entries({"ss": "/bin/true"})
    assert exc.value.code == "ssh_safety"


@pytest.mark.parametrize("available,code", [(False, 0), (True, 1), (True, 124)])
def test_failed_ssh_enumeration_rejects_full_apply(monkeypatch: pytest.MonkeyPatch, available: bool, code: int) -> None:
    m = agent()
    monkeypatch.setattr(m, "binary", lambda flags, name, fallback: "/fake/ss" if available else "")
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (code, "", "failed"))
    with pytest.raises(m.DDosError) as exc:
        m.ssh_safety_entries({})
    assert exc.value.code == "ssh_safety"
    assert "firewall was not changed" in exc.value.message


def test_saved_policy_consistency_detects_corrupt_and_changed_config(tmp_path: Path) -> None:
    m = agent()
    flags = {"dir": str(tmp_path)}
    assert m.saved_policy_consistency(flags) == "not_installed"
    policy = m.policy_from({}, {})
    Path(m.conf_path(flags)).write_text(json.dumps(policy))
    Path(m.rules_path(flags)).write_text(m.rules_text(policy, flags))
    assert m.saved_policy_consistency(flags) == "matched"
    policy["syn_rate"] = 999
    Path(m.conf_path(flags)).write_text(json.dumps(policy))
    assert m.saved_policy_consistency(flags) == "mismatch"
    Path(m.conf_path(flags)).write_text("{invalid")
    assert m.saved_policy_consistency(flags) == "unknown"
    Path(m.conf_path(flags)).write_text(json.dumps({"enabled": False}))
    assert m.saved_policy_consistency(flags) == "disabled"


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_mismatched_saved_policy_is_visible_in_ddos_screen(lang: str) -> None:
    status = antiddos.Status.from_dict({"installed": True, "enabled": True, "table": True, "saved_policy_consistency": "mismatch"})
    assert status.level() == "warn"
    assert status.to_dict()["saved_policy_consistency"] == "mismatch"
    html = dscreens.ddos_screen(dscreens.DbgView(lang=lang, ddos=status)).to_html()
    assert dscreens.DbgView(lang=lang).tr()("DDOS_SAVED_MISMATCH") in html


def test_live_rate_consistency_checks_four_limits_and_rejects_ambiguous_rules() -> None:
    m = agent()
    p = m.policy_from({}, {})
    live = "\n".join(f"update @{name} {{ ip saddr limit rate over {p[rate]}/second burst {p[burst]} packets }}" for name, rate, burst in [("syn_flood", "syn_rate", "syn_burst"), ("conn_flood", "conn_rate", "conn_burst"), ("udp_flood", "udp_rate", "udp_burst"), ("icmp_flood", "icmp_rate", "icmp_burst")])
    assert m.live_rate_consistency(live, p) == "matched"
    assert m.live_rate_consistency(live.replace("60/second", "999/second"), p) == "mismatch"
    assert m.live_rate_consistency(live + "\n" + live.splitlines()[0], p) == "unknown"
    assert m.live_rate_consistency(live.replace("/second", "/minute"), p) == "unknown"
    assert m.live_rate_consistency("", p) == "not_checked"


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_live_rate_mismatch_is_visible(lang: str) -> None:
    status = antiddos.Status.from_dict({"installed": True, "enabled": True, "table": True, "live_rate_consistency": "mismatch"})
    assert status.level() == "warn"
    assert status.to_dict()["live_rate_consistency"] == "mismatch"
    html = dscreens.ddos_screen(dscreens.DbgView(lang=lang, ddos=status)).to_html()
    assert dscreens.DbgView(lang=lang).tr()("DDOS_LIVE_RATE_MISMATCH") in html


def test_firewall_diagnostics_detects_live_upstream_objects_without_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    calls = []
    monkeypatch.setattr(m, "binary", lambda flags, name, fallback: "/fake/" + fallback)
    def execute(argv, timeout=60):
        calls.append(argv)
        if argv[1:] == ["list", "tables"]:
            return 0, "table inet rkn_guard\ntable inet obhod_ddos\n", ""
        if argv[-1] == "-S":
            if "ip6tables-legacy" in argv[0]:
                return 1, "", "permission denied"
            if "iptables-nft" in argv[0] and "ip6tables" not in argv[0]:
                return 0, "-P INPUT ACCEPT\n-N SCANNERS-BLOCK\n", ""
            return 0, "-P INPUT ACCEPT\n", ""
        return 0, "test version\n", ""
    monkeypatch.setattr(m, "run", execute)
    result = m.firewall_diagnose({})
    assert result["upstream_nft_table"] == "present"
    assert result["upstream_iptables_nft"] == "present"
    assert result["upstream_ip6tables_nft"] == "absent"
    assert result["upstream_iptables_legacy"] == "absent"
    assert result["upstream_ip6tables_legacy"] == "unknown"
    assert all(a[-1] in ("--version", "status", "--state", "tables", "-S") for a in calls)


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_upstream_object_warning_in_diagnostics(lang: str) -> None:
    view = dscreens.DbgView(lang=lang)
    html = dscreens.ddos_firewall_diag_screen(view, {"upstream_nft_table": "present"}).to_html()
    assert view.tr()("DDOS_FW_UPSTREAM_PRESENT") in html


def test_table_inspection_distinguishes_absence_from_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    monkeypatch.setattr(m, "binary", lambda *args: "/bin/true")
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (1, "", "permission denied"))
    assert m.table_inspection({}, "") == "unknown"
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (0, "table inet obhod_ddos\n", ""))
    assert m.table_inspection({}, "") == "unknown"
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (0, "table ip filter\n", ""))
    assert m.table_inspection({}, "") == "absent"
    assert m.table_inspection({}, "table inet obhod_ddos {}") == "present"


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
@pytest.mark.parametrize("data,key", [
    ({"installed": True, "enabled": False, "table": True, "table_inspection": "present"}, "DDOS_TABLE_UNEXPECTED"),
    ({"installed": False, "enabled": True, "table": True, "table_inspection": "present"}, "DDOS_TABLE_UNMANAGED"),
    ({"installed": True, "enabled": True, "table": False, "table_inspection": "unknown"}, "DDOS_TABLE_UNKNOWN"),
])
def test_table_health_never_hides_unexpected_or_unknown_state(lang: str, data: dict, key: str) -> None:
    view = dscreens.DbgView(lang=lang, ddos=antiddos.Status.from_dict(data))
    assert view.ddos.level() == "warn"
    assert view.tr()(key) in dscreens.ddos_screen(view).to_html()


def test_reconcile_requires_fresh_canonical_enabled_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path)}
    with pytest.raises(m.DDosError):
        m.reconcile_candidate(flags)
    path = Path(m.conf_path(flags))
    path.write_text('{"enabled":true}')
    Path(m.rules_path(flags)).write_text("old")
    with pytest.raises(m.DDosError):
        m.reconcile_candidate(flags)
    policy = m.policy_from({}, {})
    path.write_text(json.dumps(policy))
    fingerprint = m.reconcile_candidate(flags)[1]
    calls = []
    monkeypatch.setattr(m, "apply_rules", lambda f, p, prepared=None: calls.append(p))
    monkeypatch.setattr(m, "status", lambda flags: {})
    with pytest.raises(m.DDosError) as exc:
        m.reconcile({**flags, "expected_sha": "0" * 64})
    assert exc.value.code == "stale_reconcile" and not calls
    m.reconcile({**flags, "expected_sha": fingerprint})
    assert calls == [policy]
    policy["syn_rate"] = 999
    path.write_text(json.dumps(policy))
    with pytest.raises(m.DDosError) as exc:
        m.reconcile({**flags, "expected_sha": fingerprint})
    assert exc.value.code == "stale_reconcile" and len(calls) == 1
    policy["enabled"] = False
    path.write_text(json.dumps(policy))
    with pytest.raises(m.DDosError) as exc:
        m.reconcile({**flags, "expected_sha": fingerprint})
    assert exc.value.code == "bad_policy" and len(calls) == 1


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_reconcile_screen_explicitly_warns_and_callback_is_bounded(lang: str) -> None:
    fingerprint = "a" * 64
    st = antiddos.Status(installed=True, enabled=True, table=True, reconcile_fingerprint=fingerprint)
    view = dscreens.DbgView(lang=lang, ddos=st)
    html = dscreens.ddos_screen(view).to_html()
    assert "dbg:dd:reconcile" in html and html.count("<tg-button type=") <= ui.MAX_BUTTONS
    screen = dscreens.ddos_reconcile_screen(view, st, "a" * 16).to_html()
    assert view.tr()("DDOS_RECONCILE_NOTE") in screen
    callback = "dbg:dd:reconcile_do:" + "a" * 16
    assert callback in screen and len(callback.encode()) <= ui.MAX_CALLBACK


def test_reconcile_confirmation_is_single_use_and_bound_to_message(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace
    from BOT import dbg

    async def exercise() -> None:
        calls = []
        rendered = []
        class Bot:
            state = SimpleNamespace(ddos=antiddos.Policy().to_dict(), language="en", ssh=None)
            control = object()
            emoji_enabled = False
            admin_id = 1
            async def render(self, chat_id, msg_id, rich):
                rendered.append(rich.to_html())
        status = antiddos.Status(installed=True, enabled=True, table=True, reconcile_fingerprint="a" * 64)
        async def call(client, cfg, argv, timeout):
            calls.append(argv)
            return status
        monkeypatch.setattr(dbg.guard, "ddos_call", call)
        panel = dbg.DebugPanel(Bot())
        await panel.ddos_action(1, 10, "reconcile")
        token, fingerprint, _ = panel.ddos_reconcile_confirm[(1, 10)]
        await panel.ddos_action(1, 11, "reconcile_do:" + token)
        assert len(calls) == 1
        await panel.ddos_action(1, 10, "reconcile_do:" + token)
        assert calls[-1] == ["reconcile", "--expected_sha=" + fingerprint]
        assert len(calls) == 2
        await panel.ddos_action(1, 10, "reconcile_do:" + token)
        assert len(calls) == 2
        await panel.ddos_action(1, 10, "reconcile")
        token, fingerprint, expiry = panel.ddos_reconcile_confirm[(1, 10)]
        panel.ddos_reconcile_confirm[(1, 10)] = (token, fingerprint, 0.0)
        await panel.ddos_action(1, 10, "reconcile_do:" + token)
        assert len(calls) == 3
    asyncio.run(exercise())


def test_reconcile_fingerprint_tracks_the_effective_rkn_cache(tmp_path: Path) -> None:
    m = agent()
    flags = {"dir": str(tmp_path)}
    Path(m.conf_path(flags)).write_text(json.dumps(m.policy_from({}, {})))
    Path(m.rules_path(flags)).write_text("saved")
    Path(m.rkn_path(flags)).write_text(json.dumps({"v4": ["5.143.224.0/24"], "v6": []}))
    first = m.reconcile_candidate(flags)[1]
    Path(m.rkn_path(flags)).write_text(json.dumps({"v4": ["37.9.13.0/24"], "v6": []}))
    assert m.reconcile_candidate(flags)[1] != first


def test_reconcile_preview_does_not_offer_a_hash_for_a_different_visible_policy(tmp_path: Path) -> None:
    m = agent()
    flags = {"dir": str(tmp_path)}
    policy = m.policy_from({}, {})
    Path(m.conf_path(flags)).write_text(json.dumps(policy))
    Path(m.rules_path(flags)).write_text("saved")
    assert m.reconcile_fingerprint(flags, policy)
    visible = dict(policy, syn_rate=policy["syn_rate"] + 1)
    assert m.reconcile_fingerprint(flags, visible) == ""


def test_firewall_subprocess_inherits_mutation_lock_but_systemctl_does_not(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace
    m = agent()
    calls = []
    monkeypatch.setattr(m, "COMMAND_LOCK_FD", 123)
    monkeypatch.setattr(m.subprocess, "run", lambda argv, **kw: (calls.append((argv, kw)) or SimpleNamespace(returncode=0, stdout=b"", stderr=b"")))
    for args in (["nft", "-f", "x"], ["nft", "-c", "-f", "x"], ["nft", "delete", "table", "inet", "obhod_ddos"], ["nft", "delete", "element", "inet", "obhod_ddos", "x", "{}"]):
        assert m.run(args)[0] == 0
        assert calls[-1][1]["pass_fds"] == (123,)
    for args in (["systemctl", "enable", "--now", "x"], ["nft", "list", "tables"], ["ss", "-Hntp"]):
        assert m.run(args)[0] == 0
        assert calls[-1][1]["pass_fds"] == ()


@pytest.mark.parametrize("existed", [True, False])
@pytest.mark.parametrize("target_type", ["policy", "rules", "cache"])
def test_post_replace_write_error_restores_previous_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existed: bool, target_type: str) -> None:
    import zlib
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/bin/true"}
    target = Path({"policy": m.conf_path, "rules": m.rules_path, "cache": m.rkn_path}[target_type](flags))
    if existed:
        target.write_text("old contents")
    original = m.write_atomic
    injected = False
    def fail_after_write(path, text, mode=0o644):
        nonlocal injected
        result = original(path, text, mode)
        if str(path) == str(target) and not injected:
            injected = True
            raise m.DDosError("fs", "error after rename", "fs")
        return result
    monkeypatch.setattr(m, "write_atomic", fail_after_write)
    if target_type == "policy":
        operation = lambda: m.commit_policy_change(flags, m.policy_from({}, {}), force=True)
        monkeypatch.setattr(m, "apply_rules", lambda *args, **kwargs: pytest.fail("must not load rules"))
    elif target_type == "rules":
        monkeypatch.setattr(m, "ssh_safety_entries", lambda flags: [])
        monkeypatch.setattr(m, "nft_checkpoint", lambda *args: "")
        monkeypatch.setattr(m, "persist_firewall_backup", lambda *args: str(tmp_path / "backup.nft"))
        monkeypatch.setattr(m, "run", lambda argv, timeout=60: ((0, "", "") if argv[1:2] == ["-c"] else pytest.fail("must not load rules")))
        operation = lambda: m.apply_rules(flags, m.policy_from({}, {}))
    else:
        flags["rkn_zhex"] = zlib.compress(json.dumps({"v4": ["5.143.224.0/24"], "v6": []}).encode()).hex()
        operation = lambda: m.rkn_sync(flags)
    with pytest.raises(m.DDosError) as exc:
        operation()
    assert injected and exc.value.code == "fs"
    assert target.exists() == existed
    if existed:
        assert target.read_text() == "old contents"


def test_post_replace_rules_rollback_failure_is_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/bin/true"}
    target = Path(m.rules_path(flags))
    target.write_text("old")
    original = m.write_atomic
    def fail(path, text, mode=0o644):
        if str(path) == str(target):
            original(path, text, mode)
            raise m.DDosError("fs", "write failed after replace", "fs")
        return original(path, text, mode)
    monkeypatch.setattr(m, "write_atomic", fail)
    monkeypatch.setattr(m, "ssh_safety_entries", lambda flags: [])
    monkeypatch.setattr(m, "nft_checkpoint", lambda *args: "")
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: (0, "", ""))
    with pytest.raises(m.DDosError) as exc:
        m.apply_rules(flags, m.policy_from({}, {}))
    assert exc.value.code == "rollback_failed"


def test_sets_update_restores_saved_file_after_write_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "nft": "/bin/true"}
    target = Path(m.rules_path(flags))
    target.write_text("old")
    original = m.write_atomic
    injected = False
    def fail_once(path, text, mode=0o644):
        nonlocal injected
        result = original(path, text, mode)
        if str(path) == str(target) and not injected:
            injected = True
            raise m.DDosError("fs", "error after rename", "fs")
        return result
    monkeypatch.setattr(m, "write_atomic", fail_once)
    monkeypatch.setattr(m, "nft_checkpoint", lambda *args: "table inet obhod_ddos { set rkn_v4 { } }")
    monkeypatch.setattr(m, "persist_firewall_backup", lambda *args: str(tmp_path / "backup.nft"))
    monkeypatch.setattr(m, "run", lambda argv, timeout=60: ((0, "", "") if argv[1:2] == ["-c"] else pytest.fail("must not load rules")))
    with pytest.raises(m.DDosError) as exc:
        m.update_rkn_sets(flags, m.policy_from({}, {}), ["5.143.224.0/24"], [])
    assert injected and exc.value.code == "fs" and target.read_text() == "old"


def test_disabled_install_post_replace_failure_does_not_touch_systemd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m = agent()
    flags = {"dir": str(tmp_path), "enabled": "0"}
    target = Path(m.conf_path(flags))
    target.write_text('{"enabled":true}\n')
    Path(m.unit_path(flags)).write_text("unit")
    original = m.write_atomic
    injected = False
    def fail_once(path, text, mode=0o644):
        nonlocal injected
        result = original(path, text, mode)
        if str(path) == str(target) and not injected:
            injected = True
            raise m.DDosError("fs", "error after rename", "fs")
        return result
    monkeypatch.setattr(m, "write_atomic", fail_once)
    monkeypatch.setattr(m, "unit_checkpoint", lambda flags: {"saved": True})
    monkeypatch.setattr(m, "disable_unit", lambda flags: pytest.fail("unit not yet changed"))
    monkeypatch.setattr(m, "restore_unit", lambda checkpoint: pytest.fail("unit not yet changed"))
    with pytest.raises(m.DDosError) as exc:
        m.install(flags)
    assert injected and exc.value.code == "fs" and target.read_text() == '{"enabled":true}\n'


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_wal_recovery_preview_and_invalid_warning(lang: str) -> None:
    status = antiddos.Status(installed=True, enabled=True, table=True, transaction_state="manual", transaction_digest="a" * 64)
    view = dscreens.DbgView(lang=lang, ddos=status)
    html = dscreens.ddos_screen(view).to_html()
    assert view.tr()("DDOS_WAL_PENDING") in html and "dbg:dd:wal_recover" in html
    assert html.count("<tg-button type=") <= ui.MAX_BUTTONS
    panel = dscreens.ddos_wal_screen(view, status, "a" * 16).to_html()
    assert view.tr()("DDOS_WAL_CONFIRM_NOTE") in panel and "dbg:dd:wal_do:" in panel
    status.transaction_state = "invalid"
    html = dscreens.ddos_screen(view).to_html()
    assert view.tr()("DDOS_WAL_INVALID") in html and "dbg:dd:wal_recover" not in html


def test_wal_confirmation_is_bound_and_single_use(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace
    from BOT import dbg
    async def exercise() -> None:
        calls = []
        class Bot:
            state = SimpleNamespace(ddos=antiddos.Policy().to_dict(), language="en", ssh=None)
            control = object()
            emoji_enabled = False
            admin_id = 1
            async def render(self, chat_id, msg_id, rich): pass
        current = antiddos.Status(installed=True, enabled=True, table=True, transaction_state="manual", transaction_digest="a" * 64)
        clean = antiddos.Status(installed=True, enabled=True, table=True)
        async def status_call(client, cfg, argv, timeout):
            calls.append(argv)
            return current if len(calls)==1 else clean
        async def command(client, cfg, script, title, argv, timeout):
            calls.append(argv)
            return SimpleNamespace(data={"policy_recovered":True})
        monkeypatch.setattr(dbg.guard, "ddos_call", status_call)
        monkeypatch.setattr(dbg.guard.GuardClient, "_call", command)
        panel = dbg.DebugPanel(Bot())
        await panel.ddos_action(1, 2, "wal_recover")
        token, digest, _ = panel.ddos_wal_confirm[(1,2)]
        await panel.ddos_action(1, 3, "wal_do:"+token)
        assert len(calls)==1
        await panel.ddos_action(1, 2, "wal_do:"+token)
        assert calls[1]==["recover-policy", "--expected_sha="+digest] and calls[2]==["status"]
        await panel.ddos_action(1, 2, "wal_do:"+token)
        assert len(calls)==3
    asyncio.run(exercise())


def test_pending_policy_transaction_is_warning_even_without_installed_rules() -> None:
    for state in ("automatic", "manual", "invalid"):
        status = antiddos.Status(installed=False, transaction_state=state)
        assert status.level() == "warn" and "policy_transaction" in status.reasons()


def test_purge_removes_policy_recovery_journal() -> None:
    script = (ROOT / "Storage" / "obhod_install.sh").read_text()
    purge = script[script.index('say "stopping systemd services"'):]
    assert "/etc/obhod/.policy-transaction.json" in purge


def test_policy_comparison_ignores_source_configuration_and_order_only() -> None:
    first = antiddos.Policy(ports=[22, 443], rkn_allow=["5.143.224.2", "37.9.13.2"])
    second = antiddos.Policy(ports=[443, 22], rkn_allow=["37.9.13.2", "5.143.224.2"], custom_sources=["https://example.org/one"])
    assert not antiddos.firewall_policy_differs(first, second)
    second.syn_rate += 1
    assert antiddos.firewall_policy_differs(first, second)


@pytest.mark.parametrize("kind", ["policy", "pending", "saved", "live", "unknown", "unmanaged"])
def test_startup_never_overwrites_a_suspicious_firewall(kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import copy
    from types import SimpleNamespace
    import BOT.app as app_mod
    from tests.test_round31 import _make_bot
    bot = _make_bot(tmp_path)
    original = copy.deepcopy(bot.state.ddos)
    policy = antiddos.Policy.from_dict(original)
    status = antiddos.Status(installed=True, enabled=policy.enabled, table=True, policy=antiddos.Policy.from_dict(original), table_inspection="present")
    if kind == "policy": status.policy.syn_rate += 1
    if kind == "pending": status.transaction_state = "manual"
    if kind == "saved": status.saved_policy_consistency = "mismatch"
    if kind == "live": status.live_rate_consistency = "mismatch"
    if kind == "unknown": status.table_inspection = "unknown"
    if kind == "unmanaged": status.installed = False
    calls = []
    async def call(_guard, _cfg, argv, _timeout=90.0):
        calls.append(argv)
        if argv[0] != "status": pytest.fail("startup must not mutate suspicious firewall")
        return status
    async def ban_status(_cfg, port=0): return SimpleNamespace(active=True)
    monkeypatch.setattr(app_mod, "public_address", lambda: "")
    monkeypatch.setattr(app_mod, "ddos_call", call)
    monkeypatch.setattr(bot.guard, "status", ban_status)
    outcome = asyncio.run(bot.auto_protect())
    assert outcome["ddos"] == "review" and [item[0] for item in calls] == ["status"]
    assert bot.state.ddos == original and bot.debug.ddos is status


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_tools_warns_when_bot_policy_differs(lang: str) -> None:
    status = antiddos.Status(installed=True, enabled=True, table=True)
    view = dscreens.DbgView(lang=lang, ddos=status, ddos_bot_mismatch=True)
    assert view.tr()("DDOS_BOT_POLICY_MISMATCH") in dscreens.ddos_screen(view).to_html()


def test_rkn_sync_rejects_stale_policy_before_touching_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import zlib
    m = agent()
    flags = {"dir": str(tmp_path)}
    policy = m.policy_from({}, {})
    Path(m.conf_path(flags)).write_text(json.dumps(policy))
    cache = Path(m.rkn_path(flags))
    cache.write_text("old cache")
    encoded = zlib.compress(json.dumps({"v4": ["5.143.224.0/24"], "v6": []}).encode()).hex()
    for digest in ("bad", "0" * 64):
        with pytest.raises(m.DDosError) as exc:
            m.rkn_sync({**flags, "rkn_zhex": encoded, "expected_policy_sha": digest})
        assert exc.value.code == "stale_policy" and cache.read_text() == "old cache"
    monkeypatch.setattr(m, "status", lambda flags: {})
    result = m.rkn_sync({**flags, "rkn_zhex": encoded, "expected_policy_sha": m.policy_digest(policy)})
    assert result["notice"] == "rkn lists synced" and "5.143.224.0/24" in cache.read_text()


@pytest.mark.parametrize("kind", ["missing", "mismatch", "pending", "unknown", "bad_digest", "different"])
def test_systemd_updater_refuses_inconsistent_agent_status_before_network(kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace
    from BOT import rkn_update
    monkeypatch.setenv("OBHOD_STATE_DIR", str(tmp_path))
    (tmp_path / "state.json").write_text(json.dumps({"ddos": antiddos.Policy().to_dict()}))
    data = {"installed": True, "enabled": True, "table": True, "policy": antiddos.Policy().to_dict(), "policy_sha256": "a" * 64}
    if kind == "missing": data["installed"] = False
    if kind == "mismatch": data["saved_policy_consistency"] = "mismatch"
    if kind == "pending": data["policy_transaction"] = {"state": "manual"}
    if kind == "unknown": data["table_inspection"] = "unknown"
    if kind == "bad_digest": data["policy_sha256"] = "bad"
    if kind == "different": data["policy"]["syn_rate"] += 1
    monkeypatch.setattr(rkn_update.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=json.dumps({"ok": True, "data": data}).encode()))
    monkeypatch.setattr(antiddos, "fetch_rkn_subnets", lambda **kwargs: pytest.fail("inconsistent status must not download"))
    assert rkn_update.main() == 2


def test_operation_lock_is_bounded_and_does_not_change_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    import fcntl
    m = agent()
    monkeypatch.setattr(m, "LOCK_TIMEOUT", 0.12)
    lockpath = tmp_path / ".ddos.lock"
    with open(lockpath, "w") as owner:
        fcntl.flock(owner, fcntl.LOCK_EX)
        result = m.main(["ban-add", "--dir=" + str(tmp_path), "--ip=5.143.224.2"])
        response = json.loads(capsys.readouterr().out)
        assert result == 2 and response["code"] == "busy"
        assert not Path(m.conf_path({"dir": str(tmp_path)})).exists()
        assert not Path(m.rules_path({"dir": str(tmp_path)})).exists()
        assert m.COMMAND_LOCK_FD is None
    with open(lockpath, "r") as unlocked:
        m.acquire_operation_lock(unlocked.fileno())
        fcntl.flock(unlocked, fcntl.LOCK_UN)


@pytest.mark.parametrize("lang", list(i18n.LANGUAGES))
def test_adopt_policy_confirmation_has_warning_and_button(lang: str) -> None:
    status = antiddos.Status(installed=True, enabled=True, table=True, policy_sha256="a" * 64)
    view = dscreens.DbgView(lang=lang, ddos=status, ddos_bot_mismatch=True)
    html = dscreens.ddos_screen(view).to_html()
    assert "dbg:dd:adopt_policy" in html and html.count("<tg-button type=") <= ui.MAX_BUTTONS
    html = dscreens.ddos_adopt_screen(view, status, "a" * 16).to_html()
    assert view.tr()("DDOS_ADOPT_NOTE") in html and "dbg:dd:adopt_do:" in html


@pytest.mark.parametrize("stale", ["none", "bot", "agent", "pending", "other_action"])
def test_adopt_policy_checks_both_states_and_preserves_sources(stale: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from tests.test_round31 import _make_bot
    from BOT import dbg
    async def exercise() -> None:
        bot = _make_bot(tmp_path)
        local = antiddos.Policy.from_dict(bot.state.ddos)
        local.custom_sources = ["https://example.org/a"]
        local.disabled_sources = ["https://example.org/a"]
        bot.state.ddos = local.to_dict()
        desired = antiddos.Policy.from_dict(local.to_dict())
        desired.syn_rate = 999
        remote = antiddos.Status(installed=True, enabled=True, table=True, policy=desired, policy_sha256="a" * 64)
        calls = []
        saves = []
        async def render(*args): return None
        async def status(client, cfg, argv, timeout):
            calls.append(list(argv))
            return remote
        monkeypatch.setattr(bot, "render", render)
        monkeypatch.setattr(bot, "save", lambda: saves.append(True))
        monkeypatch.setattr(dbg.guard, "ddos_call", status)
        panel = bot.debug
        panel.ddos = remote
        await panel.ddos_action(7, 1, "adopt_policy")
        token = panel.ddos_adopt_confirm[(7,1)][0]
        if stale == "bot": bot.state.ddos["syn_rate"] += 1
        if stale == "agent": remote.policy_sha256 = "b" * 64
        if stale == "pending": remote.transaction_state = "manual"
        if stale == "other_action": await panel.ddos_action(7, 1, "reconcile")
        await panel.ddos_action(7, 1, "adopt_do:" + token)
        if stale == "none":
            assert bot.state.ddos["syn_rate"] == 999 and saves == [True]
            assert bot.state.ddos["custom_sources"] == ["https://example.org/a"]
            assert bot.state.ddos["disabled_sources"] == ["https://example.org/a"]
            assert all(call == ["status"] for call in calls)
        else:
            assert not saves and bot.state.ddos["syn_rate"] != 999
        await panel.ddos_action(7, 1, "adopt_do:" + token)
        assert len(saves) == (1 if stale == "none" else 0)
    asyncio.run(exercise())
