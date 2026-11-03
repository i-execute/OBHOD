from __future__ import annotations

import json
from pathlib import Path

import pytest

from BOT import antiddos, notify
from BOT.store import State


def status(**fields) -> antiddos.Status:
    return antiddos.Status.from_dict(fields)


def test_the_table_is_syntactically_shaped() -> None:
    body = antiddos.nft_table(antiddos.Policy())
    assert body.startswith("table inet obhod_ddos {")
    assert body.rstrip().endswith("}")
    assert body.count("{") == body.count("}")
    for name in (antiddos.SET_SYN, antiddos.SET_CONN, antiddos.SET_UDP, antiddos.SET_SCAN):
        assert "set %s {" % name in body
    assert "hook input priority raw" in body


def test_every_counter_rule_is_counted() -> None:
    body = antiddos.nft_table(antiddos.Policy())
    assert body.count("counter") >= 8
    assert "ip saddr @" + antiddos.SET_SYN + " counter drop" in body


def test_the_policy_never_lets_a_bad_number_through() -> None:
    policy = antiddos.Policy.from_dict(
        {"syn_rate": -5, "syn_burst": 0, "conn_rate": "lots", "set_size": 10, "ban_timeout": 10 ** 12, "ports": "22,443"}
    )
    assert policy.syn_rate >= 1
    assert policy.syn_burst >= 1
    assert policy.conn_rate >= 1
    assert policy.set_size >= 1024
    assert policy.ban_timeout <= 86400


def test_the_rate_cannot_be_used_to_open_a_hole() -> None:
    policy = antiddos.Policy.from_dict({"syn_rate": 10 ** 9})
    body = antiddos.nft_table(policy)
    assert "limit rate over 100000/second" in body
    assert "1000000000" not in body


def test_injected_ports_are_dropped() -> None:
    policy = antiddos.Policy.from_dict({"ports": "22; rm -rf /,443,abc,-1,70000"})
    assert policy.ports == [22, 443]
    body = antiddos.nft_table(policy)
    assert "rm -rf" not in body
    assert "abc" not in body


def test_ports_are_capped() -> None:
    policy = antiddos.Policy.from_dict({"ports": ",".join(str(item) for item in range(1000, 1200))})
    assert len(policy.ports) == antiddos.MAX_PORTS


def test_a_newline_in_the_port_field_breaks_nothing() -> None:
    policy = antiddos.Policy.from_dict({"ports": "22\n}\ntable inet evil {"})
    assert policy.ports == [22]
    assert "evil" not in antiddos.nft_table(policy)


def test_the_sysctl_file_is_sane() -> None:
    text = antiddos.sysctl_text(antiddos.Policy())
    assert "net.ipv4.tcp_syncookies = 1" in text
    assert "net.ipv4.tcp_max_syn_backlog = 8192" in text
    assert "net.core.somaxconn = 4096" in text
    assert all(" = " in line for line in text.strip().splitlines())


def test_the_policy_survives_a_state_round_trip(tmp_path: Path) -> None:
    from BOT.store import Store

    state = State()
    state.ddos = antiddos.Policy.from_dict({"syn_rate": 99, "ports": [22, 8443]}).to_dict()
    path = tmp_path / "state.json"
    Store(path).save(state)
    loaded = Store(path).load()
    assert loaded.ddos["syn_rate"] == 99
    assert loaded.ddos["ports"] == [22, 8443]


def test_a_broken_state_value_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"ddos": {"syn_rate": "x", "ports": None}}), encoding="utf-8")
    from BOT.store import Store

    policy = antiddos.Policy.from_dict(Store(path).load().ddos)
    assert policy.syn_rate == antiddos.SYN_RATE


def test_a_calm_box_is_ok() -> None:
    assert status(pps=100, conntrack=10, conntrack_max=1000, table=True).level() == "ok"


def test_a_missing_table_is_bad() -> None:
    assert status(enabled=True, table=False).level() == "bad"
    assert "table_missing" in status(enabled=True, table=False).reasons()


def test_a_disabled_box_is_not_bad() -> None:
    assert status(enabled=False, table=False).level() == "ok"


def test_the_syn_set_decides_the_level() -> None:
    small = status(table=True, syn_flood=["1.1.1.%d" % item for item in range(1, 10)])
    big = status(table=True, syn_flood=["1.1.1.%d" % item for item in range(1, 200)])
    assert small.level() == "warn"
    assert big.level() == "bad"
    assert big.under_attack() is True


def test_a_packet_spike_is_an_attack() -> None:
    assert status(table=True, pps=antiddos.PPS_BAD + 1).level() == "bad"
    assert status(table=True, pps=antiddos.PPS_WARN + 1).level() == "warn"


def test_a_full_tracking_table_is_an_attack() -> None:
    hot = status(table=True, conntrack=95, conntrack_max=100)
    assert hot.level() == "bad"
    assert hot.pressure() > 0.9
    assert status(table=True, conntrack=10, conntrack_max=0).pressure() == 0.0


def test_the_event_kind_names_the_cause() -> None:
    assert status(table=True, pps=antiddos.PPS_BAD + 1).event_kind() == "pps"
    assert status(table=True, conntrack=99, conntrack_max=100).event_kind() == "conntrack"
    assert status(enabled=True, table=False).event_kind() == "table_missing"


def test_the_headline_is_readable() -> None:
    head = status(table=True, pps=1234, conntrack=5, conntrack_max=10, syn_flood=["1.1.1.1"]).headline()
    assert "1234 pps" in head
    assert "conntrack 5/10" in head


def test_hostile_agent_output_is_ignored() -> None:
    hostile = {
        "pps": "9" * 40,
        "counters": {"DROP TABLES": 1, "syn_drop": 4, "x": "y"},
        "syn_flood": ["1.1.1.1", "<script>", "999.1.1.1", 42],
        "kernel": "6.1" + "x" * 300,
        "notice": "y" * 500,
    }
    status_value = status(**hostile)
    assert status_value.pps == 1 << 40
    assert status_value.counters == {"syn_drop": 4}
    assert status_value.syn_flood == ["1.1.1.1"]
    assert len(status_value.kernel) <= 32
    assert len(status_value.notice) <= 120


def test_a_hostile_payload_cannot_forge_a_level() -> None:
    assert status(**{"pps": {"$gt": 1}}).level() in antiddos.LEVELS
    assert status(**{"syn_flood": {"a": 1}}).syn_flood == []


def test_offenders_keep_the_order_and_the_limit() -> None:
    value = status(table=True, syn_flood=["1.1.1.1", "2.2.2.2"], scan=["2.2.2.2", "3.3.3.3"])
    assert value.offenders() == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    many = status(table=True, syn_flood=["10.0.0.%d" % item for item in range(1, 250)])
    assert len(many.offenders()) == 16


def test_dropped_adds_every_drop_counter() -> None:
    value = status(table=True, counters={"syn_drop": 10, "udp_drop": 5, "accepted": 99})
    assert value.dropped() == 15


def test_a_clean_box_has_no_findings() -> None:
    rows = [{"port": 443, "proto": "tcp", "process": "xray", "address": "0.0.0.0"}]
    assert antiddos.exposure(rows) == []
    assert antiddos.exposure_level([]) == "ok"


def test_a_panel_is_a_bad_finding() -> None:
    rows = [{"port": 54321, "proto": "tcp", "process": "x-ui", "address": "0.0.0.0"}]
    found = antiddos.exposure(rows)
    assert found and found[0].code == "panel"
    assert found[0].severity == "bad"


def test_an_open_core_api_is_a_bad_finding() -> None:
    rows = [{"port": 10085, "proto": "tcp", "process": "xray", "address": "0.0.0.0"}]
    assert antiddos.exposure(rows)[0].code == "core_api"


def test_a_local_api_is_still_reported() -> None:
    rows = [{"port": 10085, "proto": "tcp", "process": "xray", "address": "127.0.0.1"}]
    assert antiddos.exposure(rows)[0].code == "core_api"


def test_databases_and_proxies_are_separated() -> None:
    rows = [
        {"port": 6379, "proto": "tcp", "process": "redis-server", "address": "0.0.0.0"},
        {"port": 1080, "proto": "tcp", "process": "3proxy", "address": "0.0.0.0"},
    ]
    codes = [item.code for item in antiddos.exposure(rows)]
    assert codes == ["datastore", "proxy"]


def test_allowed_ports_are_skipped() -> None:
    rows = [{"port": 2222, "proto": "tcp", "process": "python3", "address": "0.0.0.0"}]
    assert antiddos.exposure(rows) != []
    assert antiddos.exposure(rows, allow=[2222]) == []


def test_an_allowed_decoy_stays_quiet() -> None:
    rows = [{"port": 21, "proto": "tcp", "process": "python3", "address": "0.0.0.0"}]
    assert [item.code for item in antiddos.exposure(rows)] == ["risky"]
    assert antiddos.exposure(rows, allow=[21]) == []


def test_an_allowed_port_cannot_hide_a_panel() -> None:
    rows = [{"port": 54321, "proto": "tcp", "process": "x-ui", "address": "0.0.0.0"}]
    assert antiddos.exposure(rows, allow=[54321])[0].code == "panel"


def test_exposure_hint_names_the_worst_thing_first() -> None:
    rows = [
        {"port": 8080, "proto": "tcp", "process": "", "address": "0.0.0.0"},
        {"port": 10085, "proto": "tcp", "process": "xray", "address": "0.0.0.0"},
    ]
    found = antiddos.exposure(rows)
    assert antiddos.exposure_hint(found) == "core_api"
    assert antiddos.exposure_level(found) == "bad"


def test_rows_are_capped_and_cleaned() -> None:
    rows = [{"port": str(item), "proto": "TCP", "process": "p" * 200, "address": "a" * 200} for item in range(1, 900)]
    found = antiddos.exposure(rows)
    assert len(found) <= 64
    assert all(len(item.process) <= 40 for item in found)


def test_bad_rows_do_not_crash_the_parser() -> None:
    rows = [None, 5, "x", {"port": "zero"}, {"port": -1}, {"port": 70000}, {"port": 22.5}]
    assert antiddos.exposure(rows) == []


def test_proc_listening_parsing() -> None:
    body = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n"
        "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1\n"
        "   2: 0100007F:1F90 0100007F:9999 01 00000000:00000000 00:00000000 00000000     0        0 333 1\n"
    )
    rows = antiddos.listening_from_proc(body, "", {12345: "xray"})
    assert {row["port"] for row in rows} == {443, 8080}
    assert rows[0]["process"] == "xray"
    assert rows[1]["address"] == "127.0.0.1"


def test_proc_listening_survives_garbage() -> None:
    assert antiddos.listening_from_proc("nonsense\n\x00\x01", "") == []
    assert antiddos.listening_from_proc("", "") == []


def test_the_ddos_kind_is_switchable_and_delivered() -> None:
    assert notify.KIND_DDOS in notify.KINDS
    assert notify.DEFAULT_ON[notify.KIND_DDOS] is True
    centre = notify.Centre()
    raised = centre.force(notify.KIND_DDOS, "203.0.113.9", "120000 pps", now=100.0)
    assert len(raised) == 1 and raised[0].kind == notify.KIND_DDOS
    assert centre.toggle(notify.KIND_DDOS) is False
    assert centre.force(notify.KIND_DDOS, "203.0.113.9", "again", now=2000.0) == []
    assert centre.toggle(notify.KIND_DDOS) is True


def test_the_ddos_notification_goes_to_the_owner_only() -> None:
    class FakeBot:
        admin_id = 42

        class State:
            admin_id = 42

        state = State()

    assert notify.delivery_target(FakeBot()) == 42

    class Stranger(FakeBot):
        class State:
            admin_id = 43

        state = State()

    assert notify.delivery_target(Stranger()) == 0


def test_the_agent_source_has_no_shell() -> None:
    root = Path(__file__).resolve().parents[1]
    body = (root / "Storage" / "remote" / "ddos_agent.py").read_text(encoding="utf-8")
    for banned in ("shell=True", "os.system", "os.popen", "eval(", "exec(", "Popen("):
        assert banned not in body, banned
    assert body.lstrip("\n").startswith("import ")


def test_every_ddos_string_exists_in_every_language() -> None:
    from BOT import i18n

    for language in i18n.LANGUAGES:
        for key in (
            "DDOS_TITLE",
            "DDOS_SUBTITLE",
            "DDOS_BTN_OPEN",
            "DDOS_BTN_INSTALL",
            "DDOS_BTN_REMOVE",
            "DDOS_BTN_REFRESH",
            "DDOS_BTN_PROBE",
            "DDOS_EMPTY",
            "DDOS_HINT",
            "DDOS_EXPOSURE",
            "DDOS_EXPOSURE_EMPTY",
            "DDOS_EXPOSURE_PANEL",
            "DDOS_EXPOSURE_CORE_API",
            "DDOS_EXPOSURE_DATASTORE",
            "DDOS_EXPOSURE_RISKY",
            "DDOS_EXPOSURE_PROXY",
            "DDOS_EXPOSURE_UNEXPECTED",
            "DDOS_EXPOSURE_NOTE",
            "NTF_KIND_DDOS",
            "NTF_HINT_DDOS",
            "NTF_MSG_DDOS",
        ):
            assert i18n.has_key(key, language), (key, language)


@pytest.mark.parametrize("language", ["en", "ru", "zh"])
def test_the_screen_renders_in_every_language(language: str) -> None:
    from BOT import dscreens

    assert i18n_ok(language)
    view = dscreens.DbgView(lang=language, ddos=status(table=True, pps=10))
    html = dscreens.ddos_screen(view).build()
    assert "<h2>" in html
    assert "{" not in html


def i18n_ok(language: str) -> bool:
    from BOT import i18n

    return language in i18n.LANGUAGES
