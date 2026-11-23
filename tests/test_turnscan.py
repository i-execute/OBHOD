from __future__ import annotations

from pathlib import Path

from BOT import antiddos, turnscan

ROOT = Path(__file__).resolve().parents[1]


def test_scan_results_update_allow_entries_and_filter_modat() -> None:
    state = turnscan.State()
    entries = state.record(
        ["8.8.8.8", "85.217.140.2"],
        ["relay.example.org"],
        now=100,
        randbelow=lambda width: 0,
        resolver=lambda host: ["1.1.1.1"] if host == "relay.example.org" else [],
    )
    assert entries == ["8.8.8.8", "1.1.1.1"]
    policy = antiddos.Policy(turn_allow=entries, freeturn_ports=[56123]).normalise()
    table = antiddos.nft_table(policy, rkn_v4=[], rkn_v6=[])
    assert "8.8.8.8" in table
    assert "1.1.1.1" in table
    assert "85.217.140.0/24" not in table
    assert state.next_scan_at == 100 + turnscan.MIN_INTERVAL


def test_scan_interval_is_bounded_and_changes_per_cycle() -> None:
    width = turnscan.MAX_INTERVAL - turnscan.MIN_INTERVAL + 1
    assert turnscan.interval(lambda size: 0) == turnscan.MIN_INTERVAL
    assert turnscan.interval(lambda size: size - 1) == turnscan.MAX_INTERVAL
    offsets = iter((1, 2))
    values = [turnscan.interval(lambda size: next(offsets)) for _ in range(2)]
    assert values[0] != values[1]
    assert all(turnscan.MIN_INTERVAL <= value <= turnscan.MAX_INTERVAL for value in values)
    assert width > 1


def test_no_legacy_fixed_vk_literals_remain_in_authored_tree() -> None:
    obsolete_values = (str(56000 + 583), ".".join(("193", "203", "43", "0")) + "/24")
    excluded = {".git", "__pycache__", ".pytest_cache"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in excluded for part in path.parts):
            continue
        body = path.read_bytes()
        for value in obsolete_values:
            assert value.encode("ascii") not in body, str(path.relative_to(ROOT))
