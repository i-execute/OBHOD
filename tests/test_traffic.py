from __future__ import annotations

import asyncio
import base64
import json
import random
import time
from pathlib import Path
from typing import Any

from BOT import ftscreens, i18n, traffic
from BOT.freeturn import FtClient
from tests.fakes import FakeFtControl, make_bot


def key_for(index: int) -> str:
    body = (index.to_bytes(4, "big") + bytes(28)).ljust(32, b"\0")[:32]
    return base64.b64encode(body).decode("ascii")


def client(index: int) -> FtClient:
    return FtClient(name="phone%d" % index, client_id="%032x" % index, ip="10.13.13.%d" % (index % 250 + 2), pub=key_for(index))


def peers(count: int, seed: int = 7) -> list[dict[str, Any]]:
    random.seed(seed)
    now = int(time.time())
    out = []
    for index in range(count):
        out.append(
            {
                "iface": "freeturn",
                "pub": key_for(index),
                "endpoint": "203.0.113.%d:%d" % (index % 250 + 1, 1024 + index % 60000),
                "allowed": "10.13.13.%d/32" % (index % 250 + 2),
                "hs": now - (index % 5000),
                "rx": random.randint(0, 50_000_000),
                "tx": random.randint(0, 50_000_000),
                "keepalive": 25,
            }
        )
    return out


def test_sizes_are_readable() -> None:
    assert traffic.human(0) == "0 B"
    assert traffic.human(999) == "999 B"
    assert traffic.human(1024) == "1.0 KiB"
    assert traffic.human(1536) == "1.5 KiB"
    assert traffic.human(1024 ** 3) == "1.0 GiB"
    assert traffic.human("bad") == "0 B"
    assert traffic.human(-5) == "0 B"
    assert traffic.speed(2048).endswith("/s")


def test_time_ranges() -> None:
    assert traffic.ago(0) == "0s"
    assert traffic.ago(5) == "5s"
    assert traffic.ago(90) == "1m 30s"
    assert traffic.ago(3700) == "1h 1m"
    assert traffic.ago(90000) == "1d 1h"
    assert traffic.stamp(0) == ""
    assert traffic.stamp(int(time.time()))[:2] == "20"


def test_a_key_must_look_like_wireguard() -> None:
    assert traffic.valid_key(key_for(1))
    for bad in ("", "short", "x" * 44, key_for(1)[:-1], key_for(1) + "!"):
        assert traffic.valid_key(bad) is False


def test_peers_are_parsed_and_filtered() -> None:
    rows = peers(3) + [{"pub": "broken"}, {"pub": ""}]
    loaded = traffic.Traffic().load(rows, ["freeturn", "freeturn", "wg0"])
    assert len(loaded.peers) == 3
    assert loaded.interfaces == ["freeturn", "wg0"]
    assert loaded.checked_at > 0


def test_the_speed_is_a_difference_of_two_samples() -> None:
    gauge = traffic.Traffic()
    first = peers(1)
    gauge.load(first, ["freeturn"])
    gauge.sample("phone0", first[0]["pub"])
    gauge.samples[first[0]["pub"]].at = time.time() - 2.0
    first[0]["rx"] += 2048
    first[0]["tx"] += 1024
    gauge.load(first, ["freeturn"])
    down, up = gauge.sample("phone0", first[0]["pub"])
    assert 900 < down < 1100
    assert 450 < up < 560


def test_the_first_sample_has_no_speed() -> None:
    gauge = traffic.Traffic().load(peers(1), ["freeturn"])
    assert gauge.sample("phone0", key_for(0)) == (0.0, 0.0)


def test_usage_merges_clients_and_history() -> None:
    gauge = traffic.Traffic().load(peers(2), ["freeturn"])
    clients = [client(0), client(1), FtClient(name="silent", pub=key_for(99))]
    rows = gauge.usage(clients, {"silent": {"rx": 4096, "tx": 0, "hs": 12345, "first_at": 12345}})
    by_name = {item.name: item for item in rows}
    assert by_name["phone0"].rx == gauge.peers[key_for(0)].rx
    assert by_name["silent"].rx == 4096
    assert by_name["silent"].hs == 12345
    assert rows == sorted(rows, key=lambda item: (-item.total, item.name))


def test_a_peer_without_a_client_is_listed_too() -> None:
    gauge = traffic.Traffic().load(peers(2), ["freeturn"])
    rows = gauge.usage([client(0)], {})
    assert len(rows) == 2
    assert any(item.name.startswith("peer-") for item in rows)


def test_totals_add_up() -> None:
    gauge = traffic.Traffic().load(peers(4), ["freeturn"])
    rows = gauge.usage([client(index) for index in range(4)], {})
    total = gauge.totals(rows)
    assert total["rx"] == sum(item.rx for item in rows)
    assert total["clients"] == 4
    assert total["peers"] == 4


def test_the_history_is_capped() -> None:
    gauge = traffic.Traffic().load(peers(50), ["freeturn"])
    rows = gauge.usage([client(index) for index in range(50)], {})
    saved = traffic.history_from(rows, limit=10)
    assert len(saved) == 10
    assert all(isinstance(value, dict) for value in saved.values())


def test_two_thousand_peers_are_read_quickly() -> None:
    rows = peers(2040)
    started = time.monotonic()
    gauge = traffic.Traffic().load(rows, ["freeturn"])
    clients = [client(index) for index in range(2040)]
    usage = gauge.usage(clients, {})
    elapsed = time.monotonic() - started
    assert len(gauge.peers) == 2040
    assert len(usage) == 2040
    assert elapsed < 2.0, elapsed
    total = gauge.totals(usage)
    assert total["clients"] == 2040
    assert total["rx"] > 0


def test_the_state_keeps_the_history_of_two_thousand_keys(tmp_path: Path) -> None:
    from BOT.store import State, Store
    from BOT.xray import XrayState

    gauge = traffic.Traffic().load(peers(2040), ["freeturn"])
    rows = gauge.usage([client(index) for index in range(2040)], {})
    state = State(xray=XrayState())
    state.traffic = traffic.history_from(rows)
    path = tmp_path / "state.json"
    started = time.monotonic()
    Store(path).save(state)
    loaded = Store(path).load()
    elapsed = time.monotonic() - started
    assert len(loaded.traffic) == 2040
    assert elapsed < 3.0, elapsed
    assert path.stat().st_size < 1_500_000


def panel_for(tmp_path: Path):
    bot = make_bot(tmp_path)
    control = FakeFtControl()
    control.peers = peers(6)
    bot.freeturn.control = control
    return bot, bot.freeturn, control


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def last(bot: Any) -> str:
    return bot.rendered[-1].to_html()


def test_the_clients_screen_shows_the_traffic(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:clients"))
    assert ["wg-peers", "all"] in control.calls
    html = last(bot)
    assert i18n.t("FT_TRAFFIC_SHORT") in html
    assert traffic.human(panel.usage[0].rx) in html


def test_the_client_menu_shows_the_counters(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:cl:owner"))
    html = last(bot)
    for label in ("FT_TRAFFIC_RX", "FT_TRAFFIC_TX", "FT_TRAFFIC_TOTAL", "FT_TRAFFIC_LAST", "FT_TRAFFIC_SPEED"):
        assert i18n.t(label) in html, label


def test_the_client_menu_refreshes_the_counters_alone(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:cl:owner"))
    control.calls.clear()
    run(panel.route(1, 0, "ft:cl:owner:t"))
    assert control.calls == [["wg-peers", "all"]]


def test_the_traffic_screen_lists_the_totals(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:tr"))
    html = last(bot)
    assert i18n.t("FT_TRAFFIC_ONLINE_COUNT") in html
    assert i18n.t("FT_TRAFFIC_PEER_COUNT") in html


def test_a_missing_wg_does_not_break_the_screen(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)

    async def broken(iface: str = "all", timeout: float = 0) -> Any:
        from BOT.freeturn import FtError

        raise FtError("the wireguard tools are not installed on this server", "wg_missing")

    control.wg_peers = broken
    run(panel.route(1, 0, "ft:clients"))
    html = last(bot)
    assert i18n.t("FT_CODE_WG_MISSING") in html
    assert panel.usage == []


def test_clients_are_paged(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    control.clients = [client(index) for index in range(2040)]
    control.peers = peers(2040)
    run(panel.route(1, 0, "ft:clients:2"))
    assert panel.page == 1
    html = last(bot)
    shown = [item.name for item in panel.view().page_rows()]
    assert len(shown) == 6
    assert shown == [item.name for item in panel.usage[6:12]]
    assert i18n.t("FT_PAGE_OF", page=2, pages=340) in html


def test_the_last_page_is_not_empty(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    control.clients = [client(index) for index in range(2040)]
    control.peers = peers(2040)
    run(panel.route(1, 0, "ft:clients:340"))
    shown = [item.name for item in panel.view().page_rows()]
    assert shown == [item.name for item in panel.usage[2034:2040]]


def test_a_silly_page_number_is_clamped(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    control.clients = [client(index) for index in range(20)]
    run(panel.route(1, 0, "ft:clients:abc"))
    assert panel.page == 0
    run(panel.route(1, 0, "ft:clients:0"))
    assert panel.page == 0


def test_page_math() -> None:
    from BOT.ftpanel import pages_of

    assert pages_of(0) == 1
    assert pages_of(6) == 1
    assert pages_of(7) == 2
    assert pages_of(2040) == 340


def test_the_history_survives_a_restart(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:clients"))
    assert bot.state.traffic
    saved = json.loads((Path(tmp_path) / "state.json").read_text(encoding="utf-8"))
    assert saved["traffic"]
    again = make_bot(tmp_path)
    assert again.state.traffic == bot.state.traffic


def test_every_new_label_exists_in_every_language() -> None:
    keys = [
        "FT_TRAFFIC_TITLE", "FT_TRAFFIC_SUBTITLE", "FT_TRAFFIC_RX", "FT_TRAFFIC_TX", "FT_TRAFFIC_TOTAL",
        "FT_TRAFFIC_SPEED", "FT_TRAFFIC_LAST", "FT_TRAFFIC_SEEN", "FT_TRAFFIC_NEVER", "FT_TRAFFIC_ONLINE",
        "FT_TRAFFIC_ONLINE_COUNT", "FT_TRAFFIC_CLIENT_COUNT", "FT_TRAFFIC_PEER_COUNT", "FT_TRAFFIC_CHECKED",
        "FT_TRAFFIC_EMPTY", "FT_PAGE_PREV", "FT_PAGE_NEXT", "FT_PAGE_OF", "FT_BTN_TRAFFIC",
        "FT_BTN_REFRESH_TRAFFIC", "FT_BUSY_TRAFFIC", "FT_CONFIRM_REMOVE_TITLE", "FT_CONFIRM_REMOVE_BODY",
    ]
    for lang in i18n.LANGUAGES:
        for key in keys:
            assert i18n.t(key, lang).strip(), (lang, key)


def test_the_traffic_screen_renders_in_every_language() -> None:
    from BOT.ui import count_buttons

    view = ftscreens.FtView(
        clients=[client(0), client(1)],
        usage=[traffic.Usage(name="phone0", rx=2048, tx=1024, hs=int(time.time())), traffic.Usage(name="phone1", rx=10, tx=20)],
        totals={"rx": 2058, "tx": 1044, "online": 1, "clients": 2, "peers": 2, "down": 100.0, "up": 50.0, "checked_at": time.time()},
        page=0,
        pages=3,
    )
    for lang in i18n.LANGUAGES:
        view.lang = lang
        for screen in (ftscreens.traffic_screen(view), ftscreens.clients_screen(view), ftscreens.client_screen(view, "phone0")):
            html = screen.to_html()
            assert html
            assert count_buttons(html) <= 18


def test_the_daily_counter_starts_today() -> None:
    gauge = traffic.Traffic().load(peers(2, seed=21), ["freeturn"])
    rows = gauge.usage([client(0), client(1)], {})
    assert all(item.day_total == 0 for item in rows), rows


def test_the_daily_counter_grows_after_a_new_sample() -> None:
    gauge = traffic.Traffic().load(peers(2, seed=22), ["freeturn"])
    first = gauge.usage([client(0), client(1)], {})
    saved = traffic.history_from(first)
    bigger = peers(2, seed=22)
    for row in bigger:
        row["rx"] = int(row["rx"]) + 4096
        row["tx"] = int(row["tx"]) + 1024
    gauge.load(bigger, ["freeturn"])
    second = gauge.usage([client(0), client(1)], saved)
    for row in second:
        assert row.day_rx == 4096, row
        assert row.day_tx == 1024, row
        assert row.day_total == 5120


def test_the_daily_counter_rolls_over_at_a_new_day() -> None:
    gauge = traffic.Traffic().load(peers(1, seed=23), ["freeturn"])
    first = gauge.usage([client(0)], {})
    saved = traffic.history_from(first)
    name = first[0].name
    saved[name]["day_at"] = time.time() - 3 * 86400
    grown = peers(1, seed=23)
    grown[0]["rx"] = int(grown[0]["rx"]) + 10 ** 6
    gauge.load(grown, ["freeturn"])
    second = gauge.usage([client(0)], saved)
    assert second[0].day_total == 0
    assert second[0].rx > 10 ** 6


def test_the_daily_counter_survives_an_interface_restart() -> None:
    gauge = traffic.Traffic().load(peers(1, seed=24), ["freeturn"])
    first = gauge.usage([client(0)], {})
    saved = traffic.history_from(first)
    reset = peers(1, seed=24)
    reset[0]["rx"] = 0
    reset[0]["tx"] = 0
    gauge.load(reset, ["freeturn"])
    second = gauge.usage([client(0)], saved)
    assert second[0].day_total == 0
    assert second[0].rx == first[0].rx


def test_the_daily_baseline_round_trips_through_the_state() -> None:
    gauge = traffic.Traffic().load(peers(3, seed=25), ["freeturn"])
    rows = gauge.usage([client(index) for index in range(3)], {})
    saved = traffic.history_from(rows)
    again = traffic.Traffic().load(peers(3, seed=25), ["freeturn"]).usage([client(index) for index in range(3)], saved)
    for before, after in zip(rows, again):
        assert (before.rx0, before.tx0) == (after.rx0, after.tx0)


def test_the_daily_totals_are_summed_for_the_traffic_screen() -> None:
    gauge = traffic.Traffic().load(peers(4, seed=26), ["freeturn"])
    rows = gauge.usage([client(index) for index in range(4)], {})
    total = gauge.totals(rows)
    assert total["day_rx"] == sum(item.day_rx for item in rows)
    assert total["day_tx"] == sum(item.day_tx for item in rows)


def test_the_daily_labels_exist_in_every_language() -> None:
    for language in i18n.LANGUAGES:
        for key in ("FT_TRAFFIC_DAY", "FT_TRAFFIC_DAY_TOTAL"):
            assert i18n.raw(key, language)


def test_a_hostile_client_name_never_reaches_the_buttons(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    control.clients = [FtClient(name="x:yes", client_id="%032x" % 7, ip="10.13.13.7"), client(0)]
    run(panel.route(1, 0, "ft:clients"))
    assert [item.name for item in panel.clients] == ["phone0"]
    assert "x:yes" not in last(bot)


def test_a_hostile_name_cannot_skip_the_removal_confirm(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    control.clients = [client(0)]
    run(panel.route(1, 0, "ft:rm:x:yes"))
    assert ["client-remove", "--name=x"] not in control.calls
    assert control.calls == []


def test_a_silly_name_is_refused_by_the_removal_route(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    for silly in ("", "..", "a" * 40, "phone 1", "phone0;rm"):
        control.calls.clear()
        run(panel.route(1, 0, "ft:rm:%s:yes" % silly))
        assert control.calls == [], silly
    assert i18n.t("FT_ERR_BAD_NAME") in last(bot)


def test_the_removal_still_asks_first(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    control.clients = [client(0)]
    control.calls.clear()
    run(panel.route(1, 0, "ft:rm:phone0"))
    assert control.calls == []
    assert i18n.t("FT_CONFIRM_REMOVE_TITLE", name="phone0") in last(bot)


def test_the_daily_row_is_on_the_client_screen(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:cl:owner"))
    assert i18n.t("FT_TRAFFIC_DAY") in last(bot)


def test_the_daily_total_is_on_the_traffic_screen(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    run(panel.route(1, 0, "ft:tr"))
    assert i18n.t("FT_TRAFFIC_DAY_TOTAL") in last(bot)


def test_a_fabricated_confirm_does_not_remove_anything(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    control.clients = [client(0)]
    control.calls.clear()
    run(panel.route(1, 0, "ft:rm:phone0:yes"))
    assert control.calls == []
    assert panel.pending == ""


def test_the_confirm_is_spent_once(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    control.clients = [client(0)]
    run(panel.route(1, 0, "ft:rm:phone0"))
    run(panel.route(1, 0, "ft:rm:phone0:yes"))
    assert [call for call in control.calls if call[0] == "client-remove"] == [["client-remove", "phone0"]]
    control.calls.clear()
    run(panel.route(1, 0, "ft:rm:phone0:yes"))
    assert [call for call in control.calls if call[0] == "client-remove"] == []


def test_a_confirm_for_one_client_never_removes_another(tmp_path: Path) -> None:
    bot, panel, control = panel_for(tmp_path)
    control.clients = [client(0), client(1)]
    run(panel.route(1, 0, "ft:rm:phone0"))
    run(panel.route(1, 0, "ft:rm:phone1:yes"))
    assert [call for call in control.calls if call[0] == "client-remove"] == []
