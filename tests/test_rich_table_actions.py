from __future__ import annotations

import re

from BOT import antiddos, dscreens, ftscreens, i18n, ui, xscreens
from BOT.freeturn import FtClient, FtState
from BOT.xray import XrayState, new_inbound


def _first_table(html: str) -> str:
    match = re.search(r"<table\b[^>]*>.*?</table>", html, re.S)
    assert match is not None
    return match.group(0)


def test_table_accepts_only_structured_text_buttons_in_cells() -> None:
    action = ui.button_cell(ui.button("Ban", "dbg:dd:rb:0:203.0.113.7", style="danger"))
    html = ui.table(
        [("stop", "203.0.113.7", "flood", action)],
        ("IP", "Reason", "Action"),
    )
    assert html.count("<th") == 3
    assert '<tg-button type="callback_data" style="danger" data="dbg:dd:rb:0:203.0.113.7">Ban</tg-button>' in html
    assert re.search(r"<td[^>]*><tg-button[^>]*>Ban</tg-button></td>", html)

    hostile = '</td><tg-button type="callback_data" data="bad">bad</tg-button><td>'
    escaped = ui.table([("field", hostile)], ("Field", "Value"))
    assert 'data="bad"' not in escaped
    assert "&lt;/td&gt;" in escaped


def test_destructive_callback_buttons_default_to_danger_style() -> None:
    destructive = (
        "dbg:dd:rb:0:203.0.113.7",
        "fb:remove",
        "sshd:remove",
        "ft:stop",
        "ft:un",
        "ft:rm:owner",
        "xr:instop:1",
        "xr:del:1",
        "xr:core:purge",
        "xr:cf:down",
        "vk:auth:clear",
        "vk:finish:call-1",
    )
    for callback in destructive:
        assert 'style="danger"' in ui.button("Destructive", callback).html(), callback
    assert 'style="danger"' not in ui.button("Unban", "dbg:dd:ub:0:203.0.113.7").html()
    assert 'style="danger"' not in ui.button("Open", "xr:in:1").html()


def test_ddos_ip_table_contains_text_actions_and_danger_reban() -> None:
    status = antiddos.Status(
        installed=True,
        enabled=True,
        table=True,
        policy=antiddos.Policy(
            manual_bans=["203.0.113.7"],
            unbanned=["198.51.100.77"],
            rkn_allow=["198.51.100.77"],
        ),
    )
    html = dscreens.ddos_ips_screen(dscreens.DbgView(lang="en", ddos=status)).to_html()
    table_html = _first_table(html)
    assert i18n.t("DDOS_COL_ACTION", "en") in table_html
    assert 'data="dbg:dd:ub:0:203.0.113.7"' in table_html
    assert 'data="dbg:dd:rb:0:198.51.100.77"' in table_html
    assert re.search(r'<tg-button[^>]*style="danger"[^>]*data="dbg:dd:rb:0:198\.51\.100\.77"', table_html)
    assert 'data="dbg:dd:ipscan:0:203.0.113.7"' in table_html
    assert ui.count_buttons(html) <= ui.MAX_BUTTONS


def test_navigation_tables_use_text_open_buttons_without_duplicate_footer_rows() -> None:
    xstate = XrayState()
    inbound = new_inbound("vless", 443, "raw", "reality")
    xstate.add(inbound)
    xhtml = xscreens.inbounds_list_screen(xscreens.XrayView(state=xstate, lang="en")).to_html()
    xtable = _first_table(xhtml)
    assert i18n.t("UI_ACTION", "en") in xtable
    assert f'data="xr:in:{inbound.id}"' in xtable
    assert f'data="xr:in:{inbound.id}"' not in xhtml.split("</table>", 1)[1]

    ftview = ftscreens.FtView(
        state=FtState(installed=True),
        clients=[FtClient(name="alice")],
        lang="en",
    )
    fhtml = ftscreens.clients_screen(ftview).to_html()
    ftable = _first_table(fhtml)
    assert i18n.t("UI_ACTION", "en") in ftable
    assert 'data="ft:cl:alice"' in ftable
    assert 'data="ft:cl:alice"' not in fhtml.split("</table>", 1)[1]
