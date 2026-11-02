import asyncio
import json
import sys
import time

sys.path.insert(0, "/home/user/obhod-src")
sys.path.insert(0, "/home/user/audit")

from BOT import ui
from tests.fakes import FakeFtControl, make_bot
from tests.test_traffic import client, peers
from live import CHAT, call, entities

ADMIN = 7610246474


def send(rich, label):
    html = rich.to_html()
    answer = call("sendRichMessage", {"chat_id": CHAT, "rich_message": json.dumps({"html": html})})
    ok = answer.get("ok")
    seen = len(entities(answer.get("result", {}).get("rich_message") or {})) if ok else 0
    print("%-28s =%s =%d/%d msg=%s" % (label, ok, seen, html.count("<tg-emoji"), answer.get("result", {}).get("message_id")), flush=True)
    return ok


async def build(panel, route, label):
    await panel.route(ADMIN, 5, route)
    return label


def main():
    ui.use_icons(True)
    bot = make_bot("/tmp/live-traffic")
    bot.cfg.admin_id = ADMIN
    bot.state.admin_id = ADMIN
    bot.state.emoji = True
    bot.expensive_limit = 10 ** 6
    ui.use_icons(True)
    control = FakeFtControl()
    control.peers = peers(6, seed=11)
    control.clients = [client(index) for index in range(6)] + [
        __import__("BOT.freeturn", fromlist=["FtClient"]).FtClient(name="owner", client_id="0" * 32, owner=True, pub=peers(1, seed=99)[0]["pub"])
    ]
    bot.freeturn.control = control
    items = []

    async def render(chat_id, msg_id, rich):
        items.append(rich)

    async def send_rich(chat_id, rich):
        items.append(rich)

    bot.render = render
    bot.send = send_rich
    ui.use_icons(True)

    for route, label in (("ft:clients", "   "), ("ft:tr", " "), ("ft:cl:owner", " "), ("ft:rm:phone3", " ")):
        items.clear()
        asyncio.run(bot.freeturn.route(ADMIN, 5, route))
        if items:
            send(items[-1], label)
        time.sleep(0.6)

    items.clear()
    control.clients = [client(index) for index in range(2040)]
    control.peers = peers(2040, seed=5)
    started = time.monotonic()
    asyncio.run(bot.freeturn.route(ADMIN, 5, "ft:clients:1"))
    spent = time.monotonic() - started
    total = bot.freeturn.traffic.totals(bot.freeturn.usage)
    if items:
        send(items[-1], "2040 , . 1")
    print("2040 :    %.2f ,  %d,  %d" % (spent, total.get("peers", 0), total.get("clients", 0)), flush=True)

    items.clear()
    asyncio.run(bot.freeturn.route(ADMIN, 5, "ft:clients:170"))
    send(items[-1], "2040 , . 170")
    ui.use_icons(False)


main()
