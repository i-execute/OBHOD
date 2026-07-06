import os
import sys
import json
import asyncio
import logging
from telethon import TelegramClient, events

from installer import installer
from strings import Strings

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "obhod.log")),
    ]
)

logger = logging.getLogger(__name__)

API_ID = int(os.environ.get("API_ID", 0))
API_HASH = os.environ.get("API_HASH", "")
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
OWNER_ID = int(os.environ.get("OWNER_ID", 0))

DATA_FILE = os.path.join(os.path.dirname(__file__), "OBHOD.json")
PREFIX = "."

s = Strings()


class DataManager:
    """Хранит список админов бота (владелец всегда привилегирован).
    Реестр самих VK TURN peer'ов лежит отдельно в /etc/wireguard/peers.json —
    его читает/пишет модуль VKTurn.py напрямую."""

    def __init__(self, owner_id):
        self.owner_id = owner_id
        self.data = self.load_data()

    def load_data(self):
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        return {"admins": []}

    def save_data(self):
        with open(DATA_FILE, "w") as f:
            json.dump(self.data, f, indent=2)

    def get_admins(self):
        return self.data.get("admins", [])

    def add_admin(self, user_id):
        if user_id not in self.data["admins"]:
            self.data["admins"].append(user_id)
            self.save_data()
            return True
        return False

    def remove_admin(self, user_id):
        if user_id in self.data["admins"]:
            self.data["admins"].remove(user_id)
            self.save_data()
            return True
        return False

    def is_privileged(self, user_id):
        return user_id == self.owner_id or user_id in self.get_admins()

    async def notify_admins(self, bot, message):
        for user_id in [self.owner_id] + self.get_admins():
            try:
                await bot.send_message(user_id, message, parse_mode="html")
            except Exception:
                pass


async def main():
    if not all([API_ID, API_HASH, BOT_TOKEN, OWNER_ID]):
        logger.error("Missing required environment variables")
        logger.error("Required: API_ID, API_HASH, BOT_TOKEN, OWNER_ID")
        sys.exit(1)

    bot = TelegramClient("OBHOD", API_ID, API_HASH)
    await bot.start(bot_token=BOT_TOKEN)

    me = await bot.get_me()
    logger.info(f"Bot started: {me.first_name} (@{me.username})")

    data_manager = DataManager(OWNER_ID)

    installer.set_context(bot, data_manager)
    logger.info("Loading modules...")
    await installer.load_all()
    logger.info(f"Loaded modules: {installer.get_loaded()}")

    @bot.on(events.NewMessage(pattern=r"^/start$"))
    async def start_handler(event):
        if not data_manager.is_privileged(event.sender_id):
            await event.reply(s.not_owner.format(line=s.line))
            return
        await event.reply(s.greeting_owner.format(line=s.line), parse_mode="html")

    @bot.on(events.NewMessage(pattern=rf"^\{PREFIX}(\w+)(?:\s+(.*))?$"))
    async def command_handler(event):
        if not data_manager.is_privileged(event.sender_id):
            return  # тихо игнорируем чужих, без утечки списка команд

        cmd_name = event.pattern_match.group(1)
        args = event.pattern_match.group(2) or ""

        commands = installer.get_commands()
        handler = commands.get(cmd_name)
        if not handler:
            return

        try:
            await handler(event, args)
        except Exception as e:
            logger.error(f"Command .{cmd_name} failed: {e}")
            await event.reply(s.error.format(line=s.line, error=str(e)), parse_mode="html")

    logger.info("Bot is ready")

    try:
        await bot.run_until_disconnected()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await bot.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bot stopped")
