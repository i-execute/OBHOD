import os
import re
import sys
import json
import asyncio
import logging

import aiohttp

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "obhod.log")),
    ],
)

logger = logging.getLogger(__name__)

BOT_DIR = os.path.dirname(__file__)
ENV_FILE = os.path.join(os.path.dirname(BOT_DIR), ".env")

API_ID_RE = re.compile(r"^\d{8}$")
API_HASH_RE = re.compile(r"^[a-f0-9]{32}$")


def read_env() -> dict:
    env = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def write_env(updates: dict):
    env = read_env()
    env.update(updates)
    with open(ENV_FILE, "w") as f:
        for k, v in env.items():
            f.write(f"{k}={v}\n")


class BotAPI:
    def __init__(self, token):
        self.token = token
        self.base = f"https://api.telegram.org/bot{token}"
        self.session = None
        self.offset = 0

    async def start(self):
        self.session = aiohttp.ClientSession()

    async def close(self):
        if self.session:
            await self.session.close()

    async def call(self, method, **params):
        async with self.session.post(f"{self.base}/{method}", json=params) as r:
            return await r.json()

    async def get_updates(self, timeout=25):
        result = await self.call(
            "getUpdates", offset=self.offset, timeout=timeout, allowed_updates=["message", "callback_query", "inline_query"]
        )
        updates = result.get("result", [])
        if updates:
            self.offset = updates[-1]["update_id"] + 1
        return updates

    async def send_message(self, chat_id, text, reply_markup=None, parse_mode="HTML"):
        params = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
        if reply_markup:
            params["reply_markup"] = reply_markup
        return await self.call("sendMessage", **params)

    async def edit_message(self, chat_id, message_id, text, reply_markup=None, parse_mode="HTML"):
        params = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": parse_mode}
        if reply_markup:
            params["reply_markup"] = reply_markup
        return await self.call("editMessageText", **params)

    async def answer_callback(self, callback_id, text=None):
        params = {"callback_query_id": callback_id}
        if text:
            params["text"] = text
        return await self.call("answerCallbackQuery", **params)

    async def answer_inline(self, inline_query_id, results):
        return await self.call("answerInlineQuery", inline_query_id=inline_query_id, results=results, cache_time=0)


async def get_bot_username(token):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://api.telegram.org/bot{token}/getMe") as r:
            data = await r.json()
            if data.get("ok") and data.get("result"):
                return data["result"]
    return None


async def run_echo_id_mode(token):
    api = BotAPI(token)
    await api.start()
    logger.info("Bootstrap: echo-id mode active")
    try:
        while True:
            updates = await api.get_updates()
            for u in updates:
                msg = u.get("message")
                if msg and "from" in msg:
                    sender_id = msg["from"]["id"]
                    await api.send_message(msg["chat"]["id"], str(sender_id), parse_mode=None)
    finally:
        await api.close()


async def run_setup_wizard(token, owner_id):
    from strings import Strings

    api = BotAPI(token)
    await api.start()

    state = {"lang": "en", "api_id": None, "api_hash": None, "stage": "language"}
    s = Strings("en")

    lang_kb = {
        "inline_keyboard": [
            [
                {"text": "English", "callback_data": "lang_en"},
                {"text": "Russian", "callback_data": "lang_ru"},
                {"text": "Chinese", "callback_data": "lang_ch"},
            ]
        ]
    }

    await api.send_message(owner_id, s.get("press_start"), reply_markup=lang_kb)

    me = await get_bot_username(token)
    bot_username = me["username"] if me else ""

    try:
        while True:
            updates = await api.get_updates()
            for u in updates:
                cq = u.get("callback_query")
                if cq and cq["from"]["id"] == owner_id:
                    data = cq["data"]
                    if data.startswith("lang_"):
                        lang = data.split("_", 1)[1]
                        state["lang"] = lang
                        s.set_language(lang)
                        await api.answer_callback(cq["id"])
                        kb = {
                            "inline_keyboard": [
                                [{"text": s.get("ask_api_id"), "switch_inline_query_current_chat": "API_ID "}]
                            ]
                        }
                        await api.edit_message(
                            owner_id, cq["message"]["message_id"], s.get("ask_api_id"), reply_markup=kb
                        )
                        state["stage"] = "api_id"

                iq = u.get("inline_query")
                if iq and iq["from"]["id"] == owner_id:
                    query = iq["query"]
                    if state["stage"] == "api_id" and query.startswith("API_ID "):
                        value = query[len("API_ID "):].strip()
                        valid = bool(API_ID_RE.match(value))
                        title = s.get("tap_transfer") if valid else s.get("invalid_value")
                        await api.answer_inline(
                            iq["id"],
                            [
                                {
                                    "type": "article",
                                    "id": "api_id_result",
                                    "title": title,
                                    "input_message_content": {"message_text": value or " "},
                                }
                            ],
                        )
                    elif state["stage"] == "api_hash" and query.startswith("API_HASH "):
                        value = query[len("API_HASH "):].strip()
                        valid = bool(API_HASH_RE.match(value))
                        title = s.get("tap_transfer") if valid else s.get("invalid_value")
                        await api.answer_inline(
                            iq["id"],
                            [
                                {
                                    "type": "article",
                                    "id": "api_hash_result",
                                    "title": title,
                                    "input_message_content": {"message_text": value or " "},
                                }
                            ],
                        )

                msg = u.get("message")
                if msg and msg.get("from", {}).get("id") == owner_id and "via_bot" in msg:
                    text = (msg.get("text") or "").strip()
                    if state["stage"] == "api_id" and API_ID_RE.match(text):
                        state["api_id"] = text
                        state["stage"] = "api_hash"
                        kb = {
                            "inline_keyboard": [
                                [{"text": s.get("ask_api_hash"), "switch_inline_query_current_chat": "API_HASH "}]
                            ]
                        }
                        await api.send_message(owner_id, s.get("ask_api_hash"), reply_markup=kb)
                    elif state["stage"] == "api_hash" and API_HASH_RE.match(text):
                        state["api_hash"] = text
                        write_env({"API_ID": state["api_id"], "API_HASH": state["api_hash"], "LANG": state["lang"]})
                        await api.send_message(owner_id, s.get("setup_complete"), parse_mode=None)
                        return
    finally:
        await api.close()


async def run_full_bot():
    from telethon import TelegramClient, events
    from installer import installer
    from strings import Strings
    from protection import Protection

    env = read_env()
    API_ID = int(env.get("API_ID", 0))
    API_HASH = env.get("API_HASH", "")
    BOT_TOKEN = env.get("BOT_TOKEN", "")
    OWNER_ID = int(env.get("OWNER_ID", 0))
    DEFAULT_LANG = env.get("LANG", "en")

    DATA_FILE = os.path.join(BOT_DIR, "OBHOD.json")
    PREFIX = "."

    class DataManager:
        def __init__(self, owner_id, default_lang):
            self.owner_id = owner_id
            self.default_lang = default_lang
            self.data = self.load_data()

        def load_data(self):
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, "r") as f:
                    return json.load(f)
            return {"admins": [], "banned": [], "languages": {}}

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

        def get_banned(self):
            return self.data.get("banned", [])

        def add_banned(self, user_id):
            if user_id not in self.data["banned"]:
                self.data["banned"].append(user_id)
                self.save_data()

        def is_privileged(self, user_id):
            return user_id == self.owner_id or user_id in self.get_admins()

        def get_language(self, user_id):
            return self.data.get("languages", {}).get(str(user_id), self.default_lang)

        def set_language(self, user_id, lang):
            self.data.setdefault("languages", {})[str(user_id)] = lang
            self.save_data()

        async def notify_admins(self, bot, message):
            for user_id in [self.owner_id] + self.get_admins():
                try:
                    await bot.send_message(user_id, message, parse_mode="html")
                except Exception:
                    pass

    bot = TelegramClient("OBHOD", API_ID, API_HASH)
    await bot.start(bot_token=BOT_TOKEN)

    me = await bot.get_me()
    logger.info(f"Bot started: {me.first_name} (@{me.username})")

    async def keepalive_loop():
        while True:
            await asyncio.sleep(180)
            try:
                await asyncio.wait_for(bot.get_me(), timeout=15)
            except Exception as e:
                logger.warning(f"Keepalive ping failed ({e}), forcing reconnect...")
                try:
                    await bot.disconnect()
                except Exception:
                    pass
                try:
                    await bot.connect()
                    logger.info("Reconnected after keepalive failure")
                except Exception as reconnect_err:
                    logger.error(f"Reconnect failed: {reconnect_err}")

    asyncio.create_task(keepalive_loop())

    data_manager = DataManager(OWNER_ID, DEFAULT_LANG)

    protection = Protection(
        bot, OWNER_ID, data_manager.get_admins, data_manager.get_banned, data_manager.add_banned
    )

    installer.set_context(bot, data_manager)
    logger.info("Loading modules...")
    await installer.load_all()
    logger.info(f"Loaded modules: {installer.get_loaded()}")

    def build_main_menu(user_id):
        lang = data_manager.get_language(user_id)
        s = Strings(lang)
        rows = [[{"text": s.get("btn_users"), "data": "menu_users"}, {"text": s.get("btn_modules"), "data": "menu_modules"}]]
        for label, handler in installer.get_menu_buttons():
            rows.append([{"text": label, "data": f"btn:{label}"}])
        return s.get("main_menu"), rows

    def to_telethon_buttons(rows):
        from telethon import Button
        out = []
        for row in rows:
            out_row = []
            for btn in row:
                out_row.append(Button.inline(btn["text"], data=btn["data"].encode()))
            out.append(out_row)
        return out

    @bot.on(events.NewMessage(pattern=r"^/start$"))
    async def start_handler(event):
        if not data_manager.is_privileged(event.sender_id):
            lang = data_manager.get_language(event.sender_id)
            s = Strings(lang)
            await event.reply(s.get("not_owner"))
            return
        text, rows = build_main_menu(event.sender_id)
        await event.reply(text, buttons=to_telethon_buttons(rows), parse_mode="html")

    _pending_inline = {}

    @bot.on(events.InlineQuery())
    async def inline_handler(event):
        if not data_manager.is_privileged(event.sender_id):
            return
        query = event.text
        for prefix, (method, validator) in installer.get_inline_inputs().items():
            if query.startswith(prefix):
                value = query[len(prefix):].strip()
                valid = validator(value) if validator else bool(value)
                _pending_inline[event.sender_id] = (prefix, method)
                title = "Tap for transfer value" if valid else "Invalid value"
                builder = event.builder
                result = builder.article(title=title, text=value or " ")
                await event.answer([result])
                return

    @bot.on(events.NewMessage(incoming=True, func=lambda e: e.is_private and e.message.via_bot_id))
    async def inline_result_handler(event):
        pending = _pending_inline.pop(event.sender_id, None)
        if not pending:
            return
        prefix, method = pending
        value = (event.raw_text or "").strip()
        await method(event, value)
        try:
            await event.delete()
        except Exception:
            pass

    @bot.on(events.CallbackQuery(pattern=b"^btn:"))
    async def button_dispatch(event):
        if not data_manager.is_privileged(event.sender_id):
            return
        label = event.data.decode().split(":", 1)[1]
        for btn_label, handler in installer.get_menu_buttons():
            if btn_label == label:
                await handler(event)
                return

    @bot.on(events.CallbackQuery(pattern=b"^menu_modules$"))
    async def menu_modules_handler(event):
        if not data_manager.is_privileged(event.sender_id):
            return
        lang = data_manager.get_language(event.sender_id)
        s = Strings(lang)
        rows = [[{"text": label, "data": f"btn:{label}"}] for label, _ in installer.get_menu_buttons()]
        await event.edit(s.get("btn_modules"), buttons=to_telethon_buttons(rows))

    @bot.on(events.CallbackQuery(pattern=b"^menu_users$"))
    async def menu_users_handler(event):
        if not data_manager.is_privileged(event.sender_id):
            return
        lang = data_manager.get_language(event.sender_id)
        s = Strings(lang)
        admins = data_manager.get_admins()
        text = f"{s.get('btn_users')}\n\nowner: {OWNER_ID}\nadmins: {', '.join(str(a) for a in admins) or '-'}"
        await event.edit(text)

    @bot.on(events.NewMessage(pattern=rf"^\{PREFIX}(\w+)(?:\s+(.*))?$"))
    async def command_handler(event):
        if not data_manager.is_privileged(event.sender_id):
            return

        if protection.check_spam(event.sender_id):
            return

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

    logger.info("Bot is ready")

    try:
        await bot.run_until_disconnected()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await bot.disconnect()


async def main():
    env = read_env()
    token = env.get("BOT_TOKEN")

    if not token:
        logger.error("BOT_TOKEN missing in .env, aborting")
        sys.exit(1)

    if not env.get("OWNER_ID"):
        await run_echo_id_mode(token)
        return

    if not env.get("API_ID") or not env.get("API_HASH"):
        owner_id = int(env["OWNER_ID"])
        await run_setup_wizard(token, owner_id)
        os.execv(sys.executable, [sys.executable] + sys.argv)
        return

    await run_full_bot()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bot stopped")
