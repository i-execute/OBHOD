import os
import json
import subprocess

import aiohttp
from telethon import events, Button

from installer import BaseModule, need_button, need_inline_input, get_mutal_access, set_mutal_core_version

UPDATE_SCRIPT = "/opt/vkturn/update_core.sh"
TOKEN_FILE = os.path.join(os.path.dirname(__file__), "..", "github_token.json")
TOKEN_FILE = os.path.abspath(TOKEN_FILE)


def load_token():
    if not os.path.exists(TOKEN_FILE):
        return None
    with open(TOKEN_FILE, "r") as f:
        return json.load(f).get("token")


def save_token(token):
    with open(TOKEN_FILE, "w") as f:
        json.dump({"token": token}, f)


def parse_repo_url(url):
    parts = url.rstrip("/").split("/")
    return parts[-2], parts[-1]


class Updater(BaseModule):
    name = "Updater"
    version = (1, 0, 0)

    strings_english = {
        "menu": "Updater",
        "btn_set_token": "Set Token",
        "btn_change_token": "Change Token",
        "btn_update_core": "Update Core",
        "btn_back": "Back",
        "token_saved": "Token saved",
        "no_releases": "No releases found",
        "select_release": "Select a version",
        "updating": "Updating, please wait...",
        "update_done": "Core updated",
        "update_failed": "Update failed",
        "no_module": "VKTurn module not tracked yet",
    }
    strings_russian = {
        "menu": "Обновления",
        "btn_set_token": "Указать токен",
        "btn_change_token": "Сменить токен",
        "btn_update_core": "Обновить ядро",
        "btn_back": "Назад",
        "token_saved": "Токен сохранен",
        "no_releases": "Релизы не найдены",
        "select_release": "Выберите версию",
        "updating": "Обновление, подождите...",
        "update_done": "Ядро обновлено",
        "update_failed": "Обновление не удалось",
        "no_module": "Модуль VKTurn еще не отслеживается",
    }
    strings_chinese = {
        "menu": "更新程序",
        "btn_set_token": "设置令牌",
        "btn_change_token": "更改令牌",
        "btn_update_core": "更新核心",
        "btn_back": "返回",
        "token_saved": "令牌已保存",
        "no_releases": "未找到发行版",
        "select_release": "选择版本",
        "updating": "正在更新，请稍候...",
        "update_done": "核心已更新",
        "update_failed": "更新失败",
        "no_module": "VKTurn 模块尚未被跟踪",
    }

    def __init__(self):
        super().__init__()
        self._releases_cache = {}

    async def on_start(self, bot, data_manager):
        self.bot = bot
        self.data_manager = data_manager
        bot.add_event_handler(self._cb_back_menu, events.CallbackQuery(pattern=b"^updater:menu$"))
        bot.add_event_handler(self._cb_update_core, events.CallbackQuery(pattern=b"^updater:update$"))
        bot.add_event_handler(self._cb_pick_release, events.CallbackQuery(pattern=b"^updater:rel:"))

    @need_button("Updater")
    async def _cb_menu(self, event):
        await self._render_menu(event)

    async def _cb_back_menu(self, event):
        await self._render_menu(event)

    async def _render_menu(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        token = load_token()
        token_btn_text = self.strings["btn_change_token"] if token else self.strings["btn_set_token"]
        kb = [
            [Button.switch_inline(token_btn_text, query="GITHUB_TOKEN ", same_peer=True)],
            [Button.inline(self.strings["btn_update_core"], b"updater:update")],
            [Button.inline(self.strings["btn_back"], b"menu_modules")],
        ]
        await event.edit(self.strings["menu"], buttons=kb)

    @need_inline_input("GITHUB_TOKEN ", validator=lambda v: len(v) > 10)
    async def _input_token(self, event, value):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        save_token(value)
        await event.reply(self.strings["token_saved"])

    async def _fetch_releases(self, repo_url):
        owner, repo = parse_repo_url(repo_url)
        token = load_token()
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        url = f"https://api.github.com/repos/{owner}/{repo}/releases"
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=headers) as r:
                if r.status != 200:
                    return []
                return await r.json()

    async def _cb_update_core(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        entry = get_mutal_access("VKTurn")
        if not entry:
            await event.edit(self.strings["no_module"])
            return

        releases = await self._fetch_releases(entry["repository"])
        if not releases:
            kb = [[Button.inline(self.strings["btn_back"], b"updater:menu")]]
            await event.edit(self.strings["no_releases"], buttons=kb)
            return

        self._releases_cache[event.sender_id] = releases[:10]
        kb = [
            [Button.inline(r.get("tag_name", "?"), f"updater:rel:{i}".encode())]
            for i, r in enumerate(releases[:10])
        ]
        kb.append([Button.inline(self.strings["btn_back"], b"updater:menu")])
        await event.edit(self.strings["select_release"], buttons=kb)

    def _run_script(self, script, *args):
        proc = subprocess.run(
            ["sudo", "-n", script, *args], capture_output=True, text=True, timeout=120
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
        return proc.stdout.strip()

    async def _cb_pick_release(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        idx = int(event.data.decode().split(":", 2)[-1])
        releases = self._releases_cache.get(event.sender_id, [])
        if idx >= len(releases):
            return
        release = releases[idx]

        asset_url = None
        for asset in release.get("assets", []):
            if "linux-amd64" in asset.get("name", ""):
                asset_url = asset.get("browser_download_url")
                break

        if not asset_url:
            await event.edit(self.strings["update_failed"])
            return

        await event.edit(self.strings["updating"])

        try:
            self._run_script(UPDATE_SCRIPT, asset_url, release.get("tag_name", ""))
        except RuntimeError:
            await event.edit(self.strings["update_failed"])
            return

        entry = get_mutal_access("VKTurn")
        if entry:
            set_mutal_core_version("VKTurn", release.get("tag_name"))

        kb = [[Button.inline(self.strings["btn_back"], b"updater:menu")]]
        await event.edit(self.strings["update_done"], buttons=kb)
