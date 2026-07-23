import os
import re
import json
import uuid
import base64
import logging
import subprocess

import aiohttp
from telethon import events, Button

from installer import BaseModule, need_button, need_command, mutal_access

logger = logging.getLogger(__name__)

ADD_SCRIPT = "/opt/vkturn/add_peer.sh"
REVOKE_SCRIPT = "/opt/vkturn/revoke_peer.sh"
ENSURE_PROFILE_SCRIPT = "/opt/vkturn/ensure_profile.sh"
ADD_CLIENT_SCRIPT = "/opt/vkturn/add_client.sh"
PEERS_DB = "/etc/wireguard/peers.json"
SERVER_HOST = os.environ.get("VKTURN_SERVER_HOST", "")

def _detect_server_host():
    """Auto-detect server external IP if VKTURN_SERVER_HOST not set."""
    if SERVER_HOST:
        return SERVER_HOST
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""

# Resolve once at import time
SERVER_HOST = _detect_server_host()

CALLS_DB_FILE = os.path.join(os.path.dirname(__file__), "..", "vkturn_calls.json")
CALLS_DB_FILE = os.path.abspath(CALLS_DB_FILE)
WRAP_KEY_FILE = "/etc/wireguard/wrap.key"

VK_API_VERSION = "5.199"
VK_API_BASE = "https://api.vk.ru/method"
VK_DEFAULT_APP_ID = 3697615
VK_REDIRECT = "https://oauth.vk.com/blank.html"
VK_DEFAULT_SCOPE = "offline"
VK_TOKEN_RE = re.compile(r"access_token=([A-Za-z0-9._-]+)")

OBF_PROFILES = ["rtpopus", "rtpopus2", "rtpopus3"]
PLATFORMS = ["ios", "android"]
ANDROID_LOCAL_LISTEN = "127.0.0.1:51900"


def _btn(text, data):
    # All inline buttons use the "primary" (blue) style project-wide.
    return Button.inline(text, data.encode() if isinstance(data, str) else data, style="primary")


def build_android_wg_conf(peer):
    """WireGuard config for Android's separate WireGuard app.

    The freeturn:// CLI only tunnels/obfuscates traffic to a local
    -listen address; it has no WireGuard fields of its own. The actual WG
    interface (using this peer's keys) has to be imported into a WireGuard
    app pointed at that local listen port.
    """
    return (
        "[Interface]\n"
        f"PrivateKey = {peer['PRIV']}\n"
        f"Address = {peer['IP']}/24\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        f"PublicKey = {peer['PUB']}\n"
        f"PresharedKey = {peer.get('PSK', '')}\n"
        f"Endpoint = {ANDROID_LOCAL_LISTEN}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )


def build_link_ios(peer, join_link, obf_key_hex, server_host, server_port, profile):
    """vkturnproxy:// import link for the iOS client (WRAP-A obfuscation profiles)."""
    settings = {
        "allowedIPs": "0.0.0.0/0",
        "clientID": str(uuid.uuid4()).upper(),
        "credPoolCooldownSeconds": 150,
        "dnsServers": "1.1.1.1",
        "numConnections": 15,
        "obfProfile": profile,
        "peerAddress": f"{server_host}:{server_port}" if server_host and server_port else "127.0.0.1:9000",
        "peerPublicKey": peer["PUB"],
        "presharedKey": peer.get("PSK", ""),
        "privateKey": peer["PRIV"],
        "tunnelAddress": f"{peer['IP']}/24",
        "turnServerOverride": "",
        "useDTLS": True,
        "useSrtp": False,
        "useUDP": True,
        "useWrap": False,
        "useWrapA": True,
        "useWrapS": True,
        "vkAuth": False,
        "vkLink": join_link,
        "wrapAPassword": "",
        "wrapKeyHex": obf_key_hex,
    }
    payload = {"version": 1, "type": "connection", "settings": settings}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"vkturnproxy://import?data={b64}"


def build_link_android(cid, obf_key_hex, server_host, server_port, profile):
    """freeturn:// share link for the Android client.

    Per the freeturn:// URI spec, the vk.me/join call link is never embedded
    in the payload (it's client-unique) - it must be handed to the Android
    client separately as -link, same as the CLI does. The Android client
    authenticates via `cid`, which the caller must first register into the
    server's clients.json allowlist (see add_client.sh / ADD_CLIENT_SCRIPT).
    """
    metadata = {
        "v": 1,
        "provider": "vk",
        "peer": f"{server_host}:{server_port}" if server_host and server_port else "127.0.0.1:9000",
        "transport": "tcp",
        "mode": "udp",
        "obf": profile,
        "key": obf_key_hex,
        "n": 15,
        "cid": cid,
        "dnss": "1.1.1.1",
        "listen": ANDROID_LOCAL_LISTEN,
    }
    raw = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"freeturn://{b64}"

def extract_vk_token(text):
    if not text:
        return None
    m = VK_TOKEN_RE.search(text)
    return m.group(1) if m else None

def build_vk_auth_url():
    return (
        "https://oauth.vk.com/authorize"
        f"?client_id={VK_DEFAULT_APP_ID}"
        f"&display=page"
        f"&redirect_uri={VK_REDIRECT}"
        f"&scope={VK_DEFAULT_SCOPE}"
        f"&response_type=token"
        f"&v={VK_API_VERSION}"
    )

def load_calls_db():
    if not os.path.exists(CALLS_DB_FILE):
        return {"token": None, "calls": {}}
    with open(CALLS_DB_FILE, "r") as f:
        return json.load(f)

def save_calls_db(db):
    tmp = CALLS_DB_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, CALLS_DB_FILE)


class VKAPIError(Exception):
    def __init__(self, error):
        self.error = error or {}
        super().__init__(str(self.error))


class VKClient:
    def __init__(self, token):
        self.token = token

    async def api(self, method, **params):
        params = dict(params)
        params["access_token"] = self.token
        params["v"] = VK_API_VERSION
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{VK_API_BASE}/{method}", data=params) as r:
                data = await r.json(content_type=None)
        if isinstance(data, dict) and "error" in data:
            raise VKAPIError(data["error"])
        return data.get("response")

    async def whoami(self):
        resp = await self.api("users.get")
        if isinstance(resp, list) and resp:
            return resp[0].get("id")
        return None

    async def start_call(self):
        resp = await self.api("calls.start")
        return resp if isinstance(resp, dict) else {}

    async def force_finish(self, call_id):
        resp = await self.api("calls.forceFinish", call_id=call_id)
        return bool(resp)


class VKTurn(BaseModule):
    name = "VKTurn"
    version = (1, 0, 0)

    strings_english = {
        "menu": "VKTurn",
        "btn_add_peer": "Add Peer",
        "btn_list_peers": "List Peers",
        "btn_back": "Back",
        "call_source": "Select call source",
        "btn_new_call": "Create New Call",
        "btn_old_call": "Use Existing Call",
        "select_profile": "Select obfuscation profile",
        "select_platform": "Select client platform",
        "btn_ios": "iOS",
        "btn_android": "Android",
        "no_calls": "No saved calls, create one first",
        "not_authorized": "VK not authorized, paste your auth URL",
        "auth_prompt": "Open the link, allow access, copy the full redirected URL and send it here",
        "ask_tag": "Send a tag for this peer",
        "peer_created": "Peer created",
        "no_peers": "No active peers",
        "revoked": "Peer revoked",
    }
    strings_russian = {
        "menu": "VKTurn",
        "btn_add_peer": "Добавить пира",
        "btn_list_peers": "Список пиров",
        "btn_back": "Назад",
        "call_source": "Выберите источник звонка",
        "btn_new_call": "Создать новый звонок",
        "btn_old_call": "Использовать старый",
        "select_profile": "Выберите профиль обфускации",
        "select_platform": "Выберите платформу клиента",
        "btn_ios": "iOS",
        "btn_android": "Android",
        "no_calls": "Нет сохраненных звонков, сначала создайте",
        "not_authorized": "VK не авторизован, вставьте ссылку авторизации",
        "auth_prompt": "Откройте ссылку, разрешите доступ, скопируйте полный URL и отправьте сюда",
        "ask_tag": "Отправьте тег для этого пира",
        "peer_created": "Пир создан",
        "no_peers": "Нет активных пиров",
        "revoked": "Пир отозван",
    }
    strings_chinese = {
        "menu": "VKTurn",
        "btn_add_peer": "添加节点",
        "btn_list_peers": "节点列表",
        "btn_back": "返回",
        "call_source": "选择通话来源",
        "btn_new_call": "创建新通话",
        "btn_old_call": "使用现有通话",
        "select_profile": "选择混淆配置",
        "select_platform": "选择客户端平台",
        "btn_ios": "iOS",
        "btn_android": "Android",
        "no_calls": "没有保存的通话，请先创建",
        "not_authorized": "VK 未授权，请粘贴授权链接",
        "auth_prompt": "打开链接，允许访问，复制完整的重定向网址并发送到这里",
        "ask_tag": "发送此节点的标签",
        "peer_created": "节点已创建",
        "no_peers": "没有活动节点",
        "revoked": "节点已撤销",
    }

    def __init__(self):
        super().__init__()
        self._pending = {}
        self._flow = {}

    @mutal_access("https://github.com/samosvalishe/free-turn-proxy", "VKTurn")
    async def on_start(self, bot, data_manager):
        self.bot = bot
        self.data_manager = data_manager

        bot.add_event_handler(self._cb_back_menu, events.CallbackQuery(pattern=b"^vkturn:menu$"))
        bot.add_event_handler(self._cb_add_peer, events.CallbackQuery(pattern=b"^vkturn:add$"))
        bot.add_event_handler(self._cb_call_source, events.CallbackQuery(pattern=b"^vkturn:src:"))
        bot.add_event_handler(self._cb_pick_call, events.CallbackQuery(pattern=b"^vkturn:call:"))
        bot.add_event_handler(self._cb_pick_profile, events.CallbackQuery(pattern=b"^vkturn:profile:"))
        bot.add_event_handler(self._cb_pick_platform, events.CallbackQuery(pattern=b"^vkturn:platform:"))
        bot.add_event_handler(self._cb_list_peers, events.CallbackQuery(pattern=b"^vkturn:list$"))
        bot.add_event_handler(self._cb_revoke, events.CallbackQuery(pattern=b"^vkturn:revoke:"))
        bot.add_event_handler(self._on_text, events.NewMessage(incoming=True, func=lambda e: e.is_private))

    def _run_script(self, script, *args):
        proc = subprocess.run(
            ["sudo", "-n", script, *args], capture_output=True, text=True, timeout=30
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
        result = {}
        for line in proc.stdout.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                result[k] = v
        return result

    @need_button("VKTurn")
    @mutal_access("https://github.com/samosvalishe/free-turn-proxy", "VKTurn")
    async def _cb_menu(self, event):
        await self._render_menu(event)

    @mutal_access("https://github.com/samosvalishe/free-turn-proxy", "VKTurn")
    async def _cb_back_menu(self, event):
        await self._render_menu(event)

    async def _render_menu(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        kb = [
            [_btn(self.strings["btn_add_peer"], b"vkturn:add")],
            [_btn(self.strings["btn_list_peers"], b"vkturn:list")],
            [_btn(self.strings["btn_back"], b"menu_modules")],
        ]
        await event.edit(self.strings["menu"], buttons=kb)

    async def _cb_add_peer(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        kb = [
            [_btn(self.strings["btn_new_call"], b"vkturn:src:new")],
            [_btn(self.strings["btn_old_call"], b"vkturn:src:old")],
            [_btn(self.strings["btn_back"], b"vkturn:menu")],
        ]
        await event.edit(self.strings["call_source"], buttons=kb)

    async def _cb_call_source(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        source = event.data.decode().split(":")[-1]

        if source == "new":
            db = load_calls_db()
            token = db.get("token")
            if not token:
                self._pending[event.sender_id] = {"stage": "vk_auth"}
                url = build_vk_auth_url()
                kb = [
                    [Button.url("Open VK Auth", url)],
                    [_btn(self.strings["btn_back"], b"vkturn:menu")],
                ]
                await event.edit(self.strings["auth_prompt"], buttons=kb)
                return

            client = VKClient(token)
            try:
                resp = await client.start_call()
            except VKAPIError as e:
                await event.edit(str(e.error))
                return

            call_id = resp.get("call_id", "")
            join_link = resp.get("join_link", "")
            if call_id:
                db["calls"][call_id] = {"call_id": call_id, "join_link": join_link}
                save_calls_db(db)

            self._flow[event.sender_id] = {"call_id": call_id, "join_link": join_link}
            await self._show_profiles(event)
            return

        db = load_calls_db()
        calls = list(db.get("calls", {}).values())
        if not calls:
            kb = [[_btn(self.strings["btn_back"], b"vkturn:add")]]
            await event.edit(self.strings["no_calls"], buttons=kb)
            return

        self._flow.setdefault(event.sender_id, {})["call_list"] = calls
        kb = [
            [_btn(c["call_id"][:12], f"vkturn:call:{i}".encode())]
            for i, c in enumerate(calls)
        ]
        kb.append([_btn(self.strings["btn_back"], b"vkturn:add")])
        await event.edit(self.strings["call_source"], buttons=kb)

    async def _cb_pick_call(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        idx = int(event.data.decode().split(":", 2)[-1])
        calls = self._flow.get(event.sender_id, {}).get("call_list", [])
        if idx >= len(calls):
            return
        call = calls[idx]
        self._flow[event.sender_id] = {"call_id": call["call_id"], "join_link": call["join_link"]}
        await self._show_profiles(event)

    async def _show_profiles(self, event):
        kb = [
            [_btn(p, f"vkturn:profile:{p}".encode())] for p in OBF_PROFILES
        ]
        kb.append([_btn(self.strings["btn_back"], b"vkturn:menu")])
        await event.edit(self.strings["select_profile"], buttons=kb)

    async def _cb_pick_profile(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        profile = event.data.decode().split(":")[-1]
        flow = self._flow.get(event.sender_id, {})
        flow["profile"] = profile
        self._flow[event.sender_id] = flow
        await self._show_platforms(event)

    async def _show_platforms(self, event):
        kb = [
            [_btn(self.strings["btn_ios"], b"vkturn:platform:ios")],
            [_btn(self.strings["btn_android"], b"vkturn:platform:android")],
            [_btn(self.strings["btn_back"], b"vkturn:menu")],
        ]
        await event.edit(self.strings["select_platform"], buttons=kb)

    async def _cb_pick_platform(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        platform = event.data.decode().split(":")[-1]
        if platform not in PLATFORMS:
            return
        flow = self._flow.get(event.sender_id, {})
        flow["platform"] = platform
        self._flow[event.sender_id] = flow
        self._pending[event.sender_id] = {"stage": "peer_tag"}
        await event.edit(self.strings["ask_tag"])

    async def _on_text(self, event):
        sender_id = event.sender_id
        if not self.data_manager.is_privileged(sender_id):
            return
        pending = self._pending.get(sender_id)
        if not pending:
            return

        text = (event.raw_text or "").strip()

        if pending["stage"] == "vk_auth":
            token = extract_vk_token(text)
            if not token:
                return
            client = VKClient(token)
            uid = await client.whoami()
            if not uid:
                return
            db = load_calls_db()
            db["token"] = token
            save_calls_db(db)
            del self._pending[sender_id]

            try:
                await event.delete()
            except Exception:
                pass

            try:
                resp = await client.start_call()
            except VKAPIError:
                return
            call_id = resp.get("call_id", "")
            join_link = resp.get("join_link", "")
            if call_id:
                db["calls"][call_id] = {"call_id": call_id, "join_link": join_link}
                save_calls_db(db)
            self._flow[sender_id] = {"call_id": call_id, "join_link": join_link}

            kb = [[_btn(p, f"vkturn:profile:{p}".encode())] for p in OBF_PROFILES]
            await event.reply(self.strings["select_profile"], buttons=kb)
            return

        if pending["stage"] == "peer_tag":
            tag = text
            flow = self._flow.get(sender_id, {})
            profile = flow.get("profile", OBF_PROFILES[0])
            platform = flow.get("platform", "ios")
            join_link = flow.get("join_link", "")

            del self._pending[sender_id]

            try:
                peer = self._run_script(ADD_SCRIPT, tag)
                proxy = self._run_script(ENSURE_PROFILE_SCRIPT, profile)
            except RuntimeError as e:
                await event.reply(str(e))
                return

            port = proxy.get("PORT")
            obf_key = proxy.get("WRAP_KEY") or self._read_wrap_key()

            if platform == "android":
                cid = str(uuid.uuid4()).upper()
                try:
                    self._run_script(ADD_CLIENT_SCRIPT, cid, tag, profile)
                except RuntimeError as e:
                    await event.reply(str(e))
                    return

                link = build_link_android(cid, obf_key, SERVER_HOST, port, profile)
                wg_conf = build_android_wg_conf(peer)
                # freeturn:// never embeds the vk call link (it's client-unique)
                # or WireGuard fields (it's tunnel-only), so both are handed to
                # the Android client separately.
                link_line = (
                    f"{link}\n\n"
                    f"-link (VK call, use separately):\n{join_link}\n\n"
                    f"WireGuard config (import into WireGuard app):\n{wg_conf}"
                )
            else:
                link = build_link_ios(peer, join_link, obf_key, SERVER_HOST, port, profile)
                link_line = link

            message = (
                f"{self.strings['peer_created']}\n\n"
                f"tag: {tag}\n"
                f"ip: {peer['IP']}\n"
                f"profile: {profile}\n"
                f"platform: {platform}\n\n"
                f"{link_line}"
            )
            await event.reply(message)

            await self.data_manager.notify_admins(self.bot, message)

    def _read_wrap_key(self):
        """Read wrap key from file, return empty string if not found."""
        try:
            with open(WRAP_KEY_FILE, "r") as f:
                return f.read().strip()
        except Exception:
            return ""

    async def _cb_list_peers(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        if not os.path.exists(PEERS_DB):
            await event.edit(self.strings["no_peers"])
            return
        with open(PEERS_DB) as f:
            peers = json.load(f)
        if not peers:
            kb = [[_btn(self.strings["btn_back"], b"vkturn:menu")]]
            await event.edit(self.strings["no_peers"], buttons=kb)
            return
        kb = [
            [_btn(f"{tag} ({info['ip']})", f"vkturn:revoke:{tag}".encode())]
            for tag, info in peers.items()
        ]
        kb.append([_btn(self.strings["btn_back"], b"vkturn:menu")])
        await event.edit(self.strings["btn_list_peers"], buttons=kb)

    async def _cb_revoke(self, event):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        tag = event.data.decode().split(":", 2)[-1]
        try:
            self._run_script(REVOKE_SCRIPT, tag)
        except RuntimeError as e:
            await event.edit(str(e))
            return
        await event.edit(self.strings["revoked"])

    @need_command("vkcalls")
    async def vkcalls_command(self, event, args):
        if not self.data_manager.is_privileged(event.sender_id):
            return
        db = load_calls_db()
        calls = list(db.get("calls", {}).values())
        if not calls:
            await event.reply(self.strings["no_calls"])
            return
        lines = [f"{c['call_id']}: {c['join_link']}" for c in calls]
        await event.reply("\n".join(lines))