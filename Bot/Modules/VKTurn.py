import os
import json
import base64
import logging
import subprocess

from installer import BaseModule, command

logger = logging.getLogger(__name__)

VK_LINK = os.environ.get("VKTURN_VK_LINK", "https://vk.me/join/REPLACE_ME")
SERVER_ENDPOINT = os.environ.get("VKTURN_ENDPOINT", "89.125.48.221:6767")
WRAP_KEY_FILE = "/etc/wireguard/wrap.key"

ADD_SCRIPT = "/opt/vkturn/add_peer.sh"
REVOKE_SCRIPT = "/opt/vkturn/revoke_peer.sh"
PEERS_DB = "/etc/wireguard/peers.json"


class VKTurn(BaseModule):
    name = "VKTurn"
    version = (1, 0, 0)

    async def on_start(self, bot, data_manager):
        self.bot = bot
        self.data_manager = data_manager
        try:
            with open(WRAP_KEY_FILE) as f:
                self.wrap_key = f.read().strip()
        except FileNotFoundError:
            self.wrap_key = ""
            logger.error("wrap.key не найден — запусти setup_root.sh на сервере")
        logger.info("VKTurn module ready")

    # --- внутренние хелперы ---

    def _run_add_peer(self, tag: str) -> dict:
        proc = subprocess.run(
            ["sudo", "-n", ADD_SCRIPT, tag],
            capture_output=True, text=True, timeout=15
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
        result = {}
        for line in proc.stdout.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                result[k] = v
        return result

    def _run_revoke_peer(self, tag: str):
        proc = subprocess.run(
            ["sudo", "-n", REVOKE_SCRIPT, tag],
            capture_output=True, text=True, timeout=15
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())

    def _build_link(self, priv: str, server_pub: str, client_ip: str) -> str:
        settings = {
            "privateKey": priv,
            "peerPublicKey": server_pub,
            "tunnelAddress": client_ip,
            "vkLink": VK_LINK,
            "peerAddress": SERVER_ENDPOINT,
            "useDTLS": True,
            "useWrap": bool(self.wrap_key),
            "wrapKeyHex": self.wrap_key,
            "numConnections": 15,
            "useUDP": True,
            "useWrapA": False,
        }
        payload = {"version": 1, "type": "connection", "settings": settings}
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return f"vkturnproxy://import?data={b64}"

    def _load_peers(self) -> dict:
        if not os.path.exists(PEERS_DB):
            return {}
        with open(PEERS_DB) as f:
            return json.load(f)

    # --- команды (доступны как .vkadd / .vklist / .vkrevoke) ---

    @command
    async def vkadd(self, event, args):
        """.vkadd <tag> — выдать новый peer + готовую ссылку"""
        tag = args.strip() or f"user_{event.sender_id}"

        try:
            r = self._run_add_peer(tag)
            link = self._build_link(r["PRIV"], r["PUB"], r["IP"])
        except Exception as e:
            logger.error(f"vkadd failed for {tag}: {e}")
            await event.reply(f"<b>Ошибка выдачи peer</b>\n<code>{e}</code>", parse_mode="html")
            return

        await event.reply(
            f"<b>Peer выдан</b>\n"
            f"tag: <code>{tag}</code>\n"
            f"ip: <code>{r['IP']}</code>\n\n"
            f"<code>{link}</code>",
            parse_mode="html"
        )
        logger.info(f"Peer added: tag={tag} ip={r['IP']}")

        await self.data_manager.notify_admins(
            self.bot,
            f"<b>[VKTurn] Новый peer</b>\ntag: <code>{tag}</code>\nip: <code>{r['IP']}</code>\n"
            f"выдал: <code>{event.sender_id}</code>"
        )

    @command
    async def vklist(self, event, args):
        """.vklist — список активных peer'ов"""
        peers = self._load_peers()
        if not peers:
            await event.reply("Активных peers нет")
            return
        lines = [f"<code>{tag}</code>: {info['ip']}" for tag, info in peers.items()]
        await event.reply(
            f"<b>Активные peers ({len(peers)})</b>\n" + "\n".join(lines),
            parse_mode="html"
        )

    @command
    async def vkrevoke(self, event, args):
        """.vkrevoke <tag> — отозвать peer по метке"""
        tag = args.strip()
        if not tag:
            await event.reply("Использование: .vkrevoke <tag>")
            return

        try:
            self._run_revoke_peer(tag)
        except Exception as e:
            logger.error(f"vkrevoke failed for {tag}: {e}")
            await event.reply(f"<b>Ошибка отзыва</b>\n<code>{e}</code>", parse_mode="html")
            return

        await event.reply(f"Peer <code>{tag}</code> отозван", parse_mode="html")
        logger.info(f"Peer revoked: tag={tag}")

        await self.data_manager.notify_admins(
            self.bot,
            f"<b>[VKTurn] Peer отозван</b>\ntag: <code>{tag}</code>\nкем: <code>{event.sender_id}</code>"
        )
