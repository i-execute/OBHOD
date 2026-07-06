# OBHOD

A standalone Telegram bot for issuing and managing VK TURN + VLESS tunnel
peers, used to wrap VLESS traffic as DTLS media packets through VK TURN
relay servers so that DPI only sees legitimate VK call traffic.

Architecture is modeled after [TGWatcher](https://github.com/i-execute/TGWatcher):
a small Telethon-based bot core with a pluggable module loader
(`.py` files dropped into `Bot/Modules` are auto-loaded on start).

The bot itself does not run the tunnel — it manages WireGuard peers on
the VPS (add / list / revoke) and hands back a ready-to-import
`vkturnproxy://import?data=...` link for each user.

## Repo layout

```
OBHOD/
├── Storage/Installation/
│   ├── QuickStart.sh     # one-liner bootstrap, downloads and runs Setuper.sh
│   ├── Setuper.sh        # clones the repo, builds venv, writes .env, sets up systemd --user
│   ├── setup_root.sh     # ONE-TIME root script: WireGuard + vk-turn-proxy server + sudoers
│   ├── add_peer.sh       # called by the bot via sudo — adds a WG peer at runtime
│   └── revoke_peer.sh    # called by the bot via sudo — removes a WG peer
└── Bot/
    ├── core.py           # bot bootstrap, command dispatch, admin/owner management
    ├── installer.py      # module loader (BaseModule / @command / @loop)
    ├── strings.py         # message templates
    └── Modules/
        └── VKTurn.py     # peer issue/list/revoke logic (.vkadd, .vklist, .vkrevoke)
```

## Installation

Two separate steps, because they need different privileges.

### 1. Install and start the bot (regular user)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/i-execute/OBHOD/main/Storage/Installation/QuickStart.sh)
```

You'll be prompted for:
- `BOT_TOKEN` — Telegram bot token from @BotFather
- `OWNER_ID` — your Telegram user ID
- `API_ID` / `API_HASH` — from https://my.telegram.org
- VK join link and the VK TURN server endpoint (`ip:port`)

This installs the bot under `~/OBHOD`, creates a venv, and registers it
as a `systemctl --user` service named `obhod`.

### 2. Set up the WireGuard / vk-turn-proxy infrastructure (root, once)

```bash
sudo bash ~/OBHOD/Storage/Installation/setup_root.sh
```

This installs WireGuard, generates the server keypair, starts the
`vk-turn-proxy` systemd service, and writes a `sudoers.d` rule so the
bot's system user can call `add_peer.sh` / `revoke_peer.sh` without a
password — nothing else is granted.

## Bot commands

| Command | Description |
|---|---|
| `.vkadd <tag>` | Issue a new peer and return a ready `vkturnproxy://` link |
| `.vklist` | List all currently active peers |
| `.vkrevoke <tag>` | Revoke a peer by its tag |

Only the owner and configured admins can run these commands.

## Notes

- Adding/removing a peer does **not** restart the WireGuard interface
  (`wg set` at runtime + config file append/removal), so existing
  connections are never dropped when a new user is added.
- Peer state is tracked in `/etc/wireguard/peers.json` on the VPS.
- No hard limit on the number of concurrent peers — tracking is by tag
  only.
