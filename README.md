<p align="center">
  <a href="https://t.me/I_execute"><img src="https://img.shields.io/badge/Telegram-@I__execute-26A5E4?style=flat&logo=telegram&logoColor=white" alt="Telegram" /></a>
</p>

# OBHOD

MTProto Telegram panel that manages `Xray` (post-quantum `VLESS` over `REALITY` / `TLS` with `mlkem768x25519plus` and `ML-DSA-65`) and `FreeTurn` (WireGuard over VK call TURN relays) locally on your Linux server.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh | sudo bash
```

Requires root on a systemd Linux host. Installs into `/opt/obhod`, keeps state in `/var/lib/obhod`, writes `/etc/obhod/obhod.env` with `0600` permissions, and runs `obhod.service`. Run `sudo obhod` in a terminal to open the management TUI.

## Core release versions

By default, OBHOD asks the GitHub releases API for the latest stable release.
If the API is unavailable or rate-limited, it uses the recommended pinned fallback:

| Component | Recommended API fallback | Minimum |
| --- | --- | --- |
| Xray | `v26.11.9` | `v26.10.31` |
| FreeTurn | `v4.2.1` | `v4.1.2` |
The latest release reported by the API is used when available; the recommended
fallback is used only when the API cannot provide a release, including rate limiting.
Releases below the minimum are refused. The fallback uses pinned SHA-256 digests;
an API-selected release without a verifiable checksum is refused instead of silently
changing versions. The pins live in both the bot and the standalone remote agents;
when updating them, update both copies and the bundled FreeTurn installer. No GitHub
token is needed, but Xray still requires access to the release download asset.

## Clients

| Kind | Platform | Client |
| --- | --- | --- |
| VLESS | All platforms | [INCY](https://github.com/INCY-DEV/incy-platforms) |
| FreeTurn | Android | [turn-proxy-android](https://github.com/hackdiaz-dev/turn-proxy-android) |
| FreeTurn | iOS | [vk-turn-proxy-ios](https://github.com/anton48/vk-turn-proxy-ios) |

## Credits

- **RKN-Guard & Scanner Subnet Defense**: inspired by [rkn-guard](https://github.com/Flecksis/rkn-guard) by [@Flecksis](https://github.com/Flecksis), re-engineered natively on `nftables` (`table inet obhod_ddos`) with interval CIDR collapsing, offline seed fallback, allowlists, manual bans, and live background synchronization.

