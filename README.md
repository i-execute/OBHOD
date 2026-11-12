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

## Clients

| Kind | Platform | Client |
| --- | --- | --- |
| VLESS | All platforms | [INCY](https://github.com/INCY-DEV/incy-platforms) |
| FreeTurn | Android | [turn-proxy-android](https://github.com/hackdiaz-dev/turn-proxy-android) |
| FreeTurn | iOS | [vk-turn-proxy-ios](https://github.com/anton48/vk-turn-proxy-ios) |

## Credits

- **RKN-Guard & Scanner Subnet Defense**: inspired by [rkn-guard](https://github.com/Flecksis/rkn-guard) by [@Flecksis](https://github.com/Flecksis), re-engineered natively on `nftables` (`table inet obhod_ddos`) with interval CIDR collapsing, offline seed fallback, allowlists, manual bans, and live background synchronization.

