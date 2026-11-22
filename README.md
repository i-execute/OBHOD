<p align="center">
  <a href="https://t.me/I_execute"><img src="https://img.shields.io/badge/Telegram-@I__execute-26A5E4?style=flat&logo=telegram&logoColor=white" alt="Telegram" /></a>
</p>

# OBHOD

MTProto Telegram panel for locally managing `Xray` (post-quantum `VLESS` over `REALITY` / `TLS` with `mlkem768x25519plus` and `ML-DSA-65`) and `FreeTurn` (WireGuard over VK call TURN relays) on a Linux server.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh | sudo bash
```

Requires root on a systemd Linux host with Python 3.13+. It installs to `/opt/obhod`, keeps state in `/var/lib/obhod`, protects `/etc/obhod/obhod.env` with mode `0600`, and runs `obhod.service`. Use `sudo obhod` for the management TUI.

## Releases

OBHOD asks the GitHub releases API for the latest stable component release. If that API is unavailable or rate-limited, it uses the recommended pinned fallback; a latest release without a verifiable checksum is refused rather than silently substituted.

| Component | Recommended fallback | Minimum |
| --- | --- | --- |
| Xray | `v26.11.9` | `v26.10.31` |
| FreeTurn | `v4.2.1` | `v4.1.2` |

Pins live in the bot and remote agents. Updating FreeTurn pins also requires updating its bundled installer artifact. No GitHub token is used.
## RKN / Anti-DDoS

The native `nftables` Anti-DDoS and optional RKN scanner-subnet filter operate in `table inet obhod_ddos`. A system install attempts activation, but verify live state in **Tools -> Anti-DDoS** and keep an out-of-band server console before changing firewall policy.
The screen includes source-list controls with a last-good cache, allowlists, scoped IP/protocol/port exceptions, manual bans, bounded logs, scheduled source updates, and explicit recovery confirmation. The optional RKN-Guard binary is a separately pinned v3.0.0 diagnostic helper only: it never replaces the native backend, starts an upstream service, or changes firewall rules. See the [RKN protection guide](docs/RKN.md).
## Interface languages

English, Russian, and Chinese catalogs are checked by the CI i18n audit.

## Clients

| Kind | Platform | Client |
| --- | --- | --- |
| VLESS | All platforms | [INCY](https://github.com/INCY-DEV/incy-platforms) |
| FreeTurn | Android | [turn-proxy-android](https://github.com/hackdiaz-dev/turn-proxy-android) |
| FreeTurn | iOS | [vk-turn-proxy-ios](https://github.com/anton48/vk-turn-proxy-ios) |

## Credits

RKN-Guard and Scanner Subnet Defense are inspired by [rkn-guard](https://github.com/Flecksis/rkn-guard) by [@Flecksis](https://github.com/Flecksis), re-engineered natively with interval CIDR collapsing, offline seed fallback, allowlists, manual bans, and background synchronization.
