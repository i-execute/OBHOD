<p align="center">
  <a href="https://t.me/I_execute"><img src="https://img.shields.io/badge/Telegram-@I__execute-26A5E4?style=flat&logo=telegram&logoColor=white" alt="Telegram" /></a>
</p>

# OBHOD

Telegram bot over MTProto that manages the server it runs on and hands out post quantum VLESS subscriptions.
It never talks to another machine over SSH: the management channel is loopback only, every agent is a local `argv`.

## Install

```
curl -fsSL https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh | sudo bash
```

Root only, installs into `/opt/obhod`, state in `/var/lib/obhod`, runs as `obhod.service`.
The installer reads the bot token with `read -r -s`, writes `/etc/obhod/obhod.env` as `0600` inside a `0700`
directory and drops the variables from the shell, so a key never reaches the process list, the history or a log.

## Cores

Nothing is hardcoded to one engine. `BOT/cores.py` is a registry, the home screen is a summary of every core
that is registered, and every button lands on a concrete core.

| Core | Role | Version |
| --- | --- | --- |
| Xray | VLESS inbounds, subscriptions | `latest` from the release api, fallback `v26.10.31` |
| FreeTurn | `vk` call transport engine, `freeturn://` links | `latest` from the release api, fallback `v4.1.2` |

Both answer through the same proto 3 envelope, so one code path parses them. They run side by side and
`Core switch` only decides which panel the bot opens by default. Adding a core is a `Core` entry plus a screen.

## Protocol

`vless` only, networks `raw`, `grpc`, `xhttp`, security `reality`, `tls`, `none`.
Encryption is always `mlkem768x25519plus.<native|xorpub|random>.<600s|300-600s|0s>[.<padding>].<key>`, and REALITY can
carry an `ML-DSA-65` signature. No `vmess`, `trojan`, `shadowsocks`, `ws`, `httpupgrade`, `kcp`, `quic`.

## Commands

`/start` shows the core summary plus the guides below. Telegram caps a command at 32 characters, so a longer
name is registered through its menu alias while the bot still accepts the long form.

| Command | Menu alias | Screen |
| --- | --- | --- |
| `/start` | same | core summary, one button per core |
| `/whitelist_bypass_wg_vk_call_raskur` | `/whitelist_bypass_wg_vk_call` | wireguard over the vk call, steps, both cores |
| `/vless_rkn_bypass_raskur` | same | vless with REALITY against RKN, steps, both cores |

## Subscriptions

3x-ui style, by raw `ip:port`, no tunnel needed: `http://203.0.113.10:2096/<64 chars>/<64 chars>`.
Both segments come from `secrets` over `A-Za-z0-9-_`. There is always exactly one subscription and it serves
every link of every enabled inbound on the server, so a new config lands in the same link without a new url.
The path is the canonical client path and does not change when an inbound is added, disabled or removed.
`/<64>/<64>/json` returns the same list as JSON, `/<64>/<64>/info` and `?format=info` return the 3x-ui page
context, `?format=clash` answers 400. The server sends `Profile-Update-Interval`, `Profile-Title`,
`Profile-Web-Page-Url`, `Support-Url`, `Announce` and `Subscription-Userinfo` with the real quota and the
traffic taken from `xray api statsquery`, answers `404` for a wrong key, a short segment or an unknown id,
rate limits each address at 60 requests a minute and backs off exponentially on repeated misses. The bot pushes the registry after
every change, so the link is live without pressing apply.

## Cores, scripts and cache

The FreeTurn install script is downloaded once, cached under `/var/lib/obhod/freeturn` as `0600` and rechecked
against its pinned `sha256` on every read, so a changed upstream file can never break a running install.
`Debug` then `Scripts` probes the upstream copy, lists every file that a fetch would replace and warns that the
cache resets, and only a second tap downloads: `https` and github hosts only, redirect hops included.

## Firewall

FreeTurn traffic arrives from the vk TURN relays, so the `Call relay firewall` screen offers `open`, `vk relays only`
and `closed`. The prefixes are the announced `AS47541` and `AS47764` ranges from `stat.ripe.net`, cached for a day,
about 95 prefixes today. `firewalld`, `ufw` and plain `iptables` are supported, the `OBHOD-FT` chain is separate
from the default policy, and nothing is interpolated into a shell.

The guard never turns the machine into a fortress. `BOT/portguard.py` builds a keep list from the ssh ports, every
xray inbound, the subscription port and the panel port, and both the bot and the agent refuse to close or to
narrow a port in that list. Only the engine port changes. A host that also runs 3x-ui keeps its own jail, its
`f2b-3x-ipl` chain and its inbounds untouched, and its configs keep working.

## Debug menu

`Debug` holds a subnet and domain scanner, a traceroute with hop count, `refresh vk subnets` which rescans the
domains and reparses the prefixes into the firewall, the open port list with the protected rows marked, the emoji
switch, an event trail, and the script cache. Every screen is rich HTML, every action that takes longer than half
a second first edits the message into a loading screen, and any failure is sent as a second message with the full
traceback in a code block.

## Localization

`BOT/strings.py` holds `EN`, `RU` and `ZH` with the same variables, 1010 today, with and without emoji.
`BOT/i18n.py` looks a variable up by name, falls back to English, refuses a missing key or a forgotten
placeholder and exposes `check_catalogs()` for the parity test. Raise messages, logs and shell output stay English.

## Security

* The proxy has no password: VLESS is a UUID plus `mlkem768x25519plus`, subscriptions are two 64 character secrets
  compared with `hmac.compare_digest`, and any invalid path returns the same `404`.
* `BOT/shell.py` runs local processes as the root the bot already is, with argv lists and without a shell, so a
  config value can never become a command line. `SshSettings` has no field that could hold a credential.
* Release downloads are allowlisted to `https` and github hosts, every redirect hop is rechecked, archives are
  capped at 256 MiB and a release without a published digest is refused instead of installed unsigned.
* The bot limits itself: 60 messages, 90 callbacks and 30 inline queries per minute per user, a smaller budget for
  expensive callbacks, a repeat inside two seconds refused, admin claim private chat only and only in the first
  fifteen minutes.
* `sub_server.py` rate limits, bounds its bucket table, sets socket timeouts, truncates paths and sanitizes headers.
* A failed core start rolls back to the `0600` backup of the previous `config.json`; the write itself is atomic.
* Units run with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `RestrictNamespaces`.
  `sshd` gets `MaxAuthTries 3`, no forwarding, no tunnel, and password login is refused while no key is present.

## Layout

```
BOT/            app, panels, screens, cores, scripts, net, subs, commands, dbg, portguard, ui, i18n, strings
Storage/remote/ agents: xray, subscription server, fail2ban, ssh, freeturn
tools/          policy assertions and the protection baseline
tests/          the suite
```

## Update

`Update` works on the source checkout the bot runs from, offers `Latest commit` and `Latest release`, checks the
new tree with `compileall` and rolls back a tree that does not compile, installs dependencies only when the file
changed, restarts after the answer is delivered and verifies the marker on the next start.

## Tests

```
python -m pytest
```

2123 tests cover the post quantum strings, links, config generation, state, subscriptions and the running
subscription server, the scanner, every screen and callback route, the admin gate, the fail2ban files, the ssh,
xray and freeturn agents, the script cache, the core registry, the port guard, the commands, the loading states,
the three catalogues with their placeholder parity, and the hardening suites in `tests/test_security.py` and
`tests/test_pentest.py`. `tests/test_source.py` fails the build on a Python comment, docstring, emoji or long
dash, and on any Cyrillic or CJK character outside `BOT/strings.py`.

`.github/workflows` runs the suite, the security jobs and CodeQL on every push;
`python tools/obhod_watchdog.py verify` must pass before a merge and `seal` accepts a new baseline.
