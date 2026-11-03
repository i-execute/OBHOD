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

`/start` shows the core summary plus both guides. Two long commands do the heavy lifting, each one opens
straight into its own transport and its own set of clients.

**WG RASKUR** - `/whitelist_bypass_wg_vk_call_raskur`

wireguard inside a vk call: the provider sees a voice stream, not a tunnel. The screen walks through the
peer, the turn relay, the rtpopus obfuscation and the firewall that keeps only the fresh vk prefixes, then
hands you the client for your phone: [free turn for android](https://github.com/hackdiaz-dev/turn-proxy-android)
and [free turn for ios](https://github.com/anton48/vk-turn-proxy-ios).

**VLESS RASKUR** - `/vless_rkn_raw_tcp_xhttp_ws_raskur`

vless over reality against the rkn: the handshake is a real tls handshake of someone else's site, with
post quantum ml-kem and the ml-dsa-65 signature on top. Clients are the
[INCY ones](https://github.com/INCY-DEV/incy-platforms), one builds for every platform.

### Clients

| Kind | Platform | Client |
| --- | --- | --- |
| FreeTurn | android | [turn-proxy-android](https://github.com/hackdiaz-dev/turn-proxy-android) |
| FreeTurn | ios | [vk-turn-proxy-ios](https://github.com/anton48/vk-turn-proxy-ios) |
| VLESS | all platforms | [INCY](https://github.com/INCY-DEV/incy-platforms) |

The bot menu registers `/whitelist_bypass_wg_vk_call` (a 32 character Telegram limit) and keeps accepting the
full names, plus the old `/vless_rkn_bypass_raskur` as an alias.

## Subscriptions

3x-ui style, but only with a permanent name: `https://<host>.<tailnet>.ts.net/<64 chars>/<64 chars>`.
Without a domain there is no endpoint at all: the `Subscriptions` screen hides apply, sync, stop and rotate,
the panel answers with a notice, the bot skips the push even when forced, and the agent refuses
`sub-install` and `sub-sync` with `no_domain`, so no file and no unit is written. The listener binds
`127.0.0.1:<sub port>` and only the tunnel publishes it.
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

## Ports

Nothing on the server is killed to make room. The installer checks `ss` (or `/proc/net`) for the subscription
port `2096` and the api port `62789` before it writes the env, and when one is taken it walks forward to the
first free neighbour and stores it as `OBHOD_SUB_PORT` / `OBHOD_API_PORT`; the same walk happens in the panel
before every apply, so the metrics listener moves off `11111` when a 3x-ui install already holds it. A port
owned by someone else is reported with the process name and the inbound is moved instead of the owner.
The vless encryption screen offers the six 3x-ui kinds, `mlkem768x25519plus.<native|xorpub|random>.<x25519|mlkem768>`,
and the keys come from `xray vlessenc` on the server, so the auth half is real and not a label.

## A permanent name

The subscription keeps the bare ip out of the url. The Xray home screen has a `domain` button that installs
tailscale from its signed repository, takes a hostname, and runs
`tailscale funnel --bg --https=443 http://127.0.0.1:<sub port>`. The name is `<hostname>.<tailnet>.ts.net`, it
survives reboots and ip changes, the certificate is real, the port stays on loopback and vless inbounds never go
through the tunnel. While the tunnel is on the subscription url is `https://<hostname>/<64>/<64>` with no port,
and while it is off the url does not exist.
The `tskey-auth-` key never travels through the chat: the `auth key` button opens the inline field, the picked
result carries an encoded payload instead of the key, and the key itself is written to `<state dir>/tunnel.key`
with mode `0600` and shown on the screen as `tskey-auth-k7...pnCe`. It is never stored in `state.json`, never in
a log and never in a rendered screen. Turning the tunnel off takes the subscription service down with it.
Behind any local proxy the server reads the visitor from `X-Forwarded-For`, falling back to `CF-Connecting-IP`
only for a loopback peer, so one visitor cannot outrun the 60 a minute limit by faking a header.

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
switch, an event trail, the script cache, and `Cheburcheck`, which asks `cheburcheck.ru` about an ip, a domain,
a subnet or an as number: the registry answer from `/api/v1/check` and the live probe stream from
`/api/v1/probe`, one line per online probe with its provider and verdict, then the share of blocking answers and
the resulting verdict. Every answer carries a quoted sentence that says what it means for the server: a blocked
verdict reads `the server is banned, xray from this address will not work from russia`, a clean one says the
opposite, and a checker that cannot be reached from the server itself is reported as `the host is already cut
off from the russian segment`. The `API reachability` button measures dns and tcp 443 against `cheburcheck.ru`
so a ban can be told apart from a broken route. Every screen is rich HTML, every action that takes longer than
half a second first edits the message into a loading screen, and any failure is sent as a second message with
the full traceback in a code block.

## RKN exposure

`Debug` also holds `RKN exposure`, which answers the question the october 2026 filter asks first: how does this
server look from the outside. It reads the kernel release, `net.mptcp.enabled`, `net.ipv4.tcp_migrate_req` and
`ss -Mln` (adding `-t` to that call hides exactly the sockets we look for), compares the release against the known
fixed builds, takes the core version from the state report and the reality fingerprints and transports from the
inbounds, and asks the registry for the asn, the owner and the country of the server address. The verdict is
`clean`, `attention` or `danger`, opened by one quoted sentence: `the server is reachable for a remote root: ...`
when an mptcp listener is up, `one weak spot is open: ...` for a mass fingerprint or a mass hosting subnet, and
`engine and kernel look right, no mptcp listener, no mass fingerprint` otherwise. A kernel series that is not in
the table is reported as untracked, never as patched. The findings block names the risk in words, and the
`what to run` block prints the commands, including the two traps: `net.mptcp.enabled=0` plus
`net.ipv4.tcp_migrate_req=0`, the nftables rule that drops tcp options as an interim only, and `ss -Mlnp` for the
check. Nothing is applied from the screen, because the host wide switches touch other services.

The generator side matches the screen: `sockopt.tcpMptcp` is `false` on every inbound, the default reality
fingerprint is `firefox` and not the mass `chrome`, `360` and `qq` are accepted, and `client_config()` renders a
client json with `mux` at `concurrency 8`, except under `xtls-rprx-vision`, where the core ignores mux and the json
says so by leaving it out.

## Honeypot

`Debug` holds `honeypot`, a daemon on decoy ports that nothing legitimate uses. Every connection is hostile by
definition, so one touch is enough: the line `honeypot ip=<HOST> port=<n> proto=<p> event=<e>` is the only shape
the fail2ban filter accepts, `maxretry = 1` and the ban is seven days. The ssh facade sends the banner of the real
`sshd` of the box and a well formed `SSH_MSG_KEXINIT` with modern algorithms, so a version scanner sees a plausible
server; ftp, telnet, redis, http and rdp answer with their own greetings. Plaintext logins are captured, the
password is stored as a truncated sha256 and never in the clear. The limits are part of the design: a global
connection cap, two per address, an idle timeout, an 8192 byte read, one log line per connection, no outbound
socket, no shell and nothing proxied. The install refuses to shadow a port that already answers.

## Notifications

`notifications` in the same menu decides what reaches the owner: a port scan (twelve distinct ports from one
address inside five minutes), ssh brute force (ten failures inside ten minutes), a new ban, a honeypot touch, a
subscription flood and a core event. Each kind has its own switch and cooldown, addresses are deduplicated, and the
queue is bounded, so an attack cannot become a message flood. Delivery goes to `admin_id` and to nobody else: with
no owner claimed the events are collected and never sent. `send a test` proves the path end to end.

## Localization

`BOT/strings.py` holds `EN`, `RU` and `ZH` with the same variables, 1325 today, with and without emoji.
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
BOT/            app, panels, screens, cores, scripts, net, subs, commands, dbg, dpi, notify, portguard, ui, i18n, strings
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

2367 tests cover the post quantum strings, links, config generation, state, subscriptions and the running
subscription server, the scanner, every screen and callback route, the admin gate, the fail2ban files, the ssh,
xray and freeturn agents, the script cache, the core registry, the port guard, the commands, the loading states,
the three catalogues with their placeholder parity, the cheburcheck client with a fake transport and a fake socket, the dpi survey with a synthetic
kernel state, the generator guards for sockopt, mux and the fingerprint, the honeypot with a live socket, its own
protocol facades and a log injection battery, the notification engine with its cooldowns and its owner-only delivery,
the emoji invariants against the vendored pack, and the hardening suites in `tests/test_security.py` and
`tests/test_pentest.py`. `tests/test_source.py` fails the build on a Python comment, docstring, emoji or long
dash, and on any Cyrillic or CJK character outside `BOT/strings.py`.

`.github/workflows` runs the suite, the security jobs and CodeQL on every push;
`python tools/obhod_watchdog.py verify` must pass before a merge and `seal` accepts a new baseline.
