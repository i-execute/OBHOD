<p align="center">
  <a href="https://t.me/I_execute"><img src="https://img.shields.io/badge/Telegram-@I__execute-26A5E4?style=flat&logo=telegram&logoColor=white" alt="Telegram" /></a>
</p>

# OBHOD

## Install

```
curl -fsSL https://raw.githubusercontent.com/i-execute/OBHOD/main/get.sh | sudo bash
```

The installer refuses a non root user, installs into `/opt/obhod`, keeps the state in `/var/lib/obhod`, and the bot is
started as `obhod.service`. Reinstalling removes the previous installation first.

## What it is

Telegram bot over MTProto that manages the Xray server it runs on and hands out post quantum VLESS subscriptions.
It never talks to another machine over SSH: the management channel is pinned to loopback.

The whole product is post quantum: the client and the server agree on `X25519MLKEM768` inside the VLESS handshake
(`mlkem768x25519plus`), and REALITY can add an `ML-DSA-65` signature (`mldsa65Seed` on the server, `pqv` in the link).
Nothing classical is offered anywhere: no `vmess`, no `trojan`, no `shadowsocks`, no `ws`, no `httpupgrade`, no `kcp`,
no `quic`, no `xtls-rprx-direct`.

The bot drives two cores side by side and picks either one from the `Core switch` screen: Xray for the VLESS inbounds and
subscriptions, and FreeTurn, a `vk` turn transport engine, for its own plans, clients and `freeturn://` links. A client app
for your platform lives in https://github.com/INCY-DEV/incy-platforms. Both cores
answer through the same proto 3 envelope, so one code path parses them, and switching the core only changes which panel
the bot opens by default.

## What it does

| Area | Behaviour |
| --- | --- |
| Protocol | `vless` only |
| Networks | `raw`, `grpc`, `xhttp` |
| Security | `reality`, `tls`, `none` |
| VLESS encryption | `mlkem768x25519plus.<native\|xorpub\|random>.<600s\|300-600s\|0s>[.<padding>].<key>` |
| REALITY signature | optional `ML-DSA-65`, enabled only when the target chain is at least 3500 bytes |
| Core | Xray pinned to `v26.10.21`, `latest` also selectable, release zip checked against a pinned digest |
| Second core | FreeTurn (`vk` turn transport) v4.1.0, install script fetched from the release on every call and checked against a pinned digest |
| Core switch | `Core switch` screen picks Xray or FreeTurn for the interface, both cores may run side by side |
| Scanner | certificate check, TLS 1.3, `h2`, and a raw ClientHello carrying a real ML-KEM-768 key share |
| Subscriptions | `http://host:port/<64 chars>/<64 chars>`, both segments from `secrets`, url safe alphabet |
| Fail2ban | jail `obhod-ipl` plus `obhod-sshd`, iptables chain `OBHOD-IPL` with exempt ports |
| SSH | port, password login, root login and public keys managed by a script that runs on the server |
| SSH key gate | the password switch is refused while the account has no public key, the screen lists the keys that open this machine with their `SHA256` fingerprints |
| Interface | rich GoyGram messages, only `callback_data` buttons, every input through an opaque inline token |
| Inline values | a fixed set of choices (fingerprint, alpn, flow, log level, ports, durations) is returned as inline results, never typed |
| Languages | `en`, `ru`, `zh`, chosen in the menu and stored in the bot state, English by default and as the fallback |

## Layout

```
.github/
  workflows/    ci, security, codeql and the protection drift job
tools/
  obhod_watchdog.py           policy assertions and the protection baseline
  obhod_protection.baseline.json
BOT/
  app.py        telegram wiring, admin gate, sshd inputs, fail2ban and sshd actions
  panel.py      xray panel, callback router, field validation, subscriptions
  screens.py    home, ssh access, settings, fail2ban, sshd, help
  xscreens.py   xray screens, relevant fields per security and network
  freeturn.py   freeturn models, plan validation, proto 3 client, link codec
  ftpanel.py    freeturn callback router, plan cycles, clients, core switch
  ftscreens.py  freeturn screens, plan, clients, owner link, logs
  xray.py       vless model, post quantum encryption, links, config, state
  scan.py       post quantum probe, certificate parsing, ranking, candidate list
  xrayrpc.py    RPC client, script bootstrap, subscription state
  guard.py      fail2ban and sshd actions for the server scripts
  bootstrap.py  installs the bot itself on the local machine
  config.py     env loading
  models.py     sshd port setting and validators
  shell.py      local command execution, root check, argv only
  store.py      atomic state file, remembers the interface language
  i18n.py       lookup by variable, fallback to English, the language switch
  strings.py    classes EN, RU and ZH with identical variables
  ui.py         rich html helpers
  inline.py     inline tokens, fixed value lists, marker payloads
Storage/
  remote/xray_agent.py    core install, config apply, keys, subscription service
  remote/sub_server.py    subscription http server
  remote/fail2ban_agent.py jail, filter, action, bans
  remote/ssh_agent.py     sshd drop in, keys, restart
  remote/freeturn_agent.py  install script download with a pinned digest, proto 3 runner
  obhod-install.sh        bot installer
  obhod.service           bot unit
get.sh                      curl one liner
tests/                      test suite
```

## FreeTurn core

FreeTurn is a second engine next to Xray, driven through the same proto 3 envelope, so one code path parses both answers.

| Point | Behaviour |
| --- | --- |
| Script source | `https://github.com/hackdiaz-dev/free-turn-proxy/releases/download/v4.1.0/install.sh`, https only, github hosts only, certificate verified |
| Integrity | sha256 `91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100`, a mismatch stops the run before anything executes |
| Cache | `/var/lib/obhod/freeturn`, directory 0700, file 0600, digest rechecked on every read |
| Invocation | `bash <script> <command> --key=value`, argv only, no shell, stdin closed, per command timeouts |
| Plan fields | method `systemd\|docker`, backend `new\|external`, udp port, tunnel port and subnet, mode `udp\|tcp`, obfuscation `rtpopus3\|rtpopus2\|rtpopus\|none`, core version |
| Secrets | the obfuscation key and client ids stay on the server, the bot keeps only the fact that a key exists |
| Clients | `owner` is protected, guests are added by name, each guest gets a completed `freeturn://` link and a cleaned client config |
| Errors | the script code set is mapped to localized text, unknown codes fall back to the message from the script |

Client apps for `freeturn://` links:

| Platform | Client |
| --- | --- |
| iOS | https://github.com/anton48/vk-turn-proxy-ios |
| Android | https://github.com/hackdiaz-dev/turn-proxy-android |

## Crypto decisions

* VLESS encryption is mandatory: `settings.decryption` always carries `mlkem768x25519plus` and the client link always
  carries `encryption=mlkem768x25519plus.<mode>.<ticket>.<public key>`. An inbound without a generated key pair refuses to
  render settings or links.
* REALITY uses an `x25519` key pair for the handshake and an optional `ML-DSA-65` seed for the signature. `mldsa65Seed`
  appears in `realitySettings` only for `reality`, and only when both the seed and the verify value exist.
* The scanner treats a target as usable only when it completes TLS 1.3, negotiates `h2`, echoes the
  `X25519MLKEM768` share, and presents a chain that validates against the system store with a live expiry date.
* Choices that depend on the selected security and network are the only ones shown first; the rest stay available in a
  collapsed block, driven by `relevant_fields(security, network)`.

## Localization

Every user facing string lives in `BOT/strings.py` as a class variable: `EN`, `RU` and `ZH` hold the same set of 746
variables, the Chinese column is written in Chinese, and parameterized strings use `{placeholders}`. `BOT/i18n.py` looks a
variable up by name (`i18n.t("HOME_TITLE", "ru")`), normalizes a language tag, falls back to English, refuses a key that is
missing or a call that forgets a placeholder, and exposes `check_catalogs()` for the parity test. The bot starts in
English, the language screen lists `en`, `ru` and `zh`, the choice is written into the state file by `store.py` and every
later message, button, hint, error and inline result is rendered in it. Raise messages, log records, RPC stages and shell
output stay English and are deliberately outside the catalogue.

## Inline input

A text value is never carried by a button. `BOT/inline.py` keeps a registry of `(field, context, mode)` triples and maps
each of them to a ten character token from `[a-z2-7]`, the first ten characters of an `hmac_sha256` over
`mode|field|context` with a key generated once at start (`inline.configure` accepts a hex secret, otherwise hashes it, and
falls back to `os.urandom(32)`). The token for the same triple is always the same inside one process, so a button that the
user presses twice behaves the same way, while two different fields never share a token and the input mode and the list
mode of one field differ on purpose.

The result of pressing an input button is `switch_inline_query_current_chat` with `"<token> "`, so the query field shows
`@bot oxw2xbkugl` and nothing else, which is exactly the Feroku flow: the user types the value after the code and the bot
resolves the code back to the field. While the value is being typed the single result is titled with a cycling symbol
(`ABXY`, `1234`, `abcd`, `wxyz` by length) so the list visibly reacts.

A field with a fixed set of values (`xr_fingerprint`, `xr_alpn`, `xr_client_flow`, `xr_log_level`, `xr_port`,
`xr_sub_port`, `xr_bantime`, `xr_ssh_bantime`, `xr_ssh_maxretry`, `xr_scan_xver`, `xr_spider_x`, `xr_client_limit`,
`xr_sub_refresh`, `ft_port`, `ft_wg_port`, `ft_wg_net`, `ssh_new_port`) has two
buttons: the pen prefills the input token and the list button prefills the list token. The list token returns one card per
allowed value, nothing to type, the same idea as `DevTool.py` in `i-execute/Modules`. A field without a fixed set (sni,
remark, dns, targets, a public key) has only the pen.

The chosen value comes back through the `chosen_inline_result` update, which the bot registers with `app.on_update`; the
update carries the result id (`i:<token>`, `o:<token>:<index>`, `s:<token>` for a stale token) and the query, and the bot
resolves the value itself instead of trusting the text. BotFather has to hand that update to the bot: send `/setinline`,
then `/setinlinefeedback` and pick `Enabled` for the bot, otherwise Telegram sends the query but never the choice.
When the inline query is sent as a message in a chat, the bot also receives a marker (`\U0001F4DD` followed by an
invisible separator, the token and a base 32 payload), deletes that message at once with `deleteMessage`, and applies the
value from the payload, so a value is never left behind in the chat history. Inline and the direct message path are both
closed to everyone except the owner: a foreign query gets an empty answer, a foreign `chosen_inline_result` is dropped
before the rate limiter, and `on_message` runs the same admin gate as every other screen. A repeated value inside eight
seconds is ignored so a double delivery cannot apply the same write twice.

## Continuous checks

`.github/workflows` runs the suite on every push and pull request: the fast job on Python 3.12, a security job with the
pentest and hardening files, a wider matrix on `main`, CodeQL with the extended query set, and a protection job that
fails when a security decision quietly changes. `tools/obhod_watchdog.py` holds the two layers: twelve policy assertions
over the source, and a sha256 baseline of the thirteen files that carry a security decision. `python
tools/obhod_watchdog.py verify` is the command that must pass before a merge, `seal` is the deliberate act that accepts a
new baseline. `CI.md` explains the triggers, the cost, and the one step that lives in the repository settings.

## Subscriptions

Each client gets two secrets of exactly 64 characters from `A-Za-z0-9-_`, produced by `secrets.choice`. The path is
`/<sub_id>/<sub_key>`, so the address looks like `http://203.0.113.10:2096/<64>/<64>`. The path of the 3x-ui panel
(`/sub/<id>`) is never used. `sub_registry` maps `sub_id` to the key, the links, the title and the filename, and
`Storage/remote/sub_server.py` serves `base64` of the link list with `profile-update-interval` and `subscription-userinfo`
headers, answering `404` for a wrong key and `403` for a disabled entry.

## Fail2ban

`Storage/remote/fail2ban_agent.py` writes three jails and one action:

| Jail | Filter | Threshold | Ban |
| --- | --- | --- | --- |
| `obhod-ipl` | `[LIMIT_IP] Email = ... \|\| Disconnecting OLD IP = ...` in the xray access log | `maxretry = 1`, `findtime = 1920` | `30m`, editable in minutes |
| `obhod-sshd` | the sshd filter over `/var/log/auth.log` or `/var/log/secure` | `maxretry = 3`, `findtime = 3600` | `3d` by default, any value with `s`, `m`, `h`, `d` or `w` |
| `obhod-subs` | `^sub 40[34] <ADDR>$` from the subscription log | `maxretry = 20`, `findtime = 600` | `3d`, the same duration as the ssh jail |

`action.d/obhod-ipl.conf` keeps an `OBHOD-IPL` chain as the first rule of `INPUT` in both `iptables` and `ip6tables`, with the
ssh and subscription ports exempted, so a banned address is dropped for TCP and still cannot reach the proxy.
Everything the agent writes is prefixed with `obhod`, so a machine that already runs [3x-ui](https://github.com/MHSanaei/3x-ui)
keeps its own `3x-ipl` jail, its `filter.d`, `jail.d` and `action.d` files and its `f2b-3x-ipl` chain untouched: the two
mechanisms sit next to each other and never share a name. An install also looks at the three `3x-ipl` files, removes them
only when the content is byte for byte what an older build of this bot wrote, and reports the presence of a foreign jail as
`coexists_3x_ui` in the status. The ssh port for the exempt list is read from `/etc/ssh/sshd_config` and from every
`/etc/ssh/sshd_config.d/*.conf`, with `Match` blocks ignored, so a non standard port never ends up banned.

All three jails carry `ignoreip = 127.0.0.1/8 ::1` by default, editable from the bot (addresses are parsed and validated,
a newline never reaches the config). Durations are written with an explicit suffix, so `bantime = 30m` is thirty minutes
and `bantime = 3d` is three days, never a bare number that fail2ban would read as seconds. The bot can install, remove,
reset and report the jails, and never touches the server without an explicit button.

## Security

The repository is written for a host that is exposed to the whole internet, so the defaults are the hardening:

* The proxy has no password at all: VLESS authenticates with a UUID and `mlkem768x25519plus`, subscriptions with two
  64 character secrets compared with `hmac.compare_digest`, and an invalid path returns the same `404` for an unknown id
  and a wrong key.
* `sub_server.py` rate limits every address (60 requests per minute by default, `429` above it), caps concurrent handlers
  with a semaphore (`503` when the queue is full), sets a fifteen second socket timeout so a slow client cannot hold a
  thread, truncates the request path, and sanitizes every header value, so a title or a filename cannot inject a header.
* The release download is allowlisted: `https` only, `github.com`, `objects.githubusercontent.com` or
  `release-assets.githubusercontent.com` only, `.zip` or `.dgst` only, no credentials in the url, at most three
  redirects and every redirect hop is checked against the same allowlist, and a local `file://` archive must live under
  `/opt`, `/tmp` or `/usr/local/bin`. A download is capped at 256 MiB and a release without a digest is refused instead
  of installed unsigned.
* The bot limits itself before it does any work: 60 messages, 90 callbacks and 30 inline queries per minute per user, a
  separate budget of 10 for an expensive callback, and the admin claim is private chat only. A callback that repeats
  inside two seconds is refused with a toast, so a double tap or a forged replay cannot fire an action twice. The
  security trail is bounded to 200 events, keeps actor, action and outcome, and marks a field as secret by name only,
  never by value.
* A failed core start is rolled back: the previous `config.json` is copied to a `0600` backup before the write, and when
  the new configuration does not come up the old one is restored and the core is started again. The config write itself
  is atomic, so a crash cannot leave a half written file, and a symlink at the target path is refused.
* `sub_server.py` answers a repeated miss with exponential backoff: ten misses or refusals from one address start a
  block that doubles from one minute up to one hour, one success clears the counters, the counter itself is capped at
  eight offences, and the bucket table is bounded to 4096 addresses so a scan cannot grow it without limit.
* The bot has no transport to another machine at all: there is no host, no user, no password, no key and no ssh client
  in the code. `BOT/shell.py` runs a local process as the same root the bot already is, with `argv` lists and without a
  shell, so a config value can never become a command line. `LocalShell.require_root` refuses to run as a plain user,
  and the state file cannot store a credential because `SshSettings` has no field for one.
* No password exists anywhere: the settings screen reports the local mode and only offers the sshd port and a public
  key, and the state file carries a port and nothing else.
* A stranger cannot claim the bot after the first fifteen minutes: with `ADMIN_ID` unset the first user claims it inside
  that window only, afterwards everyone is denied.
* Every unit runs with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  `RestrictNamespaces`, `RestrictSUIDSGID` and a narrow `RestrictAddressFamilies`. The state file is `0600` inside a `0700`
  directory and never appears in a log line; there is no password to log.
* `sshd` gets `MaxAuthTries 3`, `LoginGraceTime 20`, `X11Forwarding no`, `AllowAgentForwarding no`,
  `AllowTcpForwarding no` and `PermitTunnel no`, and password login is refused when the account has no authorized key, so
  the hardening cannot lock the administrator out.
* One client has one subscription, not one per inbound. `subscriptions` groups the clients by email, the entry carries
  every link of that client in `links`, and `sub_server` returns all of them in one base64 body. A second inbound with the
  same email inherits the identifiers of the first, so adding grpc and xhttp to a client does not create extra
  subscriptions, and rotation moves all of them at once.
* The subscription server allows ten requests per minute per address by default (`OBHOD_SUB_RATE`), and the installer
  and the bot validate their own inputs: the port is numeric inside the allowed range,
  the state directory is a simple absolute path, the timeouts are clamped, the log level is an allowlist, and the
  installer refuses a credential with a newline, a carriage return, an `=` or more than 200 characters.
* `tests/test_pentest.py` is the regression suite for this hardening: path traversal and header injection against the
  subscription server, backoff and bucket bounds, callback replay, expensive operation limits, a failed core start
  rolled back, hostile release urls and redirects, credential injection into the installer, and HTML escaping of a
  hostile inbound name.
* `tests/test_security.py` attacks the build: traversal and malformed subscription paths, header injection, a request
  flood, a slow client, hostile release urls and version strings, a credential that a state file tries to reintroduce,
  admin claim outside the window, shell metacharacters in the bootstrap script and unvalidated values.

## SSH scripts

Subscription links use `sub_address` when it is set, otherwise the address of the outbound interface of the machine
(detected without sending a packet, loopback and link local results are ignored), so a link never points at `127.0.0.1`.

The bot manages exactly one machine, the one it runs on, and it does it as a local process, not as a login. `BOT/shell.py`
holds the whole execution layer: `agent_argv` builds `[sys.executable, "-c", source, *argv]`, so the agent script and its
arguments stay separate argv entries and never meet a shell, and `LocalShell.require_root` refuses anything but `uid 0`.
`SshSettings` has a port and a mode string, `models.py` has no host, user, password, key, passphrase, fingerprint or auth
mode, and the state file cannot reintroduce one: unknown keys in `ssh` are ignored while loading. `BootstrapPlan` follows
the same rule, so `python -m BOT bootstrap` installs onto the current machine only. `requirements.txt` no longer lists
`asyncssh`, and `BOT/sshx.py` is gone.

`Storage/remote/ssh_agent.py` writes a drop in, validates it with `sshd -t`, restarts the service and rolls back on a
failure. It can change the port, switch `PasswordAuthentication`, set `PermitRootLogin` to `no` or `prohibit-password`,
and append a public key to the authorized keys of the first account that has a `.ssh` directory. Keys are appended one
after another without replacing the previous ones, and the same key is never written twice: the comparison uses the key
type and the base64 blob, so the same key with another comment is still recognised as a duplicate. Password login can be
switched back on at any time (`sshd:auth:yes`), while switching it off is refused until at least one key is present, so
the hardening cannot lock the administrator out. Both scripts are read
from this repository at call time and executed as a local argv through `BOT/shell.py`, so the repository is the single
source of truth and no copy of a script lives outside it.

## Configuration

The generated config follows the reference layout of 3x-ui: a `log` block that writes `access.log` and `error.log`
(fail2ban reads the access log), `dns` when resolvers are set, `stats`, a `policy` block with `statsUserUplink`,
`statsUserDownlink` and `statsUserOnline` per level, an `api` block with `HandlerService`, `LoggerService`, `StatsService`
and `RoutingService` plus the local `tunnel` inbound on `127.0.0.1:62789`, a `metrics` listener on `127.0.0.1:11111`,
`freedom` with `finalRules` that block `geoip:private` and a `blackhole`, and routing rules for the api, private networks
and `bittorrent`. The api port, the access log path, the dns list and the metrics listener are editable from Settings.

## Scanner

The probe sends a real ClientHello: TLS 1.3, cipher `0x1301`, the `server_name` extension, `supported_groups` with
`0x11ec` and `0x001d`, the signature algorithms Xray accepts, `supported_versions` and a key share of `0x11ec` built from a
1184 byte ML-KEM-768 encapsulation key plus a 32 byte X25519 share. It then parses the ServerHello, reads the certificate
chain through `MemoryBIO`, validates it, and reports latency, days left, the chosen group and whether the chain is long
enough for ML-DSA-65. `DEFAULT_CANDIDATES` holds 225 hosts, every one of them verified by a live run on 2026-10-27: all 225 complete the
probe, 114 of them present a chain long enough for `ML-DSA-65`, and the median latency is 114 ms.

## Tests

```
python -m pytest
```

767 tests cover the post quantum encryption strings, links, config generation, state, subscriptions, the scanner, every
screen, every callback route, the admin gate, the panel field rules, the fail2ban files, the ssh agent, the ssh key gate, the local shell, the running
subscription server, the freeturn plan rules, the link codec, the proto 3 client, the freeturn agent including digest, host and
injection refusals, the freeturn screens and router, plus the three catalogues, their placeholder parity and the hardening suite in
`tests/test_security.py`. `tests/test_source.py` fails the build if any
Python comment, docstring, emoji or long dash appears in the repository, and if any Cyrillic or CJK character appears
outside `BOT/strings.py`.
