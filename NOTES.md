# NOTES

## Эталон `turn-proxy-android` (`v5.3.1`) и `free-turn-proxy` (`v4.1.2`)
- `turn-proxy-android` вшивает релизный `install.sh` (`PROTO_VERSION=3`, SHA-256 `91fcea2aa5558d019431da31aa1f32baa0ffb943600529810e073ffa22f83100`) локально в `assets/install.sh` и исполняет его как `[sudo] bash -s -- <argv>`.
- `cmd/server/main.go` в `free-turn-proxy` `v4.1.2` всегда открывает внешний сокет `UDP` (`net.ListenPacket("udp", cfg.ListenAddr)`) вне зависимости от `-mode tcp|udp`. Слой 2 (`wire.ListenPacket`) разворачивает `rtpopus3` через AEAD ChaCha20-Poly1305 с `-obf-key` до DTLS; при несовпадении ключа/профиля/версии или закрытом UDP-порте пакет молча отбрасывается (`RX 0 B`, `DTLS: handshake error: context deadline exceeded`).
- `ShareLinkBuilder.kt` кодирует `freeturn://<base64url>` с JSON, где `transport` опускается для `tcp` и равен `"udp"` для `udp`.

## Корневая цепочка отказа `89.125.48.221:56000` после `f9e3010`
1. `ftpanel.guard_proto` возвращал `"tcp"` при `mode == "tcp"` (`use_udp=false` в логе `vpn-export_36qhv.log`), из-за чего `ft:fw:vk` / `ft:fw:open` открывали `56000/tcp`, оставляя `56000/udp` закрытым.
2. `guard_status("ufw", ...)` проверял `mentions_port` без протокола (`56000/tcp` определялся как `"vk"`), а `guard_status("iptables", ...)` проверял `iptables_chain_present()` без проверки `-C INPUT -p udp --dport <port> -j OBHOD-FT`.
3. `ensure_apply_port_open` выходил на `if found_mode == "vk": return`, оставляя `56000/udp` заблокированным.
4. `run_tool` не резолвил бинарники из `/usr/sbin:/sbin` на стороне клиента перед вызовом `systemd-run` (который ищет `argv[0]` в `PATH` вызывающего процесса до старта юнита) и не ставил `--`.
5. `heal_runtime` вызывался только на `apply` (не на `probe`, `client-conf`, `restart`, `client-list` и не на старте `Bot.run()`) и не сверял живые аргументы демона (`server.env` / `docker inspect`, версию бинаря `v4.1.2`, `owner` в `clients.json`, `ft-wg0`, `ip_forward=1`) с `install.conf`.

## Найденные баги ключей и дубли UI
- `BOT/panel.py:1309-1318`: `self.view` (`XrayView`) вместо `self.bot.view` (`BotView`) падает с `AttributeError` на 4 полях; `self.bot.ban_view` и `self.bot.sshd_view` возвращались вместо `screens.ban_screen(...)` и `screens.sshd_screen(...)` на 6 полях.
- `BOT/inline.py` / `BOT/app.py`: нет `ft_connect` для `backend == "external"`, `Bot.input_values()` заполняет только 17 из 52 полей, `INL_SAVE_DESC` вызывается с лишним `value=...`.
- Дубли UI: `tools:*` vs `dbg:*` и мёртвый `tools:fw:status` вместо `ft:fw`; `nav:quick` и `nav:emoji` дублируют `home`/`settings`; `nav:ssh` дублирует `nav:sshd`; `ftscreens.plan_screen` перегружен 5 рядами инлайн-кнопок и показывает WG-поля при `external`.
