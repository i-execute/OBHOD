# NOTES
## Environment and repo
- Python project, Telegram MTProto/GoyGram, Xray and FreeTurn controllers; local service and remote `Storage/remote/xray_agent.py` management.
- Existing env parser is `BOT/config.py`; env path is `/etc/obhod/obhod.env` (or configured `OBHOD_ENV`). Bootstrap rewrites env in `BOT/bootstrap.py`; shell installer preserves unknown env lines in `Storage/obhod_install.sh`.
- Xray subscription title is carried in Tailscale `Profile-Title` metadata from registry entry (`Storage/remote/sub_server.py`). Serverless static route can set headers in static config.
- `Bot.subs_sync` and `XrayPanel.push_subs_live` are both paths that can publish Xray subscription state; both require a tag gate.
- No actual production credentials, cloud endpoint probes, service actions, or live deployment will be used in this code/test task.

## Decisions
- Tag is an Xray-only profile title `OBHOD <tag>`; do not modify VLESS remarks/config links or FreeTurn.
- Manual tag allowed; Skip stores a sanitized local hostname as the selected tag in env.
- Subscription screen must perform external checks each display. On failure, run bounded, safe self-repair (status, install/sync, tunnel up when possible, Serverless force publish), recheck and show secret-safe diagnostic results. Never display an unvalidated/stale URL.
