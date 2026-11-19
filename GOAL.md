# GOAL
Цель: Xray subscriptions remain disabled until a user-supplied server tag is persisted (Skip stores the hostname); tagged subscription titles are used for Tailscale and Telegram Serverless only; every subscription-screen display validates links and attempts safe repair with diagnostics, without touching FreeTurn.

## Критерии готовности
- [ ] Tag prompt supports manual value and Skip→hostname; safely persists OBHOD_TAG in env and survives update/bootstrap — check: config/bootstrap/installer tests
- [ ] Missing tag blocks Xray subscription display, sync and remote access; FreeTurn remains unchanged — check: regression tests
- [ ] `OBHOD <tag>` is the profile title on Tailscale and Serverless; VLESS link names and FreeTurn unchanged — check: registry/header/static-config tests
- [ ] Every subscription-screen render validates status and exact full Xray list; failures trigger repair and visible secret-safe diagnostics — check: unit/integration/error-path tests
- [ ] Final full test, watchdog and lint run succeeds — check: recorded command outputs
- [ ] Complete changed files are packaged and delivered in Telegram — check: Telegram API success plus archive contents

## Boundaries
- Do not live-deploy or expose credentials/URLs/keys. Do not modify FreeTurn behavior.
- Preserve pre-existing uncommitted work; only add task-related changes.
