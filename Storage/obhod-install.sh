#!/usr/bin/env bash
set -euo pipefail

APP_NAME="obhod"
PREFIX="${OBHOD_PREFIX:-/opt/obhod}"
CONF_DIR="${OBHOD_CONF_DIR:-/etc/obhod}"
ENV_FILE="$CONF_DIR/obhod.env"
STATE_DIR="${OBHOD_STATE_DIR:-/var/lib/obhod}"
SERVICE="/etc/systemd/system/obhod.service"
UNIT_SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/obhod.service"
PAYLOAD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${OBHOD_PYTHON:-python3}"
DEV=0
CMD=""
ASSUME_YES=0
SKIP_DEPS=0
PURGE_ALL=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    install|uninstall|status|restart|stop|start|logs|update|reinstall) CMD="$1" ;;
    --dev) DEV=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --prefix=*) PREFIX="${1#*=}" ;;
    --env-file=*) ENV_FILE="${1#*=}"; CONF_DIR="$(dirname -- "$ENV_FILE")" ;;
    --python=*) PYTHON_BIN="${1#*=}" ;;
    --skip-deps) SKIP_DEPS=1 ;;
    --purge-all) PURGE_ALL=1 ;;
    --help|-h) CMD="help" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

[ -n "$CMD" ] || CMD="install"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

if [ "$DEV" = "1" ]; then
  PREFIX="${HOME}/.obhod/app"
  CONF_DIR="${HOME}/.obhod/etc"
  ENV_FILE="$CONF_DIR/obhod.env"
  STATE_DIR="${HOME}/.obhod/state"
  SERVICE=""
fi

require_root() {
  if [ "$(id -u)" != "0" ]; then
    cat >&2 <<EOF
error: the installer must run as root.

run it again with root privileges, for example:

  sudo bash $0 ${CMD}

nothing was changed. the bot service is installed system wide and needs root to
write $PREFIX, $CONF_DIR, $STATE_DIR and the systemd unit.
EOF
    exit 1
  fi
}

gen_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

read_value() {
  local prompt="$1" current="$2" value=""
  if [ "$ASSUME_YES" = "1" ] && [ -n "$current" ]; then
    printf '%s' "$current"
    return 0
  fi
  printf '%s' "$prompt" >&2
  read -r value || true
  if [ -z "$value" ]; then
    value="$current"
  fi
  printf '%s' "$value"
}

env_get() {
  local key="$1"
  [ -f "$ENV_FILE" ] || return 0
  awk -F= -v k="$key" '$1==k { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE"
}

check_credential() {
  local name="$1" value="$2"
  case "$value" in
    *[![:print:]]*) die "$name must not contain control characters or newlines" ;;
  esac
  case "$value" in
    *=*) die "$name must not contain an equals sign" ;;
  esac
  [ "${#value}" -le 200 ] || die "$name is too long"
}

write_env() {
  local token="$1" api_id="$2" api_hash="$3" admin_id="$4"
  check_credential BOT_TOKEN "$token"
  check_credential API_ID "$api_id"
  check_credential API_HASH "$api_hash"
  check_credential ADMIN_ID "$admin_id"
  case "$api_id" in
    *[!0-9]*) die "api_id must be a number" ;;
  esac
  case "$admin_id" in
    *[!0-9]*) die "admin id must be a number" ;;
  esac
  mkdir -p "$CONF_DIR"
  chmod 700 "$CONF_DIR"
  umask 077
  cat > "$ENV_FILE" <<EOF
BOT_TOKEN=$token
API_ID=$api_id
API_HASH=$api_hash
ADMIN_ID=$admin_id
OBHOD_STATE_DIR=$STATE_DIR
OBHOD_LOG_LEVEL=INFO
EOF
  chmod 600 "$ENV_FILE"
}

check_python() {
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "$PYTHON_BIN is not installed"
  local version
  version="$("$PYTHON_BIN" -c 'import sys; print("%d%02d" % (sys.version_info[0], sys.version_info[1]))')"
  if [ "$version" -lt 313 ]; then
    die "$PYTHON_BIN is too old, python 3.13 or newer is required"
  fi
  if ! "$PYTHON_BIN" -c 'import venv' >/dev/null 2>&1; then
    die "the venv module is missing, install python3-venv"
  fi
}

install_payload() {
  mkdir -p "$PREFIX"
  rm -rf "$PREFIX/BOT" "$PREFIX/Storage"
  cp -a "$PAYLOAD_DIR/BOT" "$PREFIX/BOT"
  mkdir -p "$PREFIX/Storage/remote"
  cp -a "$PAYLOAD_DIR/Storage/remote/." "$PREFIX/Storage/remote/"
  if [ -f "$PAYLOAD_DIR/requirements.txt" ]; then
    cp -a "$PAYLOAD_DIR/requirements.txt" "$PREFIX/requirements.txt"
  fi
  chmod -R go-w "$PREFIX/Storage/remote"
  chmod -R go-w "$PREFIX/BOT"
  find "$PREFIX/BOT" -name '__pycache__' -type d -prune -exec rm -rf {} +
}

install_venv() {
  if [ "$SKIP_DEPS" = "1" ]; then
    say "skipping the virtual environment because --skip-deps was given"
    return 0
  fi
  if [ ! -x "$PREFIX/venv/bin/python" ]; then
    "$PYTHON_BIN" -m venv "$PREFIX/venv"
  fi
  "$PREFIX/venv/bin/python" -m pip install --quiet --upgrade pip wheel
  "$PREFIX/venv/bin/python" -m pip install --quiet -r "$PREFIX/requirements.txt"
}

write_service() {
  [ -n "$SERVICE" ] || return 0
  if ! command -v systemctl >/dev/null 2>&1; then
    say "systemd not found: install finished, start the bot manually with"
    say "  $PREFIX/venv/bin/python -m BOT"
    return 0
  fi
  [ -f "$UNIT_SRC" ] || die "unit template not found at $UNIT_SRC"
  mkdir -p -m 700 /root/.goygram
  sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@ENV_FILE@|$ENV_FILE|g" -e "s|@STATE_DIR@|$STATE_DIR|g" "$UNIT_SRC" > "$SERVICE"
  chmod 644 "$SERVICE"
  systemctl daemon-reload
  systemctl enable obhod.service >/dev/null 2>&1 || true
  systemctl restart obhod.service
  say "service obhod.service started"
}

cmd_install() {
  if [ "$DEV" = "0" ]; then
    require_root
  fi
  check_python
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  if [ "$DEV" = "0" ]; then
    mkdir -p "${LOG_DIR:-/var/log/obhod}"
    chmod 700 "${LOG_DIR:-/var/log/obhod}"
  fi
  local token api_id api_hash admin_id
  token="$(env_get BOT_TOKEN)"
  api_id="$(env_get API_ID)"
  api_hash="$(env_get API_HASH)"
  admin_id="$(env_get ADMIN_ID)"
  say "free turn control bot installer"
  say "prefix:  $PREFIX"
  say "config:  $ENV_FILE"
  say "state:   $STATE_DIR"
  token="$(read_value 'telegram bot token: ' "$token")"
  api_id="$(read_value 'telegram api_id: ' "$api_id")"
  api_hash="$(read_value 'telegram api_hash: ' "$api_hash")"
  admin_id="$(read_value 'admin telegram id: ' "$admin_id")"
  [ -n "$token" ] || die "bot token is required"
  case "$token" in
    *:*) ;;
    *) die "bot token must look like 123456:ABC-DEF" ;;
  esac
  [ -n "$api_id" ] || die "api_id is required"
  [ -n "$api_hash" ] || die "api_hash is required"
  [ -n "$admin_id" ] || die "admin id is required"
  case "$api_hash" in
    *[!0-9a-fA-F]*) die "api_hash must be 32 hex characters" ;;
  esac
  [ "${#api_hash}" = "32" ] || die "api_hash must be 32 hex characters"
  install_payload
  if [ -f "$PREFIX/requirements.txt" ]; then
    install_venv
  fi
  write_env "$token" "$api_id" "$api_hash" "$admin_id"
  write_service
  say "installed"
  if [ "$DEV" = "1" ]; then
    say "run in foreground with:"
    say "  OBHOD_ENV=$ENV_FILE $PREFIX/venv/bin/python -m BOT"
  fi
}

cmd_uninstall() {
  if [ "$DEV" = "0" ]; then
    require_root
  fi
  if [ -n "$SERVICE" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop obhod.service >/dev/null 2>&1 || true
    systemctl disable obhod.service >/dev/null 2>&1 || true
    rm -f "$SERVICE"
    systemctl daemon-reload || true
  fi
  rm -rf "$PREFIX"
  say "removed $PREFIX"
  say "kept $ENV_FILE and $STATE_DIR, delete them manually to forget credentials"
}

kill_leftovers() {
  local pid
  if command -v pgrep >/dev/null 2>&1; then
    for pid in $(pgrep -f "$PREFIX/venv/bin/python" 2>/dev/null || true); do
      [ "$pid" = "$$" ] && continue
      kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in $(pgrep -f "$PREFIX/BOT" 2>/dev/null || true); do
      [ "$pid" = "$$" ] && continue
      kill -KILL "$pid" 2>/dev/null || true
    done
    say "leftover processes stopped"
  fi
}

purge_install() {
  if [ -n "$SERVICE" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop obhod.service >/dev/null 2>&1 || true
    systemctl disable obhod.service >/dev/null 2>&1 || true
    rm -f "$SERVICE"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed obhod.service >/dev/null 2>&1 || true
    say "unit removed"
  fi
  kill_leftovers
  rm -rf "$PREFIX"
  say "removed $PREFIX"
  if [ "$PURGE_ALL" = "1" ]; then
    rm -rf "$STATE_DIR"
    rm -f "$ENV_FILE"
    say "removed $ENV_FILE and $STATE_DIR"
  fi
}

cmd_reinstall() {
  if [ "$DEV" = "0" ]; then
    require_root
  fi
  say "reinstalling from scratch"
  purge_install
  cmd_install
}

cmd_status() {
  if [ -n "$SERVICE" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --no-pager --full status obhod.service || true
  else
    say "no systemd unit for this install"
  fi
  if [ -f "$ENV_FILE" ]; then
    say "config present: $ENV_FILE"
  else
    say "config missing: $ENV_FILE"
  fi
  if [ -x "$PREFIX/venv/bin/python" ]; then
    say "runtime present: $PREFIX/venv"
  else
    say "runtime missing: $PREFIX/venv"
  fi
}

cmd_service() {
  local action="$1"
  if [ -z "$SERVICE" ] || ! command -v systemctl >/dev/null 2>&1; then
    die "systemd is not available for this install"
  fi
  systemctl "$action" obhod.service
}

cmd_logs() {
  if [ -n "$SERVICE" ] && command -v journalctl >/dev/null 2>&1; then
    journalctl -u obhod.service -n 200 --no-pager
    return 0
  fi
  die "journalctl is not available"
}

cmd_help() {
  cat <<EOF
usage: bash $0 [command] [options]

commands:
  install     install the bot, create the config and the systemd unit (default)
  update      copy the payload again and reinstall dependencies
  reinstall   delete the payload, the unit and the running processes, then install again
  uninstall   remove the payload and the unit
  status      show unit state and file locations
  start       start the unit
  stop        stop the unit
  restart     restart the unit
  logs        show the last 200 journal lines

options:
  --dev             install under \$HOME/.obhod without root, for local testing
  --yes             accept values already present in the env file
  --prefix=PATH     install prefix, default /opt/obhod
  --env-file=PATH   config file, default /etc/obhod/obhod.env
  --python=PATH     interpreter used to create the venv, default python3
  --skip-deps       copy the payload only, do not build the virtual environment
  --purge-all       with reinstall: also delete the config file and the state directory

the installer refuses to run as a normal user unless --dev is given.
EOF
}

cmd_update() {
  if [ "$DEV" = "0" ]; then
    require_root
  fi
  check_python
  install_payload
  if [ -f "$PREFIX/requirements.txt" ]; then
    install_venv
  fi
  write_service
  say "updated"
}

case "$CMD" in
  install) cmd_install ;;
  update) cmd_update ;;
  uninstall) cmd_uninstall ;;
  reinstall) cmd_reinstall ;;
  status) cmd_status ;;
  start) cmd_service start ;;
  stop) cmd_service stop ;;
  restart) cmd_service restart ;;
  logs) cmd_logs ;;
  help) cmd_help ;;
  *) die "unknown command: $CMD" ;;
esac
