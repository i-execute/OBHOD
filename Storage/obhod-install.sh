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

trap '[ -n "${_SPINNER_PID:-}" ] && kill "$_SPINNER_PID" 2>/dev/null; loud_tty' EXIT

ui_init() {
  COLOR=0
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${OBHOD_NO_UI:-0}" != "1" ] && [ "${TERM:-dumb}" != "dumb" ]; then
    COLOR=1
  fi
  if [ "$COLOR" = "1" ]; then
    C_RESET=$'\033[0m'
    C_DIM=$'\033[2m'
    C_BOLD=$'\033[1m'
    C_ACC=$'\033[38;5;44m'
    C_OK=$'\033[38;5;42m'
    C_WARN=$'\033[38;5;214m'
    C_BAD=$'\033[38;5;203m'
    C_HEAD=$'\033[38;5;141m'
  else
    C_RESET=""
    C_DIM=""
    C_BOLD=""
    C_ACC=""
    C_OK=""
    C_WARN=""
    C_BAD=""
    C_HEAD=""
  fi
STEP_TOTAL=0
  STEP_NOW=0
  _SPINNER_PID=""
  _SPN_I=0
  _SPN_FRAMES=('/' '-' '\' '|' '/' '-' '\' '|' '/' '-')
  if ! locale charmap 2>/dev/null | grep -qi utf-8; then _SPN_FRAMES=('/' '-' '\\' '|'); fi
  spinner_start() {
    local msg="$1"
    if [ -t 2 ] && [ "$COLOR" = "1" ]; then
      ( idx=0; while true; do printf '\r  %s %s%s   ' "${_SPN_FRAMES[idx % ${#_SPN_FRAMES[@]}]}" "$C_DIM" "$msg" >&2; idx=$((idx+1)); sleep 0.08; done ) & _SPINNER_PID=$!; disown 2>/dev/null || true
    else
      printf '      .. %s\n' "$msg" >&2
    fi
  }
  spinner_ok() {
    local msg="$1" extra="${2:-}"
    if [ -n "$_SPINNER_PID" ]; then kill "$_SPINNER_PID" 2>/dev/null || true; wait "$_SPINNER_PID" 2>/dev/null || true; _SPINNER_PID=""; printf '\r  %sv%s %s' "$C_OK" "$C_RESET" "$msg" >&2; [ -n "$extra" ] && printf ' %s%s%s' "$C_DIM" "$extra" "$C_RESET" >&2; printf '          \n' >&2; else printf '      %sok%s %s\n' "$C_OK" "$C_RESET" "$msg" >&2; fi
  }
  spinner_fail() {
    local msg="$1"; if [ -n "$_SPINNER_PID" ]; then kill "$_SPINNER_PID" 2>/dev/null || true; wait "$_SPINNER_PID" 2>/dev/null || true; _SPINNER_PID=""; printf '\r  %sx%s %s          \n' "$C_BAD" "$C_RESET" "$msg" >&2; else printf '      %sxx%s %s\n' "$C_BAD" "$C_RESET" "$msg" >&2; fi
  }
}

hr() {
  printf '\n'
}

banner() {
  local mode="system install"
  if [ "$DEV" = "1" ]; then
    mode="dev install, no root, no systemd"
  fi
  printf '\n'
  if [ "$COLOR" = "1" ]; then
    printf '  %s+======================================+%s\n' "$C_HEAD" "$C_RESET"
    printf '  %s|%s  %sOBHOD%s                          %s|%s\n' "$C_HEAD" "$C_RESET" "$C_BOLD" "$C_HEAD" "$C_RESET" "$C_RESET"
    printf '  %s|%s  telegram control bot over xray-core %s|%s\n' "$C_HEAD" "$C_DIM" "$C_HEAD" "$C_RESET"
    printf '  %s+======================================+%s\n' "$C_HEAD" "$C_RESET"
  else
    printf '  %s%sOBHOD%s\n' "$C_HEAD" "$C_BOLD" "$C_RESET"
    printf '  %stelegram control bot over xray-core%s\n' "$C_DIM" "$C_RESET"
  fi
  printf '  %s/ %s%s\n\n' "$C_ACC" "$mode" "$C_RESET"
}

kv() {
  printf '    %s%-9s%s %s\n' "$C_DIM" "$1" "$C_RESET" "$2"
}

step() {
  STEP_NOW=$((STEP_NOW + 1))
  local total=""
  local bar=""
  if [ "$STEP_TOTAL" -gt 0 ]; then
    total="$STEP_NOW/$STEP_TOTAL"
    local filled=$((STEP_NOW * 20 / STEP_TOTAL))
    local empty=$((20 - filled))
    bar=" ["
    for i in $(seq 1 $filled); do bar="${bar}#"; done
    for i in $(seq 1 $empty); do bar="${bar}."; done
    bar="${bar}]"
  else
    total="*"
  fi
  printf '\n%s[%s]%s %s%s%s%s\n' "$C_ACC" "$total" "$C_RESET" "$C_BOLD" "$*" "$C_DIM" "$bar" "$C_RESET"
}

note_line() {
  printf '      %s..%s %s\n' "$C_DIM" "$C_RESET" "$*"
}

ok_line() {
  printf '      %sok%s %s\n' "$C_OK" "$C_RESET" "$*"
}

warn_line() {
  printf '      %s!!%s %s\n' "$C_WARN" "$C_RESET" "$*"
}

fail_line() {
  printf '      %sxx%s %s\n' "$C_BAD" "$C_RESET" "$*" >&2
}

summary_box() {
  local service_state="no unit in dev mode"
  if [ -n "$SERVICE" ] && command -v systemctl >/dev/null 2>&1; then
    service_state="$(systemctl is-active obhod.service 2>/dev/null || true)"
    [ -n "$service_state" ] || service_state="unknown"
  fi
  if [ "$COLOR" = "1" ]; then
    printf '\n  %s+= %sdone%s ===========================+%s\n' "$C_OK" "$C_BOLD" "$C_OK" "$C_RESET"
  else
    printf '\n  %s%sdone%s\n\n' "$C_OK" "$C_BOLD" "$C_RESET"
  fi
  kv "payload" "$PREFIX"
  kv "config" "$ENV_FILE"
  kv "state" "$STATE_DIR"
  kv "service" "$service_state"
  printf '\n'
  if [ "$DEV" = "1" ]; then
    kv "run it" "OBHOD_ENV=$ENV_FILE $PREFIX/venv/bin/python -m BOT"
  else
    kv "logs" "journalctl -u obhod -f"
    kv "open" "/help in the bot from the admin account"
  fi
  if [ "$COLOR" = "1" ]; then
    printf '  %s+======================================+%s\n\n' "$C_OK" "$C_RESET"
  else
    printf '\n'
  fi
}

count_files() {
  find "$1" -type f 2>/dev/null | wc -l | tr -d ' '
}

plural_files() {
  if [ "$1" = "1" ]; then
    printf '%s file' "$1"
  else
    printf '%s files' "$1"
  fi
}

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

tty_present() {
  if [ -t 0 ]; then
    return 0
  fi
  if [ -r /dev/tty ] && ( exec 3</dev/tty ) 2>/dev/null; then
    return 0
  fi
  return 1
}

TTY_ECHO_OFF=0

quiet_tty() {
  if [ "$TTY_ECHO_OFF" = "1" ]; then
    return 0
  fi
  if tty_present && stty -echo </dev/tty 2>/dev/null; then
    TTY_ECHO_OFF=1
  fi
  return 0
}

loud_tty() {
  if [ "$TTY_ECHO_OFF" = "1" ]; then
    stty echo </dev/tty 2>/dev/null || true
    TTY_ECHO_OFF=0
  fi
  return 0
}

mask_token() {
  local v="$1"
  if [ -z "$v" ]; then
    printf ''
    return
  fi
  case "$v" in
    *:*) printf '%s:****' "${v%%:*}" ;;
    *) printf '****' ;;
  esac
}

mask_hash() {
  local v="$1"
  if [ -z "$v" ]; then
    printf ''
    return
  fi
  if [ "${#v}" -le 8 ]; then
    printf '****'
  else
    printf '%s****%s' "${v:0:4}" "${v: -4}"
  fi
}

read_value() {
  local prompt="$1" current="$2" value="" silent="${3:-0}"
  if [ "$ASSUME_YES" = "1" ] && [ -n "$current" ]; then
    printf '%s' "$current"
    return 0
  fi
  if ! tty_present; then
    die "there is no terminal to read the credentials, pipe the script into bash is not enough, run bash $0 ${CMD} from a terminal or pass --env-file with the keys"
  fi
  local hint=""
  if [ -n "$current" ] && [ "$silent" = "1" ]; then
    case "$prompt" in
      *token*) hint=" [$(mask_token "$current")] " ;;
      *hash*) hint=" [$(mask_hash "$current")] " ;;
      *) hint=" [****] " ;;
    esac
    if [ "$ASSUME_YES" != "1" ]; then
      printf '      current: %s\n' "$hint" >&2
    fi
  elif [ -n "$current" ]; then
    hint=" [$current] "
    if [ "$ASSUME_YES" != "1" ]; then
      printf '      current: %s\n' "$current" >&2
    fi
  fi
  if [ "$silent" = "1" ]; then
    prompt="${prompt%: }"
    prompt="$prompt${hint}(hidden, enter to keep): "
  else
    prompt="${prompt%: }"
    prompt="$prompt${hint}(enter to keep): "
  fi
  printf '%s' "$prompt" >&2
  if [ "$silent" = "1" ]; then
    value=""
    if [ -t 0 ]; then
      exec 3<&0
    elif [ -r /dev/tty ]; then
      exec 3</dev/tty
    else
      if [ -t 0 ]; then read -rs value || true; else read -rs value </dev/tty || true; fi
      printf '\n' >&2
      [ -z "$value" ] && value="$current"
      printf '%s' "$value"
      return 0
    fi
    old_stty=""
    if command -v stty >/dev/null 2>&1; then
      old_stty=$(stty -g <&3 2>/dev/null || true)
      stty -echo <&3 2>/dev/null || true
      if command -v timeout >/dev/null 2>&1; then
        trap 'timeout 1 stty "$old_stty" <&3 2>/dev/null || true; printf "\n" >&2' EXIT INT TERM
      else
        trap 'stty "$old_stty" <&3 2>/dev/null || true; printf "\n" >&2' EXIT INT TERM
      fi
    fi
    while IFS= read -rs -n1 char <&3 2>/dev/null; do
      if [ -z "$char" ]; then
        break
      elif [ "$char" = "$(printf '\177')" ] || [ "$char" = "$(printf '\b')" ]; then
        if [ -n "$value" ]; then
          value="${value%?}"
          printf '\b \b' >&2
        fi
      elif [ "$char" = "$(printf '\003')" ]; then
        printf '\n' >&2
        [ -n "$old_stty" ] && stty "$old_stty" <&3 2>/dev/null || true
        trap - EXIT INT TERM
        exec 3<&-
        kill -INT $$
      else
        value="$value$char"
        if [ ${#value} -le 6 ]; then printf '%s' "$char" >&2; else printf '*' >&2; fi
      fi
    done
    [ -n "$old_stty" ] && stty "$old_stty" <&3 2>/dev/null || true
    trap - EXIT INT TERM
    exec 3<&-
    printf '\n' >&2
  else
    if [ -t 0 ]; then
      read -r value || true
    else
      read -r value </dev/tty || true
    fi
  fi
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

ensure_private_dir() {
  local path="$1"
  case "$path" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      die "$path is a shared system directory, point the config, the state and the logs at their own directory"
      ;;
  esac
  if [ ! -d "$path" ]; then
    mkdir -p "$path"
    chmod 700 "$path" || die "cannot tighten the permissions of $path"
    return 0
  fi
  local mode=""
  mode="$(stat -c '%a' "$path" 2>/dev/null || echo unknown)"
  case "$mode" in
    700|710|750|770) return 0 ;;
  esac
  warn_line "$path holds other files, its mode stays $mode, the config file itself is 0600"
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
  ensure_private_dir "$CONF_DIR"
  umask 077
  cat > "$ENV_FILE" <<EOF
BOT_TOKEN=$token
API_ID=$api_id
API_HASH=$api_hash
ADMIN_ID=$admin_id
OBHOD_STATE_DIR=$STATE_DIR
OBHOD_LOG_LEVEL=INFO
OBHOD_EMOJI=0
OBHOD_SUB_PORT=${SUB_PORT:-2096}
OBHOD_API_PORT=${API_PORT:-62789}
EOF
  chmod 600 "$ENV_FILE"
}

port_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -lntu 2>/dev/null | awk -v want="$port" 'NR > 1 { n = split($5, parts, ":"); if (parts[n] == want) { found = 1 } } END { exit(found ? 0 : 1) }'
    return $?
  fi
  if [ -r /proc/net/tcp ] || [ -r /proc/net/tcp6 ] || [ -r /proc/net/udp ] || [ -r /proc/net/udp6 ]; then
    local hex
    hex="$(printf '%04X' "$port")"
    awk -v want="$hex" 'FNR > 1 { split($2, parts, ":"); if (parts[2] == want) { found = 1 } } END { exit(found ? 0 : 1) }' \
      /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null
    return $?
  fi
  return 1
}

pick_port() {
  local preferred="$1" candidate="$1" limit
  limit=$((preferred + 400))
  while [ "$candidate" -le "$limit" ] && [ "$candidate" -le 65535 ]; do
    if [ "$candidate" -gt 1023 ] && ! port_listening "$candidate"; then
      printf '%s' "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
  done
  return 1
}

resolve_ports() {
  SUB_PORT="${OBHOD_SUB_PORT:-2096}"
  API_PORT="${OBHOD_API_PORT:-62789}"
  PORT_NOTES=""
  if port_listening "$SUB_PORT"; then
    local free
    free="$(pick_port "$((SUB_PORT + 1))" || true)"
    if [ -n "$free" ]; then
      PORT_NOTES="$PORT_NOTES subscription:$SUB_PORT->$free"
      warn_line "port $SUB_PORT is already listening, the subscription takes $free, that service is left alone"
      SUB_PORT="$free"
    else
      PORT_NOTES="$PORT_NOTES subscription:$SUB_PORT-busy"
      warn_line "port $SUB_PORT is already listening and no free neighbour was found, set it later in the bot"
    fi
  fi
  if port_listening "$API_PORT"; then
    local free
    free="$(pick_port "$((API_PORT + 1))" || true)"
    if [ -n "$free" ]; then
      PORT_NOTES="$PORT_NOTES api:$API_PORT->$free"
      warn_line "port $API_PORT is already listening, the xray api takes $free, nothing is stopped or killed"
      API_PORT="$free"
    else
      PORT_NOTES="$PORT_NOTES api:$API_PORT-busy"
      warn_line "port $API_PORT is already listening and no free neighbour was found, set it later in the bot"
    fi
  fi
  [ -n "$PORT_NOTES" ] || ok_line "$SUB_PORT and $API_PORT are free"
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
  local stale
  for stale in "$PREFIX/BOT" "$PREFIX/Storage" "$PREFIX/requirements.txt" "$PREFIX/.obhod-src"; do
    if [ -e "$stale" ]; then
      rm -rf "$stale"
    fi
  done
  spinner_start "copying payload..."; cp -a "$PAYLOAD_DIR/BOT" "$PREFIX/BOT"; spinner_ok "payload" "$PREFIX/BOT"
  mkdir -p "$PREFIX/Storage/remote"
  cp -a "$PAYLOAD_DIR/Storage/remote/." "$PREFIX/Storage/remote/"
  if [ -f "$PAYLOAD_DIR/requirements.txt" ]; then
    cp -a "$PAYLOAD_DIR/requirements.txt" "$PREFIX/requirements.txt"
  fi
  chmod -R go-w "$PREFIX/Storage/remote"
  chmod -R go-w "$PREFIX/BOT"
  find "$PREFIX/BOT" -name '__pycache__' -type d -prune -exec rm -rf {} +
}

INDEX_URL="${PIP_INDEX_URL:-https://pypi.org/simple/}"

check_index() {
  local url="${INDEX_URL%/}/goygram/"
  if command -v curl >/dev/null 2>&1; then
    if ! curl -fsS -o /dev/null --max-time 15 "$url"; then
      warn_line "$url is not reachable from this server, the install can stall here"
      note_line "if pip hangs, the index is the reason, set PIP_INDEX_URL to a mirror and repeat"
    else
      note_line "package index reachable: $INDEX_URL"
    fi
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    if ! "$PYTHON_BIN" -c 'import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=15)' "$url" >/dev/null 2>&1; then
      warn_line "$url is not reachable from this server, the install can stall here"
    fi
  fi
  return 0
}

install_venv() {
  if [ "$SKIP_DEPS" = "1" ]; then
    note_line "skipping the virtual environment because --skip-deps was given"
    return 0
  fi
  note_line "preparing the virtual environment in $PREFIX/venv"
  if [ -d "$PREFIX/venv" ] && [ ! -x "$PREFIX/venv/bin/python" ]; then
    note_line "the virtual environment is broken, recreating it"
    rm -rf "$PREFIX/venv"
  fi
  if [ ! -x "$PREFIX/venv/bin/python" ]; then
    "$PYTHON_BIN" -m venv "$PREFIX/venv"
  fi
  check_index
  note_line "installing the python dependencies, goygram is about one megabyte, a normal link needs a minute"
  local quiet=("--progress-bar" "off" "--quiet")
  if [ -t 1 ]; then
    quiet=()
  fi
  spinner_start "upgrading pip & wheel..."
  if ! "$PREFIX/venv/bin/python" -m pip install --disable-pip-version-check --no-input --timeout 20 --retries 2 "${quiet[@]}" --upgrade pip wheel; then spinner_fail "pip upgrade failed"; fail_line "pip could not upgrade itself"; note_line "check that $INDEX_URL is reachable from this server, or pass PIP_INDEX_URL with a mirror"; die "the python tooling did not install"; fi; spinner_ok "pip & wheel" "up to date"
  spinner_start "installing dependencies (goygram ~1 MB)..."
  if ! "$PREFIX/venv/bin/python" -m pip install --disable-pip-version-check --no-input --timeout 20 --retries 2 "${quiet[@]}" -r "$PREFIX/requirements.txt"; then spinner_fail "dependencies failed"; fail_line "the dependencies did not install"; note_line "check that $INDEX_URL is reachable from this server, or pass PIP_INDEX_URL with a mirror"; die "the python dependencies did not install"; fi; spinner_ok "dependencies" "installed"
}

unit_runtime() {
  local runtime="$PREFIX/venv/bin/python"
  if [ -x "$runtime" ]; then
    printf '%s\n' "$runtime"
    return 0
  fi
  local system_python=""
  system_python="$(command -v "$PYTHON_BIN" 2>/dev/null || true)"
  if [ "$SKIP_DEPS" = "1" ] && [ -n "$system_python" ] && [ -x "$system_python" ]; then
    printf '%s\n' "$system_python"
    return 0
  fi
  printf '%s\n' "$runtime"
  return 0
}

render_unit() {
  local target="$1" runtime=""
  [ -f "$UNIT_SRC" ] || die "unit template not found at $UNIT_SRC"
  runtime="$(unit_runtime)"
  if [ "$runtime" != "$PREFIX/venv/bin/python" ]; then
    note_line "no virtual environment, the unit starts the system python at $runtime"
  fi
  sed -e "s|@PREFIX@/venv/bin/python|$runtime|g" -e "s|@PREFIX@|$PREFIX|g" -e "s|@ENV_FILE@|$ENV_FILE|g" -e "s|@STATE_DIR@|$STATE_DIR|g" "$UNIT_SRC" > "$target"
}

write_service() {
  [ -n "$SERVICE" ] || return 0
  if ! command -v systemctl >/dev/null 2>&1; then
    warn_line "systemd not found, start the bot manually with $PREFIX/venv/bin/python -m BOT"
    return 0
  fi
  [ -f "$UNIT_SRC" ] || die "unit template not found at $UNIT_SRC"
  mkdir -p -m 700 /root/.goygram /root/.ssh
  mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d /etc/fail2ban/action.d /etc/ssh/sshd_config.d
  mkdir -p /usr/local/bin /usr/local/etc/xray /usr/local/share/xray /etc/systemd/system
  mkdir -p /var/lib/xray-manager /var/log/xray
  render_unit "$SERVICE"
  chmod 644 "$SERVICE"
  systemctl daemon-reload
  systemctl enable obhod.service >/dev/null 2>&1 || true
  systemctl restart obhod.service
  ok_line "unit $SERVICE, service restarted"
}

install_exists() {
  if [ -d "$PREFIX/BOT" ]; then
    return 0
  fi
  if [ -f "$ENV_FILE" ]; then
    return 0
  fi
  return 1
}

stop_before_rebuild() {
  if [ -n "$SERVICE" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet obhod.service 2>/dev/null; then
      systemctl stop obhod.service >/dev/null 2>&1 || true
      note_line "the running unit was stopped"
    fi
  fi
  local stopped
  stopped="$(kill_leftovers)"
  if [ -n "$stopped" ]; then
    note_line "$stopped"
  fi
}

cmd_install() {
  if [ "$DEV" = "0" ]; then
    require_root
  fi
  ui_init
  STEP_TOTAL=7
  banner
  kv host "$(hostname 2>/dev/null || echo localhost)"
  kv prefix "$PREFIX"
  kv config "$ENV_FILE"
  kv state "$STATE_DIR"

  step "checking the environment"
  check_python
  ensure_private_dir "$STATE_DIR"
  if [ "$DEV" = "0" ]; then
    ensure_private_dir "${LOG_DIR:-/var/log/obhod}"
  fi
  ok_line "$("$PYTHON_BIN" -c 'import sys; print("python %d.%d.%d" % sys.version_info[:3])')"
  if [ "$DEV" = "0" ]; then
    if ! command -v systemctl >/dev/null 2>&1; then
      warn_line "systemd is missing, the bot is copied but not started"
    fi
  fi

  step "reading the telegram credentials"
  local token api_id api_hash admin_id
  token="$(env_get BOT_TOKEN)"
  api_id="$(env_get API_ID)"
  api_hash="$(env_get API_HASH)"
  admin_id="$(env_get ADMIN_ID)"
  if [ -n "$token" ] || [ -n "$api_id" ]; then
    note_line "existing config at $ENV_FILE - press enter to keep current values"
    if [ -n "$token" ]; then
      note_line "current token: $(mask_token "$token")"
    fi
    if [ -n "$api_hash" ]; then
      note_line "current api_hash: $(mask_hash "$api_hash")"
    fi
    note_line "current services in $STATE_DIR will be kept (use --purge-all to wipe)"
  else
    note_line "the terminal echo is off until all four values are in, a paste made before the prompt will not show up either"
  fi
  quiet_tty
  token="$(read_value 'telegram bot token: ' "$token" 1)"
  api_id="$(read_value 'telegram api_id: ' "$api_id")"
  api_hash="$(read_value 'telegram api_hash: ' "$api_hash" 1)"
  admin_id="$(read_value 'admin telegram id: ' "$admin_id")"
  loud_tty
  note_line "token: $(mask_token "$token"), api_id: ${api_id:-missing}, admin id: ${admin_id:-missing}"
  if [ -z "$token" ]; then
    fail_line "the bot token is required"
    die "bot token is required"
  fi
  case "$token" in
    *:*) ;;
    *)
      fail_line "the token must look like 123456:ABC-DEF"
      die "bot token must look like 123456:ABC-DEF"
      ;;
  esac
  [ -n "$api_id" ] || die "api_id is required"
  [ -n "$api_hash" ] || die "api_hash is required"
  [ -n "$admin_id" ] || die "admin id is required"
  case "$api_hash" in
    *[!0-9a-fA-F]*)
      fail_line "api_hash must be 32 hex characters"
      die "api_hash must be 32 hex characters"
      ;;
  esac
  [ "${#api_hash}" = "32" ] || { fail_line "api_hash must be 32 hex characters"; die "api_hash must be 32 hex characters"; }
  ok_line "token ${token%%:*}:***, admin $admin_id"

  step "checking for a previous install"
  REBUILD=0
  if install_exists; then
    REBUILD=1
    note_line "a previous install was found at $PREFIX"
    if [ -d "$STATE_DIR" ]; then
      note_line "state directory $STATE_DIR will be kept - xray/freeturn configs, clients and keys stay"
      note_line "payload in $PREFIX will be refreshed, services will be updated not wiped"
    fi
    stop_before_rebuild
    ok_line "the old install is stopped and will be replaced (services kept)"
  else
    ok_line "there is nothing to replace, this is a clean install"
  fi

  step "copying the payload"
  install_payload
  FILES_COPIED="$(count_files "$PREFIX/BOT")"
  ok_line "$(plural_files "$FILES_COPIED") in $PREFIX/BOT"

  step "preparing the python runtime"
  if [ -f "$PREFIX/requirements.txt" ]; then
    install_venv
  else
    warn_line "requirements.txt is missing, the runtime is not prepared"
  fi

  step "checking the ports"
  resolve_ports

  step "writing the config and the unit"
  write_env "$token" "$api_id" "$api_hash" "$admin_id"
  ok_line "config $ENV_FILE, mode 600, subscription $SUB_PORT, api $API_PORT"
  write_service

  summary_box
  if [ "$REBUILD" = "1" ]; then
    say "installed over the previous install"
  else
    say "installed"
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
  local pid count=0
  if command -v pgrep >/dev/null 2>&1; then
    for pid in $(pgrep -f "$PREFIX/venv/bin/python" 2>/dev/null || true); do
      [ "$pid" = "$$" ] && continue
      kill -TERM "$pid" 2>/dev/null || true
      count=$((count + 1))
    done
    sleep 1
    for pid in $(pgrep -f "$PREFIX/BOT" 2>/dev/null || true); do
      [ "$pid" = "$$" ] && continue
      kill -KILL "$pid" 2>/dev/null || true
      count=$((count + 1))
    done
  fi
  if [ "$count" -gt 0 ]; then
    printf '%s leftover processes stopped' "$count"
  fi
  return 0
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
  local stopped
  stopped="$(kill_leftovers)"
  if [ -n "$stopped" ]; then
    say "$stopped"
  fi
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

if [ "${OBHOD_LIB:-0}" != "1" ]; then
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
fi