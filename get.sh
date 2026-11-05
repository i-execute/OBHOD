#!/usr/bin/env bash
set -euo pipefail

REPO="${OBHOD_REPO:-i-execute/OBHOD}"
REF="${OBHOD_REF:-}"
DEST="${OBHOD_DIR:-/opt/obhod-src}"
SRC_DIR="${OBHOD_SRC_DIR:-}"
ENV_PATH="${OBHOD_ENV_FILE:-}"
DRY_RUN=0
NO_INSTALL=0
TUI=1
ARGS=()
WORK=""

say() { printf '%s\n' "$*" ; }
note() { printf '%s\n' "$*" >&2 ; }
die() { printf 'error: %s\n' "$*" >&2 ; exit 1 ; }

check_dest() {
  case "$DEST" in
    /*) ;;
    *) die "OBHOD_DIR must be an absolute path" ;;
  esac
  case "$DEST" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|\\.|\\.\\.)
      die "OBHOD_DIR must point at a directory of its own, not $DEST" ;;
  esac
  case "$DEST" in
    */../*|*/..) die "OBHOD_DIR must not contain .." ;;
  esac
  return 0
}

ECHO_OFF=0
STDIN_EATEN=0
CLONE_TIMEOUT="${OBHOD_CLONE_TIMEOUT:-180}"
TRACE="${OBHOD_TRACE:-0}"

trace() {
  if [ "$TRACE" = "1" ]; then
    note "trace: $*"
  fi
}

detach_stdin() {
  if [ -t 0 ]; then
    return 0
  fi
  STDIN_EATEN=1
  trace "stdin is a pipe, every child gets /dev/null so nothing swallows the rest of the script"
  return 0
}

mask_token() {
  local v="$1"
  if [ -z "$v" ]; then printf ''; return; fi
  case "$v" in *:*) printf '%s:****' "${v%%:*}" ;; *) printf '****' ;; esac
}
mask_hash() {
  local v="$1"
  if [ -z "$v" ]; then printf ''; return; fi
  if [ "${#v}" -le 8 ]; then printf '****'; else printf '%s****%s' "${v:0:4}" "${v: -4}"; fi
}
env_get() {
  local key="$1" path="${2:-${ENV_PATH:-/etc/obhod/obhod.env}}"
  [ -r "$path" ] || return 0
  awk -F= -v k="$key" '$1==k { sub(/^[^=]*=/, ""); print; exit }' "$path"
}
existing_env_path() {
  if [ -n "${ENV_PATH:-}" ]; then printf '%s' "$ENV_PATH"; return; fi
  for p in "/etc/obhod/obhod.env" "/opt/obhod/.env" "/opt/obhod/obhod.env" "/etc/obhod.env"; do
    if [ -f "$p" ]; then printf '%s' "$p"; return; fi
  done
  printf '%s' "/etc/obhod/obhod.env"
}

echo_off() {
  if [ "$CREDS" = "0" ] && tty_available; then
    note "secret input will show masked as **** (first 6 chars visible) - paste is safe"
  fi
  return 0
}

echo_on() {
  return 0
}

step_done() {
  say "  done in ${1}s"
}

cleanup() {
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
  return 0
}
trap 'echo_on; cleanup' EXIT

for item in "$@"; do
  case "$item" in
    --ref=*) REF="${item#*=}" ;;
    --repo=*) REPO="${item#*=}" ;;
    --dir=*) DEST="${item#*=}" ;;
    --src=*) SRC_DIR="${item#*=}" ;;
    --env-file=*) ENV_PATH="${item#*=}" ;;
    --dry-run) DRY_RUN=1 ;;
    --no-install) NO_INSTALL=1 ;;
    --no-tui|--plain) TUI=0 ;;
    *) ARGS+=("$item") ;;
  esac
done

if [ "${#ARGS[@]}" -eq 0 ]; then
  ARGS=("install")
fi

if [ "$(id -u)" != "0" ]; then
  die "the install is possible only from root, run curl ... | sudo bash"
fi

CREDS=0
if [ -n "${OBHOD_TOKEN:-}${BOT_TOKEN:-}" ] || [ -n "${OBHOD_API_ID:-}${API_ID:-}" ] || [ -n "${OBHOD_API_HASH:-}${API_HASH:-}" ] || [ -n "${OBHOD_ADMIN_ID:-}${ADMIN_ID:-}" ]; then
  CREDS=1
fi

TOKEN="${OBHOD_TOKEN:-${BOT_TOKEN:-}}"
API_ID="${OBHOD_API_ID:-${API_ID:-}}"
API_HASH="${OBHOD_API_HASH:-${API_HASH:-}}"
ADMIN_ID="${OBHOD_ADMIN_ID:-${ADMIN_ID:-}}"

tty_available() {
  if [ -t 0 ]; then
    return 0
  fi
  if [ -c /dev/tty ] && ( exec 3</dev/tty ) 2>/dev/null; then
    return 0
  fi
  return 1
}

need_tools() {
  if [ -n "$SRC_DIR" ]; then
    return 0
  fi
  if command -v git >/dev/null 2>&1; then
    return 0
  fi
  if command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
    return 0
  fi
  die "git is needed, or curl and tar, install them and repeat"
}

download_archive() {
  local url="https://codeload.github.com/$REPO/tar.gz/${REF:-HEAD}"
  say "downloading $url"
  mkdir -p "$WORK/repo"
  if ! curl -fSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 \
      --progress-bar "$url" -o "$WORK/repo.tar.gz" </dev/null; then
    note "the archive could not be downloaded, check the network and the proxy settings"
    return 1
  fi
  if [ -n "${OBHOD_SHA256:-}" ]; then
    local actual
    actual="$(sha256sum "$WORK/repo.tar.gz" | cut -d' ' -f1)"
    [ "$actual" = "$OBHOD_SHA256" ] || die "the source archive digest does not match"
    say "source digest matches"
  fi
  tar -xzf "$WORK/repo.tar.gz" --strip-components=1 -C "$WORK/repo" </dev/null || return 1
  SRC="$WORK/repo"
  return 0
}

clone_repo() {
  local args=(clone --depth 1 --single-branch --no-tags)
  if [ -n "$REF" ]; then
    args+=(--branch "$REF")
  fi
  if [ "$TRACE" != "1" ]; then
    args+=(--quiet)
  fi
  say "cloning https://github.com/$REPO.git, the wait is capped at ${CLONE_TIMEOUT}s"
  GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true GIT_HTTP_LOW_SPEED_LIMIT=1000 GIT_HTTP_LOW_SPEED_TIME=30 \
    timeout "$CLONE_TIMEOUT" git "${args[@]}" "https://github.com/$REPO.git" "$WORK/repo" >&2 </dev/null
}

fetch_source() {
  local started
  started="$(date +%s)"
  if [ -n "$SRC_DIR" ]; then
    [ -f "$SRC_DIR/Storage/obhod-install.sh" ] || die "there is no Storage/obhod-install.sh in $SRC_DIR"
    say "source: $SRC_DIR"
    SRC="$SRC_DIR"
    return 0
  fi
  WORK="$(mktemp -d)"
  if command -v git >/dev/null 2>&1; then
    if clone_repo; then
      SRC="$WORK/repo"
      step_done "$(( $(date +%s) - started ))"
      return 0
    fi
    note "git clone did not finish, falling back to the branch archive"
    rm -rf "$WORK/repo"
  else
    say "git is missing, the branch archive is used instead"
  fi
  if download_archive; then
    step_done "$(( $(date +%s) - started ))"
    return 0
  fi
  die "the source could not be fetched: no git clone and no archive, check that github.com is reachable from this server"
}

install_helper() {
  [ "$NO_INSTALL" = "0" ] || return 0
  if [ ! -f "$DEST/get.sh" ]; then
    note "the helper /usr/local/bin/obhod-get is not installed, the bot fetches get.sh over https"
    return 0
  fi
  if install -m 700 "$DEST/get.sh" /usr/local/bin/obhod-get 2>/dev/null; then
    say "helper installed: /usr/local/bin/obhod-get"
  else
    note "the helper /usr/local/bin/obhod-get was not installed, the bot fetches get.sh over https"
  fi
  return 0
}

sync_source() {
  if [ -d "$DEST" ] && [ -e "$DEST/.obhod-src" ]; then
    rm -rf "$DEST"
  fi
  mkdir -p "$DEST"
  tar -cf - -C "$SRC" --exclude='.venv' --exclude='__pycache__' --exclude='.pytest_cache' . | tar -xf - -C "$DEST"
  : > "$DEST/.obhod-src"
  chmod 600 "$DEST/.obhod-src"
}

write_env_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  umask 077
  {
    printf 'BOT_TOKEN=%s\n' "$TOKEN"
    printf 'API_ID=%s\n' "$API_ID"
    printf 'API_HASH=%s\n' "$API_HASH"
    printf 'ADMIN_ID=%s\n' "$ADMIN_ID"
  } > "$path"
  chmod 600 "$path"
}

check_dest
need_tools
say "repository: $REPO"
say "branch: ${REF:-default}"
say "directory: $DEST"

if [ "$DRY_RUN" = "1" ]; then
  if [ -n "$SRC_DIR" ]; then
    say "source: $SRC_DIR"
  elif command -v git >/dev/null 2>&1; then
    say "step: git clone --depth 1 https://github.com/$REPO.git"
  else
    say "step: curl https://codeload.github.com/$REPO/tar.gz/${REF:-HEAD} and tar -xzf"
  fi
  say "step: syncing the files into $DEST"
  if [ "$CREDS" = "1" ]; then
    say "credentials: from the environment $(mask_token "$TOKEN") api_id:${API_ID:-missing} $(mask_hash "$API_HASH")"
  else
    _ep="$(existing_env_path)"
    if [ -f "$_ep" ]; then
      say "existing config at $_ep - press enter to keep current values"
      _t="$(env_get BOT_TOKEN "$_ep")"; [ -n "$_t" ] && say "current token: $(mask_token "$_t")"
      _h="$(env_get API_HASH "$_ep")"; [ -n "$_h" ] && say "current api_hash: $(mask_hash "$_h")"
      say "current services will be kept (state in /var/lib/obhod or OBHOD_STATE_DIR)"
    fi
    say "credentials: asked in the terminal (masked as ****, first 6 chars visible while typing)"
  fi
  if [ -n "$ENV_PATH" ]; then
    if [ "$CREDS" = "1" ]; then
      write_env_file "$ENV_PATH"
      say "env file: $ENV_PATH"
    fi
  fi
  if [ "$TUI" = "1" ]; then
    say "screen: python3 $DEST/Storage/obhod_setup.py ${ARGS[*]}"
  fi
  say "command: bash $DEST/Storage/obhod-install.sh ${ARGS[*]}"
  exit 0
fi

if [ "$NO_INSTALL" = "0" ] && [ "$CREDS" = "0" ] && ! tty_available; then
  die "there is no terminal for the input, pass BOT_TOKEN API_ID API_HASH ADMIN_ID through the environment"
fi

detach_stdin
echo_off
fetch_source
[ -f "$SRC/Storage/obhod-install.sh" ] || die "there is no Storage/obhod-install.sh in the source"
sync_source
say "files updated in $DEST"

if [ "$NO_INSTALL" = "1" ]; then
  say "the install is skipped, run it by hand: bash $DEST/Storage/obhod-install.sh ${ARGS[*]}"
  exit 0
fi

if [ "$TUI" = "1" ] && tty_available; then
  PY_BIN="$(command -v python3 || true)"
  if [ -n "$PY_BIN" ] && [ -f "$DEST/Storage/obhod_setup.py" ]; then
    TUI_ARGS=("${ARGS[@]}")
    if [ "$CREDS" = "1" ]; then
      if [ -z "$ENV_PATH" ]; then
        WORK="${WORK:-$(mktemp -d)}"
        ENV_PATH="$WORK/obhod.env"
      fi
      write_env_file "$ENV_PATH"
      TUI_ARGS+=("--env-file=$ENV_PATH" "--yes")
      unset BOT_TOKEN API_ID API_HASH ADMIN_ID OBHOD_TOKEN OBHOD_API_ID OBHOD_API_HASH OBHOD_ADMIN_ID
    fi
    echo_on
    say "starting the setup screen"
    exec "$PY_BIN" "$DEST/Storage/obhod_setup.py" "${TUI_ARGS[@]}"
  fi
  if [ -z "$PY_BIN" ]; then
    say "python3 is missing, the plain installer is used instead"
  else
    say "the setup screen source is missing, the plain installer is used instead"
  fi
fi

INSTALL_ARGS=("${ARGS[@]}")
if [ "$CREDS" = "1" ]; then
  if [ -z "$ENV_PATH" ]; then
    WORK="${WORK:-$(mktemp -d)}"
    ENV_PATH="$WORK/obhod.env"
  fi
  write_env_file "$ENV_PATH"
  INSTALL_ARGS+=("--env-file=$ENV_PATH" "--yes")
  unset BOT_TOKEN API_ID API_HASH ADMIN_ID OBHOD_TOKEN OBHOD_API_ID OBHOD_API_HASH OBHOD_ADMIN_ID
  say "credentials: from the environment $(mask_token "$TOKEN") api_id:${API_ID:-missing} admin:${ADMIN_ID:-missing}"
else
  _ep2="$(existing_env_path)"
  if [ -f "$_ep2" ]; then
    say "existing config at $_ep2 - press enter to keep current values ($(mask_token "$(env_get BOT_TOKEN "$_ep2")") / $(mask_hash "$(env_get API_HASH "$_ep2")"))"
    say "current services will be kept"
  fi
  say "credentials: asked in the terminal (masked as ****)"
fi

say "starting the installer"
if [ -t 0 ]; then
  bash "$DEST/Storage/obhod-install.sh" "${INSTALL_ARGS[@]}"
elif tty_available; then
  bash "$DEST/Storage/obhod-install.sh" "${INSTALL_ARGS[@]}" < /dev/tty
else
  bash "$DEST/Storage/obhod-install.sh" "${INSTALL_ARGS[@]}" < /dev/null
fi

echo_on
install_helper
say "done, check the service with systemctl status obhod"
say "to update later run this script again with the same keys"
say "sources on the server: $DEST"
