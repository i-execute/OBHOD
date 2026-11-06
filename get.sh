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
DEST_FIXED=0
HAS_INSTALLER_ARGS=0
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

pick_writable_dest() {
  if [ -n "${OBHOD_DIR:-}" ] || [ "${DEST_FIXED:-0}" = "1" ]; then
    return 0
  fi
  local candidate
  for candidate in "/opt/obhod-src" "/usr/local/share/obhod-src" "/var/lib/obhod-src" "/home/obhod-src"; do
    mkdir -p "$candidate" 2>/dev/null || continue
    if touch "$candidate/.obhod-write-test" 2>/dev/null; then
      rm -f "$candidate/.obhod-write-test"
      DEST="$candidate"
      return 0
    fi
    if [ -d "$candidate" ] && [ "$(ls -A "$candidate" 2>/dev/null | wc -l)" = "0" ]; then
      rmdir "$candidate" 2>/dev/null || true
    fi
  done
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
    --dir=*) DEST="${item#*=}"; DEST_FIXED=1 ;;
    --src=*) SRC_DIR="${item#*=}" ;;
    --env-file=*) ENV_PATH="${item#*=}" ;;
    --dry-run) DRY_RUN=1 ;;
    --no-install) NO_INSTALL=1 ;;
    --no-tui|--plain) TUI=0 ;;
    *) ARGS+=("$item"); HAS_INSTALLER_ARGS=1 ;;
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
  local primary="https://codeload.github.com/$REPO/tar.gz/${REF:-HEAD}"
  local fallback="https://github.com/$REPO/archive/${REF:-HEAD}.tar.gz"
  local progress=("-sS")
  if [ -t 2 ]; then
    progress=("--progress-bar")
  fi
  say "downloading $primary"
  mkdir -p "$WORK/repo"
  if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 \
      "${progress[@]}" "$primary" -o "$WORK/repo.tar.gz" </dev/null; then
    note "primary archive host failed, trying $fallback"
    if ! curl -fL --retry 2 --retry-delay 2 --connect-timeout 15 --max-time 300 \
        "${progress[@]}" "$fallback" -o "$WORK/repo.tar.gz" </dev/null; then
      note "the archive could not be downloaded, check the network and the proxy settings"
      return 1
    fi
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
  local args=(clone --depth 1 --single-branch --no-tags --filter=blob:none)
  if [ -d "$DEST/.git" ]; then
    rm -f "$DEST/.git/index.lock" 2>/dev/null || true
    args+=(--reference-if-able "$DEST" --dissociate)
  fi
  if [ -n "$REF" ]; then
    args+=(--branch "$REF")
  fi
  if [ "$TRACE" != "1" ]; then
    args+=(--quiet)
  fi
  say "cloning https://github.com/$REPO.git, the wait is capped at ${CLONE_TIMEOUT}s"
  if GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true GIT_HTTP_LOW_SPEED_LIMIT=1024 GIT_HTTP_LOW_SPEED_TIME=25 \
      timeout "$CLONE_TIMEOUT" git "${args[@]}" "https://github.com/$REPO.git" "$WORK/repo" >&2 </dev/null; then
    return 0
  fi
  rm -rf "$WORK/repo"
  note "retrying git clone over HTTP/1.1"
  GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true GIT_HTTP_LOW_SPEED_LIMIT=1024 GIT_HTTP_LOW_SPEED_TIME=25 \
    timeout "$CLONE_TIMEOUT" git -c http.version=HTTP/1.1 "${args[@]}" "https://github.com/$REPO.git" "$WORK/repo" >&2 </dev/null
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

helper_is_writable() {
  local target="$1"
  if [ -e "$target" ]; then
    [ -w "$target" ] || return 1
    local owner
    owner="$(stat -c '%u:%g' "$target" 2>/dev/null || echo "")"
    local me
    me="$(id -u):$(id -g)"
    local root_id="0:0"
    if [ "$owner" = "$me" ] || [ "$owner" = "$root_id" ]; then
      return 0
    fi
    return 1
  fi
  local dir
  dir="$(dirname "$target")"
  [ -w "$dir" ]
}

install_helper() {
  [ "$NO_INSTALL" = "0" ] || return 0
  local target="/usr/local/bin/obhod-get"
  if [ ! -f "$DEST/get.sh" ]; then
    note "the helper $target is not installed, the bot fetches get.sh over https"
    return 0
  fi
  if helper_is_writable "$target"; then
    if install -m 700 "$DEST/get.sh" "$target" 2>/dev/null; then
      say "helper installed: $target (the bot can update itself without a root shell)"
    else
      note "the helper $target was not installed, the bot keeps fetching get.sh over https"
    fi
    return 0
  fi
  if sudo -n install -m 700 "$DEST/get.sh" "$target" 2>/dev/null; then
    say "helper installed with sudo: $target"
    return 0
  fi
  note "the helper $target is owned by root and cannot be replaced from here, the bot keeps fetching get.sh over https"
  note "to let the bot self-update, run once as root: install -m 700 $DEST/get.sh $target"
  return 0
}

heal_dest() {
  local missing=0
  mkdir -p "$DEST" || return 1
  if ! touch "$DEST/.obhod-write-test" 2>/dev/null; then
    note "the directory $DEST is not writable"
    return 1
  fi
  rm -f "$DEST/.obhod-write-test"
  for item in BOT Storage get.sh; do
    if [ ! -w "$DEST/$item" ] && [ -e "$DEST/$item" ]; then
      missing=$((missing + 1))
    fi
  done
  if [ "$missing" -gt 0 ]; then
    say "some files in $DEST are read-only, the tree is recreated once"
    rm -rf "$DEST" || true
    mkdir -p "$DEST" || return 1
  fi
  return 0
}

copy_entry() {
  local item="$1"
  local name
  name="$(basename -- "$item")"
  if [ -d "$item" ]; then
    rm -rf "${DEST:?}/$name" 2>/dev/null || true
    cp -a "$item" "$DEST/" 2>/dev/null && return 0
    mkdir -p "$DEST/$name" 2>/dev/null || return 1
    cp -a "$item/." "$DEST/$name/" 2>/dev/null && return 0
    return 1
  fi
  rm -f "${DEST:?}/$name" 2>/dev/null || true
  cp -a "$item" "$DEST/$name" 2>/dev/null && return 0
  cp -f "$item" "$DEST/$name" 2>/dev/null && return 0
  return 1
}

sync_source() {
  if ! heal_dest; then
    die "the directory $DEST cannot be written: the service unit keeps it read-only, run get.sh from a root shell over ssh, or stop the service first (systemctl stop obhod)"
  fi
  if [ -e "$DEST/.obhod-src" ]; then
    if ! rm -rf "$DEST" 2>/dev/null; then
      note "some old files in $DEST refused to be removed, they are overwritten one by one"
    fi
  fi
  mkdir -p "$DEST" || die "the directory $DEST could not be created"
  local copied=0
  local failed=()
  local item
  for item in "$SRC"/* "$SRC"/.[!.]*; do
    [ -e "$item" ] || continue
    case "$(basename -- "$item")" in
      .venv|__pycache__|.pytest_cache|.obhod-src) continue ;;
    esac
    if copy_entry "$item"; then
      copied=$((copied + 1))
    else
      failed+=("$(basename -- "$item")")
    fi
  done
  if [ "${#failed[@]}" -gt 0 ]; then
    note "these paths could not be copied into $DEST: ${failed[*]}"
    note "a read-only file inside $DEST is the usual reason, the rest of the tree was updated"
    return 1
  fi
  say "copied $copied paths into $DEST (no tar pipe, so one read-only file cannot break the whole sync)"
  : > "$DEST/.obhod-src" 2>/dev/null || true
  chmod 600 "$DEST/.obhod-src" 2>/dev/null || true
  return 0
}

write_env_file() {
  local path="$1"
  if ! mkdir -p "$(dirname "$path")" 2>/dev/null; then
    note "the env directory $(dirname "$path") could not be created"
    return 1
  fi
  if ! ( umask 077; {
      printf 'BOT_TOKEN=%s\n' "$TOKEN"
      printf 'API_ID=%s\n' "$API_ID"
      printf 'API_HASH=%s\n' "$API_HASH"
      printf 'ADMIN_ID=%s\n' "$ADMIN_ID"
    } > "$path" ) 2>/dev/null; then
    note "the env file $path could not be written: $(dirname "$path") is on a read-only mount"
    return 1
  fi
  chmod 600 "$path" 2>/dev/null || true
  return 0
}

runtime_writable() {
  local path="$1"
  local dir
  dir="$(dirname "$path")"
  if [ -w "$dir" ] && [ ! -e "$path" ]; then
    return 0
  fi
  if [ -w "$path" ]; then
    return 0
  fi
  return 1
}

pick_runtime_env() {
  if [ -n "${OBHOD_ENV_FILE:-}" ]; then
    return 0
  fi
  local candidate
  local existing
  existing="$(existing_env_path)"
  if runtime_writable "$existing"; then
    ENV_PATH="$existing"
    return 0
  fi
  for candidate in "/etc/obhod/obhod.env" "/opt/obhod/obhod.env" "/var/lib/obhod/obhod.env"; do
    if runtime_writable "$candidate"; then
      ENV_PATH="$candidate"
      return 0
    fi
  done
  return 0
}

check_dest
pick_writable_dest
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
      if write_env_file "$ENV_PATH"; then
        say "env file: $ENV_PATH"
      fi
    fi
  fi
  if [ "$TUI" = "1" ] && [ "$HAS_INSTALLER_ARGS" = "0" ] && [ "$CREDS" = "0" ]; then
    say "screen: python3 $DEST/Storage/obhod_setup.py"
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
if ! sync_source; then
  die "the files were not updated completely: look at the list above, fix the permissions in $DEST and run the script again"
fi
say "files updated in $DEST"

if [ "$NO_INSTALL" = "1" ]; then
  say "the install is skipped, run it by hand: bash $DEST/Storage/obhod-install.sh ${ARGS[*]}"
  exit 0
fi

if [ "$TUI" = "1" ] && [ "$HAS_INSTALLER_ARGS" = "0" ] && [ "$CREDS" = "0" ] && tty_available; then
  PY_BIN="$(command -v python3 || true)"
  if [ -n "$PY_BIN" ] && [ -f "$DEST/Storage/obhod_setup.py" ]; then
    if [ -n "$ENV_PATH" ]; then
      export OBHOD_ENV_FILE="$ENV_PATH"
    fi
    echo_on
    say "starting the setup screen"
    exec "$PY_BIN" "$DEST/Storage/obhod_setup.py"
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
    pick_runtime_env
  fi
  if [ -z "$ENV_PATH" ] || ! write_env_file "$ENV_PATH"; then
    WORK="${WORK:-$(mktemp -d)}"
    ENV_PATH="$WORK/obhod.env"
    write_env_file "$ENV_PATH" || die "the env file could not be written anywhere, pass --env-file to a writable path"
    note "the system env directory is read-only, the config is passed from $ENV_PATH"
  fi
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
