#!/bin/bash
set -e

DOWNLOAD_URL="$1"
if [ -z "$DOWNLOAD_URL" ]; then
    echo "ERROR: usage: update_core.sh <download_url> [version_tag]" >&2
    exit 1
fi

VKTURN_HOME="/home/OBHOD"
TMP_BIN="$VKTURN_HOME/server.new"

wget -q -O "$TMP_BIN" "$DOWNLOAD_URL"
chmod +x "$TMP_BIN"

if [ -f "$VKTURN_HOME/server" ]; then
    cp "$VKTURN_HOME/server" "$VKTURN_HOME/server.bak"
fi
mv "$TMP_BIN" "$VKTURN_HOME/server"
chown OBHOD:OBHOD "$VKTURN_HOME/server"

for unit in $(systemctl list-units --all --plain --no-legend 'vk-turn-proxy-*' | awk '{print $1}'); do
    systemctl restart "$unit"
done

VERSION_TAG="$2"
if [ -n "$VERSION_TAG" ]; then
    echo "$VERSION_TAG" > "$VKTURN_HOME/server_version.txt"
fi

echo "OK"
