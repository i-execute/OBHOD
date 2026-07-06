#!/bin/bash
# revoke_peer.sh <tag> — удаляет WG peer по tag'у из рантайма, конфига и реестра.
set -e

WG_IFACE="wg0"
PEERS_DB="/etc/wireguard/peers.json"
CONF_FILE="/etc/wireguard/${WG_IFACE}.conf"

TAG="$1"
if [ -z "$TAG" ]; then
    echo "ERROR: usage: revoke_peer.sh <tag>" >&2
    exit 1
fi

[ -f "$PEERS_DB" ] || { echo "ERROR: peers db not found" >&2; exit 1; }

PUBKEY=$(jq -r --arg t "$TAG" '.[$t].pubkey // empty' "$PEERS_DB")
if [ -z "$PUBKEY" ]; then
    echo "ERROR: tag '$TAG' not found" >&2
    exit 2
fi

# убираем из рантайма
wg set "$WG_IFACE" peer "$PUBKEY" remove

# вычищаем блок [Peer] с этим pubkey из конфиг-файла (ищем по маркеру # tag=)
python3 - "$CONF_FILE" "$TAG" <<'PYEOF'
import sys, re
path, tag = sys.argv[1], sys.argv[2]
with open(path) as f:
    content = f.read()

pattern = re.compile(
    r"\n?\[Peer\]\n# tag=" + re.escape(tag) + r"\n.*?(?=\n\[Peer\]|\Z)",
    re.DOTALL
)
new_content = pattern.sub("", content)

tmp = path + ".tmp"
with open(tmp, "w") as f:
    f.write(new_content)
import os
os.replace(tmp, path)
PYEOF

# чистим реестр
python3 - "$PEERS_DB" "$TAG" <<'PYEOF'
import json, sys, os
path, tag = sys.argv[1], sys.argv[2]
db = json.load(open(path))
db.pop(tag, None)
tmp = path + ".tmp"
json.dump(db, open(tmp, "w"), indent=2)
os.replace(tmp, path)
PYEOF

echo "OK: revoked $TAG"
