#!/bin/bash
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

wg set "$WG_IFACE" peer "$PUBKEY" remove

python3 - "$CONF_FILE" "$TAG" <<'PYEOF'
import sys, re, os
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
os.replace(tmp, path)
PYEOF

python3 - "$PEERS_DB" "$TAG" <<'PYEOF'
import json, sys, os
path, tag = sys.argv[1], sys.argv[2]
db = json.load(open(path))
db.pop(tag, None)
tmp = path + ".tmp"
json.dump(db, open(tmp, "w"), indent=2)
os.replace(tmp, path)
PYEOF

# Also drop any freeturn (Android) client-id allowlisted under this tag,
# so revoking a peer revokes both WireGuard and freeturn access.
CLIENTS_DB="/etc/wireguard/clients.json"
if [ -f "$CLIENTS_DB" ]; then
    python3 - "$CLIENTS_DB" "$TAG" <<'PYEOF'
import json, sys, os
path, tag = sys.argv[1], sys.argv[2]
db = json.load(open(path))
remaining = {cid: info for cid, info in db.items() if info.get("comment") != tag}
if remaining != db:
    tmp = path + ".tmp"
    json.dump(remaining, open(tmp, "w"), indent=2)
    os.replace(tmp, path)
PYEOF
fi

echo "OK: revoked $TAG"
