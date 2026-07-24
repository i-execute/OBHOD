#!/bin/bash
set -e

# Register a freeturn client-id into the server's allowlist (clients.json).
# The Android freeturn client authenticates with this cid; without it the
# TURN proxy rejects the connection.  comment is stored alongside so that
# revoke_peer.sh can later remove it when the WireGuard peer is revoked.

CLIENTS_DB="/etc/wireguard/clients.json"
CID="$1"
COMMENT="${2:-}"

if [ -z "$CID" ]; then
    echo "ERROR: usage: add_client.sh <client_id> [comment]" >&2
    exit 1
fi

[ -f "$CLIENTS_DB" ] || echo '{}' > "$CLIENTS_DB"

if jq -e --arg c "$CID" 'has($c)' "$CLIENTS_DB" >/dev/null 2>&1; then
    echo "ERROR: client_id '$CID' already exists" >&2
    exit 2
fi

python3 - "$CLIENTS_DB" "$CID" "$COMMENT" <<'PYEOF'
import json, sys, os
path, cid, comment = sys.argv[1], sys.argv[2], sys.argv[3]
db = json.load(open(path))
db[cid] = {"comment": comment}
tmp = path + ".tmp"
json.dump(db, open(tmp, "w"), indent=2)
os.replace(tmp, path)
PYEOF

echo "CID=$CID"
echo "COMMENT=$COMMENT"
echo "OK: client added"
