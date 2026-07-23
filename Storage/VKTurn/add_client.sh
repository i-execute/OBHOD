#!/bin/bash
set -e

CLIENTS_DB="/etc/wireguard/clients.json"

CID="$1"
COMMENT="$2"
PROFILE="$3"

if [ -z "$CID" ]; then
    echo "ERROR: usage: add_client.sh <cid> <comment> [profile]" >&2
    exit 1
fi

[ -f "$CLIENTS_DB" ] || echo '{}' > "$CLIENTS_DB"

if jq -e --arg c "$CID" 'has($c)' "$CLIENTS_DB" >/dev/null; then
    echo "ERROR: cid '$CID' already in allowlist" >&2
    exit 2
fi

python3 - "$CLIENTS_DB" "$CID" "$COMMENT" <<'PYEOF'
import json, sys, os, time
path, cid, comment = sys.argv[1:4]
db = json.load(open(path))
db[cid] = {"comment": comment, "added": int(time.time())}
tmp = path + ".tmp"
json.dump(db, open(tmp, "w"), indent=2)
os.replace(tmp, path)
PYEOF

chmod 644 "$CLIENTS_DB"

# Reload the profile's proxy instance so the new cid is picked up without
# dropping unrelated clients. Prefer SIGHUP (live reload); fall back to a
# full restart if the running server build doesn't support it.
if [ -n "$PROFILE" ]; then
    systemctl kill -s HUP "vk-turn-proxy-${PROFILE}" 2>/dev/null || \
        systemctl restart "vk-turn-proxy-${PROFILE}" 2>/dev/null || true
fi

echo "OK: added $CID"
echo "CID=$CID"
