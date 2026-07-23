#!/bin/bash
set -e

WG_IFACE="wg0"
WG_SUBNET_BASE="192.168.102"
PEERS_DB="/etc/wireguard/peers.json"
CLIENTS_DB="/etc/wireguard/clients.json"
SERVER_PUB_FILE="/etc/wireguard/server_public.key"

TAG="$1"
if [ -z "$TAG" ]; then
    echo "ERROR: usage: add_peer_android.sh <tag>" >&2
    exit 1
fi

[ -f "$PEERS_DB" ] || sudo -E bash -c "echo '{}' > '$PEERS_DB'"
[ -f "$CLIENTS_DB" ] || sudo -E bash -c "echo '{}' > '$CLIENTS_DB'"

if sudo -E jq -e --arg t "$TAG" 'has($t)' "$PEERS_DB" >/dev/null 2>&1; then
    echo "ERROR: tag '$TAG' already exists, use revoke_peer.sh first" >&2
    exit 2
fi

NEXT_IP=$(sudo -E python3 - "$PEERS_DB" <<'PYEOF'
import json, sys
db = json.load(open(sys.argv[1]))
used = {int(v["ip"].split(".")[-1]) for v in db.values()}
for i in range(4, 254):
    if i not in used:
        print(i)
        break
else:
    sys.exit("no free ip")
PYEOF
)

CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
PRESHARED_KEY=$(wg genpsk)
CLIENT_IP="${WG_SUBNET_BASE}.${NEXT_IP}"
SERVER_PUB=$(sudo -E cat "$SERVER_PUB_FILE")

sudo -E wg set "$WG_IFACE" peer "$CLIENT_PUB" preshared-key <(echo "$PRESHARED_KEY") allowed-ips "${CLIENT_IP}/32"

sudo -E bash -c "cat >> '/etc/wireguard/${WG_IFACE}.conf' <<EOF

[Peer]
# tag=$TAG
PublicKey = $CLIENT_PUB
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_IP}/32
EOF"

sudo -E python3 - "$PEERS_DB" "$TAG" "$CLIENT_IP" "$CLIENT_PUB" "$PRESHARED_KEY" <<'PYEOF'
import json, sys, os
path, tag, ip, pub, psk = sys.argv[1:6]
db = json.load(open(path))
db[tag] = {"ip": ip, "pubkey": pub, "presharedkey": psk}
tmp = path + ".tmp"
json.dump(db, open(tmp, "w"), indent=2)
os.replace(tmp, path)
PYEOF

echo "PRIV=$CLIENT_PRIV"
echo "PUB=$SERVER_PUB"
echo "IP=$CLIENT_IP"
echo "PSK=$PRESHARED_KEY"
