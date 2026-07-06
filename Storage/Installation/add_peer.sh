#!/bin/bash
# add_peer.sh <tag> — добавляет WG peer в рантайме, без даунтайма остальных клиентов.
# Вызывается ботом через sudo (см. /etc/sudoers.d/vkturn).
set -e

WG_IFACE="wg0"
WG_SUBNET_BASE="192.168.102"
PEERS_DB="/etc/wireguard/peers.json"
SERVER_PUB_FILE="/etc/wireguard/server_public.key"

TAG="$1"
if [ -z "$TAG" ]; then
    echo "ERROR: usage: add_peer.sh <tag>" >&2
    exit 1
fi

[ -f "$PEERS_DB" ] || echo '{}' > "$PEERS_DB"

if jq -e --arg t "$TAG" 'has($t)' "$PEERS_DB" >/dev/null; then
    echo "ERROR: tag '$TAG' already exists, use revoke_peer.sh first" >&2
    exit 2
fi

NEXT_IP=$(python3 - "$PEERS_DB" <<'PYEOF'
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
CLIENT_IP="${WG_SUBNET_BASE}.${NEXT_IP}"
SERVER_PUB=$(cat "$SERVER_PUB_FILE")

# добавляем peer в рантайм — существующие подключения не затрагиваются
wg set "$WG_IFACE" peer "$CLIENT_PUB" allowed-ips "${CLIENT_IP}/32"

# персистентность на случай ребута сервера
cat >> "/etc/wireguard/${WG_IFACE}.conf" <<EOF

[Peer]
# tag=$TAG
PublicKey = $CLIENT_PUB
AllowedIPs = ${CLIENT_IP}/32
EOF

# атомарно дописываем в реестр
python3 - "$PEERS_DB" "$TAG" "$CLIENT_IP" "$CLIENT_PUB" <<'PYEOF'
import json, sys
path, tag, ip, pub = sys.argv[1:5]
db = json.load(open(path))
db[tag] = {"ip": ip, "pubkey": pub}
tmp = path + ".tmp"
json.dump(db, open(tmp, "w"), indent=2)
import os
os.replace(tmp, path)
PYEOF

# машиночитаемый вывод для бота
echo "PRIV=$CLIENT_PRIV"
echo "PUB=$SERVER_PUB"
echo "IP=$CLIENT_IP"
