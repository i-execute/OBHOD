#!/bin/bash
set -e

PROFILE="$1"
if [ -z "$PROFILE" ]; then
    echo "ERROR: usage: ensure_profile.sh <profile>" >&2
    exit 1
fi

PROFILES_DB="/etc/wireguard/profiles.json"
WRAP_KEY=$(cat /etc/wireguard/wrap.key)
VKTURN_HOME="/home/OBHOD"

[ -f "$PROFILES_DB" ] || echo '{}' > "$PROFILES_DB"

EXISTING_PORT=$(jq -r --arg p "$PROFILE" '.[$p].port // empty' "$PROFILES_DB")

port_is_free() {
    ! ss -Htln "sport = :$1" | grep -q . && ! ss -Huln "sport = :$1" | grep -q .
}

if [ -n "$EXISTING_PORT" ] && systemctl is-active --quiet "vk-turn-proxy-${PROFILE}"; then
    echo "PORT=$EXISTING_PORT"
    echo "PROFILE=$PROFILE"
    exit 0
fi

if [ -n "$EXISTING_PORT" ]; then
    PORT="$EXISTING_PORT"
else
    for _ in $(seq 1 50); do
        CANDIDATE=$(( (RANDOM % 64511) + 1025 ))
        if port_is_free "$CANDIDATE"; then
            PORT="$CANDIDATE"
            break
        fi
    done
fi

if [ "$PROFILE" = "wrap" ]; then
    EXEC_FLAGS="-wrap -wrap-key $WRAP_KEY"
else
    EXEC_FLAGS="-obf-profile $PROFILE -obf-key $WRAP_KEY"
fi

SERVICE_NAME="vk-turn-proxy-${PROFILE}"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=VK Turn Proxy (profile $PROFILE)
After=network.target wg-quick@wg0.service

[Service]
Type=simple
User=OBHOD
WorkingDirectory=$VKTURN_HOME
ExecStart=$VKTURN_HOME/server -listen 0.0.0.0:$PORT -connect 127.0.0.1:51820 $EXEC_FLAGS
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

ufw allow "$PORT"/tcp || true
ufw allow "$PORT"/udp || true

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

python3 - "$PROFILES_DB" "$PROFILE" "$PORT" <<'PYEOF'
import json, sys, os
path, profile, port = sys.argv[1:4]
db = json.load(open(path))
db[profile] = {"port": int(port)}
tmp = path + ".tmp"
json.dump(db, open(tmp, "w"), indent=2)
os.replace(tmp, path)
PYEOF

echo "PORT=$PORT"
echo "PROFILE=$PROFILE"
