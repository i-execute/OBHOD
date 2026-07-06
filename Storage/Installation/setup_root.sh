#!/bin/bash
# setup_root.sh — ОДНОРАЗОВЫЙ root-скрипт. Поднимает WG + vk-turn-proxy сервер.
# После этого добавление/отзыв пользователей идёт через add_peer.sh / revoke_peer.sh,
# без повторного запуска этого скрипта и без даунтайма интерфейса.
set -e

VKTURN_USER="vkturn"
VKTURN_HOME="/home/$VKTURN_USER"
WG_PORT=51820
PREFERRED_VKTURN_PORT=6767
VERSION="0.11.1"
WG_SUBNET="192.168.102.0/24"
SCRIPTS_DIR="/opt/vkturn"
BOT_SYSTEM_USER="forget"          # системный пользователь, от которого крутится OBHOD
EXT_IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)

if [ "$(id -u)" -ne 0 ]; then
    echo "Запускать от root (sudo bash setup_root.sh)"
    exit 1
fi

# --- выбор порта для vk-turn-proxy: пробуем предпочитаемый, если занят — случайный >1024 ---
port_is_free() {
    # true, если порт $1/tcp никем не занят (ни в LISTEN, ни в TIME_WAIT и т.п.)
    ! ss -Htln "sport = :$1" | grep -q .
}

if port_is_free "$PREFERRED_VKTURN_PORT"; then
    VKTURN_PORT="$PREFERRED_VKTURN_PORT"
else
    echo "Порт $PREFERRED_VKTURN_PORT занят, подбираю случайный..."
    for _ in $(seq 1 50); do
        CANDIDATE=$(( (RANDOM % 64511) + 1025 ))   # диапазон 1025-65535
        if port_is_free "$CANDIDATE"; then
            VKTURN_PORT="$CANDIDATE"
            break
        fi
    done
    if [ -z "$VKTURN_PORT" ]; then
        echo "Не удалось найти свободный порт, задай VKTURN_PORT вручную"
        exit 1
    fi
fi
echo "Использую порт для vk-turn-proxy: $VKTURN_PORT"

if ! id "$VKTURN_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$VKTURN_USER"
fi

apt update -qq && apt install -y wireguard wireguard-tools qrencode iptables-persistent jq python3

mkdir -p /etc/wireguard "$SCRIPTS_DIR"
cd /etc/wireguard

if [ ! -f server_private.key ]; then
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key
fi

SERVER_PRIV=$(cat server_private.key)
SERVER_PUB=$(cat server_public.key)

# Базовый интерфейс без peer'ов — peer'ы добавляются позже через add_peer.sh
if [ ! -f wg0.conf ]; then
    cat > wg0.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIV
Address = 192.168.102.1/24
ListenPort = $WG_PORT
EOF
fi

# реестр выданных peer'ов, ключ = tag (например tg user_id), значение = {ip, pubkey}
[ -f /etc/wireguard/peers.json ] || echo '{}' > /etc/wireguard/peers.json
chmod 644 /etc/wireguard/peers.json

sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | tee /etc/sysctl.d/99-wg-forward.conf
sysctl --system

wg-quick down wg0 2>/dev/null || true
wg-quick up wg0
systemctl enable wg-quick@wg0

# NAT + форвардинг один раз, дальше работает для любого числа peer'ов
iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o "$EXT_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o "$EXT_IFACE" -j MASQUERADE
iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
netfilter-persistent save

ufw allow $VKTURN_PORT/tcp || true
ufw allow $WG_PORT/udp || true
if grep -q 'DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw 2>/dev/null; then
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
fi
ufw reload || true

sudo -u "$VKTURN_USER" bash -c "
cd $VKTURN_HOME
if [ ! -f server ]; then
    wget -q -O server https://github.com/samosvalishe/vk-turn-proxy/releases/download/$VERSION/server-linux-amd64
    chmod +x server
fi
"

if [ ! -f /etc/wireguard/wrap.key ]; then
    sudo -u "$VKTURN_USER" "$VKTURN_HOME/server" -gen-wrap-key | tail -1 > /etc/wireguard/wrap.key
fi
WRAP_KEY=$(cat /etc/wireguard/wrap.key)

cat > /etc/systemd/system/vk-turn-proxy.service <<EOF
[Unit]
Description=VK Turn Proxy Server
After=network.target wg-quick@wg0.service

[Service]
Type=simple
User=$VKTURN_USER
WorkingDirectory=$VKTURN_HOME
ExecStart=$VKTURN_HOME/server -listen 0.0.0.0:$VKTURN_PORT -connect 127.0.0.1:$WG_PORT -wrap -wrap-key $WRAP_KEY
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vk-turn-proxy

# --- копируем управляющие скрипты и настраиваем sudoers для бота ---
cp "$(dirname "$0")/add_peer.sh" "$SCRIPTS_DIR/add_peer.sh"
cp "$(dirname "$0")/revoke_peer.sh" "$SCRIPTS_DIR/revoke_peer.sh"
chmod 750 "$SCRIPTS_DIR/add_peer.sh" "$SCRIPTS_DIR/revoke_peer.sh"
chown root:root "$SCRIPTS_DIR/add_peer.sh" "$SCRIPTS_DIR/revoke_peer.sh"

cat > /etc/sudoers.d/vkturn <<EOF
$BOT_SYSTEM_USER ALL=(root) NOPASSWD: $SCRIPTS_DIR/add_peer.sh, $SCRIPTS_DIR/revoke_peer.sh
EOF
chmod 440 /etc/sudoers.d/vkturn
visudo -c -f /etc/sudoers.d/vkturn

echo "$VKTURN_PORT" > /etc/wireguard/vkturn_port
SERVER_IP=$(curl -s ifconfig.me)

echo ""
echo "[*] Базовая инфраструктура готова"
echo "Server pubkey : $SERVER_PUB"
echo "Endpoint      : ${SERVER_IP}:${VKTURN_PORT}"
echo "Wrap key      : $WRAP_KEY"
echo "Scripts       : $SCRIPTS_DIR (доступны без пароля пользователю $BOT_SYSTEM_USER)"
echo "Peers DB      : /etc/wireguard/peers.json"
echo ""
echo "Впиши в .env бота (или он подхватится автоматически при следующем запуске Setuper.sh):"
echo "  VKTURN_ENDPOINT=${SERVER_IP}:${VKTURN_PORT}"
