#!/bin/bash
set -e

VKTURN_USER="OBHOD"
VKTURN_HOME="/home/$VKTURN_USER"
WG_PORT=51820
WG_SUBNET="192.168.102.0/24"
SCRIPTS_DIR="/opt/vkturn"
EXT_IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root"
    exit 1
fi

mkdir -p /etc/wireguard "$SCRIPTS_DIR"
cd /etc/wireguard

if [ ! -f server_private.key ]; then
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key
fi

if [ ! -f wg0.conf ]; then
    cat > wg0.conf <<EOF
[Interface]
PrivateKey = $(cat server_private.key)
Address = 192.168.102.1/24
ListenPort = $WG_PORT
EOF
fi

[ -f /etc/wireguard/peers.json ] || echo '{}' > /etc/wireguard/peers.json
[ -f /etc/wireguard/profiles.json ] || echo '{}' > /etc/wireguard/profiles.json
[ -f /etc/wireguard/clients.json ] || echo '{}' > /etc/wireguard/clients.json
[ -f /etc/wireguard/wrap.key ] || openssl rand -hex 32 > /etc/wireguard/wrap.key
chmod 644 /etc/wireguard/peers.json /etc/wireguard/profiles.json /etc/wireguard/clients.json /etc/wireguard/wrap.key

sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wg-forward.conf
sysctl --system

# Ensure OBHOD user exists before configuring sudoers
if ! id "$VKTURN_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$VKTURN_USER"
fi
loginctl enable-linger "$VKTURN_USER" || true

wg-quick down wg0 2>/dev/null || true
wg-quick up wg0
systemctl enable wg-quick@wg0

iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o "$EXT_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o "$EXT_IFACE" -j MASQUERADE
iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
netfilter-persistent save

# Allow WireGuard port via iptables (ufw conflicts with iptables-persistent)
iptables -C INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT
netfilter-persistent save

case "$(uname -m)" in
    x86_64|amd64) VKTURN_ARCH="amd64" ;;
    aarch64|arm64) VKTURN_ARCH="arm64" ;;
    *) echo "unsupported arch: $(uname -m)"; exit 1 ;;
esac

sudo -u "$VKTURN_USER" bash -c "
cd $VKTURN_HOME
if [ ! -f server ]; then
    wget -q -O server https://github.com/samosvalishe/free-turn-proxy/releases/latest/download/server-linux-${VKTURN_ARCH}
    chmod +x server
fi
"

SCRIPT_SRC_DIR="$(dirname "$0")"
cp "$SCRIPT_SRC_DIR/add_peer.sh" "$SCRIPTS_DIR/add_peer.sh"
cp "$SCRIPT_SRC_DIR/revoke_peer.sh" "$SCRIPTS_DIR/revoke_peer.sh"
cp "$SCRIPT_SRC_DIR/ensure_profile.sh" "$SCRIPTS_DIR/ensure_profile.sh"
cp "$SCRIPT_SRC_DIR/update_core.sh" "$SCRIPTS_DIR/update_core.sh"
cp "$SCRIPT_SRC_DIR/add_client.sh" "$SCRIPTS_DIR/add_client.sh"
chmod 750 "$SCRIPTS_DIR"/*.sh
chown root:root "$SCRIPTS_DIR"/*.sh

cat > /etc/sudoers.d/vkturn <<EOF
$VKTURN_USER ALL=(root) NOPASSWD: $SCRIPTS_DIR/add_peer.sh, $SCRIPTS_DIR/revoke_peer.sh, $SCRIPTS_DIR/ensure_profile.sh, $SCRIPTS_DIR/update_core.sh, $SCRIPTS_DIR/add_client.sh
EOF
chmod 440 /etc/sudoers.d/vkturn
visudo -c -f /etc/sudoers.d/vkturn

echo ""
echo "base infra ready"
echo "server pubkey: $(cat /etc/wireguard/server_public.key)"
echo "wrap key: $(cat /etc/wireguard/wrap.key)"
