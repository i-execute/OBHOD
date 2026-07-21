#!/bin/bash
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (sudo bash Setuper.sh)"
    exit 1
fi

OBHOD_USER="OBHOD"
INSTALL_DIR="/home/$OBHOD_USER/OBHOD"
ENV_FILE="$INSTALL_DIR/.env"
REPO_URL="https://github.com/i-execute/OBHOD.git"
SERVICE_NAME="obhod"

apt update -qq
apt upgrade -qq -y
apt install -qq -y wireguard wireguard-tools python3 python3-pip python3-venv git curl jq

if ! id "$OBHOD_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$OBHOD_USER"
fi
usermod -aG sudo "$OBHOD_USER" || true
loginctl enable-linger "$OBHOD_USER" || true

if [ -d "$INSTALL_DIR/.git" ]; then
    sudo -u "$OBHOD_USER" bash -c "cd $INSTALL_DIR && git pull origin main"
else
    sudo -u "$OBHOD_USER" git clone "$REPO_URL" "$INSTALL_DIR"
fi

if [ ! -f /etc/sudoers.d/vkturn ]; then
    bash "$INSTALL_DIR/Storage/VKTurn/setup_root.sh"
fi

sudo -u "$OBHOD_USER" python3 -m venv "$INSTALL_DIR/venv"
sudo -u "$OBHOD_USER" "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$OBHOD_USER" "$INSTALL_DIR/venv/bin/pip" install --quiet telethon aiohttp pyyaml gitpython requests

if [ ! -f "$ENV_FILE" ]; then
    read -rp "BOT_TOKEN: " BOT_TOKEN < /dev/tty
    if [ -z "$BOT_TOKEN" ]; then
        echo "no token provided"
        exit 1
    fi

    ME_JSON=$(curl -s "https://api.telegram.org/bot${BOT_TOKEN}/getMe")
    OK=$(echo "$ME_JSON" | jq -r '.ok')
    if [ "$OK" != "true" ]; then
        echo "invalid token"
        exit 1
    fi

    USERNAME=$(echo "$ME_JSON" | jq -r '.result.username')
    INLINE_SUPPORTED=$(echo "$ME_JSON" | jq -r '.result.supports_inline_queries')

    if [ "$INLINE_SUPPORTED" != "true" ]; then
        echo "inline mode is disabled for @$USERNAME"
        echo "enable it via @BotFather -> /setinline, then re-run this script"
        exit 1
    fi

    echo "BOT_TOKEN=$BOT_TOKEN" > "$ENV_FILE"
    chown "$OBHOD_USER:$OBHOD_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    echo "connected to @$USERNAME successfully"
    echo "message it now in DM with anything to learn your id"

    read -rp "Enter your id (from the bot's reply): " OWNER_ID < /dev/tty
    if ! [[ "$OWNER_ID" =~ ^[0-9]+$ ]]; then
        echo "invalid id"
        exit 1
    fi
    echo "OWNER_ID=$OWNER_ID" >> "$ENV_FILE"
    chown "$OBHOD_USER:$OBHOD_USER" "$ENV_FILE"
fi

UNIT_DIR="/home/$OBHOD_USER/.config/systemd/user"
sudo -u "$OBHOD_USER" mkdir -p "$UNIT_DIR"

cat > "$UNIT_DIR/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=OBHOD

[Service]
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/venv/bin/python3 -m BOT
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

chown -R "$OBHOD_USER:$OBHOD_USER" "$UNIT_DIR"

OBHOD_UID=$(id -u "$OBHOD_USER")
export XDG_RUNTIME_DIR="/run/user/$OBHOD_UID"

sudo -u "$OBHOD_USER" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" systemctl --user daemon-reload
sudo -u "$OBHOD_USER" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" systemctl --user enable --now "$SERVICE_NAME"

echo ""
echo "SSH setup complete"
echo "continue configuration inside Telegram chat with the bot"
echo ""
echo "status  : sudo -u $OBHOD_USER XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR systemctl --user status $SERVICE_NAME"
echo "logs    : sudo -u $OBHOD_USER XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR journalctl --user -u $SERVICE_NAME -f"
echo "restart : sudo -u $OBHOD_USER XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR systemctl --user restart $SERVICE_NAME"