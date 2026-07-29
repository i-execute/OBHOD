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

apt install -qq -y wireguard wireguard-tools python3 python3-pip python3-venv git curl jq

if ! id "$OBHOD_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$OBHOD_USER"
fi
loginctl enable-linger "$OBHOD_USER" || true

if [ -d "$INSTALL_DIR/.git" ]; then
    sudo -u "$OBHOD_USER" bash -c "cd $INSTALL_DIR && git fetch origin main && git reset --hard origin/main"
else
    sudo -u "$OBHOD_USER" git clone "$REPO_URL" "$INSTALL_DIR"
fi

if [ ! -f /etc/sudoers.d/vkturn ]; then
    bash "$INSTALL_DIR/Storage/VKTurn/setup_root.sh"
fi

# --- sudo-rs compatibility check ---
# Older/classic sudo accepts a single NOPASSWD line with a comma-separated
# command list. sudo-rs (the newer Rust reimplementation some Ubuntu images
# now ship) has been observed to fail to match comma-separated command
# lists on one line, silently denying every listed command. Probe it here:
# if OBHOD can't run the first vkturn script NOPASSWD, rewrite the sudoers
# file with one command per line, which both implementations accept.
if [ -f /etc/sudoers.d/vkturn ]; then
    ALLOWED=$(sudo -u "$OBHOD_USER" sudo -n -l 2>/dev/null | grep -c "/opt/vkturn/add_peer_ios.sh" || true)
    if [ "$ALLOWED" -eq 0 ]; then
        echo "detected sudo-rs (or similar) not matching comma-separated NOPASSWD list"
        echo "rewriting /etc/sudoers.d/vkturn with one command per line..."
        cat > /etc/sudoers.d/vkturn <<EOF
$OBHOD_USER ALL=(root) NOPASSWD: /opt/vkturn/add_peer_ios.sh
$OBHOD_USER ALL=(root) NOPASSWD: /opt/vkturn/add_peer_android.sh
$OBHOD_USER ALL=(root) NOPASSWD: /opt/vkturn/add_client.sh
$OBHOD_USER ALL=(root) NOPASSWD: /opt/vkturn/revoke_peer.sh
$OBHOD_USER ALL=(root) NOPASSWD: /opt/vkturn/ensure_profile.sh
$OBHOD_USER ALL=(root) NOPASSWD: /opt/vkturn/update_core.sh
EOF
        chmod 440 /etc/sudoers.d/vkturn
        visudo -c -f /etc/sudoers.d/vkturn
        if sudo -u "$OBHOD_USER" sudo -n -l 2>/dev/null | grep -q "/opt/vkturn/add_peer_ios.sh"; then
            echo "sudoers fixed: OBHOD can now run vkturn scripts NOPASSWD"
        else
            echo "WARNING: sudoers still not matching after rewrite - check manually with:"
            echo "  sudo -u $OBHOD_USER sudo -n -l"
        fi
    else
        echo "sudoers OK: OBHOD already has NOPASSWD access to vkturn scripts"
    fi
fi

sudo -u "$OBHOD_USER" python3 -m venv "$INSTALL_DIR/venv"
sudo -u "$OBHOD_USER" "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$OBHOD_USER" "$INSTALL_DIR/venv/bin/pip" install --quiet telethon aiohttp pyyaml gitpython requests

UNIT_DIR="/home/$OBHOD_USER/.config/systemd/user"
OBHOD_UID=$(id -u "$OBHOD_USER")
export XDG_RUNTIME_DIR="/run/user/$OBHOD_UID"

install_unit() {
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
    sudo -u "$OBHOD_USER" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" systemctl --user daemon-reload
}

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
        echo ""
        echo "⚠️  Inline mode is OFF for @$USERNAME"
        echo "   The Updater module (GitHub token input) needs inline mode."
        echo "   Enable it later via @BotFather -> /setinline -> @$USERNAME"
        echo ""
    else
        echo "Inline mode enabled for @$USERNAME"
    fi

    echo "BOT_TOKEN=$BOT_TOKEN" > "$ENV_FILE"
    chown "$OBHOD_USER:$OBHOD_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    install_unit
    sudo -u "$OBHOD_USER" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" systemctl --user enable --now "$SERVICE_NAME"

    echo "connected to @$USERNAME successfully"
    echo ""
    echo ">> Send ANY message to @$USERNAME in DM now."
    echo ">> The bot will reply with your numeric user ID."
    echo ">> If no reply within 10 seconds, check logs:"
    echo "   sudo -u $OBHOD_USER XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR journalctl --user -u $SERVICE_NAME -f"
    echo ""

    read -rp "Enter your id (from the bot's reply): " OWNER_ID < /dev/tty
    if ! [[ "$OWNER_ID" =~ ^[0-9]+$ ]]; then
        echo "invalid id"
        exit 1
    fi
    echo "OWNER_ID=$OWNER_ID" >> "$ENV_FILE"
    chown "$OBHOD_USER:$OBHOD_USER" "$ENV_FILE"

    sudo -u "$OBHOD_USER" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" systemctl --user restart "$SERVICE_NAME"
else
    install_unit
    sudo -u "$OBHOD_USER" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" systemctl --user enable --now "$SERVICE_NAME"
fi

echo ""
echo "SSH setup complete"
echo "continue configuration inside Telegram chat with the bot"
echo ""
echo "status  : sudo -u $OBHOD_USER XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR systemctl --user status $SERVICE_NAME"
echo "logs    : sudo -u $OBHOD_USER XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR journalctl --user -u $SERVICE_NAME -f"
echo "restart : sudo -u $OBHOD_USER XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR systemctl --user restart $SERVICE_NAME"