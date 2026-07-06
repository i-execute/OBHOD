#!/bin/bash

set -e

INSTALL_DIR="$HOME/OBHOD"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="obhod"
PYTHON_BIN="$(command -v python3)"
REPO_URL="https://github.com/i-execute/OBHOD.git"
ENV_FILE="$INSTALL_DIR/.env"

if [ -z "$PYTHON_BIN" ]; then
    echo "ERROR: python3 not found"
    exit 1
fi

echo ""
echo "Welcome back $USER"
sleep 0.5
echo "Setting up OBHOD..."
sleep 0.5
echo ""

env_is_valid() {
    [ -f "$ENV_FILE" ] || return 1

    local v_api_id v_api_hash v_bot_token v_owner_id
    v_api_id="$(grep -E '^API_ID=' "$ENV_FILE" | cut -d'=' -f2-)"
    v_api_hash="$(grep -E '^API_HASH=' "$ENV_FILE" | cut -d'=' -f2-)"
    v_bot_token="$(grep -E '^BOT_TOKEN=' "$ENV_FILE" | cut -d'=' -f2-)"
    v_owner_id="$(grep -E '^OWNER_ID=' "$ENV_FILE" | cut -d'=' -f2-)"

    [ -n "$v_api_id" ] && [ -n "$v_api_hash" ] && [ -n "$v_bot_token" ] && [ -n "$v_owner_id" ]
}

write_env_file() {
    cat > "$ENV_FILE" <<EOF
API_ID=$API_ID
API_HASH=$API_HASH
BOT_TOKEN=$BOT_TOKEN
OWNER_ID=$OWNER_ID
VKTURN_VK_LINK=$VKTURN_VK_LINK
VKTURN_ENDPOINT=$VKTURN_ENDPOINT
EOF
    chmod 600 "$ENV_FILE"
}

prompt_credentials() {
    read -rp "BOT_TOKEN       : " BOT_TOKEN < /dev/tty
    if [ -z "$BOT_TOKEN" ]; then
        echo "Enter token next time"
        exit 1
    fi

    read -rp "OWNER_ID        : " OWNER_ID < /dev/tty
    if ! [[ "$OWNER_ID" =~ ^[0-9]+$ ]]; then
        echo "Enter correct ID next time"
        exit 1
    fi

    read -rp "API_ID          : " API_ID < /dev/tty
    if ! [[ "$API_ID" =~ ^[0-9]+$ ]]; then
        echo "Enter correct API ID next time"
        exit 1
    fi

    read -rp "API_HASH        : " API_HASH < /dev/tty
    if [ -z "$API_HASH" ]; then
        echo "Enter API hash next time"
        exit 1
    fi

    read -rp "VK join link    : " VKTURN_VK_LINK < /dev/tty

    DETECTED_ENDPOINT=""
    if [ -f /etc/wireguard/vkturn_port ]; then
        DETECTED_PORT="$(cat /etc/wireguard/vkturn_port)"
        DETECTED_IP="$(curl -s ifconfig.me || true)"
        if [ -n "$DETECTED_PORT" ] && [ -n "$DETECTED_IP" ]; then
            DETECTED_ENDPOINT="${DETECTED_IP}:${DETECTED_PORT}"
        fi
    fi

    if [ -n "$DETECTED_ENDPOINT" ]; then
        read -rp "Server endpoint [$DETECTED_ENDPOINT]: " VKTURN_ENDPOINT < /dev/tty
        VKTURN_ENDPOINT="${VKTURN_ENDPOINT:-$DETECTED_ENDPOINT}"
    else
        read -rp "Server endpoint (ip:port, e.g. 89.125.48.221:6767): " VKTURN_ENDPOINT < /dev/tty
    fi

    echo ""
}

ALREADY_INSTALLED=0
if [ -d "$INSTALL_DIR/.git" ]; then
    ALREADY_INSTALLED=1
fi

if [ "$ALREADY_INSTALLED" -eq 1 ]; then
    echo "OBHOD already installed, checking .env..."

    if env_is_valid; then
        echo ""
        echo "Current config:"
        echo " API_ID          : $(grep -E '^API_ID=' "$ENV_FILE" | cut -d'=' -f2-)"
        echo " OWNER_ID        : $(grep -E '^OWNER_ID=' "$ENV_FILE" | cut -d'=' -f2-)"
        echo " VKTURN_VK_LINK  : $(grep -E '^VKTURN_VK_LINK=' "$ENV_FILE" | cut -d'=' -f2-)"
        echo " VKTURN_ENDPOINT : $(grep -E '^VKTURN_ENDPOINT=' "$ENV_FILE" | cut -d'=' -f2-)"
        echo ""

        read -rp "Change config? [y/N]: " CHANGE_ENV < /dev/tty
        if [[ "$CHANGE_ENV" =~ ^[Yy]$ ]]; then
            prompt_credentials
            write_env_file
        fi
    else
        echo ".env missing or incomplete, please fill it in again"
        echo ""
        prompt_credentials
        write_env_file
    fi

    echo "Pulling latest changes..."
    cd "$INSTALL_DIR"
    git pull origin main
else
    prompt_credentials

    echo "Cloning repository..."
    git clone "$REPO_URL" "$INSTALL_DIR"

    write_env_file

    echo "Building venv and dependencies..."
    $PYTHON_BIN -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet telethon

    echo "Building daemon configuration..."

    UNIT_DIR="$HOME/.config/obhod"
    mkdir -p "$UNIT_DIR"

    cat > "$UNIT_DIR/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=OBHOD
After=network.target

[Service]
WorkingDirectory=$INSTALL_DIR/Bot
EnvironmentFile=$ENV_FILE
ExecStart=$VENV_DIR/bin/python3 $INSTALL_DIR/Bot/core.py
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

    mkdir -p "$HOME/.config/systemd/user"
    ln -sf "$UNIT_DIR/${SERVICE_NAME}.service" "$HOME/.config/systemd/user/${SERVICE_NAME}.service"

    systemctl --user daemon-reload
    systemctl --user enable "$SERVICE_NAME"
fi

systemctl --user restart "$SERVICE_NAME"

echo ""
echo "[*] OBHOD successfully started"
echo "    I_execute.t.me"
echo ""

echo "----------------------------------"
echo " installed in   : $INSTALL_DIR"
echo " venv directory : $VENV_DIR"
echo " config         : $ENV_FILE"
echo ""
echo "Swift commands:"
echo " status  : systemctl --user status $SERVICE_NAME"
echo " logs    : journalctl --user -u $SERVICE_NAME -f"
echo " stop    : systemctl --user stop $SERVICE_NAME"
echo " restart : systemctl --user restart $SERVICE_NAME"
echo ""
echo "ВАЖНО: перед первым запуском .vkadd выполни на этой же машине от root:"
echo "  sudo bash $INSTALL_DIR/Storage/Installation/setup_root.sh"
echo "чтобы поднять WireGuard + vk-turn-proxy и настроить sudoers для $USER."
