#!/bin/bash
set -e

TEMP_INSTALLER="/tmp/obhod_setuper.sh"
REPO_RAW="https://raw.githubusercontent.com/i-execute/OBHOD/main/Storage/Installation/Setuper.sh"

echo "Downloading OBHOD setuper..."

if command -v curl &> /dev/null; then
    curl -fsSL "$REPO_RAW" -o "$TEMP_INSTALLER"
elif command -v wget &> /dev/null; then
    wget -q "$REPO_RAW" -O "$TEMP_INSTALLER"
else
    echo "ERROR: install curl or wget first"
    exit 1
fi

chmod +x "$TEMP_INSTALLER"
bash "$TEMP_INSTALLER" < /dev/tty
rm -f "$TEMP_INSTALLER"
