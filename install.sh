#!/usr/bin/env bash
# نصب AHB Panel
set -e
REPO="${REPO:-https://github.com/sajaf47/os8shsnkak.git}"
DIR=/opt/ahb-panel
[ "$(id -u)" = 0 ] || { echo "با root اجرا کن"; exit 1; }
command -v git >/dev/null || { apt-get update && apt-get install -y git; }
command -v docker >/dev/null || curl -fsSL https://get.docker.com | sh
if [ -d "$DIR/.git" ]; then git -C "$DIR" pull; else git clone "$REPO" "$DIR"; fi
cd "$DIR" && docker compose up -d --build
IP=$(curl -s ifconfig.me || echo IP)
echo "✅ نصب شد: http://$IP:2053"
