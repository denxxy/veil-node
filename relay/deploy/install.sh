#!/usr/bin/env bash
# Veil relay installer for Debian/Ubuntu VPS.
#
# Usage (from the relay/ directory of the repo, or anywhere — the script
# finds veil_relay.py next to itself):
#   sudo bash deploy/install.sh
#
# What it does:
#   1. installs python3 + venv
#   2. sets up /opt/veil-relay with a virtualenv and dependencies
#   3. creates a system user `veilrelay` and /var/lib/veil-relay
#   4. installs and starts the veil-relay systemd service on 127.0.0.1:8080
#
# For public exposure put Caddy or nginx with TLS in front (see Caddyfile),
# or run with --tls-cert/--tls-key directly.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Запусти с sudo: sudo bash $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")".." && pwd)"
SRC="$SCRIPT_DIR/veil_relay.py"
if [[ ! -f "$SRC" ]]; then
  echo "veil_relay.py не найден рядом с deploy/ ($SCRIPT_DIR)" >&2
  exit 1
fi

VEIL_DIR=/opt/veil-relay
DATA_DIR=/var/lib/veil-relay
PORT="${VEIL_PORT:-8080}"

echo "==> Установка системных пакетов"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv sqlite3 >/dev/null

echo "==> Виртуальное окружение в $VEIL_DIR"
mkdir -p "$VEIL_DIR"
python3 -m venv "$VEIL_DIR/venv"
"$VEIL_DIR/venv/bin/pip" install --upgrade -q pip
"$VEIL_DIR/venv/bin/pip" install -q "aiohttp>=3.8,<4" "cryptography>=3.4"
install -m 0644 "$SRC" "$VEIL_DIR/veil_relay.py"

echo "==> Системный пользователь и каталог данных"
id -u veilrelay >/dev/null 2>&1 || useradd --system --home "$VEIL_DIR" \
  --shell /usr/sbin/nologin veilrelay
mkdir -p "$DATA_DIR"
chown -R veilrelay:veilrelay "$DATA_DIR"
chown -R root:veilrelay "$VEIL_DIR"

echo "==> systemd-юнит"
sed "s|--port 8080|--port $PORT|" \
  "$SCRIPT_DIR/deploy/veil-relay.service" > /etc/systemd/system/veil-relay.service
systemctl daemon-reload
systemctl enable --now veil-relay.service
sleep 1
systemctl --no-pager --lines=5 status veil-relay.service || true

echo
echo "Готово. Relay слушает 127.0.0.1:$PORT (проверка: curl http://127.0.0.1:$PORT/health)"
echo "Следующий шаг — HTTPS перед relay: см. deploy/Caddyfile (Caddy + Let's Encrypt),"
echo "и/или проксирование через Cloudflare, чтобы скрыть IP сервера."
