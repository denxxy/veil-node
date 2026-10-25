#!/usr/bin/env bash
# Veil relay installer for Debian/Ubuntu VPS.
#
# Usage (from the relay/ directory of the repo, or anywhere — the script
# finds veil_relay.py next to itself):
#   sudo bash deploy/install.sh
#
# Параметры через переменные окружения (можно комбинировать):
#   VEIL_PORT=8080             порт (по умолчанию 8080)
#   VEIL_LOCAL=1               привязка 127.0.0.1 — режим «за Caddy/nginx»
#   VEIL_TLS_CERT=/путь/к/fullchain.pem
#   VEIL_TLS_KEY=/путь/к/privkey.pem
#                              собственный TLS: relay сам слушает https://
#                              (пути от Let's Encrypt/certbot; приватный ключ
#                              должен быть читаем пользователю veilrelay)
#
# По умолчанию relay привязывается к 0.0.0.0 — то есть к внешнему IP сервера.
# Варианты публичного доступа:
#   а) прямо:  VEIL_TLS_CERT=... VEIL_TLS_KEY=... VEIL_PORT=443  (рекомендуется)
#   б) прямо без TLS (только для теста): голый HTTP на 8080 — откройте порт
#      в фаерволе: ufw allow 8080/tcp (и в security group облака)
#   в) за прокси: VEIL_LOCAL=1 + Caddy (см. deploy/Caddyfile) на 443

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Запусти с sudo: sudo bash $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$SCRIPT_DIR/veil_relay.py"
if [[ ! -f "$SRC" ]]; then
  echo "veil_relay.py не найден рядом с deploy/ ($SCRIPT_DIR)" >&2
  exit 1
fi

VEIL_DIR=/opt/veil-relay
DATA_DIR=/var/lib/veil-relay
PORT="${VEIL_PORT:-8080}"
if [[ "${VEIL_LOCAL:-0}" == "1" ]]; then
  HOST=127.0.0.1
else
  HOST="${VEIL_HOST:-0.0.0.0}"
fi

ARGS="--host $HOST --port $PORT --db $DATA_DIR/envelopes.db --trust-proxy"
if [[ -n "${VEIL_TLS_CERT:-}" && -n "${VEIL_TLS_KEY:-}" ]]; then
  ARGS="$ARGS --tls-cert $VEIL_TLS_CERT --tls-key $VEIL_TLS_KEY"
fi

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
# TLS-файлы: доступ на чтение сервис-пользователю
if [[ -n "${VEIL_TLS_CERT:-}" ]]; then
  chmod o-rwx "$VEIL_TLS_CERT" "$VEIL_TLS_KEY" 2>/dev/null || true
  setfacl -m u:veilrelay:r "$VEIL_TLS_CERT" "$VEIL_TLS_KEY" 2>/dev/null || \
    echo "  (setfacl недоступен: убедитесь, что veilrelay может читать TLS-файлы)"
fi

echo "==> systemd-юнит (аргументы: $ARGS)"
sed "s|__VEIL_ARGS__|$ARGS|" \
  "$SCRIPT_DIR/deploy/veil-relay.service" > /etc/systemd/system/veil-relay.service
systemctl daemon-reload
systemctl enable --now veil-relay.service
sleep 1
systemctl --no-pager --lines=5 status veil-relay.service || true

echo
echo "Готово. Relay слушает $HOST:$PORT (проверка: curl http://127.0.0.1:$PORT/health)"
if [[ "$HOST" == "0.0.0.0" && -z "${VEIL_TLS_CERT:-}" ]]; then
  echo "⚠  Внешний доступ сейчас по голому HTTP. Для боевого использования:"
  echo "   1) сертификат: apt install certbot && certbot certonly --standalone -d relay.example.com"
  echo "   2) переустановите с VEIL_TLS_CERT=/etc/letsencrypt/live/relay.example.com/fullchain.pem \\"
  echo "                        VEIL_TLS_KEY=/etc/letsencrypt/live/relay.example.com/privkey.pem VEIL_PORT=443"
  echo "   3) откройте порт: ufw allow 443/tcp (и в security group облака)"
  echo "   Либо режим за Caddy: VEIL_LOCAL=1 + deploy/Caddyfile."
fi
