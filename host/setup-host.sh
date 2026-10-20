#!/bin/bash
# ZaSlon — установка агента на хост РЕД ОС. Запускать от root, один раз на хост:
#   sudo bash setup-host.sh "ssh-ed25519 AAAA... zaslon-panel"    (ключ — из панели, «Ключ панели»)
#   sudo bash setup-host.sh --remove                              (убрать всё, что ставил скрипт)
# Что делает:
#   • создаёт пользователя sec_fw-admin без пароля (вход только по ключу);
#   • кладёт агент в /usr/local/libexec/zaslon/agent (root, 0755);
#   • в authorized_keys ключ панели ограничен: только запуск агента, без shell и переадресаций;
#   • в sudoers разрешает пользователю ровно одну команду — агент.
set -euo pipefail

USER_NAME="${ZASLON_USER:-sec_fw-admin}"
AGENT_DIR=/usr/local/libexec/zaslon
SUDOERS=/etc/sudoers.d/zaslon
HERE="$(cd "$(dirname "$0")" && pwd)"
AGENT_SRC="$HERE/zaslon-agent"

[ "$(id -u)" = 0 ] || { echo "Запустите от root: sudo bash $0 ..." >&2; exit 1; }

if [ "${1:-}" = "--remove" ]; then
  rm -f "$SUDOERS" "$AGENT_DIR/agent"
  rmdir "$AGENT_DIR" 2>/dev/null || true
  if id "$USER_NAME" >/dev/null 2>&1; then userdel -r "$USER_NAME" 2>/dev/null || userdel "$USER_NAME"; fi
  echo "Агент удалён. Таймеры откатов (zaslon-rb-*) при необходимости остановите вручную."
  exit 0
fi

PUBKEY="${1:-}"
case "$PUBKEY" in ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;;
  *) echo "Укажите публичный ключ панели в кавычках (строка, начинается с ssh-ed25519)." >&2; exit 1;;
esac
[ -f "$AGENT_SRC" ] || { echo "Нет файла zaslon-agent рядом со скриптом ($AGENT_SRC)." >&2; exit 1; }
command -v python3 >/dev/null || { echo "Нужен python3 на хосте." >&2; exit 1; }
command -v firewall-cmd >/dev/null || echo "Внимание: firewall-cmd не найден — firewalld не установлен." >&2

if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd -m -s /bin/bash -c "ZaSlon agent" "$USER_NAME"
fi
passwd -l "$USER_NAME" >/dev/null 2>&1 || true

install -d -m 0755 -o root -g root "$AGENT_DIR"
install -m 0755 -o root -g root "$AGENT_SRC" "$AGENT_DIR/agent"
install -d -m 0700 -o root -g root /var/lib/zaslon /var/lib/zaslon/tx

# authorized_keys владеет root: пользователь не может подменить ключи
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
SSH_DIR="$HOME_DIR/.ssh"
install -d -m 0755 -o root -g root "$SSH_DIR"
printf '%s\n' "restrict,command=\"sudo -n $AGENT_DIR/agent\" $PUBKEY" > "$SSH_DIR/authorized_keys"
chown root:root "$SSH_DIR/authorized_keys"
chmod 0644 "$SSH_DIR/authorized_keys"

# sudo: только этот агент, без пароля
TMP="$(mktemp)"
echo "$USER_NAME ALL=(root) NOPASSWD: $AGENT_DIR/agent" > "$TMP"
chmod 0440 "$TMP"
if ! visudo -cf "$TMP" >/dev/null; then
  rm -f "$TMP"; echo "Проверка sudoers не прошла — ничего не изменено." >&2; exit 1
fi
mv "$TMP" "$SUDOERS"
chown root:root "$SUDOERS"

# проверка: агент отвечает на статус
if echo '{"op":"status"}' | sudo -n -u root "$AGENT_DIR/agent" | grep -q '"ok": true'; then
  echo "Готово. Агент установлен, панель может подключаться пользователем $USER_NAME."
else
  echo "Агент установлен, но проверка статуса не прошла. Запустите вручную: echo '{\"op\":\"status\"}' | sudo $AGENT_DIR/agent" >&2
  exit 1
fi
