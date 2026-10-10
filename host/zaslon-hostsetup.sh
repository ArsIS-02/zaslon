#!/bin/bash
# ZaSlon — подготовка управляемого хоста РЕД ОС (запускается от root через sudo).
#   sudo bash zaslon-hostsetup.sh --pubkey-file FILE --from "IP,IP,CIDR" [--ignore "IP IP"] [--helper FILE]
#   sudo bash zaslon-hostsetup.sh --remove
# Что делает:
#   • пользователь sec_fw-admin: без пароля (вход только по ключу), не в wheel
#   • ключ панели в authorized_keys с ограничениями: restrict + from="адреса панели"
#   • /usr/local/libexec/zaslon/zaslon-helper (root:root 0755) и sudo ТОЛЬКО на него (NOPASSWD)
#   • fail2ban: адреса панели и Mac в ignoreip + снятие текущего бана
set -u
U=sec_fw-admin
HELPER_DST=/usr/local/libexec/zaslon/zaslon-helper
SUDOERS=/etc/sudoers.d/zaslon
F2B_LOCAL=/etc/fail2ban/jail.d/zaslon.local
PUBKEY=""; FROM=""; IGNORE=""; HELPER_SRC=""; REMOVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --pubkey-file) PUBKEY="$(head -n 1 "$2")"; shift ;;
    --from) FROM="$2"; shift ;;
    --ignore) IGNORE="$2"; shift ;;
    --helper) HELPER_SRC="$2"; shift ;;
    --remove) REMOVE=1 ;;
    *) echo "неизвестный параметр $1"; exit 1 ;;
  esac; shift
done
[ "$(id -u)" -eq 0 ] || { echo "нужен root"; exit 1; }
ok() { echo "  [ok] $*"; }
warn() { echo "  [!] $*"; }
H="$(hostname -s)"
echo "ZaSlon hostsetup на $H ($(cat /etc/redos-release 2>/dev/null))"

if [ $REMOVE = 1 ]; then
  rm -f "$SUDOERS" && ok "удалён $SUDOERS"
  pkill -u "$U" 2>/dev/null; userdel -r "$U" 2>/dev/null && ok "удалён пользователь $U"
  rm -rf /usr/local/libexec/zaslon && ok "удалён helper"
  if [ -f "$F2B_LOCAL" ]; then rm -f "$F2B_LOCAL"; fail2ban-client reload >/dev/null 2>&1; ok "удалён $F2B_LOCAL"; fi
  echo "Журнал транзакций оставлен в /var/lib/zaslon (удалите вручную при необходимости)."
  exit 0
fi

[ -n "$PUBKEY" ] || { echo "нет --pubkey-file"; exit 1; }
case "$PUBKEY" in ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;; *) echo "это не открытый ключ SSH"; exit 1 ;; esac
echo "$FROM" | grep -Eq '^[0-9a-fA-F:.,/]+$' || { echo "--from: список адресов через запятую"; exit 1; }

# --- 1. пользователь
if id "$U" >/dev/null 2>&1; then ok "пользователь $U уже есть"
else
  useradd -m -c "ZaSlon firewall admin" -s /bin/bash "$U" && ok "создан пользователь $U"
fi
passwd -l "$U" >/dev/null 2>&1 && ok "пароль $U заблокирован (вход только по ключу)"
for g in wheel sudo adm; do id -nG "$U" | grep -qw "$g" && gpasswd -d "$U" "$g" >/dev/null && warn "$U удалён из группы $g"; done
UH="$(getent passwd "$U" | cut -d: -f6)"

# --- 2. ключ: каталог .ssh и authorized_keys принадлежат root — sec_fw-admin не может их подменить
SSHD="$UH/.ssh"
if [ -L "$SSHD" ] || { [ -e "$SSHD" ] && [ "$(stat -c %U "$SSHD")" != root ]; }; then rm -rf "$SSHD"; fi
install -d -m 755 -o root -g root "$SSHD"
AK="$SSHD/authorized_keys"
rm -f "$SSHD/.ak.tmp"
LINE="command=\"/usr/local/libexec/zaslon/zaslon-ssh\",restrict,from=\"$FROM\" $PUBKEY"
( umask 022; printf '%s\n' "$LINE" > "$SSHD/.ak.tmp" )
chown root:root "$SSHD/.ak.tmp"; chmod 644 "$SSHD/.ak.tmp"
mv -f "$SSHD/.ak.tmp" "$AK"
command -v restorecon >/dev/null && restorecon -R "$SSHD" 2>/dev/null
ok "ключ панели: только команды helper, вход только с: $FROM"

# --- 3. helper + обёртка + sudo
if [ -n "$HELPER_SRC" ]; then
  install -d -m 755 -o root -g root /usr/local/libexec/zaslon
  install -m 755 -o root -g root "$HELPER_SRC" "$HELPER_DST"
  WRAP_SRC="$(dirname "$HELPER_SRC")/zaslon-ssh"
  [ -f "$WRAP_SRC" ] && install -m 755 -o root -g root "$WRAP_SRC" /usr/local/libexec/zaslon/zaslon-ssh
  command -v restorecon >/dev/null && restorecon -R /usr/local/libexec/zaslon 2>/dev/null
  ok "установлен $HELPER_DST ($(/usr/bin/python3 "$HELPER_DST" version 2>/dev/null))"
fi
[ -x /usr/local/libexec/zaslon/zaslon-ssh ] || warn "нет /usr/local/libexec/zaslon/zaslon-ssh — ключ панели работать не будет"
install -d -m 700 /var/lib/zaslon
cat > "$SUDOERS.tmp" <<EOF
# ZaSlon: пользователь $U может запускать от root только helper панели
Defaults:$U !requiretty
Defaults:$U env_reset
$U ALL=(root) NOPASSWD: $HELPER_DST
EOF
chmod 440 "$SUDOERS.tmp"
if visudo -cf "$SUDOERS.tmp" >/dev/null; then mv "$SUDOERS.tmp" "$SUDOERS"; ok "sudo: $U → только $HELPER_DST"
else rm -f "$SUDOERS.tmp"; warn "ошибка в sudoers — не установлен"; fi

# --- 4. sshd
AU="$(sshd -T 2>/dev/null | awk '/^allowusers /{print $2}' | tr '\n' ' ')"
AG="$(sshd -T 2>/dev/null | awk '/^allowgroups /{print $2}' | tr '\n' ' ')"
[ -n "$AU$AG" ] && warn "в sshd задан AllowUsers/AllowGroups ($AU$AG) — добавьте $U, иначе панель не войдёт"
sshd -T 2>/dev/null | grep -q '^pubkeyauthentication yes' || warn "в sshd выключен вход по ключу (PubkeyAuthentication)"

# --- 5. fail2ban
if command -v fail2ban-client >/dev/null && systemctl -q is-active fail2ban && [ -n "$IGNORE" ]; then
  python3 - "$IGNORE" <<'PY'
import os, re, sys, glob
ips = sys.argv[1].split()
local = "/etc/fail2ban/jail.local"
def default_ignore(path):
    try: txt = open(path).read()
    except OSError: return None, None
    sec = None
    for m in re.finditer(r"(?m)^\[([^\]]+)\]|^ignoreip\s*=\s*(.*(?:\n[ \t]+.*)*)", txt):
        if m.group(1): sec = m.group(1).strip()
        elif sec == "DEFAULT": return txt, m
    return txt, None
txt, m = default_ignore(local)
if m:
    cur = re.sub(r"[#;].*", "", m.group(2)).split()
    add = [i for i in ips if i not in cur]
    if add:
        tail = re.search(r"\s*[#;].*$", m.group(2).splitlines()[0])
        new = txt[:m.start(2)] + " ".join(cur + add) + (tail.group(0) if tail else "") + txt[m.end(2):]
        open(local + ".zaslon-bak", "w").write(txt)
        open(local, "w").write(new)
        print("  [ok] fail2ban: в jail.local [DEFAULT] ignoreip добавлено: " + " ".join(add))
    else:
        print("  [ok] fail2ban: адреса уже в ignoreip")
else:
    others = [p for p in glob.glob("/etc/fail2ban/jail.d/*") if not p.endswith("zaslon.local") and "ignoreip" in open(p).read()]
    if others:
        print("  [!] fail2ban: ignoreip задан в " + ", ".join(others) + " — добавьте туда " + " ".join(ips))
    else:
        open("/etc/fail2ban/jail.d/zaslon.local", "w").write(
            "# ZaSlon: не банить панель управления и рабочий Mac\n[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 " + " ".join(ips) + "\n")
        print("  [ok] fail2ban: создан /etc/fail2ban/jail.d/zaslon.local")
PY
  fail2ban-client reload >/dev/null 2>&1 && ok "fail2ban перечитал настройки"
  for ip in $IGNORE; do fail2ban-client unban "$ip" >/dev/null 2>&1; done
  for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do
    have="$(fail2ban-client get "$j" ignoreip 2>/dev/null | sed 1d | tr -d '|`-' | tr -s ' \t' '\n')"
    for ip in $IGNORE; do
      echo "$have" | grep -qxF "$ip" || { fail2ban-client set "$j" addignoreip "$ip" >/dev/null 2>&1; warn "jail $j: у него свой ignoreip — $ip добавлен только до перезапуска fail2ban"; }
    done
  done
fi
[ -d /var/ossec ] && warn "здесь есть Wazuh — если на сервере Wazuh включён active response, добавьте $IGNORE в <white_list> менеджера"

# --- 6. проверка
if sudo -u "$U" sudo -n "$HELPER_DST" version >/dev/null 2>&1; then ok "проверка: $U может запускать helper через sudo"
else warn "проверка sudo не прошла"; fi
echo "Готово."
