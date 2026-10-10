#!/bin/bash
# ZaSlon — установка/обновление панели на хосте с Docker. Запуск на Mac или Linux:
#   bash scripts/zaslon-deploy.sh               # на хост PANEL_HOST из $ZASLON_HOME/zaslon.conf
#   bash scripts/zaslon-deploy.sh -h 10.0.0.5   # на указанный хост
# Что делает:
#   • копирует исходники панели и ключ панели ($ZASLON_HOME/keys) на хост в ~/zaslon
#   • при первой установке создаёт ~/zaslon/.env с паролем входа в панель (покажет один раз)
#   • docker compose up -d --build — сборка образа на месте (arm64 на Raspberry Pi)
#   • проверяет с этого хоста вход ключом sec_fw-admin на все хосты из users.conf
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# рабочий каталог (users.conf, ключ панели, журналы, отчёты): ZASLON_HOME или ~/ZaSlon
WORK="${ZASLON_HOME:-$HOME/ZaSlon}"
mkdir -p "$WORK" 2>/dev/null
[ -f "$WORK/zaslon.conf" ] && . "$WORK/zaslon.conf"   # PANEL_HOST=..., KNOWN_USERS="..."
# исходники панели: корень репозитория (scripts/..) или каталог panel рядом со скриптом
SRC="$SCRIPT_DIR/.."; [ -f "$SRC/docker-compose.yml" ] || SRC="$SCRIPT_DIR/panel"
SRC="$(cd "$SRC" && pwd)"
KEY="$WORK/keys/zaslon_ed25519"; USERS="$WORK/users.conf"
HOST_IP="${PANEL_HOST:-}"
while [ $# -gt 0 ]; do case "$1" in -h) HOST_IP="$2"; shift ;; *) echo "неизвестный параметр $1"; exit 1 ;; esac; shift; done
[ -f "$SRC/docker-compose.yml" ] || { echo "Нет исходников панели: $SRC"; exit 1; }
[ -n "$HOST_IP" ] || { echo "Укажите хост для панели: -h IP (или PANEL_HOST в $WORK/zaslon.conf)"; exit 1; }
[ -f "$KEY" ] || { echo "Нет ключа панели $KEY — сначала запустите zaslon-provision.sh"; exit 1; }
[ -s "$USERS" ] || { echo "Нет $USERS — сначала запустите zaslon-diag.sh"; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
SSHOPT=(-o ConnectTimeout=8 -o ControlMaster=auto -o "ControlPath=/tmp/zs-%C" -o ControlPersist=300
        -o StrictHostKeyChecking=accept-new -o NumberOfPasswordPrompts=2)
DEF="$(awk -v ip="$HOST_IP" '$1==ip {print $2; exit}' "$USERS" 2>/dev/null)"
read -r -p "Пользователь SSH на $HOST_IP [${DEF:-user}]: " U </dev/tty
U="${U:-${DEF:-user}}"
T="$U@$HOST_IP"

# список хостов для панели: IP из users.conf + короткое имя из /etc/hosts
{
  echo "["
  first=1
  while read -r ip u; do
    [ -n "$ip" ] || continue
    nm="$(awk -v ip="$ip" '$1==ip { for (i=2;i<=NF;i++) if ($i !~ /\./) { print $i; exit } ; print $2; exit }' /etc/hosts)"
    nm="${nm:-$ip}"
    [ $first = 1 ] || echo ","
    printf '  {"name": "%s", "address": "%s"}' "$nm" "$ip"
    first=0
  done < <(sort -t. -k4,4n "$USERS")
  echo; echo "]"
} > "$TMP/seed.json"
awk '{print $1}' "$USERS" | sort -t. -k4,4n > "$TMP/hosts.txt"

TAROPT=(); tar --version 2>/dev/null | grep -q bsdtar && TAROPT=(--no-mac-metadata)
COPYFILE_DISABLE=1 tar czf "$TMP/zaslon.tgz" -C "$SRC" "${TAROPT[@]}" --exclude ./data --exclude ./.env --exclude ./.git --exclude ./docs --exclude ./tests --exclude ./scripts --exclude ./tools .
cat > "$TMP/remote.sh" <<'REMOTE'
#!/bin/bash
set -u
D="$HOME/zaslon"; S="$HOME/.zaslon-deploy"
ok() { echo "  [ok] $*"; }
warn() { echo "  [!] $*"; }
mkdir -p "$D/data/keys"
tar xzf "$S/zaslon.tgz" -C "$D" --warning=no-unknown-keyword 2>/dev/null || tar xzf "$S/zaslon.tgz" -C "$D"
chmod -R a+rX "$D/app" "$D/static" "$D/host" "$D/Dockerfile" "$D/docker-compose.yml" "$D/requirements.txt" 2>/dev/null
[ -f "$D/docker-compose.yml" ] && ok "исходники обновлены в $D"
install -m 600 "$S/zaslon_ed25519" "$D/data/keys/zaslon_ed25519"
install -m 644 "$S/zaslon_ed25519.pub" "$D/data/keys/zaslon_ed25519.pub"
ok "ключ панели: $D/data/keys/"
if [ ! -f "$D/data/hosts.json" ]; then cp "$S/seed.json" "$D/data/seed.json"; ok "список хостов для первого запуска: $(grep -c address "$S/seed.json")"; fi
NEWPW=""
if [ ! -f "$D/.env" ]; then
  NEWPW="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
  TZV="$(timedatectl show -p Timezone --value 2>/dev/null)"
  printf 'ZASLON_UID=%s\nZASLON_GID=%s\nZASLON_LOGIN=admin\nZASLON_PASSWORD=%s\nZASLON_PORT=8585\nTZ=%s\n' "$(id -u)" "$(id -g)" "$NEWPW" "${TZV:-UTC}" > "$D/.env"
  chmod 600 "$D/.env"
  ok "создан $D/.env (логин и пароль панели)"
fi
if docker info >/dev/null 2>&1; then DC="docker compose"; else DC="sudo docker compose"; fi
$DC version >/dev/null 2>&1 || { warn "не найден docker compose"; exit 1; }
echo "  сборка и запуск контейнера (на Raspberry Pi первая сборка занимает несколько минут)…"
( cd "$D" && $DC up -d --build ) || { warn "docker compose завершился с ошибкой"; exit 1; }
for i in $(seq 1 60); do
  curl -fsS -o /dev/null http://127.0.0.1:8585/healthz 2>/dev/null && { ok "панель отвечает на порту 8585"; break; }
  sleep 2
done
echo "  проверка входа ключом панели на хосты:"
for ip in $(cat "$S/hosts.txt"); do
  r="$(ssh -i "$D/data/keys/zaslon_ed25519" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=6 \
        -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$D/data/known_hosts" \
        "sec_fw-admin@$ip" 'sudo -n /usr/local/libexec/zaslon/zaslon-helper version' 2>&1 | tail -n 1)"
  case "$r" in *'"ok": true'*) printf '    ✓ %-15s %s\n' "$ip" "$r" ;; *) printf '    ✗ %-15s %s\n' "$ip" "$r" ;; esac
done
rm -rf "$S"
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "  Панель: http://${IP:-<адрес>}:8585   логин: admin"
[ -n "$NEWPW" ] && echo "  Пароль: $NEWPW   (сохраните; он также лежит в $D/.env)" || echo "  Пароль: в $D/.env (ZASLON_PASSWORD)"
REMOTE

echo "Копирую панель на $T…"
ssh "${SSHOPT[@]}" "$T" 'mkdir -p ~/.zaslon-deploy' || { echo "не удалось подключиться к $T"; exit 1; }
FILES=("$TMP/zaslon.tgz" "$TMP/seed.json" "$TMP/hosts.txt" "$TMP/remote.sh" "$KEY" "$KEY.pub")
scp -q "${SSHOPT[@]}" "${FILES[@]}" "$T:.zaslon-deploy/" 2>/dev/null || scp -O -q "${SSHOPT[@]}" "${FILES[@]}" "$T:.zaslon-deploy/" || { echo "не удалось скопировать"; exit 1; }
ssh -t "${SSHOPT[@]}" "$T" 'bash ~/.zaslon-deploy/remote.sh'
ssh "${SSHOPT[@]}" -O exit "$T" 2>/dev/null
