#!/bin/bash
# ZaSlon — подготовка хостов РЕД ОС к управлению панелью (запуск на Mac или Linux из Терминала).
#   bash scripts/zaslon-provision.sh -z 10.0.0.5  # первый запуск: адрес хоста, где будет работать панель
#   bash scripts/zaslon-provision.sh              # дальше адрес берётся из $ZASLON_HOME/zaslon.conf
#   bash scripts/zaslon-provision.sh -a           # все хосты из users.conf
#   bash scripts/zaslon-provision.sh --no-mac     # не разрешать вход ключом панели с этого компьютера
#   bash scripts/zaslon-provision.sh --remove     # убрать sec_fw-admin, helper и настройки с выбранных хостов
#
# На каждом хосте (под вашим админ-пользователем, пароль SSH + пароль sudo один раз):
#   • пользователь sec_fw-admin — вход только по ключу ZaSlon и только с адресов панели (и этого Mac);
#     ключ разрешает лишь команды helper (command= в authorized_keys), .ssh принадлежит root
#   • /usr/local/libexec/zaslon/zaslon-helper и sudo только на него
#   • fail2ban: панель и этот Mac — в исключениях, текущий бан снимается
# Затем проверка входом по ключу и сбор состояния в $ZASLON_HOME/collect/<IP>.json.
# Ключ панели: $ZASLON_HOME/keys/zaslon_ed25519 (закрытый — никому не передавайте). ZASLON_HOME по умолчанию ~/ZaSlon.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# рабочий каталог (users.conf, ключ панели, журналы, отчёты): ZASLON_HOME или ~/ZaSlon
WORK="${ZASLON_HOME:-$HOME/ZaSlon}"
mkdir -p "$WORK" 2>/dev/null
[ -f "$WORK/zaslon.conf" ] && . "$WORK/zaslon.conf"   # PANEL_HOST=..., KNOWN_USERS="..."
USERS="$WORK/users.conf"
KEYDIR="$WORK/keys"; KEY="$KEYDIR/zaslon_ed25519"
COL="$WORK/collect"; LOGS="$WORK/logs"
HOSTDIR="$SCRIPT_DIR/../host"; [ -d "$HOSTDIR" ] || HOSTDIR="$SCRIPT_DIR/host"
HELPER="$HOSTDIR/zaslon-helper"; WRAP="$HOSTDIR/zaslon-ssh"; SETUP="$HOSTDIR/zaslon-hostsetup.sh"
ZIP="${PANEL_HOST:-}"; ALL=0; NOMAC=0; REMOVE=0
while [ $# -gt 0 ]; do case "$1" in
  -a) ALL=1 ;; -z) ZIP="$2"; shift ;; --no-mac) NOMAC=1 ;; --remove) REMOVE=1 ;;
  *) echo "неизвестный параметр $1"; exit 1 ;; esac; shift; done
[ -f "$HELPER" ] && [ -f "$WRAP" ] && [ -f "$SETUP" ] || { echo "Нет $HOSTDIR/zaslon-helper, zaslon-ssh или zaslon-hostsetup.sh"; exit 1; }
[ -s "$USERS" ] || { echo "Нет $USERS — сначала запустите zaslon-diag.sh"; exit 1; }
[ -n "$ZIP" ] || [ $REMOVE = 1 ] || { echo "Укажите адрес хоста, где будет работать панель: -z IP (запомнится в $WORK/zaslon.conf)"; exit 1; }
if [ -n "$ZIP" ] && ! grep -qs "^PANEL_HOST=$ZIP\$" "$WORK/zaslon.conf"; then
  { grep -vs '^PANEL_HOST=' "$WORK/zaslon.conf"; echo "PANEL_HOST=$ZIP"; } > "$WORK/zaslon.conf.tmp" && mv "$WORK/zaslon.conf.tmp" "$WORK/zaslon.conf"
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
for d in "$COL" "$LOGS" "$KEYDIR"; do
  mkdir -p "$d" 2>/dev/null
  if ! ( : > "$d/.wtest" ) 2>/dev/null; then mv "$d" "$d.broken-$STAMP" 2>/dev/null && mkdir -p "$d"; fi
  rm -f "$d/.wtest" 2>/dev/null
done
chmod 700 "$KEYDIR"
LOG="$LOGS/provision-$STAMP.log"
exec > >(tee "$LOG") 2>&1

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
SSHOPT=(-o ConnectTimeout=8 -o ControlMaster=auto -o "ControlPath=/tmp/zs-%C" -o ControlPersist=180
        -o StrictHostKeyChecking=accept-new -o NumberOfPasswordPrompts=2 -o ServerAliveInterval=15)
KEYOPT=(-o ConnectTimeout=8 -o BatchMode=yes -o IdentitiesOnly=yes -i "$KEY" -o StrictHostKeyChecking=accept-new -o ControlMaster=no -o ControlPath=none)
KNOWN_USERS="${KNOWN_USERS:-user redos}"
IFACE="$(route -n get "$ZIP" 2>/dev/null | awk '/interface:/{print $2}')"
MYIP="$(ipconfig getifaddr "${IFACE:-en0}" 2>/dev/null)"

echo "ZaSlon provision, $(date '+%Y-%m-%d %H:%M:%S %z'), этот Mac: ${MYIP:-IP не определён}, панель: $ZIP"

# --- ключ панели
if [ ! -f "$KEY" ]; then
  ssh-keygen -q -t ed25519 -N "" -C "zaslon-panel" -f "$KEY" && echo "Создан ключ панели: $KEY"
fi
chmod 600 "$KEY"
FROM="$ZIP,172.16.0.0/12,127.0.0.1"
[ $NOMAC = 0 ] && [ -n "$MYIP" ] && FROM="$FROM,$MYIP"
IGN="$ZIP${MYIP:+ $MYIP}"
echo "Ключом панели можно будет входить только с: $FROM"

# --- список хостов
echo
echo "Хосты из users.conf:"
k=0; IPS=(); USR=()
while read -r ip u; do
  [ -n "$ip" ] || continue
  k=$((k+1)); IPS[$k]="$ip"; USR[$k]="$u"
  nm="$(awk -v ip="$ip" '$1==ip {print $2; exit}' /etc/hosts)"
  printf '  %2d) %-15s %-30s (админ: %s)\n' "$k" "$ip" "${nm:-—}" "$u"
done < <(sort -t. -k4,4n "$USERS")
if [ $ALL = 1 ]; then SEL="$(seq 1 $k | tr '\n' ' ')"
else
  read -r -p "Какие хосты $([ $REMOVE = 1 ] && echo 'ОЧИСТИТЬ' || echo 'подготовить')? Номера через пробел, Enter = все: " SEL </dev/tty
  [ -z "$SEL" ] && SEL="$(seq 1 $k | tr '\n' ' ')"
fi

ask_user() {
  local ip="$1" saved="$2" list="" i=0 u c
  for u in $saved $KNOWN_USERS $(awk '{print $2}' "$USERS"); do case " $list " in *" $u "*) ;; *) list="$list $u" ;; esac; done
  echo "  Под каким админ-пользователем подключаться к $ip?"
  for u in $list; do i=$((i+1)); printf '    %d) %s%s\n' "$i" "$u" "$([ "$u" = "$saved" ] && echo '   ← в прошлый раз')"; done
  echo "    или введите имя; - пропустить хост"
  while :; do
    read -r -p "  Пользователь${saved:+ [Enter = $saved]}: " c </dev/tty
    [ -z "$c" ] && [ -n "$saved" ] && { U="$saved"; return; }
    [ -z "$c" ] && continue
    [ "$c" = "-" ] && { U="-"; return; }
    if [[ "$c" =~ ^[0-9]+$ ]]; then i=0; for u in $list; do i=$((i+1)); [ "$i" = "$c" ] && { U="$u"; return; }; done; echo "  нет такого номера"; continue; fi
    U="$c"; return
  done
}

OKH=""; FAILH=""
for n in $SEL; do
  ip="${IPS[$n]}"; [ -n "$ip" ] || continue
  echo; echo "===== $ip ====="
  ask_user "$ip" "${USR[$n]}"
  [ "$U" = "-" ] && { echo "  пропущен"; continue; }
  T="$U@$ip"
  SEEN="$(ssh "${SSHOPT[@]}" "$T" 'mkdir -p ~/.zaslon-setup && echo "${SSH_CLIENT%% *}"' 2>"$TMP/err")"
  if [ -z "$SEEN" ]; then
    echo "  ! не удалось подключиться: $(grep -v '^Warning' "$TMP/err" | tail -n 1)"; FAILH="$FAILH $ip"; continue
  fi
  # адрес этого Mac так, как его видит хост (надёжнее, чем угадывать интерфейс)
  HFROM="$FROM"; HIGN="$IGN"
  if [ $NOMAC = 0 ]; then
    case ",$HFROM," in *",$SEEN,"*) ;; *) HFROM="$HFROM,$SEEN" ;; esac
    case " $HIGN " in *" $SEEN "*) ;; *) HIGN="$HIGN $SEEN" ;; esac
    MYIP="${MYIP:-$SEEN}"
  fi
  awk -v ip="$ip" '$1!=ip' "$USERS" > "$USERS.tmp" && echo "$ip $U" >> "$USERS.tmp" && mv "$USERS.tmp" "$USERS"
  if ! scp -q "${SSHOPT[@]}" "$HELPER" "$WRAP" "$SETUP" "$KEY.pub" "$T:.zaslon-setup/" 2>"$TMP/err"; then
    scp -O -q "${SSHOPT[@]}" "$HELPER" "$WRAP" "$SETUP" "$KEY.pub" "$T:.zaslon-setup/" 2>>"$TMP/err" || { echo "  ! не удалось скопировать: $(tail -n 1 "$TMP/err")"; FAILH="$FAILH $ip"; continue; }
  fi
  if [ $REMOVE = 1 ]; then
    ssh -t "${SSHOPT[@]}" "$T" "sudo bash ~/.zaslon-setup/zaslon-hostsetup.sh --remove; rm -rf ~/.zaslon-setup"
    ssh "${SSHOPT[@]}" -O exit "$T" 2>/dev/null; OKH="$OKH $ip"; continue
  fi
  echo "  установка (нужен пароль sudo пользователя $U)"
  ssh -t "${SSHOPT[@]}" "$T" "sudo bash ~/.zaslon-setup/zaslon-hostsetup.sh --pubkey-file ~/.zaslon-setup/zaslon_ed25519.pub --from '$HFROM' --ignore '$HIGN' --helper ~/.zaslon-setup/zaslon-helper; rc=\$?; rm -rf ~/.zaslon-setup; exit \$rc"
  rc=$?
  ssh "${SSHOPT[@]}" -O exit "$T" 2>/dev/null
  [ $rc -eq 0 ] || { echo "  ! установка завершилась с кодом $rc"; FAILH="$FAILH $ip"; continue; }
  if [ $NOMAC = 1 ]; then OKH="$OKH $ip"; continue; fi
  echo "  проверка входа ключом панели и сбор состояния..."
  if ssh "${KEYOPT[@]}" "sec_fw-admin@$ip" 'sudo -n /usr/local/libexec/zaslon/zaslon-helper collect --peer "${SSH_CLIENT%% *}"' > "$COL/$ip.json" 2>"$TMP/err" \
     && grep -q '"ok": true' "$COL/$ip.json"; then
    echo "  ✓ sec_fw-admin входит по ключу, helper работает — состояние: collect/$ip.json ($(wc -c < "$COL/$ip.json" | tr -d ' ') байт)"
    OKH="$OKH $ip"
  else
    echo "  ! проверка не прошла: $(tail -n 2 "$TMP/err" | tr '\n' ' ') $(head -c 300 "$COL/$ip.json")"
    FAILH="$FAILH $ip"
  fi
done

echo
echo "Итог: готовы —${OKH:- нет}; не удалось —${FAILH:- нет}"
echo "Журнал: $LOG"
