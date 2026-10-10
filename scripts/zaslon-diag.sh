#!/bin/bash
# ZaSlon — обнаружение хостов из /etc/hosts и диагностика firewall/SELinux на хостах РЕД ОС (только чтение).
# Запуск на Mac (или Linux) из Терминала:
#   bash scripts/zaslon-diag.sh       # спросит, какие хосты проверять; перед КАЖДЫМ подключением спросит пользователя
#   bash scripts/zaslon-diag.sh -a    # все хосты с открытым SSH без вопроса о выборе (пользователь всё равно спрашивается)
# • Отпечатки новых хостов добавляются в ~/.ssh/known_hosts автоматически (без yes/no).
# • Перед вводом пароля проверяется, не закрыт ли SSH и не заблокирован ли ваш адрес (fail2ban и т. п.).
# • Пароль SSH спрашивается не больше 2 раз на попытку — чтобы fail2ban не забанил за перебор.
# • Пароли вы вводите сами; в журнал они не попадают.
# Отчёты: $ZASLON_HOME/fw-diag/   Журнал: $ZASLON_HOME/logs/   Пользователи по хостам: $ZASLON_HOME/users.conf (по умолчанию ZASLON_HOME=~/ZaSlon)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# рабочий каталог (users.conf, ключ панели, журналы, отчёты): ZASLON_HOME или ~/ZaSlon
WORK="${ZASLON_HOME:-$HOME/ZaSlon}"
mkdir -p "$WORK" 2>/dev/null
[ -f "$WORK/zaslon.conf" ] && . "$WORK/zaslon.conf"   # PANEL_HOST=..., KNOWN_USERS="..."
DIAG="$SCRIPT_DIR/diag-redos-fw.sh"
OUT="$WORK/fw-diag"
LOGS="$WORK/logs"
USERS="$WORK/users.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"
# папки отчётов и журналов должны быть доступны на запись; если нет — откладываем испорченную и создаём новую
for d in "$OUT" "$LOGS"; do
  mkdir -p "$d" 2>/dev/null
  if ! ( : > "$d/.wtest" ) 2>/dev/null; then
    mv "$d" "$d.broken-$STAMP" 2>/dev/null && mkdir -p "$d" && echo "Папка $d была недоступна на запись — отложена в $d.broken-$STAMP, создана новая"
  fi
  rm -f "$d/.wtest" 2>/dev/null
  ( : > "$d/.wtest" ) 2>/dev/null || { echo "Нет записи в $d. Исправьте: sudo chown -R \"$(id -un)\":staff \"$WORK\" && chmod -R u+rwX \"$WORK\""; exit 1; }
  rm -f "$d/.wtest"
done
touch "$USERS"
ALL=0
while getopts "a" o; do case "$o" in a) ALL=1 ;; *) exit 1 ;; esac; done
[ -f "$DIAG" ] || { echo "Нет $DIAG"; exit 1; }

LOG="$LOGS/run-$STAMP.log"
exec > >(tee "$LOG") 2>&1

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CM="/tmp/zs-%C"
# accept-new: новый отпечаток добавляется сам; ИЗМЕНИВШИЙСЯ отпечаток известного хоста — отказ (защита от подмены)
SSHOPT=(-o ConnectTimeout=8 -o ControlMaster=auto -o "ControlPath=$CM" -o ControlPersist=180
        -o StrictHostKeyChecking=accept-new -o NumberOfPasswordPrompts=2 -o ServerAliveInterval=15)
KNOWN_USERS="${KNOWN_USERS:-user redos}"
t() { local s="$1"; shift; perl -e 'alarm shift; exec @ARGV' "$s" "$@"; }
IFACE="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
MYIP="$(ipconfig getifaddr "${IFACE:-en0}" 2>/dev/null)"

echo "ZaSlon diag, $(date '+%Y-%m-%d %H:%M:%S %z'), этот Mac: $(scutil --get LocalHostName 2>/dev/null) ${MYIP:+($MYIP)}"

# --- 1. хосты из /etc/hosts (IPv4, без localhost/broadcast)
awk '!/^[[:space:]]*#/ && NF>=2 && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $1 !~ /^127\./ && $1 != "255.255.255.255" && $1 != "0.0.0.0" {
       sub(/#.*/, ""); if (!seen[$1]++) { names=$2; for (i=3;i<=NF;i++) names=names" "$i; print $1"\t"names } }' /etc/hosts > "$TMP/hosts"
N=$(wc -l < "$TMP/hosts" | tr -d ' ')
[ "$N" -gt 0 ] || { echo "В /etc/hosts нет IPv4-хостов"; exit 1; }
echo "В /etc/hosts хостов: $N. Проверяю пинг и SSH..."

# --- 2. пинг + состояние порта 22 + баннер sshd (параллельно)
# ssh:     порт открыт, sshd ответил баннером
# nobanner: TCP открыт, но sshd молчит/рвёт соединение — часто так выглядит бан (tcp_wrappers, MaxStartups)
# refused: соединение отклонено — sshd не запущен или ваш адрес заблокирован правилом REJECT (fail2ban)
# timeout: пакеты отбрасываются — firewall закрыл 22 или бан правилом DROP
probe() {  # одно TCP-соединение на хост: статус + баннер sshd
  local ip="$1" r b
  r="$(t 5 nc -v -G 3 "$ip" 22 </dev/null 2>&1 | head -n 3 | LC_ALL=C tr -d '\r')"
  b="$(echo "$r" | grep -m1 '^SSH-')"
  if [ -n "$b" ]; then echo "ssh|$b"
  else case "$r" in
    *succeeded*|*open*) echo "nobanner|" ;;
    *refused*) echo "refused|" ;;
    *) echo "timeout|" ;;
  esac; fi
}
i=0
while IFS=$'\t' read -r ip names; do
  i=$((i+1))
  ( if ping -c 1 -t 2 -q "$ip" >/dev/null 2>&1; then
      p="$(probe "$ip")"
      printf '%s\t%s\t%s\t%s\n' "$ip" "${p%%|*}" "${p#*|}" "$names" > "$TMP/up.$i"
    fi ) &
done < "$TMP/hosts"
wait
cat "$TMP"/up.* 2>/dev/null | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$TMP/up"
[ -s "$TMP/up" ] || { echo "Ни один хост не ответил на пинг."; exit 1; }

state_text() {
  case "$1" in
    ssh) echo "SSH открыт ($2)" ;;
    nobanner) echo "SSH: порт открыт, но sshd не отвечает — возможно, ваш адрес заблокирован" ;;
    refused) echo "SSH отклоняет соединение — sshd выключен или ваш адрес заблокирован (fail2ban)" ;;
    timeout) echo "SSH не отвечает — порт закрыт firewall или ваш адрес заблокирован" ;;
  esac
}
echo
echo "Отвечают на пинг:"
k=0; IPS=(); NAMES=(); ST=()
while IFS=$'\t' read -r ip s banner names; do
  k=$((k+1)); IPS[$k]="$ip"; NAMES[$k]="${names%% *}"; ST[$k]="$s"
  printf '  %2d) %-15s  %-26s %s\n' "$k" "$ip" "$names" "$(state_text "$s" "$banner")"
done < "$TMP/up"
BAN=0; for s in "${ST[@]}"; do case "$s" in nobanner|refused|timeout) BAN=1 ;; esac; done
if [ $BAN = 1 ]; then
  echo
  echo "  Если на хосте стоит fail2ban и ваш адрес ${MYIP:-этого Mac} мог попасть в бан, снимите его с консоли хоста:"
  echo "    sudo fail2ban-client status sshd"
  echo "    sudo fail2ban-client set sshd unbanip ${MYIP:-<IP этого Mac>}"
  echo "  и (чтобы больше не банил) добавьте адрес в исключения: ignoreip = 127.0.0.1/8 ${MYIP:-<IP>} в /etc/fail2ban/jail.local"
fi

# --- 3. выбор хостов
all_ssh() { local j=0 s; SEL=""; for s in "${ST[@]}"; do j=$((j+1)); [ "$s" = ssh ] && SEL="$SEL $j"; done; }
if [ $ALL = 1 ]; then all_ssh
else
  echo
  read -r -p "Какие проверить? Номера через пробел, Enter = все, где SSH открыт: " SEL </dev/tty
  [ -z "$SEL" ] && all_ssh
fi
[ -n "${SEL// /}" ] || { echo "Нечего проверять."; exit 0; }

# --- выбор пользователя перед каждым подключением
ask_user() {  # $1 = IP, $2 = пользователь в прошлый раз; результат в U ("-" = пропустить)
  local ip="$1" saved="$2" list="" i=0 u c
  for u in $saved $KNOWN_USERS $(awk '{print $2}' "$USERS"); do
    case " $list " in *" $u "*) ;; *) list="$list $u" ;; esac
  done
  echo "  Под каким пользователем подключаться к $ip?"
  for u in $list; do i=$((i+1)); printf '    %d) %s%s\n' "$i" "$u" "$([ "$u" = "$saved" ] && echo '   ← в прошлый раз')"; done
  echo "    или введите имя; - пропустить хост"
  while :; do
    read -r -p "  Пользователь${saved:+ [Enter = $saved]}: " c </dev/tty
    [ -z "$c" ] && [ -n "$saved" ] && { U="$saved"; return; }
    [ -z "$c" ] && continue
    [ "$c" = "-" ] && { U="-"; return; }
    if [[ "$c" =~ ^[0-9]+$ ]]; then
      i=0; for u in $list; do i=$((i+1)); [ "$i" = "$c" ] && { U="$u"; return; }; done
      echo "  нет такого номера"; continue
    fi
    U="$c"; return
  done
}

# разбор ошибки ssh -> понятная причина
explain() {
  case "$1" in
    *"REMOTE HOST IDENTIFICATION HAS CHANGED"*|*"Host key verification failed"*)
      echo "  ! Отпечаток хоста изменился (хост переустановлен или подмена). Если уверены, что это ваш хост:"
      echo "      ssh-keygen -R $2   — и запустите скрипт снова"; return 2 ;;
    *"Permission denied"*)
      echo "  ! Неверный пользователь или пароль (либо этому пользователю вход по SSH запрещён: AllowUsers/AllowGroups)."
      echo "    Внимание: каждая неудачная попытка считается fail2ban — после ~5 ошибок адрес банится."; return 1 ;;
    *"Connection refused"*)
      echo "  ! Соединение отклонено — sshd выключен или ваш адрес только что заблокирован (fail2ban)."; return 2 ;;
    *"timed out"*|*"Operation timed out"*)
      echo "  ! Нет ответа — порт закрыт firewall или ваш адрес заблокирован правилом DROP."; return 2 ;;
    *"Connection closed"*|*"Connection reset"*|*"kex_exchange_identification"*)
      echo "  ! Хост закрыл соединение до входа — похоже на бан (fail2ban/hosts.deny) или лимит MaxStartups."; return 2 ;;
    *"Too many authentication failures"*)
      echo "  ! Слишком много попыток входа (MaxAuthTries)."; return 1 ;;
    *) echo "  ! Не удалось подключиться: $(echo "$1" | grep -v '^Warning: Permanently added' | tail -n 2 | tr '\n' ' ')"; return 1 ;;
  esac
}

# --- 4. диагностика
OKH=""; FAILH=""
for n in $SEL; do
  ip="${IPS[$n]}"; name="${NAMES[$n]}"
  [ -n "$ip" ] || continue
  echo
  echo "===== $name ($ip) ====="
  case "${ST[$n]}" in ssh) ;; *) echo "  $(state_text "${ST[$n]}")"; read -r -p "  Всё равно попробовать? [y/N]: " c </dev/tty; [ "$c" = y ] || { FAILH="$FAILH $name"; continue; } ;; esac
  SAVED="$(awk -v ip="$ip" '$1==ip {print $2; exit}' "$USERS")"
  ask_user "$ip" "$SAVED"
  CONNECTED=0
  while [ "$U" != "-" ]; do
    T="$U@$ip"
    echo "  подключаюсь как $T"
    OS="$(ssh "${SSHOPT[@]}" "$T" 'uname -s; cat /etc/redos-release 2>/dev/null || (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")' 2>"$TMP/err")"
    if [ -n "$OS" ]; then CONNECTED=1; break; fi
    explain "$(cat "$TMP/err")" "$ip"; rc=$?
    if [ $rc = 2 ]; then break; fi
    ask_user "$ip" ""
  done
  [ $CONNECTED = 1 ] || { echo "  пропущен"; FAILH="$FAILH $name"; continue; }
  awk -v ip="$ip" '$1!=ip' "$USERS" > "$USERS.tmp" && echo "$ip $U" >> "$USERS.tmp" && mv "$USERS.tmp" "$USERS"
  echo "  $(echo "$OS" | tr '\n' ' ')"
  case "$OS" in Linux*) ;; *) echo "  не Linux — пропускаю"; ssh "${SSHOPT[@]}" -O exit "$T" 2>/dev/null; continue ;; esac

  # отчёт, оставшийся на хосте от прошлого запуска (если не скачался), — можно забрать без повторной диагностики
  LEFT="$(ssh "${SSHOPT[@]}" "$T" 'ls -1t fw-diag-*.txt 2>/dev/null | head -n 1' 2>/dev/null)"
  if [ -n "$LEFT" ]; then
    read -r -p "  На хосте уже есть отчёт $LEFT — забрать его без повторной диагностики? [Y/n]: " c </dev/tty
    if [ "$c" != n ] && [ "$c" != N ]; then
      if scp -q "${SSHOPT[@]}" "$T:$LEFT" "$OUT/" 2>"$TMP/err" || scp -O -q "${SSHOPT[@]}" "$T:$LEFT" "$OUT/" 2>>"$TMP/err"; then
        ssh "${SSHOPT[@]}" "$T" 'rm -f ~/fw-diag-*.txt ~/diag-redos-fw.sh'
        echo "  ✓ отчёт получен"; OKH="$OKH $name"
      else
        echo "  ! отчёт не скачался: $(tail -n 2 "$TMP/err" | tr '\n' ' ')"; FAILH="$FAILH $name"
      fi
      ssh "${SSHOPT[@]}" -O exit "$T" 2>/dev/null
      continue
    fi
  fi
  if ! scp -q "${SSHOPT[@]}" "$DIAG" "$T:diag-redos-fw.sh" 2>"$TMP/err"; then
    scp -O -q "${SSHOPT[@]}" "$DIAG" "$T:diag-redos-fw.sh" 2>>"$TMP/err" || { echo "  ! не удалось скопировать скрипт: $(tail -n 1 "$TMP/err")"; FAILH="$FAILH $name"; continue; }
  fi
  echo "  запуск диагностики (нужен пароль sudo пользователя $U)"
  ssh -t "${SSHOPT[@]}" "$T" "sudo bash ~/diag-redos-fw.sh"; rc=$?
  if [ $rc -ne 0 ]; then
    echo "  ! диагностика не выполнилась (код $rc). Частая причина: у $U нет прав sudo — попробуйте другого пользователя."
    ssh "${SSHOPT[@]}" "$T" 'rm -f ~/diag-redos-fw.sh' 2>/dev/null
    ssh "${SSHOPT[@]}" -O exit "$T" 2>/dev/null
    FAILH="$FAILH $name"; continue
  fi
  if scp -q "${SSHOPT[@]}" "$T:fw-diag-*.txt" "$OUT/" 2>"$TMP/err" || scp -O -q "${SSHOPT[@]}" "$T:fw-diag-*.txt" "$OUT/" 2>>"$TMP/err"; then
    ssh "${SSHOPT[@]}" "$T" 'rm -f ~/fw-diag-*.txt ~/diag-redos-fw.sh'
    echo "  ✓ отчёт получен"; OKH="$OKH $name"
  else
    echo "  ! отчёт не скачался: $(tail -n 2 "$TMP/err" | tr '\n' ' ')"; FAILH="$FAILH $name"
  fi
  ssh "${SSHOPT[@]}" -O exit "$T" 2>/dev/null
done

echo
echo "Итог: получены отчёты —${OKH:- нет}; не удалось —${FAILH:- нет}"
echo "Отчёты: $OUT"
ls -1t "$OUT" | head -n 20
echo "Журнал этого запуска: $LOG"
