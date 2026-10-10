#!/bin/bash
# diag-redos-fw.sh — ТОЛЬКО ЧТЕНИЕ. Собирает состояние firewalld / iptables / nftables / SELinux / SSH
# на хосте РЕД ОС, чтобы спроектировать веб-панель управления firewall. Ничего не меняет.
#   sudo bash diag-redos-fw.sh
# Отчёт: ~/fw-diag-<хост>-<время>.txt (домашняя папка пользователя, запустившего sudo)
[ "$(id -u)" -eq 0 ] || { echo "Запустите через sudo: sudo bash $0"; exit 1; }

HOST="$(hostname -s)"
STAMP="$(date +%Y%m%d-%H%M%S)"
UH="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)"
REPORT="${UH:-/root}/fw-diag-${HOST}-${STAMP}.txt"
exec > >(tee "$REPORT") 2>&1

sec() { printf '\n==================== %s\n' "$*"; }
run() { printf -- '--- $ %s\n' "$*"; timeout 20 bash -c "$*" 2>&1 | head -n "${LIMIT:-80}"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "fw-diag, $(date '+%Y-%m-%d %H:%M:%S %z'), хост $HOST"

sec "Система"
run 'cat /etc/redos-release 2>/dev/null || cat /etc/os-release'
run 'uname -srm'
run 'python3 --version; sudo -V | head -n1; bash --version | head -n1'
run 'ip -br addr'
run 'ip route show default'
run 'systemd-detect-virt 2>/dev/null; cat /proc/device-tree/model 2>/dev/null | tr -d "\0"; echo'

sec "Пакеты"
run 'rpm -q firewalld python3-firewall iptables iptables-nft iptables-legacy iptables-services nftables ipset policycoreutils policycoreutils-python-utils libselinux-utils setools-console setroubleshoot-server audit fail2ban cockpit cockpit-selinux podman docker-ce docker 2>&1 | sort'

sec "firewalld"
run 'systemctl is-enabled firewalld; systemctl is-active firewalld'
if have firewall-cmd && systemctl -q is-active firewalld; then
  run 'firewall-cmd --version; firewall-cmd --state'
  run 'grep -E "^(FirewallBackend|DefaultZone|LogDenied|AllowZoneDrifting|IPv6_rpfilter|IndividualCalls|CleanupOnExit|NftablesFlowtable|StrictForwardPorts)" /etc/firewalld/firewalld.conf'
  run 'firewall-cmd --get-default-zone; firewall-cmd --get-active-zones'
  LIMIT=200 run 'for z in $(firewall-cmd --get-active-zones | grep -v "^ " | awk "{print \$1}"); do firewall-cmd --zone=$z --list-all; done'
  run 'firewall-cmd --get-zones'
  run 'firewall-cmd --get-policies 2>/dev/null && for p in $(firewall-cmd --get-policies); do firewall-cmd --policy=$p --list-all 2>/dev/null | head -n 15; done'
  run 'firewall-cmd --direct --get-all-rules; firewall-cmd --direct --get-all-chains; firewall-cmd --direct --get-all-passthroughs'
  run 'firewall-cmd --get-ipsets'
  run 'firewall-cmd --get-log-denied; firewall-cmd --query-panic'
  run 'firewall-cmd --check-config'
  run 'diff <(firewall-cmd --list-all) <(firewall-cmd --permanent --list-all) && echo "runtime = permanent (зона по умолчанию)"'
  run 'ls -la /etc/firewalld/zones/ /etc/firewalld/services/ /etc/firewalld/policies/ 2>/dev/null'
  run 'firewall-cmd --get-services | wc -w'
fi

sec "iptables"
run 'iptables -V; ip6tables -V'
run 'alternatives --display iptables 2>/dev/null | head -n 5; readlink -f "$(command -v iptables)"'
run 'systemctl is-enabled iptables ip6tables 2>&1; systemctl is-active iptables ip6tables 2>&1'
run 'ls -la /etc/sysconfig/iptables* /etc/sysconfig/ip6tables* 2>/dev/null'
LIMIT=150 run 'iptables-save'
run 'echo "строк правил IPv4: $(iptables-save | grep -c "^-A")  IPv6: $(ip6tables-save | grep -c "^-A")"'
run 'iptables-legacy-save 2>/dev/null | grep -c "^-A" | sed "s/^/правил в legacy-таблицах: /"'

sec "nftables"
run 'nft --version'
run 'systemctl is-enabled nftables; systemctl is-active nftables'
run 'nft list tables'
run 'for t in $(nft list tables | awk "{print \$2\":\"\$3}"); do f=${t%%:*}; n=${t#*:}; echo "$f $n: $(nft list table $f $n | grep -cE "^\s+(ip|ip6|tcp|udp|ct|iif|oif|meta|jump|goto|accept|drop|reject|counter|log)")"; done'
run 'ls -la /etc/sysconfig/nftables.conf /etc/nftables* 2>/dev/null'

sec "SELinux"
if have getenforce; then
  run 'getenforce; sestatus'
  run 'grep -E "^SELINUX(TYPE)?=" /etc/selinux/config'
  run 'command -v semanage setsebool getsebool ausearch sealert audit2why'
  run 'getsebool -a | wc -l; getsebool -a | grep -c " on$" | sed "s/^/включено: /"'
  run 'semanage boolean -l -C 2>/dev/null'
  run 'semanage port -l -C 2>/dev/null'
  run 'semanage fcontext -l -C 2>/dev/null | head -n 30'
  run 'semanage permissive -l 2>/dev/null'
  run 'semodule -l 2>/dev/null | wc -l; semodule -lfull 2>/dev/null | awk "\$1>=400" | head -n 20'
  run 'systemctl is-active auditd'
  run 'ausearch -m AVC,USER_AVC -ts today 2>/dev/null | grep -c "type=AVC" | sed "s/^/AVC-отказов сегодня: /"'
  run 'ausearch -m AVC -ts today 2>/dev/null | grep "type=AVC" | tail -n 5'
else
  echo "SELinux-утилит нет (getenforce не найден)"
fi

sec "Открытые порты и службы"
LIMIT=120 run 'ss -tulpnH'
run 'systemctl list-units --type=service --state=running --no-legend --plain | awk "{print \$1}" | head -n 80 | tr "\n" " "; echo'

sec "SSH (как будет подключаться панель)"
run 'sshd -T 2>/dev/null | grep -E "^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|allowgroups|maxstartups|usedns) "'
run 'ls -la '"${UH:-/root}"'/.ssh/ 2>/dev/null; wc -l < '"${UH:-/root}"'/.ssh/authorized_keys 2>/dev/null | sed "s/^/ключей в authorized_keys: /"'
run 'id '"${SUDO_USER:-root}"'; sudo -l -U '"${SUDO_USER:-root}"' 2>/dev/null | tail -n 8'
run 'ls /etc/sudoers.d/ 2>/dev/null'

sec "Прочее"
run 'systemctl is-active fail2ban cockpit.socket docker podman 2>&1'
run 'timedatectl 2>/dev/null | grep -E "Time zone|synchronized"'
run 'df -h / | tail -n 1'

echo
echo "Отчёт: $REPORT"
chown "${SUDO_USER:-root}" "$REPORT" 2>/dev/null
