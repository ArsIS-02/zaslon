#!/bin/bash
# Интеграционный тест транзакций zaslon-helper с поддельными firewall-cmd / systemctl / systemd-run.
# Подменяет программы в /usr/local/sbin — запускайте ТОЛЬКО в одноразовом контейнере:
#   docker run --rm -v "$PWD":/src -w /src python:3.12-slim bash -c 'ZASLON_TEST_CONTAINER=1 bash tests/test_tx.sh'
[ "${ZASLON_TEST_CONTAINER:-}" = 1 ] || { echo "Только в одноразовом контейнере: ZASLON_TEST_CONTAINER=1"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
H="$ROOT/host/zaslon-helper"
mkdir -p /tmp/fake && install -m 755 "$ROOT"/tests/fakes/* /usr/local/sbin/
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
FW() { python3 -c "import json; d=json.load(open('/tmp/fake/fw.json')); print($1)"; }
fail=0; chk() { if [ "$1" = "$2" ]; then echo "  ok: $3"; else echo "  FAIL: $3 (got '$1', want '$2')"; fail=1; fi; }
rm -f /tmp/fake/fw.json; rm -rf /var/lib/zaslon; : > /tmp/fake/systemd-run.log; : > /tmp/fake/systemctl.log
echo "1. add port with rollback -> pending, timer armed before ops"
r=$(echo '{"ops":[{"op":"port","action":"add","zone":"public","port":"8080","proto":"tcp"}],"rollback":60}' | python3 $H apply --peer 10.42.0.5)
chk "$(echo "$r" | J 'd["tx"]["status"]')" pending "status pending"
chk "$(grep -c zaslon-rb /tmp/fake/systemd-run.log)" 1 "timer armed"
ID=$(echo "$r" | J 'd["tx"]["id"]')
python3 $H rollback $ID --auto >/dev/null
chk "$(FW 'd["rt"]["public"]["ports"]')" "['22/tcp']" "rolled back runtime"
chk "$(FW 'd["pm"]["public"]["ports"]')" "['22/tcp']" "rolled back permanent"
echo "2. half-applied source (permanent fails) is undone"
r=$(echo '{"ops":[{"op":"source","action":"add","zone":"trusted","source":"10.9.9.0/24"}],"rollback":60}' | python3 $H apply --peer 10.42.0.5)
chk "$(echo "$r" | J 'd["ok"]')" False "apply failed"
chk "$(FW 'd["rt"]["trusted"]["sources"]')" "[]" "runtime source undone"
chk "$(grep -c 'stop zaslon-rb' /tmp/fake/systemctl.log)" 1 "timer stopped after failure"
echo "3. permanent-only ssh removal is refused by guard"
r=$(echo '{"ops":[{"op":"service","action":"remove","zone":"public","service":"ssh","runtime":false},{"op":"port","action":"remove","zone":"public","port":"22","proto":"tcp","runtime":false}],"rollback":60}' | python3 $H apply --peer 10.42.0.5)
chk "$(echo "$r" | J 'd["ok"]')" False "refused"
echo "$r" | J 'd["error"]'
chk "$(FW 'd["pm"]["public"]["services"]')" "['ssh']" "permanent ssh restored"
echo "4. rollback < 30 refused"
r=$(echo '{"ops":[{"op":"port","action":"add","port":"81"}],"rollback":5}' | python3 $H apply)
chk "$(echo "$r" | J 'd["ok"]')" False "short rollback refused"
echo "5. injection attempts"
for bad in '{"op":"service","action":"add","service":"-a"}' '{"op":"direct","action":"add","chain":"INPUT","args":"--modprobe=/tmp/x -j ACCEPT"}' '{"op":"direct","action":"add","family":"eb","chain":"INPUT","args":"-j ACCEPT"}' '{"op":"iptables","action":"delete","table":"filter","rule":"-A INPUT -t nat -j ACCEPT"}' '{"op":"sebool","name":"-P","value":"on"}'; do
  r=$(echo "{\"ops\":[$bad],\"rollback\":60}" | python3 $H apply)
  chk "$(echo "$r" | J 'd["ok"]')" False "rejected: $bad"
done
chk "$(python3 $H confirm ../../etc/passwd | J 'd["ok"]')" False "bad tx id"
echo "6. forward-port on ssh port refused"
ROOT="$ROOT" python3 - <<'PY'
import importlib.machinery, importlib.util
import os
l = importlib.machinery.SourceFileLoader("zh", os.environ["ROOT"] + "/host/zaslon-helper"); sp = importlib.util.spec_from_loader("zh", l); zh = importlib.util.module_from_spec(sp); l.exec_module(zh)
zh.run = lambda a, **k: (0, "x dev eth0 src y", "")
z = {"public": {"name": "public", "default": True, "interfaces": ["eth0"], "sources": [], "services": ["ssh"], "ports": [], "rich_rules": [], "target": "default",
     "forward_ports": ["port=22:proto=tcp:toport=2222:toaddr="]}}
cat = {"ssh": {"ports": ["22/tcp"]}}
print("  forward-port:", zh.ssh_allowed("10.42.0.5", z, cat, [22]))
z["public"]["forward_ports"] = []
z["public"]["rich_rules"] = ['rule family="ipv4" source address="10.42.0.0/24" destination address="10.0.0.1" reject']
print("  destination reject (conservative):", zh.ssh_allowed("10.42.0.5", z, cat, [22]))
z["public"]["rich_rules"] = ['rule family="ipv4" source-port port="22" protocol="tcp" accept']
z["public"]["services"] = []
print("  source-port accept is not ssh:", zh.ssh_allowed("10.42.0.5", z, cat, [22]))
PY
exit $fail
