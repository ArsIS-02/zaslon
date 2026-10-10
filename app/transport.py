"""How ZaSlon talks to hosts: OpenSSH client (agentless) or demo fixtures."""
import asyncio
import copy
import json
import os
import re
import shlex
import tempfile
import time
import uuid

from . import store

CM_DIR = os.environ.get("ZASLON_CM_DIR", "/tmp/zaslon-cm")


class HostError(Exception):
    def __init__(self, message, kind="error", detail=""):
        super().__init__(message)
        self.kind = kind
        self.detail = detail


def explain(stderr, rc):
    e = stderr or ""
    if "REMOTE HOST IDENTIFICATION HAS CHANGED" in e or "Host key verification failed" in e:
        return HostError("Отпечаток SSH-ключа хоста изменился. Если хост переустановлен — сбросьте отпечаток в настройках хоста.",
                         "hostkey", e)
    if "Permission denied" in e:
        return HostError("Ключ панели не принят. Запустите zaslon-provision.sh для этого хоста "
                         "(или проверьте пользователя и адрес панели в from=).", "auth", e)
    if "Connection refused" in e:
        return HostError("Соединение отклонено: sshd не запущен или адрес панели заблокирован (fail2ban).", "refused", e)
    if "timed out" in e or "No route to host" in e:
        return HostError("Хост не отвечает по SSH (выключен, закрыт firewall или бан DROP).", "timeout", e)
    if "Could not resolve hostname" in e:
        return HostError("Не удалось разрешить имя хоста.", "dns", e)
    if "a password is required" in e or "a terminal is required" in e:
        return HostError("sudo требует пароль: на хосте не настроено правило sudo для helper (запустите zaslon-provision.sh).",
                         "sudo", e)
    if "zaslon-helper" in e and ("No such file" in e or "command not found" in e or "not found" in e):
        return HostError("На хосте нет zaslon-helper (запустите zaslon-provision.sh).", "helper", e)
    if "Identity file" in e and "not accessible" in e or "no such identity" in e.lower():
        return HostError("Нет файла ключа панели. Скопируйте ключ в data/keys/zaslon_ed25519.", "key", e)
    last = [l for l in e.splitlines() if l.strip() and not l.startswith("Warning: Permanently added")]
    return HostError(f"Ошибка SSH (код {rc}): {last[-1] if last else 'нет подробностей'}", "ssh", e)


def usable_key(path):
    """ssh отказывается от ключа с правами шире 0600 или чужим владельцем — тогда работаем с приватной копией."""
    try:
        st = os.stat(path)
    except OSError:
        return path
    if st.st_uid == os.getuid() and (st.st_mode & 0o077) == 0:
        return path
    dst = os.path.join(tempfile.gettempdir(), f"zaslon-key-{os.getuid()}")
    try:
        if not os.path.exists(dst) or os.path.getmtime(dst) < st.st_mtime:
            with open(path, "rb") as f:
                data = f.read()
            fd = os.open(dst + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(dst + ".tmp", dst)
        return dst
    except OSError:
        return path


class SSHTransport:
    def __init__(self, host, settings):
        self.h = host
        self.s = settings

    def _args(self, fresh=False):
        key = self.s["key_path"]
        kh = os.path.join(store.DATA, "known_hosts")
        a = ["ssh", "-p", str(self.h.get("port") or self.s.get("ssh_port", 22)), "-i", key,
             "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
             "-o", f"UserKnownHostsFile={kh}", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=10",
             "-o", "ServerAliveCountMax=3", "-o", "LogLevel=ERROR"]
        if fresh:
            a += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
        else:
            os.makedirs(CM_DIR, mode=0o700, exist_ok=True)
            a += ["-o", "ControlMaster=auto", "-o", f"ControlPath={CM_DIR}/%C", "-o", "ControlPersist=90"]
        user = self.h.get("user") or self.s["ssh_user"]
        a.append(f"{user}@{self.h['address']}")
        return a

    async def _run(self, remote, stdin=None, timeout=180, fresh=False):
        self.s = dict(self.s, key_path=usable_key(self.s["key_path"]))
        if not os.path.exists(self.s["key_path"]):
            raise HostError(f"Нет ключа панели {self.s['key_path']}. Скопируйте ~/ZaSlon/keys/zaslon_ed25519 в data/keys/.", "key")
        # stderr в файл: фоновый ControlMaster может держать открытым канал stderr
        with tempfile.TemporaryFile() as errf:
            proc = await asyncio.create_subprocess_exec(
                *self._args(fresh), remote, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=errf)
            try:
                out, _ = await asyncio.wait_for(proc.communicate(stdin.encode() if stdin else None), timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise HostError(f"Хост не ответил за {timeout} с", "timeout")
            errf.seek(0)
            err = errf.read().decode("utf-8", "replace")
        return proc.returncode, out.decode("utf-8", "replace"), err

    async def helper(self, args, stdin=None, timeout=180, fresh=False):
        cmd = "sudo -n " + shlex.quote(self.s["helper"]) + " " + " ".join(args) + ' --peer "${SSH_CLIENT%% *}"'
        rc, out, err = await self._run(cmd, stdin=stdin, timeout=timeout, fresh=fresh)
        line = next((l for l in reversed(out.strip().splitlines()) if l.startswith("{")), "")
        if line:
            try:
                return json.loads(line)
            except ValueError:
                pass
        if rc == 255 or not out:
            raise explain(err, rc)
        raise HostError(f"Неожиданный ответ helper: {out[:300]}", "helper", err)

    async def collect(self):
        return await self.helper(["collect"], timeout=240)

    async def version(self):
        return await self.helper(["version"], timeout=30)

    async def nft_table(self, family, name):
        return await self.helper(["nft-table", shlex.quote(family), shlex.quote(name)])

    async def avc(self, since):
        return await self.helper(["avc", "--since", shlex.quote(since)], timeout=180)

    async def history(self):
        return await self.helper(["history"])

    async def apply(self, req):
        return await self.helper(["apply"], stdin=json.dumps(req, ensure_ascii=False), timeout=600)

    async def confirm(self, txid, fresh=True):
        return await self.helper(["confirm", shlex.quote(txid)], fresh=fresh, timeout=60)

    async def rollback(self, txid):
        return await self.helper(["rollback", shlex.quote(txid)], timeout=300)


# ---------------------------------------------------------------------------- demo
_demo_state = {}
_demo_tx = {}


class DemoTransport:
    """Works on fixtures built from the real diagnostic reports; changes are simulated in memory."""

    def __init__(self, host, settings):
        self.h = host
        self.s = settings

    def _base(self):
        key = self.h["id"]
        if key not in _demo_state:
            p = os.path.join(store.DEMO_DIR, f"{self.h['address']}.json")
            if not os.path.exists(p):
                raise HostError("Для этого хоста нет демо-данных", "demo")
            with open(p, encoding="utf-8") as f:
                _demo_state[key] = json.load(f)
        return _demo_state[key]

    async def collect(self):
        await asyncio.sleep(0.4)
        d = copy.deepcopy(self._base())
        d["time"] = int(time.time())
        d["pending"] = [{k: t.get(k) for k in ("id", "created", "deadline", "note")}
                        for t in _demo_tx.values() if t["host"] == self.h["id"] and t["status"] == "pending"]
        d["demo"] = True
        return d

    async def version(self):
        return {"ok": True, "version": "demo"}

    async def nft_table(self, family, name):
        d = self._base()
        if family == "inet" and name == "firewalld":
            return {"ok": True, "text": "# демо: таблица firewalld генерируется самим firewalld\n"
                                        "# на реальном хосте здесь будет полный вывод nft -a list table inet firewalld\n"}
        lines = [f"table {family} {name} {{"]
        fam = "ipv6" if family == "ip6" else "ipv4"
        t = d["iptables"].get(fam, {}).get("tables", {}).get(name, {})
        for ch, info in t.get("chains", {}).items():
            lines.append(f"\tchain {ch} {{  # policy {info['policy']}")
            for r in t.get("rules", []):
                if r["chain"] == ch:
                    lines.append("\t\t# iptables: " + r["rule"])
            lines.append("\t}")
        lines.append("}")
        return {"ok": True, "text": "\n".join(lines)}

    async def avc(self, since):
        return {"ok": True, "events": []}

    async def history(self):
        res = [{k: t.get(k) for k in ("id", "created", "status", "note", "results", "error", "rolled_back_by", "deadline")}
               for t in _demo_tx.values() if t["host"] == self.h["id"]]
        res.sort(key=lambda t: t["id"], reverse=True)
        return {"ok": True, "history": res}

    def _zone(self, d, name, perm=False):
        fw = d["firewalld"]
        return fw["zones_permanent" if perm else "zones"].setdefault(
            name, {"name": name, "ports": [], "services": [], "sources": [], "rich_rules": [], "interfaces": []})

    def _do(self, d, o):
        """Simulate the ops that matter for the UI; returns (text, inverse)."""
        fw = d["firewalld"]
        op, act = o["op"], o.get("action")
        key = {"port": "ports", "service": "services", "source": "sources", "rich": "rich_rules",
               "forward-port": "forward_ports", "icmp-block": "icmp_blocks"}.get(op)
        if key:
            if not fw.get("running"):
                raise HostError("firewalld не запущен", "apply")
            zone = o.get("zone") or fw.get("default_zone", "public")
            if op == "port":
                val = f"{o['port']}/{o.get('proto', 'tcp')}"
            elif op == "service":
                val = o["service"]
            elif op == "source":
                val = o["source"]
            elif op == "rich":
                val = o["rule"]
            elif op == "forward-port":
                val = f"port={o['port']}:proto={o.get('proto', 'tcp')}:toport={o.get('toport', '')}:toaddr={o.get('toaddr', '')}"
            else:
                val = o["icmptype"]
            res = []
            layers = ([False] if o.get("runtime", True) else []) + ([True] if o.get("permanent", True) else [])
            for perm in layers:
                lst = self._zone(d, zone, perm).setdefault(key, [])
                if act == "add" and val not in lst:
                    lst.append(val)
                    res.append(f"{'permanent' if perm else 'runtime'}: добавлено {val} (зона {zone})")
                elif act == "remove" and val in lst:
                    lst.remove(val)
                    res.append(f"{'permanent' if perm else 'runtime'}: удалено {val} (зона {zone})")
            inv = dict(o, action="remove" if act == "add" else "add", zone=zone)
            return "; ".join(res) or "без изменений", inv if res else None
        if op == "masquerade":
            z = self._zone(d, o["zone"])
            z["masquerade"] = act == "add"
            return f"masquerade {act}", dict(o, action="remove" if act == "add" else "add")
        if op == "default-zone":
            old = fw.get("default_zone")
            for z in fw["zones"].values():
                z["default"] = z["name"] == o["zone"]
            fw["default_zone"] = o["zone"]
            return f"зона по умолчанию: {old} → {o['zone']}", dict(o, zone=old)
        if op == "log-denied":
            old = fw.get("log_denied")
            fw["log_denied"] = o["value"]
            return f"LogDenied: {old} → {o['value']}", dict(o, value=old)
        if op == "target":
            z = self._zone(d, o["zone"])
            old = z.get("target")
            z["target"] = o["target"]
            self._zone(d, o["zone"], True)["target"] = o["target"]
            return f"target {o['zone']}: {old} → {o['target']}", dict(o, target=old)
        if op == "unit" and o.get("unit") == "firewalld":
            if act == "start":
                fw["running"] = fw["active"] = True
                fw.setdefault("zones", {"public": {"name": "public", "default": True, "active": True, "target": "default",
                                                   "interfaces": [], "services": ["ssh", "dhcpv6-client"], "ports": [],
                                                   "sources": [], "rich_rules": []}})
                fw.setdefault("zones_permanent", copy.deepcopy(fw["zones"]))
                fw.setdefault("default_zone", "public")
                fw.setdefault("services_catalog", {})
                fw.setdefault("drift", [])
                fw.setdefault("policies", {})
            elif act == "stop":
                fw["running"] = fw["active"] = False
            elif act in ("enable", "disable"):
                fw["enabled"] = "enabled" if act == "enable" else "disabled"
            inv = {"start": "stop", "stop": "start", "enable": "disable", "disable": "enable"}[act]
            return f"systemctl {act} firewalld", dict(o, action=inv)
        if op == "sebool":
            for b in d["selinux"].get("booleans", []):
                if b["name"] == o["name"]:
                    old = "on" if b["state"] else "off"
                    b["state"] = o["value"] == "on"
                    if b["name"] not in d["selinux"].setdefault("booleans_local", []):
                        d["selinux"]["booleans_local"].append(b["name"])
                    return f"{b['name']}: {old} → {o['value']}", dict(o, value=old)
            raise HostError(f"нет переключателя {o['name']}", "apply")
        if op == "selinux-enforce":
            se = d["selinux"]
            if se.get("mode") == "Disabled":
                raise HostError("SELinux выключен", "apply")
            old = "1" if se["mode"] == "Enforcing" else "0"
            se["mode"] = "Enforcing" if str(o["value"]) == "1" else "Permissive"
            return f"setenforce {o['value']}", dict(o, value=old)
        if op == "selinux-config":
            old = d["selinux"].get("config_mode")
            d["selinux"]["config_mode"] = o["value"]
            return f"SELINUX={old} → {o['value']} (после перезагрузки)", dict(o, value=old)
        if op == "seport":
            lst = d["selinux"].setdefault("ports_local", [])
            if act == "add":
                lst.append({"type": o["type"], "proto": o.get("proto", "tcp"), "ports": [str(o["port"])]})
                return f"semanage port {o['port']}/{o.get('proto', 'tcp')} → {o['type']}", dict(o, action="delete")
            for p in lst:
                if p["type"] == o["type"] and str(o["port"]) in p["ports"]:
                    p["ports"].remove(str(o["port"]))
            d["selinux"]["ports_local"] = [p for p in lst if p["ports"]]
            return f"semanage port: удалено {o['port']}", dict(o, action="add")
        if op == "f2b-unban":
            for j in d["fail2ban"].get("jails", []):
                if o["ip"] in j["banned"]:
                    j["banned"].remove(o["ip"])
            return f"fail2ban: снят бан {o['ip']}", None
        if op == "direct":
            lst = d["firewalld"].setdefault("direct_rules", [])
            rule = f"{o.get('family', 'ipv4')} {o.get('table', 'filter')} {o.get('chain', 'INPUT')} {o.get('priority', 0)} {o.get('args', '')}"
            if act == "add" and rule not in lst:
                lst.append(rule)
                d["firewalld"].setdefault("direct_rules_permanent", []).append(rule)
            elif act == "remove":
                d["firewalld"]["direct_rules"] = [r for r in lst if r != rule]
                d["firewalld"]["direct_rules_permanent"] = [r for r in d["firewalld"].get("direct_rules_permanent", []) if r != rule]
            return f"direct {act}: {rule}", dict(o, action="remove" if act == "add" else "add")
        if op == "iptables":
            return f"iptables {act}: {o.get('rule')}", None
        if op == "interface":
            return f"interface {o.get('interface')} → {o.get('zone')}", None
        raise HostError(f"операция {op} в демо-режиме не поддерживается", "apply")

    async def apply(self, req):
        await asyncio.sleep(0.6)
        d = self._base()
        txid = time.strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
        tx = {"id": txid, "host": self.h["id"], "created": int(time.time()), "note": req.get("note", ""),
              "ops": req["ops"], "inverse": [], "results": [], "status": "applying", "rollback": req.get("rollback", 60)}
        snapshot = copy.deepcopy(d)
        try:
            for i, o in enumerate(req["ops"]):
                text, inv = self._do(d, o)
                tx["results"].append({"op": i, "ok": True, "text": text})
                if inv:
                    tx["inverse"].append(inv)
        except HostError as ex:
            _demo_state[self.h["id"]] = snapshot
            tx["status"] = "failed"
            tx["error"] = str(ex)
            _demo_tx[txid] = tx
            return {"ok": False, "error": str(ex), "tx": tx}
        tx["snapshot"] = snapshot
        if tx["rollback"] > 0 and tx["inverse"]:
            tx["status"] = "pending"
            tx["deadline"] = int(time.time()) + int(tx["rollback"])
            loop = asyncio.get_running_loop()
            loop.call_later(int(tx["rollback"]), self._auto_rb, txid)
        else:
            tx["status"] = "confirmed"
        tx["guard"] = {"ssh_allowed": True, "reason": "демо"}
        _demo_tx[txid] = tx
        return {"ok": True, "tx": {k: v for k, v in tx.items() if k != "snapshot"}}

    def _auto_rb(self, txid):
        tx = _demo_tx.get(txid)
        if tx and tx["status"] == "pending":
            _demo_state[tx["host"]] = tx.pop("snapshot")
            tx["status"] = "rolled_back"
            tx["rolled_back_by"] = "timer"

    async def confirm(self, txid, fresh=True):
        await asyncio.sleep(0.3)
        tx = _demo_tx.get(txid)
        if not tx:
            raise HostError("транзакция не найдена", "tx")
        if tx["status"] == "pending":
            tx["status"] = "confirmed"
            tx.pop("snapshot", None)
        return {"ok": tx["status"] == "confirmed", "status": tx["status"], "tx": {k: v for k, v in tx.items() if k != "snapshot"}}

    async def rollback(self, txid):
        tx = _demo_tx.get(txid)
        if not tx:
            raise HostError("транзакция не найдена", "tx")
        if tx["status"] == "pending":
            _demo_state[tx["host"]] = tx.pop("snapshot")
            tx["status"] = "rolled_back"
            tx["rolled_back_by"] = "user"
        return {"ok": True, "status": tx["status"], "tx": {k: v for k, v in tx.items() if k != "snapshot"}}


def transport_for(host, settings):
    if host.get("demo") or settings.get("demo") or str(host.get("address", "")).startswith("demo"):
        return DemoTransport(host, settings)
    return SSHTransport(host, settings)


async def reset_hostkey(host):
    kh = os.path.join(store.DATA, "known_hosts")
    if not os.path.exists(kh):
        return False
    target = host["address"] if int(host.get("port") or 22) == 22 else f"[{host['address']}]:{host['port']}"
    proc = await asyncio.create_subprocess_exec("ssh-keygen", "-R", target, "-f", kh,
                                                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    await proc.wait()
    return proc.returncode == 0
