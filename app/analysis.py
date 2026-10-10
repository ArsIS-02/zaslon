"""Derived views over a collected host state: ports matrix, Docker exposure, findings, summary numbers."""
import re


def plural(n, one, few, many):
    n = abs(int(n))
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many

BRIDGE_PREFIX = ("docker", "br-", "virbr", "veth", "cni", "podman", "lo")
EPHEMERAL_FROM = 32768

KNOWN = {  # common port → hint (for display only)
    22: "SSH", 25: "SMTP", 53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos", 111: "rpcbind", 123: "NTP",
    137: "NetBIOS", 139: "SMB", 161: "SNMP", 199: "SNMP mux", 323: "chrony", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    464: "kpasswd", 514: "syslog", 546: "DHCPv6", 631: "CUPS", 636: "LDAPS", 749: "kadmin", 953: "rndc", 1514: "Wazuh",
    1515: "Wazuh enroll", 2049: "NFS", 3000: "Grafana", 3100: "Loki", 3306: "MySQL", 3389: "RDP", 4151: "Kaspersky",
    5353: "mDNS", 5355: "LLMNR", 5432: "PostgreSQL", 5666: "NRPE", 8080: "HTTP-alt", 8443: "HTTPS-alt", 8484: "LogAtlas",
    8585: "ZaSlon", 9090: "Cockpit", 9091: "Transmission/websm", 9093: "Alertmanager", 9100: "node_exporter",
    9200: "Elasticsearch", 9443: "Portainer", 10000: "Webmin", 10050: "Zabbix agent", 10051: "Zabbix server",
    12201: "GELF", 13000: "Kaspersky", 15000: "Kaspersky", 55000: "Wazuh API",
}


def _is_bridge(ifname):
    return ifname.startswith(BRIDGE_PREFIX)


def external_zones(fw):
    """Zones that face the real network: bound to a non-bridge interface or to sources, plus the default zone
    (it receives every interface that is not assigned to a zone)."""
    zones = fw.get("zones") or {}
    res = [z for z in zones.values()
           if [i for i in z.get("interfaces", []) if not _is_bridge(i)] or z.get("sources")]
    dz = zones.get(fw.get("default_zone"))
    if dz and dz not in res:
        res.append(dz)
    return res


def _expand(item):
    """'8000-8005/tcp' -> (8000, 8005, 'tcp')"""
    rng, _, proto = item.partition("/")
    a, _, b = rng.partition("-")
    try:
        return int(a), int(b or a), proto or "tcp"
    except ValueError:
        return None


def docker_published(state):
    """Ports published by Docker (DNAT in nat/DOCKER) — reachable from the network bypassing firewalld zones."""
    res = []
    for fam in ("ipv4", "ipv6"):
        t = ((state.get("iptables") or {}).get(fam) or {}).get("tables", {}).get("nat", {})
        for r in t.get("rules", []):
            rule = r["rule"]
            if "-j DNAT" not in rule or not rule.startswith("-A DOCKER"):
                continue
            mp = re.search(r"-p (\w+)", rule)
            md = re.search(r"--dport (\d+(?::\d+)?)", rule)
            mt = re.search(r"--to-destination (\S+)", rule)
            ms = re.search(r"(?<!! )-d (\S+)", rule)
            if not md:
                continue
            port = md.group(1).replace(":", "-")
            res.append({"family": fam, "port": port, "proto": mp.group(1) if mp else "tcp",
                        "to": mt.group(1) if mt else "", "bind": ms.group(1) if ms else "",
                        "packets": r.get("packets")})
    return res


def ports_matrix(state):
    fw = state.get("firewalld") or {}
    running = bool(fw.get("running"))
    cat = fw.get("services_catalog") or {}
    rows = {}

    def row(port, proto):
        k = (port, proto)
        if k not in rows:
            rows[k] = {"port": port, "proto": proto, "allowed": [], "listen": [], "docker": [], "hint": KNOWN.get(port if isinstance(port, int) else -1, "")}
        return rows[k]

    ranges = []
    if running:
        for z in external_zones(fw):
            for p in z.get("ports", []):
                e = _expand(p)
                if not e:
                    continue
                a, b, pr = e
                if b - a <= 32:
                    for x in range(a, b + 1):
                        row(x, pr)["allowed"].append({"zone": z["name"], "via": "port", "item": p})
                else:
                    ranges.append((a, b, pr, z["name"], p))
            for s in z.get("services", []):
                for p in cat.get(s, {}).get("ports", []):
                    e = _expand(p)
                    if not e:
                        continue
                    a, b, pr = e
                    if b - a <= 32:
                        for x in range(a, b + 1):
                            row(x, pr)["allowed"].append({"zone": z["name"], "via": "service", "item": s})
                    else:
                        ranges.append((a, b, pr, z["name"], f"service {s}"))
            if z.get("target") == "ACCEPT":
                ranges.append((1, 65535, "tcp", z["name"], "target ACCEPT"))
                ranges.append((1, 65535, "udp", z["name"], "target ACCEPT"))
    for l in state.get("listening") or []:
        if l.get("local_only"):
            continue
        r = row(l["port"], l["proto"])
        r["listen"].append({"addr": l["addr"], "process": l.get("process") or "", "processes": l.get("processes", [])})
    for dp in docker_published(state):
        e = _expand(f"{dp['port']}/{dp['proto']}")
        if e and e[1] - e[0] <= 32:
            for x in range(e[0], e[1] + 1):
                row(x, dp["proto"])["docker"].append(dp)
    for r in rows.values():
        if isinstance(r["port"], int):
            for a, b, pr, zn, item in ranges:
                if pr == r["proto"] and a <= r["port"] <= b:
                    r["allowed"].append({"zone": zn, "via": "range", "item": item})
        procs = sorted({p for x in r["listen"] for p in (x["processes"] or [x["process"]]) if p})
        r["processes"] = procs
        only_proxy = procs and all(p == "docker-proxy" for p in procs)
        r["ephemeral"] = (r["proto"] == "udp" and r["port"] >= EPHEMERAL_FROM and not r["allowed"] and not r["docker"])
        if r["docker"]:
            r["status"] = "docker"
        elif not running and r["listen"]:
            r["status"] = "exposed"
        elif r["allowed"] and r["listen"]:
            r["status"] = "open"
        elif r["allowed"]:
            r["status"] = "stale"
        elif r["listen"]:
            r["status"] = "blocked"
        else:
            r["status"] = "unknown"
        if only_proxy and not r["docker"]:
            r["status"] = "docker"
        if not r["hint"] and r["allowed"]:
            r["hint"] = next((cat.get(a["item"], {}).get("short", "") for a in r["allowed"] if a["via"] == "service"), "")
    res = sorted(rows.values(), key=lambda r: (r["port"], r["proto"]))
    return res


def drift(state):
    return (state.get("firewalld") or {}).get("drift") or []


HELPER_VERSION = "1.1.0"


def _ver(v):
    try:
        return tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return (0,)


def findings(state, ports=None):
    f = []
    fw = state.get("firewalld") or {}
    se = state.get("selinux") or {}
    sshd = state.get("sshd") or {}
    f2b = state.get("fail2ban") or {}
    ports = ports if ports is not None else ports_matrix(state)

    def add(sev, area, title, detail="", action=None):
        f.append({"severity": sev, "area": area, "title": title, "detail": detail, "action": action})

    if not fw.get("installed", True):
        add("high", "firewall", "firewalld не установлен", "Хост не защищён межсетевым экраном.")
    elif not fw.get("running"):
        exposed = [r for r in ports if r["status"] == "exposed" and not r.get("ephemeral")]
        n = len(exposed)
        add("high", "firewall", "firewalld выключен",
            f"{n} {plural(n, 'сетевая служба доступна', 'сетевые службы доступны', 'сетевых служб доступны')} из сети без фильтрации. "
            "Правила iptables есть только у Docker.",
            {"kind": "start-firewalld"})
    if fw.get("running"):
        if fw.get("enabled") not in ("enabled", None, ""):
            add("medium", "firewall", "firewalld не включён в автозапуск", f"Состояние автозапуска: {fw.get('enabled')}",
                {"kind": "enable-firewalld"})
        for z in external_zones(fw):
            if z.get("target") == "ACCEPT":
                add("high", "firewall", f"Зона {z['name']} пропускает весь трафик (target ACCEPT)",
                    f"Интерфейсы: {', '.join(z.get('interfaces', [])) or '—'}")
            n = len(z.get("ports", []))
            if n >= 25:
                add("medium", "firewall", f"В зоне {z['name']} открыто {n} {plural(n, 'порт', 'порта', 'портов')}",
                    "Многие из них могут быть остатками старых экспериментов — сверьте с тем, что реально слушает.")
        stale = [r for r in ports if r["status"] == "stale"]
        if stale:
            add("low", "firewall", f"Открыто в firewall, но никто не слушает: {len(stale)}",
                ", ".join(f"{r['port']}/{r['proto']}" for r in stale[:30]) + (" …" if len(stale) > 30 else ""),
                {"kind": "close-stale", "ports": [f"{r['port']}/{r['proto']}" for r in stale]})
        d = drift(state)
        if d:
            add("medium", "firewall", f"Текущие и сохранённые правила расходятся: {len(d)}",
                "После перезагрузки или firewall-cmd --reload часть правил пропадёт или появится.",
                {"kind": "drift"})
        if fw.get("log_denied") in ("off", None):
            add("info", "firewall", "Журналирование отброшенных пакетов выключено (LogDenied=off)",
                "Для расследований полезно unicast — отказы будут видны в журнале ядра.", {"kind": "log-denied"})
        if fw.get("panic"):
            add("high", "firewall", "Включён режим паники — весь сетевой трафик отбрасывается")
    dock = [r for r in ports if r["docker"]]
    if dock:
        add("medium", "docker", f"Docker публикует {len(dock)} {plural(len(dock), 'порт', 'порта', 'портов')} в обход зон firewalld",
            ", ".join(f"{r['port']}/{r['proto']}→{r['docker'][0]['to']}" for r in dock[:20]) +
            ". Такие порты доступны из сети, даже если в зоне их нет. Ограничивайте через привязку к адресу (127.0.0.1:порт) "
            "или политику firewalld для зоны docker.")
    # SELinux
    mode = se.get("mode")
    if se.get("tools") is False:
        add("info", "selinux", "Утилиты SELinux не установлены")
    elif mode == "Disabled":
        add("medium", "selinux", "SELinux выключен",
            "Включение требует перезагрузки и переразметки файлов; на Raspberry Pi сначала проверьте поддержку в ядре.")
    elif mode == "Permissive":
        add("medium", "selinux", "SELinux в разрешающем режиме (Permissive)", "Нарушения журналируются, но не блокируются.",
            {"kind": "selinux-enforce"})
    if mode and mode != "Disabled" and se.get("config_mode") and se.get("config_mode") != mode.lower():
        add("low", "selinux", "Режим SELinux в конфиге отличается от текущего",
            f"сейчас {mode}, после перезагрузки будет {se.get('config_mode')}")
    avc = se.get("avc_today") or []
    if avc:
        add("low", "selinux", f"Отказы SELinux сегодня: {len(avc)}",
            "; ".join(sorted({f"{a.get('comm', '?')} → {a.get('tclass', '?')}" for a in avc})[:8]))
    if se.get("permissive_domains"):
        add("info", "selinux", f"Домены в permissive: {', '.join(se['permissive_domains'][:10])}")
    # SSH
    prl = sshd.get("permitrootlogin")
    if prl == "yes":
        add("medium", "ssh", "SSH: разрешён вход root по паролю (PermitRootLogin yes)",
            "Рекомендуется prohibit-password или no.")
    if sshd.get("passwordauthentication") == "yes":
        add("low", "ssh", "SSH: разрешён вход по паролю", "Вход по ключам надёжнее; пароли перебирают боты.")
    # fail2ban
    if f2b.get("installed") is False or (f2b and not f2b.get("active")):
        add("low", "fail2ban", "fail2ban не работает", "Перебор паролей SSH ничем не ограничен.")
    for j in f2b.get("jails") or []:
        if j.get("banned"):
            add("info", "fail2ban", f"fail2ban ({j['name']}): заблокировано адресов — {len(j['banned'])}",
                ", ".join(j["banned"][:20]), {"kind": "f2b", "jail": j["name"]})
    hv = state.get("helper")
    if hv and hv != "demo" and _ver(hv) < _ver(HELPER_VERSION):
        add("info", "zaslon", f"На хосте старая версия helper ({hv}, есть {HELPER_VERSION})",
            "Обновите: bash ~/ZaSlon/zaslon-provision.sh (выберите этот хост).")
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    f.sort(key=lambda x: order[x["severity"]])
    return f


def summary(state):
    if not state:
        return None
    fw = state.get("firewalld") or {}
    se = state.get("selinux") or {}
    pm = ports_matrix(state)
    fnd = findings(state, pm)
    ext = external_zones(fw) if fw.get("running") else []
    ipt = state.get("iptables") or {}
    ipt_rules = sum(len(t.get("rules", [])) for fam in ("ipv4", "ipv6") for t in ((ipt.get(fam) or {}).get("tables") or {}).values())
    facts = state.get("facts") or {}
    return {
        "time": state.get("time"),
        "hostname": facts.get("hostname"),
        "os": facts.get("os"), "arch": facts.get("arch"), "model": facts.get("model"), "kernel": facts.get("kernel"),
        "firewalld": "running" if fw.get("running") else ("stopped" if fw.get("installed", True) else "absent"),
        "firewalld_version": fw.get("version"),
        "default_zone": fw.get("default_zone"),
        "zones_ext": [z["name"] for z in ext],
        "open_ports": sum(len(z.get("ports", [])) for z in ext),
        "open_services": sum(len(z.get("services", [])) for z in ext),
        "listening": len([r for r in pm if r["listen"] and not r.get("ephemeral")]),
        "stale": len([r for r in pm if r["status"] == "stale"]),
        "docker_published": len([r for r in pm if r["docker"]]),
        "iptables_rules": ipt_rules,
        "selinux": se.get("mode") or ("нет" if se.get("tools") is False else "?"),
        "fail2ban": "active" if (state.get("fail2ban") or {}).get("active") else "inactive",
        "banned": sum(len(j.get("banned", [])) for j in (state.get("fail2ban") or {}).get("jails") or []),
        "findings": {s: len([x for x in fnd if x["severity"] == s]) for s in ("high", "medium", "low", "info")},
        "pending": len(state.get("pending") or []),
        "peer_info": state.get("peer_info"),
        "demo": bool(state.get("demo")),
        "errors": state.get("errors") or [],
    }


def enrich(state):
    """State + derived data for the UI."""
    pm = ports_matrix(state)
    return {"state": state, "ports": pm, "findings": findings(state, pm), "summary": summary(state),
            "docker": docker_published(state)}
