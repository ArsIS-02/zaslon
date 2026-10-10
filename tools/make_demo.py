#!/usr/bin/env python3
"""Synthetic demo data for ZaSlon (fictional network 10.42.0.0/24) in the zaslon-helper `collect` format.
   python3 tools/make_demo.py   ->  app/demo/<ip>.json + app/demo/seed.json
Nothing here comes from a real network."""
import copy
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "app", "demo")
NOW = int(time.time())

CATALOG = {
    "ssh": ("SSH", ["22/tcp"]), "http": ("WWW (HTTP)", ["80/tcp"]), "https": ("WWW (HTTPS)", ["443/tcp"]),
    "dns": ("DNS", ["53/tcp", "53/udp"]), "dhcp": ("DHCP", ["67/udp"]), "dhcpv6-client": ("DHCPv6 Client", ["546/udp"]),
    "mdns": ("Multicast DNS (mDNS)", ["5353/udp"]), "cockpit": ("Cockpit", ["9090/tcp"]),
    "samba": ("Samba", ["139/tcp", "445/tcp", "137/udp", "138/udp"]), "nfs": ("NFS4", ["2049/tcp"]),
    "rpc-bind": ("rpc-bind", ["111/tcp", "111/udp"]), "mountd": ("mountd", ["20048/tcp", "20048/udp"]),
    "postgresql": ("PostgreSQL", ["5432/tcp"]), "mysql": ("MySQL", ["3306/tcp"]), "ntp": ("NTP", ["123/udp"]),
    "zabbix-agent": ("Zabbix Agent", ["10050/tcp"]), "snmp": ("SNMP", ["161/udp"]), "syslog": ("syslog", ["514/udp"]),
    "prometheus": ("Prometheus", ["9090/tcp"]), "prometheus-node-exporter": ("Prometheus Node Exporter", ["9100/tcp"]),
    "grafana": ("Grafana", ["3000/tcp"]), "mqtt": ("MQTT", ["1883/tcp"]), "rdp": ("RDP", ["3389/tcp"]),
    "vnc-server": ("VNC Server", ["5900-5903/tcp"]), "ipp": ("IPP", ["631/tcp"]), "smtp": ("SMTP", ["25/tcp"]),
    "wireguard": ("WireGuard", ["51820/udp"]), "openvpn": ("OpenVPN", ["1194/udp"]), "ftp": ("FTP", ["21/tcp"]),
    "llmnr": ("LLMNR", ["5355/tcp", "5355/udp"]), "kerberos": ("Kerberos", ["88/tcp", "88/udp"]), "ldap": ("LDAP", ["389/tcp"]),
}
SERVICES = {k: {"short": v[0], "description": "", "ports": v[1], "custom": False} for k, v in CATALOG.items()}
ICMP = ["destination-unreachable", "echo-reply", "echo-request", "parameter-problem", "redirect", "router-advertisement",
        "router-solicitation", "source-quench", "time-exceeded", "timestamp-reply", "timestamp-request"]
BOOLS = [
    ("httpd_can_network_connect", "Allow httpd to can network connect", False),
    ("httpd_can_network_connect_db", "Allow httpd to can network connect db", False),
    ("container_manage_cgroup", "Allow container to manage cgroup", False),
    ("samba_enable_home_dirs", "Allow samba to enable home dirs", False),
    ("samba_export_all_rw", "Allow samba to export all rw", False),
    ("nfs_export_all_rw", "Allow nfs to export all rw", True),
    ("use_nfs_home_dirs", "Support NFS home directories", False),
    ("ssh_sysadm_login", "Allow ssh logins as sysadm_r:sysadm_t", False),
    ("daemons_dump_core", "Allow daemons to dump core", False),
    ("domain_can_mmap_files", "Allow domain to can mmap files", False),
    ("zabbix_can_network", "Allow zabbix to can network", False),
    ("virt_use_nfs", "Allow virt to use nfs", False),
]
PORT_TYPES = [("ssh_port_t", "tcp", ["22"]), ("http_port_t", "tcp", ["80", "81", "443", "488", "8008", "8009", "8443", "9000"]),
              ("http_cache_port_t", "tcp", ["8080", "8118", "8123", "10001-10010"]), ("websm_port_t", "tcp", ["9090"]),
              ("postgresql_port_t", "tcp", ["5432", "9898"]), ("smbd_port_t", "tcp", ["137-139", "445"]),
              ("nfs_port_t", "tcp", ["2049", "20048-20049"]), ("syslogd_port_t", "udp", ["514", "601", "20514"]),
              ("zabbix_agent_port_t", "tcp", ["10050"]), ("unreserved_port_t", "tcp", ["61000-65535", "1024-32767"])]


def zone(name, *, default=False, active=False, target="default", interfaces=(), sources=(), services=(), ports=(),
         rich=(), protocols=(), forward_ports=(), masquerade=False, icmp=()):
    return {"name": name, "active": active, "default": default, "target": target, "interfaces": list(interfaces),
            "sources": list(sources), "services": list(services), "ports": list(ports), "protocols": list(protocols),
            "forward": True, "masquerade": masquerade, "forward_ports": list(forward_ports), "source_ports": [],
            "icmp_blocks": list(icmp), "icmp_block_inversion": False, "rich_rules": list(rich), "ingress_priority": "0",
            "egress_priority": "0"}


def std_zones():
    names = ["block", "dmz", "drop", "external", "home", "internal", "trusted", "work"]
    z = {n: zone(n, target={"block": "%%REJECT%%", "drop": "DROP", "trusted": "ACCEPT"}.get(n, "default"),
                 services=["ssh"] if n in ("dmz", "external", "home", "internal", "work") else []) for n in names}
    return z


def listen(proto, addr, port, proc, pid=1000):
    return {"proto": proto, "state": "LISTEN" if proto == "tcp" else "UNCONN", "addr": addr, "scope": "", "port": port,
            "process": proc, "pid": pid, "processes": [proc], "local_only": addr.startswith("127.") or addr == "::1"}


def ipt(docker=()):
    """iptables-save view: Docker chains + DNAT for published ports."""
    filt = {"chains": {c: {"policy": "ACCEPT", "packets": 0, "bytes": 0} for c in ("INPUT", "FORWARD", "OUTPUT")}, "rules": []}
    nat = {"chains": {c: {"policy": "ACCEPT", "packets": 0, "bytes": 0} for c in ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING")},
           "rules": []}
    if docker:
        for c in ("DOCKER", "DOCKER-FORWARD", "DOCKER-ISOLATION-STAGE-1", "DOCKER-USER"):
            filt["chains"][c] = {"policy": "-", "packets": 0, "bytes": 0}
            nat["chains"].setdefault("DOCKER", {"policy": "-", "packets": 0, "bytes": 0})
        filt["rules"] += [{"chain": "FORWARD", "rule": "-A FORWARD -j DOCKER-USER", "packets": 51234, "bytes": 40211843},
                          {"chain": "FORWARD", "rule": "-A FORWARD -j DOCKER-FORWARD", "packets": 51234, "bytes": 40211843},
                          {"chain": "DOCKER-FORWARD", "rule": "-A DOCKER-FORWARD -i docker0 ! -o docker0 -j ACCEPT", "packets": 1201, "bytes": 88112}]
        nat["rules"].append({"chain": "POSTROUTING", "rule": "-A POSTROUTING -s 172.18.0.0/16 ! -o br-5c1e0a7d2b31 -j MASQUERADE",
                             "packets": 812, "bytes": 51022})
        for port, to in docker:
            ip, dport = to.split(":")
            filt["rules"].append({"chain": "DOCKER", "rule": f"-A DOCKER -d {ip}/32 ! -i br-5c1e0a7d2b31 -o br-5c1e0a7d2b31 -p tcp -m tcp --dport {dport} -j ACCEPT",
                                  "packets": 300 + port % 97, "bytes": 21000 + port})
            nat["rules"].append({"chain": "DOCKER", "rule": f"-A DOCKER ! -i br-5c1e0a7d2b31 -p tcp -m tcp --dport {port} -j DNAT --to-destination {to}",
                                 "packets": 120 + port % 31, "bytes": 7200 + port})
    text = "\n".join(["# Generated by iptables-nft-save v1.8.9", "*filter"] +
                     [f":{c} {i['policy']} [{i['packets']}:{i['bytes']}]" for c, i in filt["chains"].items()] +
                     [f"[{r['packets']}:{r['bytes']}] {r['rule']}" for r in filt["rules"]] + ["COMMIT", "*nat"] +
                     [f":{c} {i['policy']} [{i['packets']}:{i['bytes']}]" for c, i in nat["chains"].items()] +
                     [f"[{r['packets']}:{r['bytes']}] {r['rule']}" for r in nat["rules"]] + ["COMMIT"])
    return {"ipv4": {"text": text, "tables": {"filter": filt, "nat": nat}, "error": ""},
            "ipv6": {"text": "", "tables": {}, "error": ""}, "version": "iptables v1.8.9 (nf_tables)", "legacy_rules": 0,
            "service": "inactive"}


def nft(docker, fw=True):
    t = []
    if fw:
        t.append({"family": "inet", "name": "firewalld", "rules": 214, "chains": 61, "managed_by": "firewalld"})
    if docker:
        t += [{"family": "ip", "name": "filter", "rules": 18, "chains": 7, "managed_by": "iptables-nft"},
              {"family": "ip", "name": "nat", "rules": 9, "chains": 5, "managed_by": "iptables-nft"}]
    return {"version": "nftables v1.0.9 (Old Doc Yak #3)", "tables": t, "service": "inactive"}


def selinux(mode, local_bools=(), local_ports=(), avc=(), config=None):
    s = {"tools": True, "mode": mode, "status": {"Loaded policy name": "targeted"}, "config_mode": config or mode.lower(),
         "policy": "targeted", "semanage": True}
    if mode == "Disabled":
        return s
    lb = dict(local_bools)
    s["booleans"] = [{"name": n, "state": lb.get(n, d), "default": d, "description": desc} for n, desc, d in BOOLS]
    s["booleans_local"] = sorted(lb)
    s["ports"] = [{"type": a, "proto": b, "ports": c} for a, b, c in PORT_TYPES]
    s["ports_local"] = [{"type": a, "proto": b, "ports": c} for a, b, c in local_ports]
    s["fcontext_local"] = ["/srv/share(/.*)?                                   all files          system_u:object_r:samba_share_t:s0"] if local_ports else []
    s["permissive_domains"] = []
    s["avc_today"] = list(avc)
    return s


def host(ip, name, os_, arch, model, kernel, *, fw_running=True, zones=None, default_zone="public", listening=(),
         docker=(), se=None, f2b_banned=None, sshd=None, drift=(), log_denied="off", misc=None, policies=None):
    fw = {"installed": True, "active": fw_running, "enabled": "enabled" if fw_running else "disabled",
          "conf": {"DefaultZone": "public", "FirewallBackend": "nftables", "LogDenied": log_denied, "IPv6_rpfilter": "strict"},
          "running": fw_running}
    if fw_running:
        zs = std_zones()
        zs.update(zones or {})
        perm = copy.deepcopy(zs)
        for d in drift:
            lst = perm[d["zone"]][d["kind"]]
            if d["where"] == "runtime-only" and d["value"] in lst:
                lst.remove(d["value"])
        fw.update({"version": "2.3.1", "default_zone": default_zone, "log_denied": log_denied, "panic": False,
                   "zones": zs, "zones_permanent": perm, "policies": policies or {}, "ipsets": [], "icmptypes": ICMP,
                   "direct_rules": [], "direct_rules_permanent": [], "services_catalog": SERVICES, "drift": list(drift)})
    f2b = {"installed": f2b_banned is not None, "active": f2b_banned is not None}
    if f2b_banned is not None:
        f2b["jails"] = [{"name": "sshd", "banned": list(f2b_banned), "total_banned": len(f2b_banned) + 7, "currently_failed": 2,
                         "ignoreip": ["127.0.0.1/8", "::1", "10.42.0.5"]}]
    d = {"helper": "demo", "time": NOW, "_collected": NOW, "peer": "10.42.0.5", "ok": True, "errors": [], "pending": [],
         "facts": {"hostname": name, "os": os_, "kernel": kernel, "arch": arch, "model": model, "virt": "none",
                   "addresses": [{"ifname": "end0" if "Raspberry" in model else "enp3s0", "addr": ip, "prefix": 24,
                                  "family": "inet", "state": "UP"}] +
                                ([{"ifname": "docker0", "addr": "172.17.0.1", "prefix": 16, "family": "inet", "state": "UP"}] if docker else []),
                   "uptime": 86400 * 12},
         "firewalld": fw, "iptables": ipt(docker), "nftables": nft(docker, fw_running), "listening": list(listening),
         "selinux": se or selinux("Enforcing"), "fail2ban": f2b,
         "sshd": sshd or {"port": "22", "listenaddress": ["[::]:22", "0.0.0.0:22"], "permitrootlogin": "prohibit-password",
                          "pubkeyauthentication": "yes", "passwordauthentication": "no", "maxstartups": "10:30:100"},
         "misc": misc or {"docker": "active" if docker else "inactive", "podman": False, "cockpit": "inactive",
                          "networkmanager": "active"}}
    if fw_running:
        d["peer_info"] = {"zone": default_zone, "why": "interface", "ssh_allowed": True,
                          "reason": f"зона {default_zone} (interface): служба ssh"}
    return d


def build():
    pi = "RED OS release (8.0.3) DESKTOP"
    srv = "RED OS release (8.0.3) SERVER"
    hosts = []
    # 1. Raspberry Pi with Docker: published ports bypass the zone, stale leftovers, root login
    docker = [(3000, "172.18.0.2:3000"), (8080, "172.18.0.3:80"), (9100, "172.18.0.4:9100"), (1883, "172.18.0.5:1883")]
    hosts.append(("gateway-pi", "10.42.0.10", host(
        "10.42.0.10", "gateway-pi", pi, "aarch64", "Raspberry Pi 4 Model B Rev 1.5", "6.12.25-1.red80.aarch64",
        zones={"public": zone("public", default=True, active=True, interfaces=["end0"], services=["ssh", "mdns", "dhcpv6-client"],
                              ports=["22/tcp", "80/tcp", "443/tcp", "3000/tcp", "9100/tcp", "5000/tcp", "8443/tcp", "25/tcp", "6881/udp"]),
               "docker": zone("docker", active=True, target="ACCEPT", interfaces=["docker0", "br-5c1e0a7d2b31"])},
        listening=[listen("tcp", "0.0.0.0", 22, "sshd"), listen("tcp", "0.0.0.0", 80, "nginx"), listen("tcp", "0.0.0.0", 443, "nginx"),
                   listen("tcp", "0.0.0.0", 3000, "docker-proxy"), listen("tcp", "0.0.0.0", 8080, "docker-proxy"),
                   listen("tcp", "0.0.0.0", 9100, "docker-proxy"), listen("tcp", "0.0.0.0", 1883, "docker-proxy"),
                   listen("udp", "0.0.0.0", 5353, "avahi-daemon"), listen("tcp", "127.0.0.1", 5432, "postgres"),
                   listen("udp", "127.0.0.1", 323, "chronyd"), listen("tcp", "0.0.0.0", 9090, "systemd")],
        docker=docker, se=selinux("Disabled"), f2b_banned=["203.0.113.47", "198.51.100.23"],
        sshd={"port": "22", "listenaddress": ["0.0.0.0:22"], "permitrootlogin": "yes", "pubkeyauthentication": "yes",
              "passwordauthentication": "yes"},
        misc={"docker": "active", "podman": False, "cockpit": "active", "networkmanager": "active"})))
    # 2. NAS: SELinux enforcing with local customisations, AVC denials, runtime-only drift
    avc = [{"time": "сегодня 09:14:02", "comm": "nginx", "perms": ["name_connect"], "tclass": "tcp_socket", "dest": "8585",
            "scontext": "system_u:system_r:httpd_t:s0", "tcontext": "system_u:object_r:unreserved_port_t:s0", "result": "denied"},
           {"time": "сегодня 09:14:07", "comm": "nginx", "perms": ["name_connect"], "tclass": "tcp_socket", "dest": "8585",
            "scontext": "system_u:system_r:httpd_t:s0", "tcontext": "system_u:object_r:unreserved_port_t:s0", "result": "denied"},
           {"time": "сегодня 11:02:51", "comm": "smbd", "perms": ["read"], "tclass": "dir", "name": "backup",
            "scontext": "system_u:system_r:smbd_t:s0", "tcontext": "unconfined_u:object_r:user_home_t:s0", "result": "denied"}]
    hosts.append(("nas", "10.42.0.20", host(
        "10.42.0.20", "nas", srv, "x86_64", "", "6.12.101-1.red80.x86_64",
        zones={"public": zone("public", default=True, active=True, interfaces=["enp3s0"],
                              services=["ssh", "samba", "nfs", "rpc-bind", "mountd", "cockpit", "dhcpv6-client"],
                              ports=["8000/tcp", "5432/tcp"],
                              rich=['rule family="ipv4" source address="10.42.0.0/24" service name="postgresql" accept'])},
        listening=[listen("tcp", "0.0.0.0", 22, "sshd"), listen("tcp", "0.0.0.0", 445, "smbd"), listen("tcp", "0.0.0.0", 139, "smbd"),
                   listen("tcp", "0.0.0.0", 2049, "rpc.nfsd"), listen("tcp", "0.0.0.0", 111, "rpcbind"), listen("udp", "0.0.0.0", 111, "rpcbind"),
                   listen("tcp", "0.0.0.0", 20048, "rpc.mountd"), listen("tcp", "0.0.0.0", 9090, "systemd"),
                   listen("tcp", "0.0.0.0", 5432, "postgres"), listen("udp", "0.0.0.0", 137, "nmbd"), listen("udp", "0.0.0.0", 138, "nmbd")],
        se=selinux("Enforcing", local_bools=[("samba_enable_home_dirs", True), ("httpd_can_network_connect", True)],
                   local_ports=[("http_port_t", "tcp", ["8585"])], avc=avc),
        f2b_banned=[], drift=[{"zone": "public", "kind": "ports", "value": "8000/tcp", "where": "runtime-only"}],
        misc={"docker": "inactive", "podman": False, "cockpit": "active", "networkmanager": "active"})))
    # 3. Monitoring Pi 5: lots of open ports, Permissive SELinux, Docker
    mon_ports = [f"{p}/tcp" for p in (22, 80, 443, 3000, 3100, 8086, 9090, 9093, 9100, 9115, 9187, 9256, 1883, 8883, 5601,
                                      9200, 9300, 10050, 10051, 2003, 2004, 8125, 4317, 4318, 6831, 14268, 16686)] + ["514/udp", "161/udp"]
    mdocker = [(3000, "172.18.0.2:3000"), (9093, "172.18.0.3:9093"), (3100, "172.18.0.4:3100"), (16686, "172.18.0.5:16686"),
               (4317, "172.18.0.5:4317"), (8086, "172.18.0.6:8086")]
    mlisten = [listen("tcp", "0.0.0.0", 22, "sshd"), listen("tcp", "0.0.0.0", 80, "caddy"), listen("tcp", "0.0.0.0", 443, "caddy"),
               listen("tcp", "0.0.0.0", 9090, "prometheus"), listen("tcp", "0.0.0.0", 9100, "node_exporter"),
               listen("tcp", "0.0.0.0", 10050, "zabbix_agentd"), listen("udp", "0.0.0.0", 514, "rsyslogd"),
               listen("udp", "0.0.0.0", 161, "snmpd")] + [listen("tcp", "0.0.0.0", p, "docker-proxy") for p, _ in mdocker]
    hosts.append(("monitoring", "10.42.0.30", host(
        "10.42.0.30", "monitoring", pi, "aarch64", "Raspberry Pi 5 Model B Rev 1.0", "6.12.25-1.red80.aarch64",
        zones={"public": zone("public", default=True, active=True, interfaces=["end0"], services=["ssh", "dhcpv6-client"], ports=mon_ports),
               "docker": zone("docker", active=True, target="ACCEPT", interfaces=["docker0", "br-5c1e0a7d2b31"])},
        listening=mlisten, docker=mdocker, se=selinux("Permissive", config="permissive"), f2b_banned=[],
        log_denied="unicast")))
    # 4. Workstation with firewalld stopped
    hosts.append(("workstation", "10.42.0.40", host(
        "10.42.0.40", "workstation", "RED OS release (8.0.3) DESKTOP", "x86_64", "", "6.12.101-1.red80.x86_64",
        fw_running=False,
        listening=[listen("tcp", "0.0.0.0", 22, "sshd"), listen("tcp", "0.0.0.0", 3389, "xrdp"), listen("tcp", "0.0.0.0", 631, "cupsd"),
                   listen("udp", "0.0.0.0", 5353, "avahi-daemon"), listen("tcp", "0.0.0.0", 5900, "x11vnc"),
                   listen("tcp", "0.0.0.0", 8000, "python3"), listen("udp", "0.0.0.0", 5355, "systemd-resolve")],
        se=selinux("Enforcing"), f2b_banned=None,
        sshd={"port": "22", "permitrootlogin": "prohibit-password", "pubkeyauthentication": "yes", "passwordauthentication": "yes"})))
    return hosts


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    seed = []
    for name, ip, d in build():
        with open(os.path.join(OUT, f"{ip}.json"), "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
        seed.append({"name": name, "address": ip})
        print(ip, name)
    with open(os.path.join(OUT, "seed.json"), "w", encoding="utf-8") as f:
        json.dump(seed, f, ensure_ascii=False, indent=1)
