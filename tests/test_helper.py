"""Parser and SSH-guard tests for host/zaslon-helper (no root, no firewalld needed).
   python3 tests/test_helper.py"""
import importlib.machinery
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
loader = importlib.machinery.SourceFileLoader("zh", os.path.join(ROOT, "host", "zaslon-helper"))
spec = importlib.util.spec_from_loader("zh", loader)
zh = importlib.util.module_from_spec(spec)
loader.exec_module(zh)
fx = lambda n: open(os.path.join(FIX, n), encoding="utf-8").read()
CAT = {"ssh": {"ports": ["22/tcp"]}, "mdns": {"ports": ["5353/udp"]}, "dhcpv6-client": {"ports": ["546/udp"]}}
zh.run = lambda args, **kw: (0, "10.42.0.5 dev enp3s0 src 10.42.0.20", "") if args[:3] == ["ip", "route", "get"] else (1, "", "")

zs = zh.parse_fw_blocks(fx("zones.txt"))
assert set(zs) == {"docker", "libvirt", "public"}
assert zs["public"]["default"] and zs["public"]["active"] and zs["public"]["interfaces"] == ["enp3s0"]
assert "8000-8010/tcp" in zs["public"]["ports"] and zs["libvirt"]["rich_rules"] == ['rule priority="32767" reject']
pol = zh.parse_fw_blocks(fx("policies.txt"))
assert len(pol["allow-host-ipv6"]["rich_rules"]) == 2 and pol["allow-host-ipv6"]["priority"] == "-15000"

ss = zh.parse_ss(fx("ss.txt"))
assert len(ss) == 7
assert [x for x in ss if x["port"] == 80][0]["processes"] == ["nginx"] and [x for x in ss if x["port"] == 80][0]["addr"] == "::"
assert [x for x in ss if x["port"] == 53][0]["local_only"]

ipt = zh.parse_iptables_save(fx("iptables-save.txt"))
assert ipt["filter"]["chains"]["INPUT"]["packets"] == 100
assert ipt["filter"]["rules"][0]["packets"] == 12 and ipt["nat"]["rules"][1]["rule"].endswith("172.18.0.3:80")

# SSH guard
P = "10.42.0.5"
ok = lambda z: zh.ssh_allowed(P, z, CAT, [22])[0]
assert ok(zs)
z = {k: dict(v) for k, v in zs.items()}
z["public"] = dict(zs["public"], services=["mdns"], ports=["80/tcp"])
assert not ok(z)
z["public"] = dict(z["public"], rich_rules=['rule family="ipv4" source address="10.42.0.0/24" service name="ssh" accept'])
assert ok(z)
z["public"] = dict(zs["public"], rich_rules=['rule family="ipv4" source address="10.42.0.0/24" reject'])
assert not ok(z)
z["public"] = dict(zs["public"], rich_rules=['rule priority="32767" reject'])
assert ok(z)
z["public"] = dict(zs["public"], rich_rules=['rule family="ipv4" source NOT address="10.42.0.0/24" drop'])
assert ok(z)
z["public"] = dict(zs["public"], forward_ports=["port=22:proto=tcp:toport=2222:toaddr="])
assert not ok(z)
z["public"] = dict(zs["public"], rich_rules=['rule family="ipv4" source address="10.42.0.0/24" destination address="10.9.9.9" reject'])
assert not ok(z)  # conservative: unknown condition on a deny rule
z["public"] = dict(zs["public"], services=[], ports=[], rich_rules=['rule family="ipv4" source-port port="22" protocol="tcp" accept'])
assert not ok(z)
z["public"] = dict(zs["public"], target="ACCEPT", services=[], ports=[])
assert ok(z)

# misc parsers / validators
b = zh.parse_semanage_bool("SELinux boolean                State  Default Description\n\nabrt_anon_write                (off  ,  off)  Allow abrt to anon write\nhttpd_can_network_connect      (on   ,   on)  Allow httpd to can network connect\n")
assert b[1]["name"] == "httpd_can_network_connect" and b[1]["state"] and b[0]["state"] is False
pt = zh.parse_semanage_port("SELinux Port Type              Proto    Port Number\n\nhttp_port_t                    tcp      80, 81, 443\nsyslogd_port_t                 udp      1514, 514\n")
assert pt[0]["ports"] == ["80", "81", "443"] and pt[1]["proto"] == "udp"
avc = zh.parse_avc("----\ntype=AVC msg=audit(10/10/2026 01:00:00.123:456) : avc:  denied  { name_connect } for  pid=1234 comm=nginx dest=8080 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:http_cache_port_t:s0 tclass=tcp_socket permissive=0\n")
assert avc[0]["comm"] == "nginx" and avc[0]["perms"] == ["name_connect"] and avc[0]["dest"] == "8080"
for bad in ("99999", "22;reboot", "-1", "22\n"):
    try:
        zh.v_port(bad)
        raise SystemExit(f"port validation failed for {bad!r}")
    except zh.Bad:
        pass
for bad in ("-a", "-P", "x" * 70, "a b"):
    try:
        zh.v_name(bad)
        raise SystemExit(f"name validation failed for {bad!r}")
    except zh.Bad:
        pass
for bad in (["--modprobe=/tmp/x"], ["-t", "nat"], ["-F"], ["-M", "/x"]):
    try:
        zh.safe_ipt_tokens(bad)
        raise SystemExit(f"iptables token check failed for {bad}")
    except zh.Bad:
        pass
assert zh.safe_ipt_tokens(["-s", "203.0.113.5", "-p", "tcp", "--dport", "22", "-j", "DROP"])
assert zh.fwd_value({"port": "80", "proto": "tcp", "toport": "8080"}) == "port=80:proto=tcp:toport=8080"
print("ALL OK")
