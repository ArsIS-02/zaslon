#!/usr/bin/python3
"""Заглушки системных команд для тестов. Состояние хранится в $ZASLON_FAKE/state.json.
Имя файла-ссылки определяет команду (firewall-cmd, systemctl, ...)."""
import json
import os
import re
import sys

FAKE = os.environ["ZASLON_FAKE"]
S = os.path.join(FAKE, "state.json")
name = os.path.basename(sys.argv[0])
args = sys.argv[1:]


def load():
    with open(S) as f:
        return json.load(f)


def save(st):
    with open(S, "w") as f:
        json.dump(st, f)


def out(text="", rc=0):
    if text:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    sys.exit(rc)


def err(text, rc=1):
    sys.stderr.write(text + "\n")
    sys.exit(rc)


st = load()
fw = st["fw"]

if name == "firewall-cmd":
    if not fw["running"] and args != ["--state"]:
        err("firewall-cmd: FirewallD is not running", 252)
    perm = "--permanent" in args
    rest = [a for a in args if a != "--permanent"]
    zone = fw["default"]
    for a in list(rest):
        if a.startswith("--zone="):
            zone = a.split("=", 1)[1]
            rest.remove(a)
    if rest == ["--state"]:
        out("running" if fw["running"] else "not running")
    if rest == ["--get-default-zone"]:
        out(fw["default"])
    if rest == ["--list-all-zones"]:
        lines = []
        for zn in sorted(fw["zones"]):
            zz = fw["zones"][zn]["pm" if perm else "rt"]
            lines.append("%s (%sactive)" % (zn, "default, " if zn == fw["default"] else ""))
            lines.append("  target: default")
            lines.append("  interfaces: " + " ".join(zz.get("interfaces", [])))
            lines.append("  services: " + " ".join(zz.get("services", [])))
            lines.append("  ports: " + " ".join(zz.get("ports", [])))
            lines.append("  rich rules:")
            lines.extend("\t" + r for r in zz.get("rich-rules", []))
        out("\n".join(lines))
    if rest == ["--get-zones"]:
        out(" ".join(sorted(fw["zones"])))
    if zone not in fw["zones"]:
        err("firewall-cmd: INVALID_ZONE: %s" % zone, 1)
    z = fw["zones"][zone]
    bucket = z["pm" if perm else "rt"]
    cmd = rest[0] if rest else ""
    m = re.match(r"--(list|query|add|remove)-(ports|port|services|service|interfaces|rich-rules)(?:=(.*))?$", cmd)
    if not m:
        err("firewall-cmd: unsupported %r" % args, 2)
    verb, what, val = m.group(1), m.group(2), m.group(3)
    key = {"port": "ports", "service": "services"}.get(what, what)
    if verb == "list":
        out(" ".join(bucket.get(key, [])) if key != "rich-rules" else "\n".join(bucket.get(key, [])))
    if verb == "query":
        sys.exit(0 if val in bucket.get(key, []) else 1)
    if verb == "add":
        lst = bucket.setdefault(key, [])
        if val not in lst:
            lst.append(val)
        save(st)
        out("success")
    if verb == "remove":
        lst = bucket.setdefault(key, [])
        if val in lst:
            lst.remove(val)
        save(st)
        out("success")

elif name == "systemctl":
    svc = fw["service"]
    if args[:1] == ["is-active"]:
        out(svc["active"], 0 if svc["active"] == "active" else 3)
    if args[:1] == ["is-enabled"]:
        out(svc["enabled"], 0 if svc["enabled"] == "enabled" else 1)
    if args[:1] == ["start"]:
        svc["active"] = "active"; fw["running"] = True
    elif args[:1] == ["stop"]:
        if args[1:] == ["firewalld"]:
            svc["active"] = "inactive"; fw["running"] = False
        else:
            st.setdefault("stopped_timers", []).append(args[1])
    elif args[:1] == ["enable"]:
        svc["enabled"] = "enabled"
    elif args[:1] == ["disable"]:
        svc["enabled"] = "disabled"
    save(st)
    out()

elif name == "systemd-run":
    unit = [a.split("=", 1)[1] for a in args if a.startswith("--unit=")][0]
    st.setdefault("timers", {})[unit] = args
    save(st)
    out()

elif name == "getenforce":
    out(st["selinux"]["runtime"])

elif name == "setenforce":
    if st["selinux"]["runtime"] == "Disabled":
        err("setenforce: SELinux is disabled", 1)
    st["selinux"]["runtime"] = "Enforcing" if args[0] == "1" else "Permissive"
    save(st)
    out()

elif name == "getsebool":
    b = st["bools"]
    if args[:1] == ["-a"]:
        out("\n".join("%s --> %s" % (k, "on" if v else "off") for k, v in sorted(b.items())))
    if args[0] not in b:
        err("getsebool: SELinux boolean %s does not exist." % args[0], 1)
    out("%s --> %s" % (args[0], "on" if b[args[0]] else "off"))

elif name == "setsebool":
    a = [x for x in args if x != "-P"]
    if a[0] not in st["bools"]:
        err("setsebool: %s is not a valid boolean" % a[0], 1)
    st["bools"][a[0]] = a[1] == "on"
    st.setdefault("persist_bools", {})
    if "-P" in args:
        st["persist_bools"][a[0]] = a[1]
    save(st)
    out()

else:
    err("shim: unknown command %s" % name, 127)
