"""Тесты агента на заглушках команд (без реального firewalld/SELinux).
Запуск: python3 tests/test_agent.py"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "host", "zaslon-agent")
SHIMS = os.path.join(ROOT, "tests", "shims")

TMP = tempfile.mkdtemp(prefix="zaslon-test-")
FAKE = os.path.join(TMP, "fake")
STATE = os.path.join(TMP, "state")
SEL = os.path.join(TMP, "selinux-config")
os.makedirs(FAKE)
SELINUX_TEXT = "# test\nSELINUX=enforcing\nSELINUXTYPE=targeted\n"
with open(SEL, "w") as f:
    f.write(SELINUX_TEXT)


def reset():
    st = {
        "fw": {
            "running": True, "default": "public",
            "service": {"active": "active", "enabled": "enabled"},
            "zones": {
                "public": {"rt": {"ports": ["22/tcp"], "services": ["ssh", "dhcpv6-client"],
                                  "interfaces": ["eth0"], "rich-rules": []},
                           "pm": {"ports": ["22/tcp"], "services": ["ssh", "dhcpv6-client"],
                                  "interfaces": [], "rich-rules": []}},
                "trusted": {"rt": {"ports": [], "services": [], "interfaces": [], "rich-rules": []},
                            "pm": {"ports": [], "services": [], "interfaces": [], "rich-rules": []}},
            },
        },
        "selinux": {"runtime": "Enforcing"},
        "bools": {"httpd_can_network_connect": False, "samba_enable_home_dirs": True},
    }
    with open(os.path.join(FAKE, "state.json"), "w") as f:
        json.dump(st, f)
    with open(SEL, "w") as f:
        f.write(SELINUX_TEXT)
    txdir = os.path.join(STATE, "tx")
    if os.path.isdir(txdir):
        for n in os.listdir(txdir):
            os.remove(os.path.join(txdir, n))


def fake():
    with open(os.path.join(FAKE, "state.json")) as f:
        return json.load(f)


def call(op, **args):
    env = dict(os.environ)
    env.update({
        "PATH": SHIMS + os.pathsep + env.get("PATH", ""),
        "ZASLON_FAKE": FAKE, "ZASLON_STATE": STATE, "ZASLON_SELINUX_CONFIG": SEL,
        "ZASLON_AGENT_PATH": AGENT, "ZASLON_TEST_NONROOT": "1",
    })
    p = subprocess.run([sys.executable, "-I", AGENT], input=json.dumps({"op": op, "args": args}),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, universal_newlines=True)
    assert p.stdout.strip(), "агент ничего не вернул: %s" % p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])


def rollback(tid):
    env = dict(os.environ)
    env.update({"PATH": SHIMS + os.pathsep + env.get("PATH", ""), "ZASLON_FAKE": FAKE,
                "ZASLON_STATE": STATE, "ZASLON_SELINUX_CONFIG": SEL, "ZASLON_TEST_NONROOT": "1"})
    subprocess.run([sys.executable, "-I", AGENT, "--rollback-timer", tid], env=env, check=True)


def ok(r):
    assert r.get("ok"), r
    return r


def test_status():
    reset()
    r = ok(call("status"))
    assert r["firewalld"]["running"] and r["firewalld"]["enabled"]
    names = [z["name"] for z in r["zones"]]
    assert names == ["public", "trusted"], names
    assert r["default_zone"] == "public"
    assert r["selinux"]["runtime"] == "enforcing" and r["selinux"]["config"] == "enforcing"
    pub = r["zones"][0]
    assert pub["ports_perm"] == ["22/tcp"] and "ssh" in pub["services_perm"], pub
    assert pub["interfaces"] == ["eth0"] and pub["default"] is True


def test_port_open_close_and_confirm():
    reset()
    r = ok(call("port_change", zone="public", port="8080", proto="tcp", add=True, timeout=120))
    assert r["changed"] and r["tx"]
    st = fake()["fw"]["zones"]["public"]
    assert "8080/tcp" in st["rt"]["ports"] and "8080/tcp" in st["pm"]["ports"]
    tx = ok(call("tx_list"))
    assert any(i["id"] == r["tx"] and i["state"] == "pending" for i in tx["items"])
    ok(call("tx_confirm", id=r["tx"]))
    assert fake().get("stopped_timers") and "zaslon-rb-" in fake()["stopped_timers"][0]
    again = ok(call("port_change", zone="public", port="8080", proto="tcp", add=True))
    assert again["changed"] is False
    close = ok(call("port_change", zone="public", port="22", proto="tcp", add=False, timeout=0))
    assert close["changed"]
    st = fake()["fw"]["zones"]["public"]
    assert "22/tcp" not in st["rt"]["ports"] and "22/tcp" not in st["pm"]["ports"]


def test_manual_rollback_restores_port():
    reset()
    r = ok(call("port_change", zone="public", port="22", proto="tcp", add=False, timeout=120))
    st = fake()["fw"]["zones"]["public"]
    assert "22/tcp" not in st["rt"]["ports"]
    back = ok(call("tx_rollback", id=r["tx"]))
    assert back["state"] == "rolled_back" and not back["errors"], back
    st = fake()["fw"]["zones"]["public"]
    assert "22/tcp" in st["rt"]["ports"] and "22/tcp" in st["pm"]["ports"]


def test_timer_rolls_back_unconfirmed_change():
    reset()
    r = ok(call("port_change", zone="trusted", port="9000-9010", proto="udp", add=True, timeout=60))
    assert "9000-9010/udp" in fake()["fw"]["zones"]["trusted"]["rt"]["ports"]
    rollback(r["tx"])   # то, что запустит systemd по истечении таймера
    st = fake()["fw"]["zones"]["trusted"]
    assert "9000-9010/udp" not in st["rt"]["ports"] and "9000-9010/udp" not in st["pm"]["ports"]
    assert ok(call("tx_list"))["items"][0]["state"] == "rolled_back"


def test_timer_does_not_roll_back_confirmed():
    reset()
    r = ok(call("port_change", zone="trusted", port="443", proto="tcp", add=True, timeout=60))
    ok(call("tx_confirm", id=r["tx"]))
    rollback(r["tx"])
    assert "443/tcp" in fake()["fw"]["zones"]["trusted"]["rt"]["ports"]


def test_service_change():
    reset()
    r = ok(call("service_change", zone="public", service="http", add=True, timeout=0))
    assert r["changed"]
    assert "http" in fake()["fw"]["zones"]["public"]["pm"]["services"]


def test_validation():
    reset()
    bad = [
        dict(zone="public", port="0", proto="tcp", add=True),
        dict(zone="public", port="70000", proto="tcp", add=True),
        dict(zone="public", port="80;rm -rf /", proto="tcp", add=True),
        dict(zone="public", port="80", proto="icmp", add=True),
        dict(zone="../etc", port="80", proto="tcp", add=True),
        dict(zone="nope", port="80", proto="tcp", add=True),
        dict(zone="public", port="9000-8000", proto="tcp", add=True),
    ]
    for args in bad:
        r = call("port_change", **args)
        assert r["ok"] is False and r["kind"] == "validation", (args, r)
    assert call("service_change", zone="public", service="ssh; id", add=True)["ok"] is False


def test_firewalld_off_blocks_port_changes_and_rolls_back():
    reset()
    r = ok(call("firewalld_set", running=False, enabled=False, timeout=120))
    assert r["changed"]
    assert fake()["fw"]["service"] == {"active": "inactive", "enabled": "disabled"}
    blocked = call("port_change", zone="public", port="80", proto="tcp", add=True)
    assert blocked["ok"] is False and blocked["kind"] == "firewalld_off", blocked
    rollback(r["tx"])
    assert fake()["fw"]["service"] == {"active": "active", "enabled": "enabled"}


def test_selinux_permissive_and_rollback():
    reset()
    r = ok(call("selinux_mode", mode="permissive", timeout=120))
    assert r["changed"] and not r.get("reboot_required")
    assert fake()["selinux"]["runtime"] == "Permissive"
    assert "SELINUX=permissive" in open(SEL).read()
    rollback(r["tx"])
    assert fake()["selinux"]["runtime"] == "Enforcing"
    assert open(SEL).read() == SELINUX_TEXT


def test_selinux_disabled_needs_reboot():
    reset()
    r = ok(call("selinux_mode", mode="disabled", timeout=0))
    assert r["reboot_required"] is True
    assert "SELINUX=disabled" in open(SEL).read()


def test_selinux_boolean():
    reset()
    r = ok(call("selinux_bool", name="httpd_can_network_connect", value=True, persistent=True, timeout=120))
    assert r["changed"] and fake()["bools"]["httpd_can_network_connect"] is True
    assert fake()["persist_bools"]["httpd_can_network_connect"] == "on"
    rollback(r["tx"])
    assert fake()["bools"]["httpd_can_network_connect"] is False
    bad = call("selinux_bool", name="no_such_bool", value=True)
    assert bad["ok"] is False and bad["kind"] == "validation"
    lst = ok(call("selinux_booleans"))
    assert any(i["name"] == "samba_enable_home_dirs" and i["value"] for i in lst["items"])


def test_unknown_op_and_bad_json():
    reset()
    assert call("rm_rf")["ok"] is False
    env = dict(os.environ, PATH=SHIMS + os.pathsep + os.environ["PATH"], ZASLON_FAKE=FAKE,
               ZASLON_STATE=STATE, ZASLON_TEST_NONROOT="1", ZASLON_SELINUX_CONFIG=SEL)
    p = subprocess.run([sys.executable, "-I", AGENT], input="{not json", stdout=subprocess.PIPE,
                       universal_newlines=True, env=env)
    assert json.loads(p.stdout)["ok"] is False


if __name__ == "__main__":
    os.makedirs(STATE, exist_ok=True)
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print("ok   ", t.__name__)
        except Exception as e:  # noqa
            failed += 1
            print("FAIL ", t.__name__, "->", e)
    print("%d passed, %d failed" % (len(tests) - failed, failed))
    sys.exit(1 if failed else 0)
