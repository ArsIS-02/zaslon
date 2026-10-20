"""Сквозной тест: панель (uvicorn) → ssh-заглушка → агент с заглушками firewalld/SELinux.
Запуск: python3 tests/test_panel_e2e.py"""
import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="zaslon-e2e-")
DATA = os.path.join(TMP, "data")
FAKE = os.path.join(TMP, "fake")
STATE = os.path.join(TMP, "state")
SEL = os.path.join(TMP, "selinux-config")
PW = "e2e-pass-123"
os.makedirs(os.path.join(DATA, "keys"))
os.makedirs(FAKE)
with open(os.path.join(DATA, "keys", "zaslon_ed25519"), "w") as f:
    f.write("dummy")
PUB = "ssh-ed25519 AAAAE2E zaslon-test"
with open(os.path.join(DATA, "keys", "zaslon_ed25519.pub"), "w") as f:
    f.write(PUB + "\n")
with open(SEL, "w") as f:
    f.write("SELINUX=enforcing\nSELINUXTYPE=targeted\n")
with open(os.path.join(FAKE, "state.json"), "w") as f:
    json.dump({"fw": {"running": True, "default": "public",
                      "service": {"active": "active", "enabled": "enabled"},
                      "zones": {"public": {"rt": {"ports": ["22/tcp"], "services": ["ssh"], "interfaces": ["eth0"], "rich-rules": []},
                                           "pm": {"ports": ["22/tcp"], "services": ["ssh"], "interfaces": [], "rich-rules": []}},
                                "trusted": {"rt": {"ports": [], "services": [], "interfaces": [], "rich-rules": []},
                                            "pm": {"ports": [], "services": [], "interfaces": [], "rich-rules": []}}}},
               "selinux": {"runtime": "Enforcing"}, "bools": {"httpd_can_network_connect": False}}, f)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


PORT = free_port()
BASE = "http://127.0.0.1:%d" % PORT
env = dict(os.environ)
env.update({
    "PATH": os.path.join(ROOT, "tests", "shims") + os.pathsep + env.get("PATH", ""),
    "ZASLON_DATA": DATA, "ZASLON_PASSWORD": PW, "ZASLON_LOGIN": "admin",
    "ZASLON_FAKE": FAKE, "ZASLON_STATE": STATE, "ZASLON_SELINUX_CONFIG": SEL,
    "ZASLON_AGENT_PATH": os.path.join(ROOT, "host", "zaslon-agent"), "ZASLON_TEST_NONROOT": "1",
})
server = subprocess.Popen([sys.executable, "-m", "uvicorn", "panel.app:app", "--port", str(PORT),
                           "--host", "127.0.0.1"], cwd=ROOT, env=env,
                          stdout=subprocess.DEVNULL, stderr=open(os.path.join(TMP, "server.log"), "w"))
for _ in range(100):
    try:
        urllib.request.urlopen(BASE + "/healthz", timeout=1)
        break
    except Exception:  # noqa
        time.sleep(0.1)

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPRedirectHandler())


def req(method, path, body=None, csrf=True, expect=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    if csrf:
        r.add_header("X-Zaslon", "1")
    try:
        resp = opener.open(r, timeout=60)
        code, text = resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        code, text = e.code, e.read().decode()
    try:
        d = json.loads(text)
    except ValueError:
        d = {"raw": text}
    if expect is not None:
        assert code == expect, (method, path, code, text[:300])
    return code, d


def test_auth():
    req("POST", "/api/hosts", {"address": "127.0.0.1"}, expect=401)
    code, d = req("POST", "/api/login", {"login": "admin", "password": "wrong"}, expect=401)
    req("POST", "/api/login", {"login": "admin", "password": PW}, expect=200)
    req("POST", "/api/hosts/x/port", {"zone": "public"}, csrf=False, expect=403)


def test_key_and_host():
    _, d = req("GET", "/api/key", expect=200)
    assert d["key"] == PUB
    code, d = req("POST", "/api/hosts", {"name": "test", "address": "a;b"}, expect=400)
    code, d = req("POST", "/api/hosts", {"name": "test", "address": "127.0.0.1", "user": "sec_fw-admin", "port": 22},
                  expect=200)
    assert d["status"]["firewalld"]["running"] is True
    assert d["host"]["address"] == "127.0.0.1"


def hid():
    _, d = req("GET", "/api/hosts", expect=200)
    return d["hosts"][0]["id"]


def test_status_and_port_flow():
    h = hid()
    _, st = req("GET", "/api/hosts/%s/status" % h, expect=200)
    assert [z["name"] for z in st["zones"]] == ["public", "trusted"]
    _, d = req("POST", "/api/hosts/%s/port" % h,
               {"zone": "trusted", "port": "8080", "proto": "tcp", "add": True, "timeout": 120}, expect=200)
    assert d["changed"] and d["tx"]
    _, tx = req("GET", "/api/hosts/%s/tx" % h, expect=200)
    assert any(p["id"] == d["tx"] for p in tx["pending"])
    req("POST", "/api/hosts/%s/tx/%s/confirm" % (h, d["tx"]), {}, expect=200)
    _, tx = req("GET", "/api/hosts/%s/tx" % h, expect=200)
    assert not any(p["id"] == d["tx"] for p in tx["pending"])
    _, d2 = req("POST", "/api/hosts/%s/port" % h,
                {"zone": "trusted", "port": "8080", "proto": "tcp", "add": False, "timeout": 0}, expect=200)
    assert d2["changed"]


def test_rollback_via_api():
    h = hid()
    _, d = req("POST", "/api/hosts/%s/port" % h,
               {"zone": "trusted", "port": "9999", "proto": "udp", "add": True, "timeout": 120}, expect=200)
    req("POST", "/api/hosts/%s/tx/%s/rollback" % (h, d["tx"]), {}, expect=200)
    with open(os.path.join(FAKE, "state.json")) as f:
        st = json.load(f)
    assert "9999/udp" not in st["fw"]["zones"]["trusted"]["rt"]["ports"]


def test_selinux_and_firewalld():
    h = hid()
    _, d = req("POST", "/api/hosts/%s/selinux/mode" % h, {"mode": "permissive", "timeout": 0}, expect=200)
    assert d["changed"] and d["reboot_required"] is False
    _, b = req("GET", "/api/hosts/%s/selinux/booleans" % h, expect=200)
    assert any(i["name"] == "httpd_can_network_connect" for i in b["items"])
    req("POST", "/api/hosts/%s/selinux/bool" % h,
        {"name": "httpd_can_network_connect", "value": True, "persistent": True, "timeout": 0}, expect=200)
    _, d = req("POST", "/api/hosts/%s/firewalld" % h, {"running": False, "enabled": False, "timeout": 120}, expect=200)
    assert d["changed"]
    code, err = req("POST", "/api/hosts/%s/port" % h,
                    {"zone": "public", "port": "80", "proto": "tcp", "add": True}, expect=409)
    assert err["kind"] == "firewalld_off", err
    req("POST", "/api/hosts/%s/tx/%s/rollback" % (h, d["tx"]), {}, expect=200)


def test_audit_and_delete():
    h = hid()
    _, a = req("GET", "/api/audit", expect=200)
    assert a["items"] and any(i["op"] == "port_change" for i in a["items"])
    req("DELETE", "/api/hosts/" + h, expect=200)
    _, d = req("GET", "/api/hosts", expect=200)
    assert d["hosts"] == []


if __name__ == "__main__":
    failed = 0
    try:
        for name, fn in [(k, v) for k, v in list(globals().items()) if k.startswith("test_")]:
            try:
                fn()
                print("ok   ", name)
            except Exception as e:  # noqa
                failed += 1
                print("FAIL ", name, "->", e)
    finally:
        server.terminate()
        server.wait(timeout=10)
    print("%d failed" % failed)
    if failed:
        print("лог сервера:", os.path.join(TMP, "server.log"))
    sys.exit(1 if failed else 0)
