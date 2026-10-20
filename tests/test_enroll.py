"""Регистрация хоста по одноразовому токену и отпечаток CA. Запуск: python3 tests/test_enroll.py"""
import hashlib
import os
import ssl
import subprocess
import sys
import tempfile
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="zaslon-enroll-")
DATA = os.path.join(TMP, "data")
os.makedirs(os.path.join(DATA, "keys"))
for name in ("zaslon_ed25519", "zaslon_ed25519.pub"):
    with open(os.path.join(DATA, "keys", name), "w") as f:
        f.write("ssh-ed25519 AAAATEST zaslon-test\n" if name.endswith(".pub") else "dummy")
os.environ["ZASLON_DATA"] = DATA
os.environ["ZASLON_PASSWORD"] = "enroll-pass-123"

from starlette.testclient import TestClient  # noqa: E402
from panel import app as appmod, remote  # noqa: E402

PW = "enroll-pass-123"
OK_STATUS = {"ok": True, "firewalld": {"running": True, "enabled": True}, "selinux": {"runtime": "enforcing"},
             "zones": [], "pending": []}
calls = {"fail": False}


def fake_call(host, data, op, args=None, timeout=60):
    if calls["fail"]:
        raise remote.AgentError("Нет связи с %s по SSH" % host["address"], "ssh", 502)
    return dict(OK_STATUS)


appmod.remote.call = fake_call
client = TestClient(appmod.app)
HDR = {"X-Zaslon": "1"}
RESULTS = []


def case(fn):
    try:
        fn()
        RESULTS.append(("ok", fn.__name__))
    except Exception:
        RESULTS.append(("FAIL", fn.__name__))
        traceback.print_exc()
    return fn


def login():
    r = client.post("/api/login", json={"login": "admin", "password": PW}, headers=HDR)
    assert r.status_code == 200, r.text


@case
def test_token_needs_session():
    c = TestClient(appmod.app)
    r = c.post("/api/enroll/token", json={"address": "10.0.0.5"}, headers=HDR)
    assert r.status_code == 401, r.status_code


@case
def test_token_and_enroll_once():
    login()
    r = client.post("/api/enroll/token", json={"name": "homeserver", "address": "10.0.0.5", "user": "sec_fw-admin"},
                    headers=HDR)
    assert r.status_code == 200, r.text
    tok = r.json()["token"]
    # без заголовка CSRF — отказ
    r = TestClient(appmod.app).post("/api/enroll", json={"token": tok})
    assert r.status_code == 403, r.status_code
    # скрипт без cookie, с заголовком и токеном
    anon = TestClient(appmod.app)
    r = anon.post("/api/enroll", json={"token": "wrong-token"}, headers=HDR)
    assert r.status_code == 403, r.status_code
    r = anon.post("/api/enroll", json={"token": tok}, headers=HDR)
    assert r.status_code == 200, r.text
    assert r.json()["host"]["address"] == "10.0.0.5" and r.json()["host"]["name"] == "homeserver"
    hosts = client.get("/api/hosts").json()["hosts"]
    assert any(h["address"] == "10.0.0.5" for h in hosts), hosts
    # повторное использование — отказ
    r = anon.post("/api/enroll", json={"token": tok}, headers=HDR)
    assert r.status_code == 403, r.status_code


@case
def test_failed_check_keeps_token_usable():
    login()
    tok = client.post("/api/enroll/token", json={"name": "lab", "address": "10.0.0.7", "user": "sec_fw-admin"},
                      headers=HDR).json()["token"]
    anon = TestClient(appmod.app)
    calls["fail"] = True
    try:
        r = anon.post("/api/enroll", json={"token": tok}, headers=HDR)
        assert r.status_code == 502, r.status_code
        assert not any(h["address"] == "10.0.0.7" for h in client.get("/api/hosts").json()["hosts"])
    finally:
        calls["fail"] = False
    r = anon.post("/api/enroll", json={"token": tok}, headers=HDR)
    assert r.status_code == 200, r.text


@case
def test_duplicate_address_rejected():
    login()
    tok = client.post("/api/enroll/token", json={"name": "dup", "address": "10.0.0.5", "user": "sec_fw-admin"},
                      headers=HDR).json()["token"]
    r = TestClient(appmod.app).post("/api/enroll", json={"token": tok}, headers=HDR)
    assert r.status_code == 409, r.status_code


@case
def test_token_validation():
    login()
    r = client.post("/api/enroll/token", json={"address": "bad address!", "user": "sec_fw-admin"}, headers=HDR)
    assert r.status_code == 400, r.status_code


@case
def test_ca_fingerprint_matches_script_check():
    info = client.get("/api/install-info").json()
    assert info["ca_sha256"] == "" and info["install_sha256"], info
    crt = os.path.join(TMP, "root.crt")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
                    os.path.join(TMP, "k.pem"), "-out", crt, "-days", "2", "-subj", "/CN=zaslon-test"],
                   check=True, capture_output=True)
    os.makedirs(os.path.join(DATA, "ca"), exist_ok=True)
    with open(crt) as src, open(os.path.join(DATA, "ca", "root.crt"), "w") as dst:
        dst.write(src.read())
    info = client.get("/api/install-info").json()
    # та же сумма, что считает скрипт: openssl x509 -outform DER | sha256sum
    der = subprocess.run(["openssl", "x509", "-in", crt, "-outform", "DER"], check=True,
                         capture_output=True).stdout
    assert info["ca_sha256"] == hashlib.sha256(der).hexdigest(), info["ca_sha256"]
    r = client.get("/dl/ca.crt")
    assert r.status_code == 200 and b"BEGIN CERTIFICATE" in r.content


@case
def test_script_is_valid_sh():
    subprocess.run(["sh", "-n", os.path.join(ROOT, "host", "zaslon-install.sh")], check=True)


@case
def test_logout_revokes_session_server_side():
    c = TestClient(appmod.app)
    r = c.post("/api/login", json={"login": "admin", "password": PW}, headers=HDR)
    assert r.status_code == 200
    token = c.cookies.get(appmod.auth.COOKIE)
    assert token and c.get("/api/hosts").status_code == 200
    # та же cookie в другом клиенте (как если бы её скопировали)
    other = TestClient(appmod.app)
    other.cookies.set(appmod.auth.COOKIE, token)
    assert other.get("/api/hosts").status_code == 200
    assert c.post("/api/logout", headers=HDR).status_code == 200
    assert other.get("/api/hosts").status_code == 401
    assert c.get("/api/hosts").status_code == 401


if __name__ == "__main__":
    failed = [n for s, n in RESULTS if s == "FAIL"]
    for s, n in RESULTS:
        print(s if s == "ok" else "FAIL", n)
    print("%d failed" % len(failed))
    sys.exit(1 if failed else 0)
