"""Persistent storage: hosts, settings, cached host state, audit log. Plain JSON files under DATA."""
import json
import os
import re
import secrets
import threading
import time

DATA = os.environ.get("ZASLON_DATA", "/data")
HOSTS = os.path.join(DATA, "hosts.json")
SETTINGS = os.path.join(DATA, "settings.json")
STATE_DIR = os.path.join(DATA, "state")
AUDIT = os.path.join(DATA, "audit.jsonl")
DEMO_DIR = os.path.join(os.path.dirname(__file__), "demo")
_lock = threading.RLock()

DEFAULT_SETTINGS = {
    "ssh_user": "sec_fw-admin",
    "ssh_port": 22,
    "key_path": os.path.join(DATA, "keys", "zaslon_ed25519"),
    "helper": "/usr/local/libexec/zaslon/zaslon-helper",
    "rollback_seconds": 60,
    "auto_confirm": True,
    "panel_name": "ZaSlon",
    "demo": os.environ.get("ZASLON_DEMO", "") == "1",
}

HOST_FIELDS = ("name", "address", "port", "user", "description", "role", "location", "tags", "demo", "order")


def _read(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def init():
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(os.path.join(DATA, "keys"), exist_ok=True)
    os.makedirs(os.path.join(DATA, "reports"), exist_ok=True)
    with _lock:
        if not os.path.exists(HOSTS):
            demo = get_settings()["demo"]
            seed = _read(os.path.join(DATA, "seed.json"), None) or (_read(os.path.join(DEMO_DIR, "seed.json"), []) if demo else [])
            hosts = []
            for i, s in enumerate(seed):
                h = new_host(dict(s, demo=demo or s.get("demo", False), order=i))
                hosts.append(h)
            _write(HOSTS, hosts)


# ------------------------------------------------------------------ settings
def get_settings():
    s = dict(DEFAULT_SETTINGS)
    s.update(_read(SETTINGS, {}))
    if os.environ.get("ZASLON_DEMO", "") == "1":
        s["demo"] = True
    return s


def save_settings(upd):
    with _lock:
        s = _read(SETTINGS, {})
        for k in ("ssh_user", "ssh_port", "key_path", "rollback_seconds", "auto_confirm", "panel_name", "demo"):
            if k in upd:
                s[k] = upd[k]
        s["rollback_seconds"] = max(30, min(600, int(s.get("rollback_seconds", 60))))
        s["ssh_port"] = int(s.get("ssh_port", 22))
        _write(SETTINGS, s)
    return get_settings()


# ------------------------------------------------------------------ hosts
RE_ADDR = re.compile(r"^[A-Za-z0-9_.:-]{1,253}$")
RE_USER = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")


class Invalid(ValueError):
    pass


def clean_host(d, partial=False):
    out = {}
    if "name" in d or not partial:
        name = str(d.get("name", "")).strip()
        if not name or len(name) > 64:
            raise Invalid("Укажите имя хоста (до 64 символов)")
        out["name"] = name
    if "address" in d or not partial:
        a = str(d.get("address", "")).strip()
        if not RE_ADDR.match(a):
            raise Invalid("Адрес: IP или DNS-имя")
        out["address"] = a
    if "port" in d:
        try:
            p = int(d.get("port") or 22)
        except ValueError:
            raise Invalid("Порт SSH — число")
        if not 0 < p < 65536:
            raise Invalid("Порт SSH вне диапазона")
        out["port"] = p
    if "user" in d:
        u = str(d.get("user") or "").strip()
        if u and not RE_USER.match(u):
            raise Invalid("Недопустимое имя пользователя")
        out["user"] = u
    for k in ("description", "role", "location"):
        if k in d:
            out[k] = str(d.get(k) or "").strip()[:500]
    if "tags" in d:
        tags = d.get("tags") or []
        if isinstance(tags, str):
            tags = [t for t in re.split(r"[,\s]+", tags) if t]
        out["tags"] = [str(t)[:32] for t in tags][:12]
    if "demo" in d:
        out["demo"] = bool(d.get("demo"))
    if "order" in d:
        out["order"] = int(d.get("order") or 0)
    return out


def new_host(d):
    h = {"id": secrets.token_hex(4), "port": 22, "user": "", "description": "", "role": "", "location": "",
         "tags": [], "demo": False, "order": 0, "created": int(time.time())}
    h.update(clean_host(d))
    return h


def list_hosts():
    hs = _read(HOSTS, [])
    hs.sort(key=lambda h: (h.get("order", 0), h.get("name", "")))
    return hs


def get_host(hid):
    for h in list_hosts():
        if h["id"] == hid:
            return h
    return None


def add_host(d):
    with _lock:
        hs = list_hosts()
        h = new_host(d)
        if any(x["address"] == h["address"] and x.get("port", 22) == h.get("port", 22) for x in hs):
            raise Invalid("Хост с таким адресом уже есть")
        h["order"] = max([x.get("order", 0) for x in hs] + [0]) + 1
        hs.append(h)
        _write(HOSTS, hs)
        return h


def update_host(hid, d):
    with _lock:
        hs = list_hosts()
        for h in hs:
            if h["id"] == hid:
                h.update(clean_host(d, partial=True))
                h["updated"] = int(time.time())
                _write(HOSTS, hs)
                return h
    return None


def reorder(ids):
    with _lock:
        hs = list_hosts()
        pos = {i: n for n, i in enumerate(ids)}
        for h in hs:
            h["order"] = pos.get(h["id"], len(pos) + h.get("order", 0))
        _write(HOSTS, hs)


def delete_host(hid):
    with _lock:
        hs = list_hosts()
        n = [h for h in hs if h["id"] != hid]
        if len(n) == len(hs):
            return False
        _write(HOSTS, n)
        try:
            os.remove(os.path.join(STATE_DIR, f"{hid}.json"))
        except OSError:
            pass
        return True


# ------------------------------------------------------------------ state cache
def save_state(hid, state):
    _write(os.path.join(STATE_DIR, f"{hid}.json"), state)


def load_state(hid):
    return _read(os.path.join(STATE_DIR, f"{hid}.json"), None)


# ------------------------------------------------------------------ audit
def audit(host, action, detail=None, ok=True):
    rec = {"t": int(time.time()), "host": host.get("name") if host else None, "host_id": host.get("id") if host else None,
           "action": action, "ok": ok, "detail": detail}
    with _lock:
        os.makedirs(DATA, exist_ok=True)
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def read_audit(host_id=None, limit=300):
    try:
        with open(AUDIT, encoding="utf-8") as f:
            lines = f.readlines()[-5000:]
    except OSError:
        return []
    res = []
    for l in reversed(lines):
        try:
            r = json.loads(l)
        except ValueError:
            continue
        if host_id and r.get("host_id") != host_id:
            continue
        res.append(r)
        if len(res) >= limit:
            break
    return res
