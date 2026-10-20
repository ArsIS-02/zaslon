"""Вход в панель: форма + cookie-сессия. Basic оставлен для curl -u."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time

COOKIE = "zaslon_session"
TTL = 12 * 3600
LOCAL = ("127.0.0.1", "::1", "localhost")
PUBLIC = {"/healthz", "/login.html", "/api/login", "/api/logout",
          "/favicon.ico", "/manifest.webmanifest", "/apple-touch-icon.png"}


def _key(pw):
    return hashlib.sha256(("zaslon-session:" + pw).encode("utf-8")).digest()


def make_session(pw):
    """Токен сессии: срок, идентификатор сессии и подпись. Идентификатор нужен, чтобы выход отзывал именно эту сессию."""
    exp = str(int(time.time()) + TTL)
    sid = secrets.token_hex(12)
    body = exp + "." + sid
    return "%s.%s" % (body, hmac.new(_key(pw), body.encode(), hashlib.sha256).hexdigest())


def _revoked(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def revoke(path, token):
    """Отзывает сессию (выход). Записи живут до истечения срока сессии и затем удаляются."""
    try:
        exp, sid, _sig = token.split(".", 2)
        exp = int(exp)
    except (ValueError, AttributeError):
        return
    now = time.time()
    data = {k: v for k, v in _revoked(path).items() if v > now}
    data[sid] = exp
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def valid_session(token, pw, revoked_path=None):
    try:
        exp, sid, sig = token.split(".", 2)
        if int(exp) < time.time():
            return False
    except (ValueError, AttributeError):
        return False
    if revoked_path and sid in _revoked(revoked_path):
        return False
    good = hmac.new(_key(pw), (exp + "." + sid).encode(), hashlib.sha256).hexdigest()
    return secrets.compare_digest(sig.encode(), good.encode())


def valid_basic(header, check):
    """check(login, password) -> bool; общая проверка с формой входа, чтобы пароль из интерфейса работал везде."""
    if not header.lower().startswith("basic "):
        return False
    try:
        u, _, p = base64.b64decode(header[6:]).decode("utf-8").partition(":")
    except Exception:  # noqa
        return False
    return bool(check(u, p))


PBKDF_ITER = 200_000


def make_record(pw):
    """Хэш пароля панели (PBKDF2-SHA256 с солью). Открытый пароль на диск не пишется."""
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF_ITER)
    return {"alg": "pbkdf2-sha256", "iter": PBKDF_ITER, "salt": salt.hex(), "hash": h.hex()}


def verify_record(pw, rec):
    try:
        salt = bytes.fromhex(rec["salt"])
        h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, int(rec["iter"]))
        return secrets.compare_digest(h.hex(), rec["hash"])
    except (KeyError, ValueError, TypeError):
        return False


def read_record(path):
    try:
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
        return rec if isinstance(rec, dict) and rec.get("hash") else None
    except (OSError, ValueError):
        return None


def write_record(path, rec):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(rec, f)
    os.replace(tmp, path)
