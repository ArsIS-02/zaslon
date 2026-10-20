"""Одноразовые токены регистрации хоста. Панель выдаёт токен вместе с командой установки;
скрипт на хосте в конце вызывает /api/enroll с токеном, и хост добавляется сам.
В файле лежит только SHA-256 токена. Токен живёт TTL секунд и работает один раз."""
import hashlib
import json
import os
import secrets
import tempfile
import threading
import time

TTL = 3600
MAX_ITEMS = 200


class Enroll:
    def __init__(self, data):
        self.dir = data
        self.path = os.path.join(data, "enroll.json")
        self.lock = threading.Lock()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                items = json.load(f)
        except (IOError, OSError, ValueError):
            return []
        return items if isinstance(items, list) else []

    def _save(self, items):
        os.makedirs(self.dir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    @staticmethod
    def _digest(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self, name, address, user, port):
        """Новый токен для хоста. Истёкшие и использованные записи удаляются."""
        token = secrets.token_urlsafe(24)
        now = time.time()
        rec = {"h": self._digest(token), "name": name, "address": address, "user": user,
               "port": int(port), "exp": int(now + TTL), "used": False, "pending": False,
               "created": time.strftime("%Y-%m-%d %H:%M:%S")}
        with self.lock:
            items = [i for i in self._load() if i.get("exp", 0) > now and not i.get("used")]
            items.append(rec)
            self._save(items[-MAX_ITEMS:])
        return token, rec["exp"]

    def claim(self, token):
        """Резервирует токен на время проверки. Возвращает запись или None (нет, истёк, уже использован)."""
        now = time.time()
        digest = self._digest(token or "")
        with self.lock:
            items = self._load()
            for rec in items:
                if rec.get("h") == digest:
                    if rec.get("used") or rec.get("pending") or rec.get("exp", 0) <= now:
                        return None
                    rec["pending"] = True
                    self._save(items)
                    return dict(rec)
        return None

    def finish(self, token, ok):
        """ok=True — токен использован; ok=False — резерв снимается, токен можно повторить до истечения."""
        digest = self._digest(token or "")
        with self.lock:
            items = self._load()
            for rec in items:
                if rec.get("h") == digest:
                    rec["pending"] = False
                    rec["used"] = bool(ok)
            self._save(items)
