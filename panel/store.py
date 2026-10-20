"""Хранилище панели: список хостов (JSON) и журнал действий (JSON lines). Всё в ZASLON_DATA."""
import json
import os
import tempfile
import threading
import time


class Store:
    def __init__(self, data):
        self.dir = data
        os.makedirs(data, exist_ok=True)
        self.hosts_path = os.path.join(data, "hosts.json")
        self.audit_path = os.path.join(data, "audit.jsonl")
        self.lock = threading.Lock()

    def _load(self):
        try:
            with open(self.hosts_path, encoding="utf-8") as f:
                return json.load(f)
        except (IOError, OSError, ValueError):
            return []

    def _save(self, items):
        fd, tmp = tempfile.mkstemp(dir=self.dir)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.hosts_path)

    def hosts(self):
        with self.lock:
            return self._load()

    def get(self, hid):
        for h in self.hosts():
            if h["id"] == hid:
                return h
        return None

    def add(self, host):
        with self.lock:
            items = self._load()
            if any(h["address"] == host["address"] for h in items):
                return None
            items.append(host)
            self._save(items)
            return host

    def remove(self, hid):
        with self.lock:
            items = self._load()
            left = [h for h in items if h["id"] != hid]
            if len(left) == len(items):
                return False
            self._save(left)
            return True

    def audit(self, entry):
        entry = dict(entry, ts=time.strftime("%Y-%m-%d %H:%M:%S"))
        with self.lock:
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def audit_tail(self, n=200):
        try:
            with open(self.audit_path, encoding="utf-8") as f:
                lines = f.readlines()[-n:]
        except (IOError, OSError):
            return []
        out = []
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out
