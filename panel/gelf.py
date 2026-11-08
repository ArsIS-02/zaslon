"""Отправка журнала действий в Graylog по GELF (UDP или TCP). Только стандартная библиотека.

Включается переменными окружения:
    ZASLON_GELF_HOST   адрес входа GELF (пусто — отправка выключена)
    ZASLON_GELF_PORT   порт, по умолчанию 12201
    ZASLON_GELF_PROTO  udp (по умолчанию) или tcp
    ZASLON_GELF_SOURCE поле source в Graylog, по умолчанию zaslon

Сообщения уходят из фонового потока через очередь: недоступный Graylog не задерживает запросы
к панели, а при переполнении очереди лишние записи отбрасываются (журнал на диске остаётся полным).
"""
import json
import logging
import os
import queue
import socket
import struct
import threading
import time
import zlib

log = logging.getLogger("zaslon.gelf")

CHUNK = 8000          # полезная нагрузка UDP-части, с запасом под MTU и заголовок 12 байт
MAX_CHUNKS = 128      # предел GELF
QUEUE_MAX = 1000


def udp_packets(payload, chunk=CHUNK):
    """Готовые UDP-датаграммы: одна, если влезает, иначе части с заголовком 0x1e 0x0f."""
    data = zlib.compress(payload)
    if len(data) <= chunk:
        return [data]
    parts = [data[i:i + chunk] for i in range(0, len(data), chunk)]
    if len(parts) > MAX_CHUNKS:
        raise ValueError("GELF: сообщение слишком большое (%d частей)" % len(parts))
    mid = os.urandom(8)
    return [b"\x1e\x0f" + mid + struct.pack("BB", i, len(parts)) + p for i, p in enumerate(parts)]


def message(short, fields, source, level=6, ts=None):
    """Словарь GELF 1.1: свои поля получают префикс «_», пустые значения не отправляются."""
    msg = {"version": "1.1", "host": source, "short_message": str(short)[:1000] or "-",
           "timestamp": round(ts if ts is not None else time.time(), 3), "level": int(level)}
    for k, v in fields.items():
        if v is None or v == "" or v == [] or v == {}:
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        elif isinstance(v, (list, tuple, set)):
            v = ", ".join(str(x) for x in v)
        elif isinstance(v, dict):
            v = json.dumps(v, ensure_ascii=False, sort_keys=True)
        key = "_" + "".join(c if c.isalnum() or c == "_" else "_" for c in str(k))
        if key in ("_id", "_source"):
            key = "_f" + key
        msg[key] = v
    return msg


class Sender:
    def __init__(self, host, port=12201, proto="udp", source="zaslon", timeout=2.0):
        self.host, self.port = host, int(port)
        self.proto = (proto or "udp").lower()
        self.source = source or "zaslon"
        self.timeout = timeout
        self.status = {"sent": 0, "errors": 0, "last_ok": None, "last_error": ""}
        self._q = queue.Queue(QUEUE_MAX)
        self._t = None

    @classmethod
    def from_env(cls, env=os.environ):
        host = (env.get("ZASLON_GELF_HOST") or "").strip()
        if not host:
            return None
        try:
            port = int(env.get("ZASLON_GELF_PORT") or 12201)
        except ValueError:
            port = 12201
        return cls(host, port, env.get("ZASLON_GELF_PROTO") or "udp", env.get("ZASLON_GELF_SOURCE") or "zaslon")

    def send_now(self, msg):
        """Отправить сразу, в вызывающем потоке. Ошибки сети поднимаются наверх."""
        raw = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        if self.proto == "tcp":
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.sendall(raw + b"\0")
        else:
            infos = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_DGRAM)
            fam, _, _, _, addr = infos[0]
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                for p in udp_packets(raw):
                    s.sendto(p, addr)

    def submit(self, short, fields, level=6, ts=None):
        """Поставить сообщение в очередь фонового потока. Никогда не бросает исключений."""
        try:
            self._q.put_nowait(message(short, fields, self.source, level, ts))
        except queue.Full:
            self.status["errors"] += 1
            self.status["last_error"] = "очередь переполнена"
            return
        if self._t is None or not self._t.is_alive():
            self._t = threading.Thread(target=self._run, name="zaslon-gelf", daemon=True)
            self._t.start()

    def _run(self):
        while True:
            msg = self._q.get()
            try:
                self.send_now(msg)
                self.status["sent"] += 1
                self.status["last_ok"] = time.time()
            except (OSError, ValueError) as e:
                self.status["errors"] += 1
                self.status["last_error"] = str(e)
                log.warning("GELF %s:%s: %s", self.host, self.port, e)
            finally:
                self._q.task_done()

    def flush(self, timeout=5.0):
        """Дождаться отправки очереди (для тестов и остановки)."""
        end = time.time() + timeout
        while self._q.unfinished_tasks and time.time() < end:
            time.sleep(0.02)


# ---------- что из журнала уходит в Graylog ----------

# syslog-уровни: 4 — warning, 5 — notice, 6 — info
WARN_OPS = {"login_failed", "admin_password", "host_enroll", "host_add", "host_remove", "tx_rollback"}


def level_for(entry):
    op, args = entry.get("op"), entry.get("args") or {}
    if not entry.get("ok", True) or op in WARN_OPS:
        return 4
    if op == "selinux_mode" and str(args.get("mode", "")).lower() in ("permissive", "disabled"):
        return 4
    if op == "firewalld_set" and args.get("running") is False:
        return 4
    return 5 if op not in ("login", "logout") else 6


def fields_for(entry, address=""):
    """Поля zs_* для записи журнала. Аргументы операции раскладываются в zs_arg_<имя>."""
    args = entry.get("args") or {}
    f = {"zs_source": "zaslon", "homelab_app": "zaslon", "zs_op": entry.get("op", ""),
         "zs_who": entry.get("who", ""), "zs_host": entry.get("host", ""), "zs_host_address": address,
         "zs_ok": bool(entry.get("ok", True)), "zs_error": entry.get("error", ""), "zs_tx": entry.get("tx", ""),
         "zs_client_ip": entry.get("ip", ""), "zs_login": entry.get("login", "")}
    for k, v in args.items():
        if k == "id":
            k = "tx_id"
        f["zs_arg_" + k] = v
    return f


# ---------- пульс панели ----------

HB_EVERY = int(os.environ.get("ZASLON_GELF_HEARTBEAT") or 3600)


def heartbeat(sender, hosts_total):
    """Пульс панели: раз в час. По его отсутствию Graylog замечает, что молчит сама панель
    (алерт «Тишина: ZaSlon»)."""
    if not sender:
        return
    sender.submit("ZaSlon: панель на связи (хостов %d)" % hosts_total,
                  {"zs_source": "zaslon", "homelab_app": "zaslon", "zs_event": "heartbeat",
                   "zs_hosts_total": hosts_total}, 6)


def start_heartbeat(sender, stats_fn, every=None):
    """Фоновый пульс панели: первый — через минуту после старта, дальше раз в `every` секунд
    (по умолчанию час). stats_fn() → hosts_total. Без настроенного GELF поток не стартует."""
    if sender is None:
        log.info("GELF не настроен — пульс панели выключен")
        return None
    every = every or HB_EVERY

    def loop():
        time.sleep(60)               # дать панели подняться; первый пульс — через минуту
        while True:
            try:
                heartbeat(sender, stats_fn())
            except Exception as e:   # noqa: BLE001 — пульс не должен умирать из-за одного прохода
                log.warning("heartbeat: проход не удался: %s", e)
            time.sleep(every)

    t = threading.Thread(target=loop, name="zaslon-heartbeat", daemon=True)
    t.start()
    log.info("heartbeat: пульс панели каждые %d с", every)
    return t
