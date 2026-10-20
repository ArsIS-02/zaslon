"""ZaSlon — веб-панель управления firewalld, портами и SELinux на хостах РЕД ОС."""
import asyncio
import hashlib
import os
import ssl
import subprocess
import time
import uuid
from urllib.parse import quote

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import FileResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import auth, remote
from .enroll import Enroll
from .store import Store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")
DATA = os.environ.get("ZASLON_DATA", "/data")
PASSWORD = os.environ.get("ZASLON_PASSWORD", "")
LOGIN = os.environ.get("ZASLON_LOGIN", "admin")
ADMIN_FILE = os.path.join(DATA, "admin.json")
DOWNLOADS = {"zaslon-agent", "setup-host.sh", "zaslon-install.sh"}
store = Store(DATA)
enrolls = Enroll(DATA)
CA_FILE = os.path.join(DATA, "ca", "root.crt")   # корневой сертификат, которым подписан HTTPS панели
INSTALL_SCRIPT = os.path.join(ROOT, "host", "zaslon-install.sh")
ENROLL_PATH = "/api/enroll"
REVOKED = os.path.join(DATA, "sessions_revoked.json")   # отозванные по выходу сессии


def admin_record():
    """Пароль, заданный в интерфейсе (data/admin.json). Если его нет — пароль из .env."""
    return auth.read_record(ADMIN_FILE)


def secret():
    """Секрет для подписи cookie: меняется вместе с паролем, поэтому смена пароля выбрасывает все сессии."""
    rec = admin_record()
    return rec["hash"] if rec else PASSWORD


def check_login(login, password):
    if not secrets_eq(login, LOGIN):
        return False
    rec = admin_record()
    if rec:
        return auth.verify_record(password, rec)
    return bool(PASSWORD) and secrets_eq(password, PASSWORD)


def secrets_eq(a, b):
    import secrets as _s
    return _s.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def ensure_key():
    """Ключ панели создаётся один раз. Ключ без пароля нужен, чтобы панель ходила на хосты сама."""
    path = remote.key_path(DATA)
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "zaslon-panel", "-f", path],
                   check=False)


def j(data, status=200):
    return JSONResponse(data, status_code=status)


def fail(msg, status=400, kind="error"):
    return JSONResponse({"ok": False, "error": msg, "kind": kind}, status_code=status)


async def body(request):
    try:
        d = await request.json()
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


# ---------- вход ----------

async def login_page(request):
    return FileResponse(os.path.join(STATIC, "login.html"), media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store"})


async def index(request):
    return FileResponse(os.path.join(STATIC, "index.html"), media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store"})


async def login(request):
    d = await body(request)
    if not check_login(str(d.get("login", "")), str(d.get("password", ""))):
        await asyncio.sleep(1)
        return fail("Неверный логин или пароль", 401, "auth")
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    resp = j({"ok": True})
    resp.set_cookie(auth.COOKIE, auth.make_session(secret()), max_age=auth.TTL, httponly=True,
                    samesite="strict", secure=secure, path="/")
    return resp


async def logout(request):
    token = request.cookies.get(auth.COOKIE, "")
    if token:
        try:
            os.makedirs(DATA, exist_ok=True)
            auth.revoke(REVOKED, token)
        except OSError:
            pass
    resp = j({"ok": True})
    resp.delete_cookie(auth.COOKIE, path="/", samesite="strict")
    return resp


class Guard(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path
        if path == ENROLL_PATH:
            # скрипт на хосте не имеет cookie: доступ даёт только одноразовый токен в теле запроса
            if request.method != "POST" or request.headers.get("x-zaslon") != "1":
                return fail("Запрос отклонён (защита от CSRF)", 403, "csrf")
            return await call_next(request)
        if path in auth.PUBLIC or path.startswith("/static/") or path.startswith("/dl/"):
            return await call_next(request)
        if not secret():
            host = request.client.host if request.client else ""
            if host not in auth.LOCAL:
                return Response("ZaSlon: пароль не задан — задайте ZASLON_PASSWORD в .env или пароль в интерфейсе.",
                                status_code=403)
        elif not (auth.valid_session(request.cookies.get(auth.COOKIE, ""), secret(), REVOKED)
                  or auth.valid_basic(request.headers.get("authorization", ""), check_login)):
            if request.method == "GET" and not path.startswith("/api/"):
                return RedirectResponse("/login.html?next=" + quote(path), status_code=302)
            return fail("Нужен вход", 401, "auth")
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-zaslon") != "1":
            return fail("Запрос отклонён (защита от CSRF)", 403, "csrf")
        return await call_next(request)


# ---------- хосты ----------

async def list_hosts(request):
    return j({"ok": True, "hosts": store.hosts()})


async def add_host(request):
    d = await body(request)
    address = str(d.get("address", "")).strip()
    user = str(d.get("user") or "sec_fw-admin").strip()
    try:
        port = int(d.get("port") or 22)
    except (TypeError, ValueError):
        port = 0
    problem = remote.valid_host(address, user, port)
    if problem:
        return fail(problem, 400, "validation")
    if any(h["address"] == address for h in store.hosts()):
        return fail("Хост с адресом %s уже добавлен" % address, 409, "duplicate")
    name = (str(d.get("name") or "").strip() or address)[:64]
    host = {"id": uuid.uuid4().hex[:12], "name": name, "address": address, "user": user,
            "port": port, "added": time.strftime("%Y-%m-%d %H:%M:%S")}
    # сначала проверяем связь: неработающий хост в список не попадает (кроме force)
    try:
        status = await run_in_threadpool(remote.call, host, DATA, "status", None, 30)
    except remote.AgentError as e:
        if not d.get("force"):
            return fail(str(e), e.status, e.kind)
        status = None
    store.add(host)
    store.audit({"who": "panel", "host": name, "op": "host_add", "ok": True,
                 "message": "Добавлен хост %s (%s)%s" % (name, address,
                                                         " — без проверки связи" if status is None else "")})
    return j({"ok": True, "host": host, "status": status})


async def enroll_token(request):
    """Токен для команды установки: привязан к имени, адресу и пользователю из формы."""
    d = await body(request)
    address = str(d.get("address", "")).strip()
    user = str(d.get("user") or "sec_fw-admin").strip()
    try:
        port = int(d.get("port") or 22)
    except (TypeError, ValueError):
        port = 0
    problem = remote.valid_host(address, user, port)
    if problem:
        return fail(problem, 400, "validation")
    name = (str(d.get("name") or "").strip() or address)[:64]
    token, exp = enrolls.create(name, address, user, port)
    return j({"ok": True, "token": token, "expires": exp})


async def enroll(request):
    """Вызывается скриптом установки на хосте в конце работы. Проверяет связь и добавляет хост."""
    d = await body(request)
    token = str(d.get("token", ""))
    rec = enrolls.claim(token)
    if not rec:
        return fail("Токен недействителен, истёк или уже использован. Сформируйте команду заново в панели.",
                    403, "auth")
    ok = False
    try:
        if any(h["address"] == rec["address"] for h in store.hosts()):
            return fail("Хост с адресом %s уже добавлен" % rec["address"], 409, "duplicate")
        host = {"id": uuid.uuid4().hex[:12], "name": rec["name"], "address": rec["address"],
                "user": rec["user"], "port": rec["port"], "added": time.strftime("%Y-%m-%d %H:%M:%S")}
        try:
            status = await run_in_threadpool(remote.call, host, DATA, "status", None, 30)
        except remote.AgentError as e:
            return fail(str(e), e.status, e.kind)
        store.add(host)
        ok = True
    finally:
        enrolls.finish(token, ok)
    store.audit({"who": "host", "host": host["name"], "op": "host_enroll", "ok": True,
                 "message": "Хост %s (%s) зарегистрирован автоматически после установки агента"
                 % (host["name"], host["address"])})
    return j({"ok": True, "host": host, "status": status})


async def delete_host(request):
    hid = request.path_params["hid"]
    h = store.get(hid)
    if not h:
        return fail("Хост не найден", 404, "not_found")
    store.remove(hid)
    store.audit({"who": "panel", "host": h["name"], "op": "host_remove", "ok": True,
                 "message": "Удалён хост %s" % h["name"]})
    return j({"ok": True})


def host_or_404(hid):
    h = store.get(hid)
    if not h:
        raise remote.AgentError("Хост не найден", "not_found", 404)
    return h


TITLES = {
    "port_change": "Изменение порта",
    "service_change": "Изменение службы",
    "firewalld_set": "Изменение firewalld",
    "selinux_mode": "Смена режима SELinux",
    "selinux_bool": "Булева опция SELinux",
    "tx_confirm": "Подтверждение изменения",
    "tx_rollback": "Откат изменения",
}

STATUS_TTL = 5
STATUS_CACHE = {}   # hid -> (время, ответ статуса): короткий кэш, сбрасывается при изменениях


def agent_handler(op, mutating):
    """Общий обработчик: вызывает агента, пишет журнал действий."""
    async def handler(request):
        hid = request.path_params["hid"]
        args = await body(request)
        if "tid" in request.path_params:
            args["id"] = request.path_params["tid"]
        try:
            host = host_or_404(hid)
            if op == "status":
                hit = STATUS_CACHE.get(hid)
                if hit and time.time() - hit[0] < STATUS_TTL:
                    return j(hit[1])
            res = await run_in_threadpool(remote.call, host, DATA, op, args)
            if op == "status":
                STATUS_CACHE[hid] = (time.time(), res)
            if mutating:
                STATUS_CACHE.pop(hid, None)
        except remote.AgentError as e:
            if mutating:
                store.audit({"who": "panel", "host": hid, "op": op, "args": args, "ok": False,
                             "message": TITLES.get(op, op), "error": str(e)})
            return fail(str(e), e.status, e.kind)
        if mutating:
            store.audit({"who": "panel", "host": host["name"], "op": op, "args": args, "ok": True,
                         "message": res.get("message") or TITLES.get(op, op), "tx": res.get("tx")})
        return j(res)
    return handler


async def get_key(request):
    try:
        with open(remote.key_path(DATA) + ".pub", encoding="utf-8") as f:
            return j({"ok": True, "key": f.read().strip()})
    except (IOError, OSError):
        return fail("Ключ панели не создан. Перезапустите панель или выполните ssh-keygen в каталоге данных.",
                    500, "error")


async def audit(request):
    return j({"ok": True, "items": store.audit_tail()})


async def admin_info(request):
    rec = admin_record()
    return j({"ok": True, "login": LOGIN, "source": "интерфейс" if rec else ".env"})


async def admin_password(request):
    d = await body(request)
    cur, new = str(d.get("current", "")), str(d.get("new", ""))
    if not check_login(LOGIN, cur):
        return fail("Текущий пароль указан неверно", 403, "auth")
    if len(new) < 8:
        return fail("Новый пароль — не короче 8 символов", 400, "validation")
    if new == cur:
        return fail("Новый пароль должен отличаться от текущего", 400, "validation")
    os.makedirs(DATA, exist_ok=True)
    auth.write_record(ADMIN_FILE, auth.make_record(new))
    store.audit({"who": "admin", "host": "", "op": "admin_password", "ok": True,
                 "message": "Пароль панели изменён"})
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    resp = j({"ok": True})
    # текущая сессия остаётся активной под новым паролем, остальные выходят
    resp.set_cookie(auth.COOKIE, auth.make_session(secret()), max_age=auth.TTL, httponly=True,
                    samesite="strict", secure=secure, path="/")
    return resp


def file_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def ca_fingerprint():
    """SHA-256 от DER корневого сертификата панели; пусто, если сертификат не положен в data/ca/."""
    try:
        with open(CA_FILE, encoding="ascii") as f:
            der = ssl.PEM_cert_to_DER_cert(f.read())
    except (OSError, ValueError):
        return ""
    return hashlib.sha256(der).hexdigest()


async def install_info(request):
    key = ""
    kp = remote.key_path(DATA) + ".pub"
    if os.path.exists(kp):
        with open(kp, encoding="utf-8") as f:
            key = f.read().strip()
    return j({"ok": True, "agent_sha256": file_sha256(os.path.join(ROOT, "host", "zaslon-agent")),
              "install_sha256": file_sha256(INSTALL_SCRIPT), "ca_sha256": ca_fingerprint(), "key": key})


async def download(request):
    name = request.path_params["name"]
    if name == "ca.crt":
        if not os.path.exists(CA_FILE):
            return Response("not found", status_code=404)
        return FileResponse(CA_FILE, media_type="application/x-pem-file",
                            headers={"Cache-Control": "no-store"})
    if name not in DOWNLOADS:
        return Response("not found", status_code=404)
    return FileResponse(os.path.join(ROOT, "host", name), media_type="text/plain; charset=utf-8",
                        headers={"Cache-Control": "no-store"})


async def healthz(request):
    return j({"ok": True})


ROUTES = [
    Route("/", index, methods=["GET"]),
    Route("/login.html", login_page, methods=["GET"]),
    Route("/healthz", healthz, methods=["GET"]),
    Mount("/static", StaticFiles(directory=STATIC), name="static"),
    Route("/api/login", login, methods=["POST"]),
    Route("/api/logout", logout, methods=["POST"]),
    Route("/api/key", get_key, methods=["GET"]),
    Route("/api/admin", admin_info, methods=["GET"]),
    Route("/api/admin/password", admin_password, methods=["POST"]),
    Route("/api/install-info", install_info, methods=["GET"]),
    Route("/api/enroll/token", enroll_token, methods=["POST"]),
    Route("/api/enroll", enroll, methods=["POST"]),
    Route("/dl/{name}", download, methods=["GET"]),
    Route("/api/audit", audit, methods=["GET"]),
    Route("/api/hosts", list_hosts, methods=["GET"]),
    Route("/api/hosts", add_host, methods=["POST"]),
    Route("/api/hosts/{hid}", delete_host, methods=["DELETE"]),
    Route("/api/hosts/{hid}/status", agent_handler("status", False), methods=["GET"]),
    Route("/api/hosts/{hid}/selinux/booleans", agent_handler("selinux_booleans", False), methods=["GET"]),
    Route("/api/hosts/{hid}/port", agent_handler("port_change", True), methods=["POST"]),
    Route("/api/hosts/{hid}/service", agent_handler("service_change", True), methods=["POST"]),
    Route("/api/hosts/{hid}/firewalld", agent_handler("firewalld_set", True), methods=["POST"]),
    Route("/api/hosts/{hid}/selinux/mode", agent_handler("selinux_mode", True), methods=["POST"]),
    Route("/api/hosts/{hid}/selinux/bool", agent_handler("selinux_bool", True), methods=["POST"]),
    Route("/api/hosts/{hid}/tx", agent_handler("tx_list", False), methods=["GET"]),
    Route("/api/hosts/{hid}/tx/{tid}/confirm", agent_handler("tx_confirm", True), methods=["POST"]),
    Route("/api/hosts/{hid}/tx/{tid}/rollback", agent_handler("tx_rollback", True), methods=["POST"]),
]

ensure_key()
app = Starlette(routes=ROUTES, middleware=[Middleware(Guard)])
