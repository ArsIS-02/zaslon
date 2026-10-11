"""ZaSlon — web panel for firewalld / iptables / SELinux on RED OS hosts."""
import asyncio
import base64
import contextlib
import os
import re
import secrets
import time

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import analysis, report, store
from .transport import HostError, reset_hostkey, transport_for

STATIC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
VERSION = "1.0.1"
_host_locks = {}


def lock_for(hid):
    if hid not in _host_locks:
        _host_locks[hid] = asyncio.Lock()
    return _host_locks[hid]


def j(data, status=200):
    return JSONResponse(data, status_code=status)


def err(message, status=400, kind="error", detail=""):
    return JSONResponse({"ok": False, "error": message, "kind": kind, "detail": detail[-2000:] if detail else ""},
                        status_code=status)


async def body(request):
    try:
        return await request.json()
    except Exception:  # noqa
        return {}


def host_or_404(hid):
    h = store.get_host(hid)
    if not h:
        raise HTTPException(404, "Хост не найден")
    return h


def host_view(h):
    st = store.load_state(h["id"])
    return dict(h, summary=analysis.summary(st) if st else None, last_error=(st or {}).get("_last_error"))


# ------------------------------------------------------------------ pages
def _icon(rel, media_type):
    """Значки и манифест по адресам, которые браузеры запрашивают сами (ярлыки, плитки, «На главный экран»)."""
    return FileResponse(os.path.join(STATIC, rel), media_type=media_type, headers={"Cache-Control": "public, max-age=86400"})


async def index(request):
    return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-store"})


async def healthz(request):
    return Response("ok")


# ------------------------------------------------------------------ settings
async def get_settings(request):
    s = store.get_settings()
    key = s["key_path"]
    pub = ""
    if os.path.exists(key + ".pub"):
        with open(key + ".pub") as f:
            pub = f.read().strip()
    return j({"ok": True, "settings": s, "key_present": os.path.exists(key), "public_key": pub, "version": VERSION})


async def put_settings(request):
    d = await body(request)
    return j({"ok": True, "settings": store.save_settings(d)})


# ------------------------------------------------------------------ hosts CRUD
async def list_hosts(request):
    return j({"ok": True, "hosts": [host_view(h) for h in store.list_hosts()], "settings": store.get_settings()})


async def add_host(request):
    d = await body(request)
    try:
        h = store.add_host(d)
    except store.Invalid as ex:
        return err(str(ex))
    store.audit(h, "host-add", {k: h.get(k) for k in ("name", "address", "port")})
    return j({"ok": True, "host": host_view(h)})


async def update_host(request):
    hid = request.path_params["hid"]
    old = host_or_404(hid)
    d = await body(request)
    try:
        h = store.update_host(hid, d)
    except store.Invalid as ex:
        return err(str(ex))
    changed = {k: [old.get(k), h.get(k)] for k in d if old.get(k) != h.get(k)}
    store.audit(h, "host-edit", changed)
    return j({"ok": True, "host": host_view(h)})


async def delete_host(request):
    hid = request.path_params["hid"]
    h = host_or_404(hid)
    store.delete_host(hid)
    store.audit(h, "host-delete", {"address": h["address"]})
    return j({"ok": True})


async def reorder_hosts(request):
    d = await body(request)
    store.reorder(d.get("ids") or [])
    return j({"ok": True})


# ------------------------------------------------------------------ host operations
async def refresh(h):
    t = transport_for(h, store.get_settings())
    try:
        st = await t.collect()
    except HostError as ex:
        old = store.load_state(h["id"]) or {}
        if old:
            old["_last_error"] = {"t": int(time.time()), "error": str(ex), "kind": ex.kind}
            store.save_state(h["id"], old)
        raise
    if not st.get("ok", True):
        raise HostError(st.get("error", "helper вернул ошибку"), "helper")
    st["_collected"] = int(time.time())
    store.save_state(h["id"], st)
    return st


async def host_state(request):
    h = host_or_404(request.path_params["hid"])
    st = store.load_state(h["id"])
    if not st or request.query_params.get("refresh") == "1":
        try:
            async with lock_for(h["id"]):
                st = await refresh(h)
        except HostError as ex:
            if not st:
                return err(str(ex), 502, ex.kind, ex.detail)
            return j(dict(analysis.enrich(st), ok=True, host=h, error=str(ex), error_kind=ex.kind))
    return j(dict(analysis.enrich(st), ok=True, host=h))


async def refresh_all(request):
    hosts = store.list_hosts()

    async def one(h):
        try:
            async with lock_for(h["id"]):
                await refresh(h)
            return {"id": h["id"], "ok": True}
        except HostError as ex:
            return {"id": h["id"], "ok": False, "error": str(ex), "kind": ex.kind}
    res = await asyncio.gather(*(one(h) for h in hosts))
    return j({"ok": True, "results": res, "hosts": [host_view(h) for h in store.list_hosts()]})


async def test_host(request):
    h = host_or_404(request.path_params["hid"])
    t = transport_for(h, store.get_settings())
    t0 = time.time()
    try:
        v = await t.version()
    except HostError as ex:
        return err(str(ex), 502, ex.kind, ex.detail)
    return j({"ok": True, "version": v.get("version"), "ms": int((time.time() - t0) * 1000)})


async def reset_key(request):
    h = host_or_404(request.path_params["hid"])
    ok = await reset_hostkey(h)
    store.audit(h, "hostkey-reset", None, ok)
    return j({"ok": ok})


async def nft_table(request):
    h = host_or_404(request.path_params["hid"])
    fam, name = request.path_params["family"], request.path_params["name"]
    if fam not in ("ip", "ip6", "inet", "arp", "bridge", "netdev") or not re.match(r"^[A-Za-z0-9_.-]{1,64}$", name):
        return err("bad table")
    try:
        return j(await transport_for(h, store.get_settings()).nft_table(fam, name))
    except HostError as ex:
        return err(str(ex), 502, ex.kind, ex.detail)


async def avc(request):
    h = host_or_404(request.path_params["hid"])
    since = request.query_params.get("since", "today")
    try:
        return j(await transport_for(h, store.get_settings()).avc(since))
    except HostError as ex:
        return err(str(ex), 502, ex.kind, ex.detail)


async def history(request):
    h = host_or_404(request.path_params["hid"])
    res = {"ok": True, "local": store.read_audit(h["id"], 200)}
    try:
        res["remote"] = (await transport_for(h, store.get_settings()).history()).get("history", [])
    except HostError as ex:
        res["remote_error"] = str(ex)
    return j(res)


def describe_ops(ops):
    return [{k: v for k, v in o.items() if k not in ("runtime", "permanent") or v is False} for o in ops]


async def apply(request):
    h = host_or_404(request.path_params["hid"])
    d = await body(request)
    ops = d.get("ops") or []
    if not isinstance(ops, list) or not ops:
        return err("Нет изменений")
    s = store.get_settings()
    try:
        rb = max(30, min(600, int(d.get("rollback", s["rollback_seconds"]))))
    except (TypeError, ValueError):
        rb = s["rollback_seconds"]
    auto = bool(d.get("auto_confirm", s["auto_confirm"]))
    req = {"ops": ops, "rollback": rb, "note": str(d.get("note", ""))[:300]}
    t = transport_for(h, s)
    async with lock_for(h["id"]):
        try:
            res = await t.apply(req)
        except HostError as ex:
            store.audit(h, "apply", {"ops": describe_ops(ops), "error": str(ex)}, False)
            return err(str(ex), 502, ex.kind, ex.detail)
        tx = res.get("tx") or {}
        if not res.get("ok"):
            store.audit(h, "apply", {"ops": describe_ops(ops), "error": res.get("error"), "tx": tx.get("id")}, False)
            return j({"ok": False, "error": res.get("error"), "tx": tx}, 200)
        confirm = None
        if tx.get("status") == "pending" and auto:
            # подтверждаем НОВЫМ соединением: если правила закрыли SSH — подтверждение не пройдёт и хост откатится сам
            await asyncio.sleep(1.5)
            try:
                c = await t.confirm(tx["id"], fresh=True)
                confirm = {"ok": c.get("ok"), "status": c.get("status")}
                tx["status"] = c.get("status", tx["status"])
            except HostError as ex:
                confirm = {"ok": False, "error": str(ex)}
        store.audit(h, "apply", {"ops": describe_ops(ops), "tx": tx.get("id"), "status": tx.get("status"),
                                 "results": [r.get("text") for r in tx.get("results", [])], "note": req["note"]})
        try:
            st = await refresh(h)
            view = analysis.enrich(st)
        except HostError:
            view = None
    return j({"ok": True, "tx": tx, "confirm": confirm, "view": view})


async def tx_confirm(request):
    h = host_or_404(request.path_params["hid"])
    txid = request.path_params["txid"]
    t = transport_for(h, store.get_settings())
    try:
        res = await t.confirm(txid, fresh=True)
    except HostError as ex:
        return err(str(ex), 502, ex.kind, ex.detail)
    store.audit(h, "confirm", {"tx": txid, "status": res.get("status")}, bool(res.get("ok")))
    st = store.load_state(h["id"])
    if st and res.get("ok"):
        st["pending"] = [p for p in st.get("pending") or [] if p.get("id") != txid]
        store.save_state(h["id"], st)
        res["view"] = analysis.enrich(st)
    return j(res)


async def tx_rollback(request):
    h = host_or_404(request.path_params["hid"])
    txid = request.path_params["txid"]
    t = transport_for(h, store.get_settings())
    async with lock_for(h["id"]):
        try:
            res = await t.rollback(txid)
        except HostError as ex:
            return err(str(ex), 502, ex.kind, ex.detail)
        store.audit(h, "rollback", {"tx": txid, "status": res.get("status")}, bool(res.get("ok")))
        try:
            st = await refresh(h)
            res["view"] = analysis.enrich(st)
        except HostError:
            pass
    return j(res)


# ------------------------------------------------------------------ reports
async def report_html(request):
    h = host_or_404(request.path_params["hid"])
    st = store.load_state(h["id"])
    if not st:
        return err("Сначала обновите состояние хоста", 404)
    html = report.render(h, analysis.enrich(st), store.read_audit(h["id"], 30))
    fn = report.filename(h, "html")
    disp = "attachment" if request.query_params.get("download") else "inline"
    return HTMLResponse(html, headers={"Content-Disposition": f'{disp}; filename="{fn}"', "Cache-Control": "no-store"})


async def report_pdf(request):
    h = host_or_404(request.path_params["hid"])
    st = store.load_state(h["id"])
    if not st:
        return err("Сначала обновите состояние хоста", 404)
    html = report.render(h, analysis.enrich(st), store.read_audit(h["id"], 30))
    try:
        pdf = await report.to_pdf(html)
    except report.PdfError as ex:
        return err(str(ex), 501, "pdf")
    fn = report.filename(h, "pdf")
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{fn}"'})


async def audit_all(request):
    return j({"ok": True, "audit": store.read_audit(None, 500)})


@contextlib.asynccontextmanager
async def lifespan(app):
    store.init()
    yield


async def http_error(request, exc):
    return err(exc.detail, exc.status_code)


routes = [
    Route("/", index),
    Route("/healthz", healthz),
    Route("/favicon.ico", lambda r: _icon("icons/favicon.ico", "image/x-icon")),
    Route("/apple-touch-icon.png", lambda r: _icon("icons/apple-touch-icon.png", "image/png")),
    Route("/apple-touch-icon-precomposed.png", lambda r: _icon("icons/apple-touch-icon.png", "image/png")),
    Route("/manifest.webmanifest", lambda r: _icon("manifest.webmanifest", "application/manifest+json")),
    Route("/api/settings", get_settings, methods=["GET"]),
    Route("/api/settings", put_settings, methods=["PUT"]),
    Route("/api/hosts", list_hosts, methods=["GET"]),
    Route("/api/hosts", add_host, methods=["POST"]),
    Route("/api/hosts/order", reorder_hosts, methods=["PUT"]),
    Route("/api/hosts/refresh", refresh_all, methods=["POST"]),
    Route("/api/hosts/{hid}", update_host, methods=["PUT"]),
    Route("/api/hosts/{hid}", delete_host, methods=["DELETE"]),
    Route("/api/hosts/{hid}/state", host_state, methods=["GET"]),
    Route("/api/hosts/{hid}/test", test_host, methods=["POST"]),
    Route("/api/hosts/{hid}/hostkey", reset_key, methods=["DELETE"]),
    Route("/api/hosts/{hid}/nft/{family}/{name}", nft_table, methods=["GET"]),
    Route("/api/hosts/{hid}/avc", avc, methods=["GET"]),
    Route("/api/hosts/{hid}/history", history, methods=["GET"]),
    Route("/api/hosts/{hid}/apply", apply, methods=["POST"]),
    Route("/api/hosts/{hid}/tx/{txid}/confirm", tx_confirm, methods=["POST"]),
    Route("/api/hosts/{hid}/tx/{txid}/rollback", tx_rollback, methods=["POST"]),
    Route("/api/hosts/{hid}/report.html", report_html, methods=["GET"]),
    Route("/api/hosts/{hid}/report.pdf", report_pdf, methods=["GET"]),
    Route("/api/audit", audit_all, methods=["GET"]),
    Mount("/static", StaticFiles(directory=STATIC), name="static"),
]

PUBLIC_PATHS = {"/healthz", "/favicon.ico", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png",
                "/manifest.webmanifest"}


class BasicAuth(BaseHTTPMiddleware):
    """Вход в панель. Панель управляет firewall всех хостов, поэтому без пароля (ZASLON_PASSWORD)
    она отвечает только на запросы с этой же машины (127.0.0.1)."""

    async def dispatch(self, request, call_next):
        path = request.url.path
        # проверка работы и значки (браузер и плитки запрашивают их без пароля) — открыты
        if path in PUBLIC_PATHS or path.startswith("/static/icons/"):
            return await call_next(request)
        pw = os.environ.get("ZASLON_PASSWORD", "")
        if not pw:
            host = request.client.host if request.client else ""
            if host in ("127.0.0.1", "::1", "localhost"):
                return await self._csrf(request, call_next)
            return Response("ZaSlon: пароль не задан (ZASLON_PASSWORD в .env) — доступ только с самого хоста.", status_code=403)
        login = os.environ.get("ZASLON_LOGIN", "admin")
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                u, _, p = base64.b64decode(auth[6:]).decode("utf-8").partition(":")
                if secrets.compare_digest(u, login) and secrets.compare_digest(p, pw):
                    return await self._csrf(request, call_next)
            except Exception:  # noqa
                pass
        return Response("Нужен вход", status_code=401, headers={"WWW-Authenticate": 'Basic realm="ZaSlon", charset="UTF-8"'})

    async def _csrf(self, request, call_next):
        # изменяющие запросы — только из самой панели (заголовок ставит fetch в util.js; чужая страница его не подставит)
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-zaslon") != "1":
            return Response("Запрос отклонён (CSRF)", status_code=403)
        return await call_next(request)


app = Starlette(routes=routes, lifespan=lifespan, exception_handlers={HTTPException: http_error},
                middleware=[Middleware(BasicAuth)])
