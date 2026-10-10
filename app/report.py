"""Host report: self-contained HTML (A4, print-ready) and PDF via headless Chromium."""
import asyncio
import base64
import glob
import html
import os
import shutil
import tempfile
import time

from .analysis import external_zones, plural

STATIC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
SEV = {"high": ("Высокая", "#b4443e"), "medium": ("Средняя", "#b07a1c"), "low": ("Низкая", "#3f7aa3"), "info": ("Инфо", "#6b7782")}
STATUS = {"open": ("открыт · слушает", "#2f7d5b"), "stale": ("открыт · никто не слушает", "#b07a1c"),
          "blocked": ("слушает · закрыт firewall", "#6b7782"), "docker": ("Docker в обход зон", "#b4443e"),
          "exposed": ("доступен без firewall", "#b4443e"), "unknown": ("—", "#6b7782")}


class PdfError(Exception):
    pass


def e(x):
    return html.escape("" if x is None else str(x))


def filename(h, ext):
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in h["name"])
    return f"zaslon-{safe}-{time.strftime('%Y%m%d-%H%M')}.{ext}"


def _font(name):
    p = os.path.join(STATIC, "fonts", name)
    try:
        with open(p, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except OSError:
        return ""


def _fonts_css():
    css = []
    for fam, fn, w in (("Inter", "Inter-Regular.woff", 400), ("Inter", "Inter-Medium.woff", 500),
                       ("Inter", "Inter-SemiBold.woff", 600), ("ZMono", "DejaVuSansMono.woff", 400)):
        b = _font(fn)
        if b:
            css.append(f"@font-face{{font-family:{fam};src:url(data:font/woff;base64,{b}) format('woff');font-weight:{w};}}")
    return "\n".join(css)


def ts(t):
    return time.strftime("%d.%m.%Y %H:%M", time.localtime(t)) if t else "—"


def setype(ctx):
    p = (ctx or "").split(":")
    return p[2] if len(p) > 2 else (ctx or "")


def kv(rows):
    return "<table class='kv'>" + "".join(f"<tr><th>{e(k)}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"


def chips(items, cls=""):
    if not items:
        return "<span class='muted'>—</span>"
    return " ".join(f"<span class='chip {cls}'>{e(i)}</span>" for i in items)


CSS = """
@page { size: A4; margin: 14mm 13mm 16mm 13mm; }
* { box-sizing: border-box; }
body { font-family: Inter, 'DejaVu Sans', Arial, sans-serif; color: #1d2329; font-size: 10.5pt; line-height: 1.45; margin: 0;
       -webkit-print-color-adjust: exact; print-color-adjust: exact; background: #fff; }
.page { max-width: 190mm; margin: 0 auto; padding: 8mm 0; }
header.top { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 2px solid #1d2329;
             padding-bottom: 8px; margin-bottom: 14px; }
.brand { display: flex; align-items: center; gap: 10px; }
.brand svg { width: 30px; height: 30px; }
.brand b { font-size: 13pt; letter-spacing: .02em; }
.brand span { display: block; color: #6b7782; font-size: 9pt; }
h1 { font-size: 20pt; margin: 4px 0 2px; font-weight: 600; letter-spacing: -.01em; }
h2 { font-size: 13pt; margin: 22px 0 8px; font-weight: 600; border-bottom: 1px solid #d9dee3; padding-bottom: 4px;
     break-after: avoid; }
h3 { font-size: 10.5pt; margin: 14px 0 6px; font-weight: 600; color: #39434d; break-after: avoid; }
.meta { color: #56616c; font-size: 9.5pt; text-align: right; }
.muted { color: #8a949e; }
.tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 8px 0 4px; }
.tile { border: 1px solid #d9dee3; border-radius: 6px; padding: 8px 10px; break-inside: avoid; }
.tile .l { font-size: 8.5pt; color: #6b7782; text-transform: uppercase; letter-spacing: .04em; }
.tile .v { font-size: 15pt; font-weight: 600; margin-top: 2px; }
.tile .s { font-size: 8.5pt; color: #6b7782; }
.v.bad { color: #b4443e; } .v.warn { color: #b07a1c; } .v.good { color: #2f7d5b; }
table { width: 100%; border-collapse: collapse; font-size: 9pt; margin: 4px 0 8px; }
th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid #e6e9ec; vertical-align: top; }
thead th { background: #f1f3f5; font-weight: 600; color: #39434d; font-size: 8.5pt; text-transform: uppercase; letter-spacing: .03em; }
tr { break-inside: avoid; }
table.kv th { width: 34%; color: #56616c; font-weight: 500; background: none; }
.chip { display: inline-block; border: 1px solid #d0d6dc; border-radius: 4px; padding: 0 5px; margin: 1px 0; font-size: 8.5pt;
        font-family: ZMono, monospace; background: #f7f8f9; }
.sev { display: inline-block; color: #fff; border-radius: 3px; padding: 0 6px; font-size: 8pt; font-weight: 600; white-space: nowrap; }
.st { display: inline-block; border-radius: 3px; padding: 0 5px; font-size: 8pt; white-space: nowrap; border: 1px solid; }
.mono, pre { font-family: ZMono, 'DejaVu Sans Mono', monospace; font-size: 8pt; }
pre { white-space: pre-wrap; word-break: break-all; background: #f7f8f9; border: 1px solid #e6e9ec; border-radius: 4px;
      padding: 6px 8px; margin: 4px 0; }
.two { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.note { background: #f7f8f9; border-left: 3px solid #3f7aa3; padding: 6px 10px; font-size: 9pt; color: #39434d; margin: 6px 0; }
footer { margin-top: 24px; border-top: 1px solid #d9dee3; padding-top: 6px; color: #8a949e; font-size: 8.5pt;
         display: flex; justify-content: space-between; }
@media screen { body { background: #e9ecef; } .page { background: #fff; padding: 14mm 13mm; margin: 16px auto;
                box-shadow: 0 1px 6px rgba(0,0,0,.12); } }
"""

LOGO = ("<svg viewBox='0 0 32 32' aria-hidden='true'><rect x='2' y='2' width='28' height='28' rx='6' fill='#1d2329'/>"
        "<path d='M9 10h14l-14 12h14' fill='none' stroke='#7fb6d3' stroke-width='2.6' stroke-linecap='round' stroke-linejoin='round'/>"
        "<path d='M6 16h3M23 16h3' stroke='#7fb6d3' stroke-width='2' stroke-linecap='round'/></svg>")


def render(h, view, audit):
    st = view["state"]
    s = view["summary"] or {}
    facts = st.get("facts") or {}
    fw = st.get("firewalld") or {}
    se = st.get("selinux") or {}
    f2b = st.get("fail2ban") or {}
    sshd = st.get("sshd") or {}
    ipt = st.get("iptables") or {}
    nft = st.get("nftables") or {}
    out = []
    w = out.append
    w(f"<!doctype html><html lang='ru'><head><meta charset='utf-8'><title>ZaSlon — {e(h['name'])}</title>"
      f"<meta name='viewport' content='width=device-width,initial-scale=1'><style>{_fonts_css()}{CSS}</style></head><body><div class='page'>")
    w(f"<header class='top'><div class='brand'>{LOGO}<div><b>ZaSlon</b><span>отчёт по межсетевому экрану и SELinux</span></div></div>"
      f"<div class='meta'>Сформирован: {ts(time.time())}<br>Данные собраны: {ts(st.get('_collected') or st.get('time'))}"
      f"{'<br><b>демо-данные</b>' if st.get('demo') else ''}</div></header>")
    w(f"<h1>{e(h['name'])}</h1><div class='muted'>{e(h['address'])} · {e(facts.get('os'))} · {e(facts.get('arch'))}"
      f"{' · ' + e(facts.get('model')) if facts.get('model') else ''} · ядро {e(facts.get('kernel'))}</div>")
    if h.get("description") or h.get("role") or h.get("location"):
        w("<div class='note'>" + " · ".join(e(x) for x in (h.get("role"), h.get("location"), h.get("description")) if x) + "</div>")

    # --- tiles
    fd = s.get("findings") or {}
    fwv = {"running": ("работает", "good"), "stopped": ("выключен", "bad"), "absent": ("нет", "bad")}.get(s.get("firewalld"), ("?", ""))
    sev_mode = {"Enforcing": "good", "Permissive": "warn", "Disabled": "bad"}.get(s.get("selinux"), "")
    w("<div class='tiles'>")
    w(f"<div class='tile'><div class='l'>firewalld</div><div class='v {fwv[1]}'>{fwv[0]}</div><div class='s'>зона по умолчанию: {e(s.get('default_zone') or '—')}</div></div>")
    w(f"<div class='tile'><div class='l'>Открыто в зонах</div><div class='v'>{s.get('open_ports', 0)}</div><div class='s'>портов, служб: {s.get('open_services', 0)}</div></div>")
    w(f"<div class='tile'><div class='l'>Слушают в сети</div><div class='v'>{s.get('listening', 0)}</div><div class='s'>без отклика: {s.get('stale', 0)}</div></div>")
    w(f"<div class='tile'><div class='l'>Docker в обход</div><div class='v {'warn' if s.get('docker_published') else ''}'>{s.get('docker_published', 0)}</div><div class='s'>опубликованных портов</div></div>")
    w(f"<div class='tile'><div class='l'>SELinux</div><div class='v {sev_mode}'>{e(s.get('selinux'))}</div><div class='s'>в конфиге: {e(se.get('config_mode') or '—')}</div></div>")
    w(f"<div class='tile'><div class='l'>iptables</div><div class='v'>{s.get('iptables_rules', 0)}</div><div class='s'>{e(ipt.get('version', ''))}</div></div>")
    w(f"<div class='tile'><div class='l'>fail2ban</div><div class='v {'good' if s.get('fail2ban') == 'active' else 'warn'}'>{'работает' if s.get('fail2ban') == 'active' else 'не работает'}</div><div class='s'>в бане: {s.get('banned', 0)}</div></div>")
    w(f"<div class='tile'><div class='l'>Замечания</div><div class='v {'bad' if fd.get('high') else 'warn' if fd.get('medium') else ''}'>{sum(fd.values()) if fd else 0}</div>"
      f"<div class='s'>высоких {fd.get('high', 0)} · средних {fd.get('medium', 0)} · низких {fd.get('low', 0)}</div></div>")
    w("</div>")

    # --- findings
    w("<h2>Замечания</h2>")
    if view["findings"]:
        w("<table><thead><tr><th style='width:11%'>Важность</th><th style='width:12%'>Область</th><th>Что найдено</th></tr></thead><tbody>")
        for f in view["findings"]:
            lbl, col = SEV[f["severity"]]
            w(f"<tr><td><span class='sev' style='background:{col}'>{lbl}</span></td><td>{e(f['area'])}</td>"
              f"<td><b>{e(f['title'])}</b>{'<br><span class=muted>' + e(f['detail']) + '</span>' if f.get('detail') else ''}</td></tr>")
        w("</tbody></table>")
    else:
        w("<p class='muted'>Замечаний нет.</p>")

    # --- firewalld
    w("<h2>firewalld</h2>")
    if fw.get("running"):
        conf = fw.get("conf") or {}
        w(kv([("Версия", e(fw.get("version"))), ("Бэкенд", e(conf.get("FirewallBackend", "nftables"))),
              ("Зона по умолчанию", e(fw.get("default_zone"))), ("Автозапуск", e(fw.get("enabled"))),
              ("Журнал отказов (LogDenied)", e(fw.get("log_denied"))), ("Режим паники", "да" if fw.get("panic") else "нет")]))
        for z in sorted((fw.get("zones") or {}).values(), key=lambda z: (not z.get("default"), not z.get("active"), z["name"])):
            if not (z.get("active") or z.get("default")):
                continue
            ext = z in external_zones(fw)
            w(f"<h3>Зона {e(z['name'])}{' (по умолчанию)' if z.get('default') else ''}{' — смотрит в сеть' if ext else ''}</h3>")
            w(kv([("target", e(z.get("target"))), ("Интерфейсы", chips(z.get("interfaces"))), ("Источники", chips(z.get("sources"))),
                  ("Службы", chips(z.get("services"))), (f"Порты ({len(z.get('ports', []))})", chips(z.get("ports"))),
                  ("Протоколы", chips(z.get("protocols"))), ("Проброс портов", chips(z.get("forward_ports"))),
                  ("Маскарадинг", "да" if z.get("masquerade") else "нет"),
                  ("Rich rules", "<br>".join(f"<span class='mono'>{e(r)}</span>" for r in z.get("rich_rules", [])) or "<span class='muted'>—</span>")]))
        pol = fw.get("policies") or {}
        if pol:
            w("<h3>Политики</h3><table><thead><tr><th>Политика</th><th>Приоритет</th><th>target</th><th>Откуда → куда</th><th>Службы / порты</th></tr></thead><tbody>")
            for p in pol.values():
                w(f"<tr><td>{e(p['name'])}{' <span class=muted>(активна)</span>' if p.get('active') else ''}</td><td>{e(p.get('priority'))}</td>"
                  f"<td>{e(p.get('target'))}</td><td>{e(' '.join(p.get('ingress_zones', [])))} → {e(' '.join(p.get('egress_zones', [])))}</td>"
                  f"<td>{chips(p.get('services', []) + p.get('ports', []))}</td></tr>")
            w("</tbody></table>")
        dr = fw.get("drift") or []
        if dr:
            w("<h3>Расхождения текущих и сохранённых правил</h3><table><thead><tr><th>Зона</th><th>Что</th><th>Значение</th><th>Где есть</th></tr></thead><tbody>")
            for d in dr:
                w(f"<tr><td>{e(d['zone'])}</td><td>{e(d['kind'])}</td><td class='mono'>{e(d['value'])}</td><td>{'только сейчас (runtime)' if d['where'] == 'runtime-only' else 'только сохранено (permanent)' if d['where'] == 'permanent-only' else e(d['where'])}</td></tr>")
            w("</tbody></table>")
        if fw.get("direct_rules") or fw.get("direct_rules_permanent"):
            w("<h3>Прямые правила (direct)</h3><pre>" + e("\n".join(fw.get("direct_rules_permanent") or fw.get("direct_rules"))) + "</pre>")
    else:
        w("<p><b>firewalld не работает.</b> Входящий трафик не фильтруется (кроме правил Docker).</p>")

    # --- ports
    w("<h2>Сетевые порты: firewall и реальные службы</h2>")
    rows = [r for r in view["ports"] if not r.get("ephemeral")]
    w("<table><thead><tr><th style='width:11%'>Порт</th><th style='width:15%'>Назначение</th><th style='width:22%'>Разрешён в firewall</th>"
      "<th>Слушает</th><th style='width:18%'>Docker</th><th style='width:16%'>Итог</th></tr></thead><tbody>")
    for r in rows:
        lbl, col = STATUS.get(r["status"], ("?", "#888"))
        allowed = ", ".join(sorted({f"{a['zone']}: {a['item']}" for a in r["allowed"]}))
        w(f"<tr><td class='mono'>{r['port']}/{r['proto']}</td><td>{e(r.get('hint'))}</td><td>{e(allowed) or '<span class=muted>—</span>'}</td>"
          f"<td>{e(', '.join(r.get('processes', []))) or '<span class=muted>—</span>'}</td>"
          f"<td class='mono'>{e(', '.join(d['to'] for d in r['docker'])) or '<span class=muted>—</span>'}</td>"
          f"<td><span class='st' style='color:{col};border-color:{col}'>{lbl}</span></td></tr>")
    w("</tbody></table>")
    eph = [r for r in view["ports"] if r.get("ephemeral")]
    if eph:
        w(f"<p class='muted'>Не показано {len(eph)} {plural(len(eph), 'временный UDP-порт', 'временных UDP-порта', 'временных UDP-портов')} (≥32768), закрытых firewall.</p>")

    # --- iptables / nftables
    w("<h2>iptables и nftables</h2>")
    w(kv([("iptables", e(ipt.get("version"))), ("Сервис iptables", e(ipt.get("service"))),
          ("Правил в legacy-таблицах", e(ipt.get("legacy_rules"))), ("nftables", e(nft.get("version"))),
          ("Сервис nftables", e(nft.get("service")))]))
    for fam in ("ipv4", "ipv6"):
        tabs = (ipt.get(fam) or {}).get("tables") or {}
        if not tabs:
            continue
        w(f"<h3>iptables {fam}</h3><table><thead><tr><th>Таблица</th><th>Цепочки (политика)</th><th>Правил</th><th>Из них Docker</th></tr></thead><tbody>")
        for tn, t in tabs.items():
            ch = ", ".join(f"{c} ({i['policy']})" for c, i in t["chains"].items())
            dock = len([r for r in t["rules"] if r["chain"].startswith("DOCKER") or "docker" in r["rule"] or "br-" in r["rule"]])
            w(f"<tr><td>{e(tn)}</td><td class='mono'>{e(ch)}</td><td>{len(t['rules'])}</td><td>{dock}</td></tr>")
        w("</tbody></table>")
    if nft.get("tables"):
        w("<h3>Таблицы nftables</h3><table><thead><tr><th>Семейство</th><th>Таблица</th><th>Правил</th><th>Кем создана</th></tr></thead><tbody>")
        for t in nft["tables"]:
            w(f"<tr><td>{e(t['family'])}</td><td>{e(t['name'])}</td><td>{e(t.get('rules'))}</td><td>{e(t.get('managed_by') or '—')}</td></tr>")
        w("</tbody></table>")

    # --- SELinux
    w("<h2>SELinux</h2>")
    if se.get("tools") is False:
        w("<p class='muted'>Утилиты SELinux не установлены.</p>")
    else:
        w(kv([("Текущий режим", e(se.get("mode"))), ("Режим в конфиге", e(se.get("config_mode"))), ("Политика", e(se.get("policy"))),
              ("semanage", "есть" if se.get("semanage") else "нет")]))
        if se.get("mode") != "Disabled":
            loc = set(se.get("booleans_local") or [])
            bl = [b for b in se.get("booleans") or [] if b["name"] in loc or (b.get("default") is not None and b["state"] != b["default"])]
            w("<div class='two'><div>")
            w("<h3>Изменённые переключатели (booleans)</h3>")
            if bl:
                w("<table><thead><tr><th>Переключатель</th><th>Сейчас</th><th>По умолчанию</th></tr></thead><tbody>")
                for b in bl:
                    w(f"<tr><td class='mono'>{e(b['name'])}</td><td>{'вкл' if b['state'] else 'выкл'}</td><td>{'—' if b.get('default') is None else 'вкл' if b['default'] else 'выкл'}</td></tr>")
                w("</tbody></table>")
            else:
                w("<p class='muted'>Нет изменений относительно политики.</p>")
            w("</div><div><h3>Локальные метки портов</h3>")
            pl = se.get("ports_local") or []
            if pl:
                w("<table><thead><tr><th>Тип</th><th>Протокол</th><th>Порты</th></tr></thead><tbody>")
                for p in pl:
                    w(f"<tr><td class='mono'>{e(p['type'])}</td><td>{e(p['proto'])}</td><td class='mono'>{e(', '.join(p['ports']))}</td></tr>")
                w("</tbody></table>")
            else:
                w("<p class='muted'>Нет.</p>")
            w("</div></div>")
            if se.get("fcontext_local"):
                w("<h3>Локальные контексты файлов</h3><pre>" + e("\n".join(se["fcontext_local"][:40])) + "</pre>")
            if se.get("permissive_domains"):
                w("<h3>Домены в permissive</h3><p>" + chips(se["permissive_domains"]) + "</p>")
            avc = se.get("avc_today") or []
            w(f"<h3>Отказы (AVC) за сегодня: {len(avc)}</h3>")
            if avc:
                w("<table><thead><tr><th>Время</th><th>Процесс</th><th>Действие</th><th>Объект</th><th>Контекст</th></tr></thead><tbody>")
                for a in avc[-25:]:
                    w(f"<tr><td>{e(a.get('time'))}</td><td>{e(a.get('comm'))}</td><td>{e(' '.join(a.get('perms', [])))}</td>"
                      f"<td>{e(a.get('tclass'))} {e(a.get('name') or a.get('path') or a.get('dest') or '')}</td>"
                      f"<td class='mono'>{e(setype(a.get('scontext')))} → {e(setype(a.get('tcontext')))}</td></tr>")
                w("</tbody></table>")

    # --- fail2ban & ssh
    w("<div class='two'><div><h2>fail2ban</h2>")
    if f2b.get("active"):
        w("<table><thead><tr><th>Jail</th><th>В бане</th><th>Исключения</th></tr></thead><tbody>")
        for jl in f2b.get("jails") or []:
            w(f"<tr><td>{e(jl['name'])}</td><td class='mono'>{e(', '.join(jl.get('banned', []))) or '—'}</td><td class='mono'>{e(' '.join(jl.get('ignoreip', [])))}</td></tr>")
        w("</tbody></table>")
    else:
        w("<p class='muted'>fail2ban не работает.</p>")
    w("</div><div><h2>SSH</h2>")
    w(kv([(k, e(" ".join(v) if isinstance(v, list) else v)) for k, v in sshd.items()]) if sshd else "<p class='muted'>Нет данных.</p>")
    w("</div></div>")

    # --- audit
    w("<h2>Изменения через ZaSlon</h2>")
    acts = [a for a in audit if a.get("action") in ("apply", "rollback", "confirm")]
    if acts:
        w("<table><thead><tr><th style='width:16%'>Когда</th><th style='width:12%'>Действие</th><th>Подробности</th></tr></thead><tbody>")
        for a in acts[:30]:
            d = a.get("detail") or {}
            txt = "; ".join(d.get("results") or []) or e(d.get("error") or d.get("status") or "")
            w(f"<tr><td>{ts(a['t'])}</td><td>{e(a['action'])}{'' if a.get('ok') else ' ✗'}</td><td>{e(txt)}</td></tr>")
        w("</tbody></table>")
    else:
        w("<p class='muted'>Изменений через панель не было.</p>")
    if st.get("errors"):
        w("<p class='muted'>Не удалось собрать: " + e("; ".join(st["errors"])) + "</p>")
    w(f"<footer><span>ZaSlon · {e(h['name'])} ({e(h['address'])})</span><span>{ts(time.time())}</span></footer>")
    w("</div></body></html>")
    return "".join(out)


def find_chromium():
    for c in (os.environ.get("ZASLON_CHROMIUM"), "chromium", "chromium-browser", "google-chrome", "headless_shell"):
        if c and shutil.which(c):
            return shutil.which(c)
    for p in sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome")) + sorted(glob.glob("/opt/pw-browsers/chromium_headless_shell-*/*/headless_shell")):
        if os.access(p, os.X_OK):
            return p
    return None


async def to_pdf(doc):
    exe = find_chromium()
    if not exe:
        raise PdfError("В контейнере нет Chromium для PDF. Откройте HTML-отчёт и сохраните его в PDF через печать браузера.")
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "report.html")
        dst = os.path.join(d, "report.pdf")
        with open(src, "w", encoding="utf-8") as f:
            f.write(doc)
        args = [exe, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run",
                "--disable-extensions", "--hide-scrollbars", "--no-pdf-header-footer", "--run-all-compositor-stages-before-draw",
                f"--user-data-dir={os.path.join(d, 'profile')}", f"--print-to-pdf={dst}", "file://" + src]
        env = dict(os.environ, HOME=d)
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.DEVNULL,
                                                    stderr=asyncio.subprocess.PIPE, env=env)
        try:
            _, er = await asyncio.wait_for(proc.communicate(), 120)
        except asyncio.TimeoutError:
            proc.kill()
            raise PdfError("Chromium не успел сформировать PDF")
        if not os.path.exists(dst):
            raise PdfError("Chromium не создал PDF: " + er.decode("utf-8", "replace")[-400:])
        with open(dst, "rb") as f:
            return f.read()
