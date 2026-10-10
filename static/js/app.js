import { h, svg, ICON, api, toast, modal, confirmDlg, plural, ago, dt, field, busy } from "./util.js";
import { describe, risky, riskText, touchesSSH, key, inverseKey } from "./ops.js";
import { renderHost } from "./host.js";

// ------------------------------------------------------------------ state
export const S = {
  hosts: [],
  settings: {},
  views: {},        // host id -> enriched state from /state
  loading: {},      // host id -> bool
  errors: {},       // host id -> {error, kind, detail}
  queue: {},        // host id -> [ops]
  pending: {},      // host id -> [{id, deadline, note}]
  sub: {},          // host id -> current subview
  ui: {},           // per-view ui state (filters etc.)
};
const main = document.getElementById("main");

// ------------------------------------------------------------------ boot
async function loadHosts() {
  const d = await api("/api/hosts");
  S.hosts = d.hosts;
  S.settings = d.settings;
  document.getElementById("demo-badge").hidden = !S.settings.demo && !S.hosts.some((x) => x.demo);
  for (const x of S.hosts) {
    if (x.summary && x.summary.pending) S.pending[x.id] = S.pending[x.id] || [];
  }
}

export function host(id) { return S.hosts.find((x) => x.id === id); }

function route() {
  const m = location.hash.match(/^#\/h\/([^/]+)(?:\/([\w-]+))?/);
  return m ? { host: m[1], sub: m[2] || null } : { host: null };
}

export function go(hid, sub) {
  location.hash = hid ? `#/h/${hid}/${sub || S.sub[hid] || "summary"}` : "#/";
}

export function render() {
  renderTabs();
  const r = route();
  main.innerHTML = "";
  if (r.host && host(r.host)) {
    if (r.sub) S.sub[r.host] = r.sub;
    renderHost(main, r.host, S.sub[r.host] || "summary");
  } else {
    renderOverview(main);
  }
  renderQueueBar();
  renderPendingBar();
}
window.addEventListener("hashchange", render);

// ------------------------------------------------------------------ tabs
function statusOf(x) {
  if (S.loading[x.id]) return "busy";
  const s = x.summary;
  if (!s) return "";
  if (S.errors[x.id] || x.last_error) return "bad";
  if (s.firewalld !== "running" || s.findings.high) return "bad";
  if (s.findings.medium) return "warn";
  return "ok";
}

function renderTabs() {
  const tabs = document.getElementById("tabs");
  const r = route();
  tabs.innerHTML = "";
  tabs.appendChild(h("button", { class: "tab" + (!r.host ? " active" : ""), onclick: () => go(null) },
    svg('<path d="M4 5h7v7H4zM13 5h7v4h-7zM13 11h7v8h-7zM4 14h7v5H4z"/>'), "Обзор"));
  for (const x of S.hosts) {
    const s = x.summary;
    const f = s ? s.findings : null;
    const n = f ? f.high + f.medium : 0;
    tabs.appendChild(h("button", { class: "tab" + (r.host === x.id ? " active" : ""), title: x.address, onclick: () => go(x.id) },
      h("span", { class: "dot " + statusOf(x) }), x.name,
      n ? h("span", { class: "cnt " + (f.high ? "high" : "medium") }, n) : null,
      (S.queue[x.id] || []).length ? h("span", { class: "cnt", title: "подготовлено изменений" }, "✎" + S.queue[x.id].length) : null));
  }
  tabs.appendChild(h("button", { class: "tab add", title: "Добавить хост", onclick: () => hostDialog() }, svg(ICON.plus), "Хост"));
}

// ------------------------------------------------------------------ overview
const PCOL = { open: "var(--ok)", stale: "var(--warn)", docker: "var(--dock)", blocked: "var(--info)", exposed: "var(--bad)" };

function renderOverview(root) {
  const head = h("div", { class: "page-head" },
    h("div", null, h("h1", null, "Обзор хостов"),
      h("div", { class: "sub" }, `${S.hosts.length} ${plural(S.hosts.length, "хост", "хоста", "хостов")} · межсетевой экран, SELinux и сетевые службы`)),
    h("div", { class: "actions" },
      h("button", { class: "btn", onclick: () => hostDialog() }, svg(ICON.plus), "Добавить хост"),
      h("button", { class: "btn primary", onclick: (e) => refreshAll(e.currentTarget) }, svg(ICON.refresh), "Опросить все")));
  root.appendChild(head);
  if (!S.hosts.length) {
    root.appendChild(h("div", { class: "card" }, h("div", { class: "empty" }, h("h3", null, "Хостов пока нет"),
      h("p", null, "Добавьте хост РЕД ОС, подготовленный скриптом zaslon-provision.sh."),
      h("button", { class: "btn primary", onclick: () => hostDialog() }, svg(ICON.plus), "Добавить хост"))));
    return;
  }
  // aggregate tiles
  const sums = S.hosts.map((x) => x.summary).filter(Boolean);
  const tot = (k) => sums.reduce((a, s) => a + (s[k] || 0), 0);
  const fwOff = sums.filter((s) => s.firewalld !== "running").length;
  const seOff = sums.filter((s) => s.selinux !== "Enforcing").length;
  const hi = sums.reduce((a, s) => a + s.findings.high, 0), me = sums.reduce((a, s) => a + s.findings.medium, 0);
  root.appendChild(h("div", { class: "tiles" },
    tile("Хостов опрошено", `${sums.length}/${S.hosts.length}`, sums.length ? "последний: " + ago(Math.max(...sums.map((s) => s.time || 0))) : "нажмите «Опросить все»"),
    tile("firewalld выключен", fwOff, fwOff ? "хосты без фильтрации" : "везде работает", fwOff ? "bad" : "ok"),
    tile("SELinux не Enforcing", seOff, "Disabled или Permissive", seOff ? "warn" : "ok"),
    tile("Открыто в зонах", tot("open_ports"), `портов; служб: ${tot("open_services")}`),
    tile("Без отклика", tot("stale"), "открыто, но никто не слушает", tot("stale") ? "warn" : ""),
    tile("Docker в обход", tot("docker_published"), "опубликованных портов", tot("docker_published") ? "warn" : ""),
    tile("Замечания", hi + me, `высоких ${hi} · средних ${me}`, hi ? "bad" : me ? "warn" : "ok")));

  const grid = h("div", { class: "hosts-grid" });
  for (const x of S.hosts) grid.appendChild(hostCard(x));
  root.appendChild(grid);

  // comparison table
  if (sums.length) {
    const rows = S.hosts.map((x) => {
      const s = x.summary;
      if (!s) return h("tr", null, h("td", null, x.name), h("td", { colspan: 9, class: "dim" }, "не опрошен"));
      return h("tr", { style: { cursor: "pointer" }, onclick: () => go(x.id) },
        h("td", null, h("b", null, x.name), h("div", { class: "dim mono" }, x.address)),
        h("td", null, osName(s.os), h("div", { class: "dim small" }, s.model || s.arch)),
        h("td", null, s.firewalld === "running" ? h("span", { class: "tag ok" }, "работает") : h("span", { class: "tag bad" }, "выключен")),
        h("td", null, s.default_zone || "—"),
        h("td", { class: "num" }, s.open_ports), h("td", { class: "num" }, s.listening), h("td", { class: "num" }, s.stale || "—"),
        h("td", { class: "num" }, s.docker_published || "—"),
        h("td", null, h("span", { class: "tag " + (s.selinux === "Enforcing" ? "ok" : s.selinux === "Permissive" ? "warn" : "bad") }, s.selinux)),
        h("td", null, findingBar(s.findings)));
    });
    root.appendChild(h("div", { class: "section-title" }, "Сравнение"));
    root.appendChild(h("div", { class: "card" }, h("div", { class: "bd flush tbl-wrap" },
      h("table", { class: "tbl" }, h("thead", null, h("tr", null, ["Хост", "Система", "firewalld", "Зона", "Открыто", "Слушает", "Без отклика", "Docker", "SELinux", "Замечания"].map((t, i) => h("th", { class: i >= 4 && i <= 7 ? "num" : "" }, t)))),
        h("tbody", null, rows)))));
  }
}

export function osName(os) {
  return (os || "").replace("RED OS release", "РЕД ОС").replace(/\s*\(([\d.]+)\)/, " $1");
}

export function tile(label, value, sub, cls = "") {
  return h("div", { class: "tile" }, h("div", { class: "l" }, label), h("div", { class: "v " + cls }, value), sub ? h("div", { class: "s" }, sub) : null);
}

function findingBar(f) {
  const parts = [["high", "var(--bad)"], ["medium", "var(--warn)"], ["low", "var(--accent)"], ["info", "var(--info)"]];
  const tot = parts.reduce((a, [k]) => a + (f[k] || 0), 0) || 1;
  return h("div", { style: { minWidth: "120px" } },
    h("div", { class: "bar" }, parts.map(([k, c]) => f[k] ? h("i", { style: { width: (100 * f[k] / tot) + "%", background: c }, title: `${k}: ${f[k]}` }) : null)),
    h("div", { class: "dim small", style: { marginTop: "3px" } },
      [["high", "высок."], ["medium", "средн."], ["low", "низк."], ["info", "инфо"]].filter(([k]) => f[k]).map(([k, l]) => `${f[k]} ${l}`).join(" · ") || "замечаний нет"));
}

function hostCard(x) {
  const s = x.summary;
  const st = statusOf(x);
  const card = h("div", { class: "hcard", onclick: () => go(x.id) },
    h("div", { class: "top" }, h("span", { class: "dot " + st }), h("span", { class: "nm" }, x.name), h("span", { class: "addr" }, x.address)));
  if (!s) {
    card.appendChild(h("div", { class: "os" }, x.role || x.description || "состояние ещё не собиралось"));
    card.appendChild(h("button", { class: "btn sm", onclick: (e) => { e.stopPropagation(); refreshHost(x.id, e.currentTarget); } }, svg(ICON.refresh), "Опросить"));
    if (x.last_error || S.errors[x.id]) card.appendChild(h("div", { class: "err" }, (S.errors[x.id] || x.last_error).error));
    return card;
  }
  card.appendChild(h("div", { class: "os" }, [osName(s.os), s.model || s.arch].filter(Boolean).join(" · ")));
  card.appendChild(h("div", { class: "row" },
    s.firewalld === "running" ? h("span", { class: "tag ok" }, "firewalld") : h("span", { class: "tag bad" }, "firewalld выкл"),
    h("span", { class: "tag " + (s.selinux === "Enforcing" ? "ok" : s.selinux === "Permissive" ? "warn" : "bad") }, "SELinux " + s.selinux),
    h("span", { class: "tag " + (s.fail2ban === "active" ? "ok" : "warn") }, s.fail2ban === "active" ? "fail2ban" : "fail2ban выкл"),
    s.pending ? h("span", { class: "tag warn" }, "ждёт подтверждения") : null,
    x.tags && x.tags.length ? x.tags.map((t) => h("span", { class: "tag" }, t)) : null));
  card.appendChild(h("div", { class: "nums" },
    h("div", null, h("b", null, s.open_ports), h("span", null, "открыто")),
    h("div", null, h("b", null, s.listening), h("span", null, "слушает")),
    h("div", null, h("b", { style: { color: s.stale ? "var(--warn)" : "" } }, s.stale), h("span", null, "не слушают")),
    h("div", null, h("b", { style: { color: s.docker_published ? "var(--dock)" : "" } }, s.docker_published), h("span", null, "Docker"))));
  card.appendChild(findingBar(s.findings));
  card.appendChild(h("div", { class: "legend" }, h("span", null, "обновлено " + ago(s.time)), x.last_error ? h("span", { style: { color: "var(--bad)" } }, "ошибка последнего опроса") : null));
  return card;
}

// ------------------------------------------------------------------ refresh
export async function refreshHost(hid, btn) {
  S.loading[hid] = true;
  delete S.errors[hid];
  renderTabs();
  if (btn) busy(btn);
  try {
    const v = await api(`/api/hosts/${hid}/state?refresh=1`);
    S.views[hid] = v;
    if (v.error) { S.errors[hid] = { error: v.error, kind: v.error_kind }; toast(`${host(hid).name}: ${v.error}`, "err"); }
    S.pending[hid] = (v.state && v.state.pending) || [];
    await loadHosts();
  } catch (e) {
    S.errors[hid] = { error: e.message, kind: e.kind, detail: e.detail };
    toast(`${host(hid) ? host(hid).name : hid}: ${e.message}`, "err");
  } finally {
    S.loading[hid] = false;
    if (btn) busy(btn, false);
    render();
  }
}

async function refreshAll(btn) {
  busy(btn);
  S.hosts.forEach((x) => { S.loading[x.id] = true; });
  renderTabs();
  try {
    const d = await api("/api/hosts/refresh", { method: "POST" });
    const bad = d.results.filter((r) => !r.ok);
    for (const r of d.results) { if (!r.ok) S.errors[r.id] = { error: r.error, kind: r.kind }; else delete S.errors[r.id]; delete S.views[r.id]; }
    S.hosts = d.hosts;
    toast(bad.length ? `Опрошено ${d.results.length - bad.length} из ${d.results.length}. Ошибки: ${bad.map((r) => host(r.id).name).join(", ")}` :
      `Опрошены все хосты (${d.results.length})`, bad.length ? "err" : "ok");
  } catch (e) { toast(e.message, "err"); }
  S.hosts.forEach((x) => { S.loading[x.id] = false; });
  busy(btn, false);
  render();
}
document.getElementById("btn-refresh-all").onclick = (e) => refreshAll(e.currentTarget);

export async function getView(hid, force = false) {
  if (S.views[hid] && !force) return S.views[hid];
  S.loading[hid] = true;
  try {
    const v = await api(`/api/hosts/${hid}/state${force ? "?refresh=1" : ""}`);
    S.views[hid] = v;
    S.pending[hid] = (v.state && v.state.pending) || [];
    if (v.error) S.errors[hid] = { error: v.error, kind: v.error_kind }; else delete S.errors[hid];
    return v;
  } finally {
    S.loading[hid] = false;
  }
}

// ------------------------------------------------------------------ change queue
export function queued(hid) { return S.queue[hid] || []; }

export function enqueue(hid, ...ops) {
  const q = S.queue[hid] = S.queue[hid] || [];
  for (const o of ops) {
    const k = key(o), ik = inverseKey(o);
    const inv = ik ? q.findIndex((x) => key(x) === ik) : -1;
    if (inv >= 0) { q.splice(inv, 1); continue; }           // добавили и тут же убрали — взаимно сокращаются
    if (!q.some((x) => key(x) === k)) q.push(o);
  }
  render();
}

export function dequeue(hid, idx) {
  (S.queue[hid] || []).splice(idx, 1);
  render();
}

export function isQueued(hid, pred) {
  return queued(hid).some(pred);
}

function renderQueueBar() {
  const bar = document.getElementById("queue-bar");
  const r = route();
  const q = r.host ? queued(r.host) : [];
  bar.innerHTML = "";
  if (!q.length) { bar.hidden = true; return; }
  bar.hidden = false;
  bar.append(
    svg(ICON.queue),
    h("span", null, "Подготовлено изменений: "), h("span", { class: "n" }, q.length),
    h("button", { class: "btn ghost sm", onclick: () => reviewDialog(r.host) }, "Просмотреть"),
    h("button", { class: "btn ghost sm", onclick: () => { S.queue[r.host] = []; render(); } }, "Очистить"),
    h("button", { class: "btn primary", onclick: () => reviewDialog(r.host) }, svg(ICON.play), "Применить…"));
}

function reviewDialog(hid) {
  const x = host(hid);
  const q = queued(hid);
  const rb = h("input", { type: "number", min: 30, max: 600, value: S.settings.rollback_seconds || 60, style: { width: "80px" } });
  const auto = h("input", { type: "checkbox", checked: S.settings.auto_confirm !== false });
  const note = h("input", { type: "text", placeholder: "необязательно: зачем это изменение", style: { width: "100%" } });
  const anyRisk = q.some(risky), ssh = q.some(touchesSSH);
  const list = h("ol", { class: "oplist" }, q.map((o, i) => h("li", null, h("span", { class: "num" }, i + 1),
    h("span", { class: "txt" }, describe(o), riskText(o) ? h("span", { class: "tag warn", style: { marginLeft: "6px" } }, riskText(o)) : null),
    h("button", { class: "btn ghost icon sm", title: "Убрать из списка", onclick: () => { dequeue(hid, i); m.close(); if (queued(hid).length) reviewDialog(hid); } }, svg(ICON.x)))));
  const m = modal({
    title: `Применить на ${x.name}`, wide: true,
    body: h("div", null,
      list,
      ssh ? h("div", { class: "note warn" }, "Изменения затрагивают доступ по SSH. Helper на хосте проверит, что панель сохраняет доступ, и откажется применять, если SSH закроется.") : null,
      h("div", { class: "note" }, "Все изменения применяются одной транзакцией. Если подтверждение не придёт за указанное время, хост сам вернёт всё как было — так невозможно потерять доступ к хосту."),
      h("div", { class: "form-row mt" },
        field("Таймер отката, с", rb),
        h("label", { class: "chk", style: { paddingBottom: "6px" } }, auto, "Подтвердить автоматически, если панель после изменения снова подключается"),
      ),
      h("div", { class: "mt" }, field("Комментарий", note))),
    foot: (close) => [
      h("button", { class: "btn ghost", onclick: close }, "Отмена"),
      h("button", { class: "btn " + (anyRisk ? "danger" : "primary"), onclick: async (e) => {
        busy(e.currentTarget);
        await applyQueue(hid, { rollback: +rb.value, auto_confirm: auto.checked, note: note.value });
        close();
      } }, svg(ICON.play), `Применить (${q.length})`),
    ],
  });
}

export async function applyNow(hid, ops, note = "") {
  enqueue(hid, ...ops);
  reviewDialog(hid);
}

async function applyQueue(hid, opts) {
  const ops = queued(hid).slice();
  try {
    const d = await api(`/api/hosts/${hid}/apply`, { method: "POST", body: { ops, ...opts }, allowFail: true });
    if (!d.ok) {
      resultDialog(hid, d, false);
      return;
    }
    S.queue[hid] = [];
    if (d.view) S.views[hid] = d.view;
    const tx = d.tx || {};
    if (tx.status === "pending") {
      S.pending[hid] = [{ id: tx.id, deadline: tx.deadline, note: tx.note }];
    } else {
      S.pending[hid] = (d.view && d.view.state && d.view.state.pending) || [];
    }
    await loadHosts();
    resultDialog(hid, d, true);
  } catch (e) {
    toast(e.message, "err");
  }
  render();
}

function resultDialog(hid, d, ok) {
  const tx = d.tx || {};
  const res = tx.results || [];
  const status = { confirmed: ["Применено и подтверждено", "ok"], pending: ["Применено — ждёт подтверждения", "warn"],
    failed: ["Не применено — всё возвращено", "bad"], rolled_back: ["Откачено", "warn"] }[tx.status] || [ok ? "Готово" : "Ошибка", ok ? "ok" : "bad"];
  modal({
    title: status[0], wide: true,
    body: h("div", null,
      d.error ? h("div", { class: "note bad" }, d.error) : null,
      d.confirm && !d.confirm.ok ? h("div", { class: "note warn" }, "Автоподтверждение не прошло: ", d.confirm.error || d.confirm.status, ". Если панель потеряла доступ, хост откатит изменения сам по таймеру.") : null,
      tx.guard && tx.guard.reason ? h("div", { class: "note " + (tx.guard.ssh_allowed ? "ok" : "bad") }, "Доступ панели по SSH: ", tx.guard.reason) : null,
      res.length ? h("ol", { class: "oplist" }, res.map((r, i) => h("li", null, h("span", { class: "num" }, r.ok ? "✓" : "✗"), h("span", { class: "txt" + (r.ok ? "" : " muted") }, r.text)))) : null,
      tx.undo && tx.undo.length ? h("details", { class: "mt" }, h("summary", null, "Что было возвращено"), h("ol", { class: "oplist" }, tx.undo.map((r) => h("li", null, h("span", { class: "txt" }, r.text))))) : null,
      tx.id ? h("div", { class: "dim small mt" }, "Транзакция ", h("span", { class: "mono" }, tx.id)) : null),
    foot: (close) => h("button", { class: "btn primary", onclick: close }, "Закрыть"),
  });
}

// ------------------------------------------------------------------ pending transactions
let pendTimer = null;
function renderPendingBar() {
  const bar = document.getElementById("pending-bar");
  const items = [];
  for (const [hid, list] of Object.entries(S.pending)) for (const p of list || []) if (p.deadline && p.deadline * 1000 > Date.now() - 5000) items.push([hid, p]);
  bar.innerHTML = "";
  clearInterval(pendTimer);
  if (!items.length) { bar.hidden = true; return; }
  bar.hidden = false;
  const [hid, p] = items[0];
  const cd = h("span", { class: "countdown" });
  const tick = () => {
    const left = Math.round(p.deadline - Date.now() / 1000);
    cd.textContent = left > 0 ? `${left} с` : "откат…";
    if (left < -3) { clearInterval(pendTimer); S.pending[hid] = []; refreshHost(hid); }
  };
  tick();
  pendTimer = setInterval(tick, 1000);
  bar.append(svg(ICON.shield), h("span", null, `${host(hid) ? host(hid).name : hid}: изменения ждут подтверждения, автооткат через `), cd,
    h("button", { class: "btn sm danger", onclick: async (e) => { busy(e.currentTarget); await txAction(hid, p.id, "rollback"); } }, svg(ICON.undo), "Откатить"),
    h("button", { class: "btn sm primary", onclick: async (e) => { busy(e.currentTarget); await txAction(hid, p.id, "confirm"); } }, svg(ICON.check), "Подтвердить"));
}

export async function txAction(hid, txid, act) {
  try {
    const d = await api(`/api/hosts/${hid}/tx/${txid}/${act}`, { method: "POST", allowFail: true });
    if (d.view) S.views[hid] = d.view;
    S.pending[hid] = (S.pending[hid] || []).filter((p) => p.id !== txid);
    toast(act === "confirm" ? (d.ok ? "Изменения подтверждены" : `Не подтверждено: ${d.status || d.error}`) : "Изменения откачены", d.ok ? "ok" : "err");
    await loadHosts();
  } catch (e) { toast(e.message, "err"); }
  render();
}

// ------------------------------------------------------------------ dialogs: host / settings / audit
export function hostDialog(x = null) {
  const v = x || { name: "", address: "", port: 22, user: "", description: "", role: "", location: "", tags: [] };
  const inp = {
    name: h("input", { type: "text", value: v.name, placeholder: "например, homelab" }),
    address: h("input", { type: "text", value: v.address, placeholder: "192.168.1.10 или имя" }),
    port: h("input", { type: "number", value: v.port || 22, min: 1, max: 65535 }),
    user: h("input", { type: "text", value: v.user || "", placeholder: S.settings.ssh_user || "sec_fw-admin" }),
    role: h("input", { type: "text", value: v.role || "", placeholder: "сервер Wazuh, NAS, …" }),
    location: h("input", { type: "text", value: v.location || "", placeholder: "стойка, комната" }),
    tags: h("input", { type: "text", value: (v.tags || []).join(", "), placeholder: "pi, docker" }),
    description: h("textarea", { rows: 3, style: { fontFamily: "Inter, sans-serif", fontSize: "13px" } }, v.description || ""),
    demo: h("input", { type: "checkbox", checked: !!v.demo }),
  };
  const msg = h("div");
  const data = () => ({ name: inp.name.value, address: inp.address.value, port: +inp.port.value, user: inp.user.value,
    role: inp.role.value, location: inp.location.value, tags: inp.tags.value, description: inp.description.value, demo: inp.demo.checked });
  modal({
    title: x ? `Хост ${x.name}` : "Новый хост",
    body: h("div", null,
      h("div", { class: "form-grid" },
        field("Имя", inp.name), field("Адрес", inp.address),
        field("Порт SSH", inp.port), field("Пользователь SSH (пусто — из настроек)", inp.user),
        field("Роль", inp.role), field("Расположение", inp.location),
        field("Метки (через запятую)", inp.tags, "wide"), field("Описание", inp.description, "wide"),
        h("label", { class: "chk wide" }, inp.demo, "Демо-режим (без подключения, на сохранённых данных)")),
      msg),
    foot: (close) => [
      x ? h("button", { class: "btn danger", style: { marginRight: "auto" }, onclick: async () => {
        if (!await confirmDlg("Удалить хост?", `Хост ${x.name} (${x.address}) будет удалён из панели. На самом хосте ничего не изменится.`, { ok: "Удалить", danger: true })) return;
        await api(`/api/hosts/${x.id}`, { method: "DELETE" });
        delete S.views[x.id]; close(); await loadHosts(); go(null); render();
      } }, svg(ICON.trash), "Удалить") : null,
      x ? h("button", { class: "btn ghost", title: "Удалить сохранённый отпечаток SSH-ключа хоста", onclick: async (e) => {
        busy(e.currentTarget);
        const d = await api(`/api/hosts/${x.id}/hostkey`, { method: "DELETE", allowFail: true });
        busy(e.currentTarget, false);
        msg.replaceChildren(h("div", { class: "note " + (d.ok ? "ok" : "warn") }, d.ok ? "Отпечаток сброшен — при следующем подключении будет принят новый." : "Сохранённого отпечатка нет."));
      } }, svg(ICON.key), "Сбросить отпечаток") : null,
      x ? h("button", { class: "btn", onclick: async (e) => {
        busy(e.currentTarget);
        try {
          await api(`/api/hosts/${x.id}`, { method: "PUT", body: data() });
          const d = await api(`/api/hosts/${x.id}/test`, { method: "POST" });
          msg.replaceChildren(h("div", { class: "note ok" }, `Подключение есть: helper ${d.version}, ${d.ms} мс`));
        } catch (er) { msg.replaceChildren(h("div", { class: "note bad" }, er.message)); }
        busy(e.currentTarget, false);
      } }, svg(ICON.plug), "Проверить") : null,
      h("button", { class: "btn ghost", onclick: close }, "Отмена"),
      h("button", { class: "btn primary", onclick: async (e) => {
        busy(e.currentTarget);
        try {
          const d = x ? await api(`/api/hosts/${x.id}`, { method: "PUT", body: data() }) : await api("/api/hosts", { method: "POST", body: data() });
          close(); await loadHosts();
          if (!x) { go(d.host.id); refreshHost(d.host.id); } else render();
          toast(x ? "Сохранено" : "Хост добавлен", "ok");
        } catch (er) { msg.replaceChildren(h("div", { class: "note bad" }, er.message)); busy(e.currentTarget, false); }
      } }, x ? "Сохранить" : "Добавить"),
    ],
  });
}

async function settingsDialog() {
  const d = await api("/api/settings");
  const s = d.settings;
  const inp = {
    ssh_user: h("input", { type: "text", value: s.ssh_user }),
    ssh_port: h("input", { type: "number", value: s.ssh_port }),
    key_path: h("input", { type: "text", value: s.key_path }),
    rollback_seconds: h("input", { type: "number", value: s.rollback_seconds, min: 30, max: 600 }),
    auto_confirm: h("input", { type: "checkbox", checked: s.auto_confirm }),
    demo: h("input", { type: "checkbox", checked: s.demo }),
  };
  modal({
    title: "Настройки панели", wide: true,
    body: h("div", null,
      h("div", { class: "form-grid" },
        field("Пользователь SSH на хостах", inp.ssh_user), field("Порт SSH по умолчанию", inp.ssh_port),
        field("Закрытый ключ панели (в контейнере)", inp.key_path, "wide"),
        field("Таймер отката по умолчанию, с", inp.rollback_seconds),
        h("div", { class: "f", style: { justifyContent: "flex-end" } },
          h("label", { class: "chk" }, inp.auto_confirm, "Подтверждать автоматически"),
          h("label", { class: "chk" }, inp.demo, "Демо-режим для всех хостов"))),
      h("div", { class: "section-title" }, "Ключ панели"),
      d.key_present ? h("div", { class: "note ok" }, "Закрытый ключ найден.") : h("div", { class: "note bad" }, "Закрытого ключа нет. Скопируйте ~/ZaSlon/keys/zaslon_ed25519 (и .pub) в каталог data/keys/ рядом с docker-compose.yml."),
      d.public_key ? h("div", null, h("div", { class: "dim small" }, "Открытый ключ (устанавливается на хосты скриптом zaslon-provision.sh):"),
        h("pre", { class: "code", style: { borderRadius: "6px", whiteSpace: "pre-wrap", wordBreak: "break-all" } }, d.public_key)) : null,
      h("div", { class: "dim small mt" }, `ZaSlon ${d.version}`)),
    foot: (close) => [
      h("button", { class: "btn ghost", onclick: close }, "Отмена"),
      h("button", { class: "btn primary", onclick: async () => {
        await api("/api/settings", { method: "PUT", body: { ssh_user: inp.ssh_user.value, ssh_port: +inp.ssh_port.value, key_path: inp.key_path.value,
          rollback_seconds: +inp.rollback_seconds.value, auto_confirm: inp.auto_confirm.checked, demo: inp.demo.checked } });
        close(); S.views = {}; await loadHosts(); render(); toast("Настройки сохранены", "ok");
      } }, "Сохранить"),
    ],
  });
}
document.getElementById("btn-settings").onclick = settingsDialog;

export function auditTable(list) {
  if (!list.length) return h("div", { class: "empty" }, "Записей нет");
  const name = { apply: "Изменение", confirm: "Подтверждение", rollback: "Откат", "host-add": "Хост добавлен", "host-edit": "Хост изменён",
    "host-delete": "Хост удалён", "hostkey-reset": "Сброс отпечатка" };
  return h("table", { class: "tbl" }, h("thead", null, h("tr", null, h("th", null, "Когда"), h("th", null, "Хост"), h("th", null, "Действие"), h("th", null, "Подробности"))),
    h("tbody", null, list.map((a) => {
      const d = a.detail || {};
      let det = "";
      if (a.action === "apply") det = (d.results && d.results.length ? d.results.join("; ") : (d.ops || []).map(describe).join("; ")) + (d.error ? " — " + d.error : "");
      else if (a.action === "host-edit") det = Object.entries(d).map(([k, v]) => `${k}: ${JSON.stringify(v[0])} → ${JSON.stringify(v[1])}`).join("; ");
      else det = d ? Object.entries(d).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join("; ") : "";
      return h("tr", null, h("td", { class: "nowrap" }, dt(a.t)), h("td", null, a.host || "—"),
        h("td", null, h("span", { class: "tag " + (a.ok ? "" : "bad") }, name[a.action] || a.action)), h("td", { class: "small" }, det));
    })));
}

document.getElementById("btn-audit").onclick = async () => {
  const d = await api("/api/audit");
  modal({ title: "Журнал действий панели", wide: true, body: h("div", { class: "tbl-wrap" }, auditTable(d.audit)) });
};

// ------------------------------------------------------------------ start
(async () => {
  main.appendChild(h("div", { class: "loading" }, h("span", { class: "spin" }), "Загрузка…"));
  try { await loadHosts(); } catch (e) { main.innerHTML = ""; main.appendChild(h("div", { class: "err-box" }, e.message)); return; }
  render();
})();
