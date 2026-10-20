import { T, tc, getLang, setLang, getTheme, setTheme, applyStatic } from "./i18n.js";
import { HELP } from "./help.js";

// ZaSlon — интерфейс. Без сборки и фреймворков.
// Всё, что приходит с сервера, выводится через textContent / DOM-узлы, не через innerHTML.

const $app = document.getElementById("app");
const $progress = document.getElementById("progress");
const $toast = document.getElementById("toast");
const SVGNS = "http://www.w3.org/2000/svg";
let timers = [];

// ---------- DOM-помощники ----------

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "class") e.className = v;
    else if (k === "dataset") Object.assign(e.dataset, v);
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, "");
    else if (k === "placeholder" || k === "title" || k === "aria-label") e.setAttribute(k, T(v));
    else e.setAttribute(k, v);
  }
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(T(String(k))));
  }
  return e;
}

function icon(name, cls = "ico") {
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("class", cls);
  s.setAttribute("aria-hidden", "true");
  const u = document.createElementNS(SVGNS, "use");
  u.setAttribute("href", "#i-" + name);
  s.append(u);
  return s;
}

function badge(text, tone = "") {
  return el("span", { class: "badge " + tone }, text);
}

function pill(text, tone) {
  return el("span", { class: "pill " + tone }, el("i", { class: "dot" }), text);
}

function toast(msg, bad) {
  $toast.textContent = T(msg);
  $toast.className = "toast" + (bad ? " bad" : "");
  $toast.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => ($toast.hidden = true), 4000);
}

// ---------- API ----------

async function api(path, opts = {}) {
  const o = { method: opts.method || "GET", headers: { "X-Zaslon": "1" }, credentials: "same-origin" };
  if (opts.body !== undefined) {
    o.body = JSON.stringify(opts.body);
    o.headers["Content-Type"] = "application/json";
  }
  let r;
  try { r = await fetch(path, o); }
  catch (e) { throw Object.assign(new Error("Панель недоступна"), { kind: "network" }); }
  if (r.status === 401) {
    location.replace("/login.html?next=" + encodeURIComponent(location.pathname + location.hash));
    throw Object.assign(new Error(T("Нужен вход")), { kind: "auth" });
  }
  let d = null;
  try { d = await r.json(); } catch (e) { /* не JSON */ }
  if (!r.ok || !d || d.ok === false) {
    throw Object.assign(new Error((d && d.error) || tc("Ошибка HTTP ", r.status)), { kind: d && d.kind });
  }
  return d;
}

// ---------- ход выполнения ----------
// Панель не знает точного прогресса SSH-вызова, поэтому показывает этапы и время.
// Длительности запоминаются в браузере: при повторе прогресс идёт по реальному времени прошлого раза.

const DUR_KEY = "zaslon-durations";
function loadDur() { try { return JSON.parse(localStorage.getItem(DUR_KEY) || "{}"); } catch (e) { return {}; } }
function saveDur(map) { try { localStorage.setItem(DUR_KEY, JSON.stringify(map)); } catch (e) { /* без хранилища */ } }

function task(title, steps, promise) {
  const durs = loadDur();
  const known = durs[title];
  const est = steps.reduce((a, s) => a + s.ms, 0) || 1000;
  const scale = known ? known / est : 1;                    // подгоняем этапы под прошлый результат
  const total = known || est;
  const start = performance.now();
  const stepEl = el("div", { class: "p-step" }, steps[0] ? steps[0].l : "");
  const timeEl = el("span", { class: "p-time" }, "0 с");
  const hintEl = el("span", { class: "p-hint" }, known ? tc("обычно ~", Math.round(known / 1000), " с") : "");
  const bar = el("i");
  const row = el("div", { class: "ptask" },
    el("div", { class: "p-top" }, el("span", { class: "spinner" }), el("b", null, title), timeEl),
    stepEl,
    el("div", { class: "p-bar" }, bar),
    el("div", { class: "p-foot" }, hintEl));
  $progress.append(row);
  const tick = setInterval(() => {
    const ms = performance.now() - start;
    let acc = 0, cur = steps.length - 1;
    for (let i = 0; i < steps.length; i++) {
      if (ms < (acc + steps[i].ms) * scale) { cur = i; break; }
      acc += steps[i].ms * scale;
    }
    bar.style.width = Math.min(92, (ms / total) * 100) + "%";
    stepEl.textContent = steps[cur] ? T(steps[cur].l) : stepEl.textContent;
    if (ms > total * 1.2) stepEl.textContent += T(" — дольше обычного");
    timeEl.textContent = tc(Math.round(ms / 1000), " с");
  }, 200);
  const finish = (state, msg) => {
    clearInterval(tick);
    const took = performance.now() - start;
    if (state === "ok") {
      const d = loadDur(); d[title] = Math.round(took);
      saveDur(d);
    }
    row.classList.add(state);
    row.querySelector(".spinner").replaceWith(icon(state === "ok" ? "check" : "alert", "ico p-ico"));
    bar.style.width = "100%";
    stepEl.textContent = T(msg || (state === "ok" ? "Готово" : "Ошибка"));
    hintEl.textContent = "";
    if (state === "err") {
      row.append(el("button", { class: "small", onclick: () => row.remove() }, "Закрыть"));
    } else {
      setTimeout(() => row.remove(), 1400);
    }
  };
  return promise.then(
    (v) => { finish("ok"); return v; },
    (e) => { finish("err", e.message); throw e; });
}

// act — то же, что task: принимает уже запущенный промис (запрос к API)
function act(title, steps, promise) {
  return task(title, steps, promise);
}

// ---------- маршрутизация ----------

function clearTimers() { timers.forEach(clearInterval); timers = []; }

// статусы хостов для верхних вкладок и сводки: id -> ответ статуса или "err"
const hostStat = {};
let hostsCache = null;

async function renderTabs() {
  const box = document.getElementById("tabs");
  if (!box) return;
  const hash = location.hash || "#/";
  if (!hostsCache) {
    try { hostsCache = (await api("/api/hosts")).hosts; } catch { hostsCache = []; }
  }
  const tab = (href, label, dot, cnt) => {
    const on = href === "#/" ? (hash === "#/" || hash === "") : (hash === href || hash.startsWith(href + "/"));
    return el("a", { href, class: "tab" + (on ? " on" : "") },
      dot ? el("i", { class: "dot " + dot }) : null, label, cnt ? el("span", { class: "cnt" }, String(cnt)) : null);
  };
  const items = [tab("#/", "Обзор")];
  for (const h of hostsCache) {
    const s = hostStat[h.id];
    let dot = "";
    let cnt = null;
    if (s === "err") dot = "bad";
    else if (s) { dot = s.firewalld.running ? "ok" : "off"; if (s.pending.length) { dot = "warn"; cnt = s.pending.length; } }
    items.push(tab("#/h/" + h.id, h.name, dot || "loading", cnt));
  }
  items.push(tab("#/audit", "Журнал"));
  box.replaceChildren(...items);
}

function route() {
  clearTimers();
  hostsCache = null;
  document.querySelectorAll(".overlay").forEach((n) => n.remove());
  const h = location.hash || "#/";
  let m;
  renderTabs();
  paintChrome();
  if ((m = h.match(/^#\/h\/([\w-]+)(?:\/(\w+))?$/))) return hostView(m[1], m[2] || "firewall");
  if (h === "#/audit") return auditView();
  if (h === "#/admin") return adminView();
  if ((m = h.match(/^#\/help(?:\/([\w-]+))?$/))) return helpView(m[1]);
  return hostsView();
}

// ---------- диалоги подтверждения (в стиле приложения, не браузерные) ----------

function ask(message, { title = "Подтвердите действие", ok = "Да", cancel = "Нет", danger = false } = {}) {
  return new Promise((resolve) => {
    let overlay;
    const done = (v) => {
      document.removeEventListener("keydown", onKey);
      overlay.remove();
      resolve(v);
    };
    const onKey = (e) => { if (e.key === "Escape") done(false); };
    overlay = el("div", { class: "overlay" },
      el("div", { class: "card dialog", role: "alertdialog", "aria-modal": "true" },
        el("h2", null, title),
        el("p", { class: "muted" }, message),
        el("div", { class: "actions" },
          el("button", { type: "button", onclick: () => done(false) }, cancel),
          el("button", { type: "button", class: danger ? "danger" : "primary", onclick: () => done(true) }, ok))));
    document.addEventListener("keydown", onKey);
    document.body.append(overlay);
    overlay.querySelector(".actions .primary, .actions .danger").focus();
  });
}

// ---------- список хостов ----------

function hostCard(h) {
  const dot = el("i", { class: "dot loading" });
  const card = el("a", { class: "card host", href: "#/h/" + h.id },
    el("div", { class: "host-head" },
      el("span", { class: "host-ico" }, icon("server")),
      el("div", null, el("h2", null, h.name), el("p", { class: "muted mono" }, h.user + "@" + h.address + ":" + h.port))),
    el("div", { class: "host-state" }, dot, el("span", { class: "muted" }, "проверка…")),
    el("div", { class: "host-counts" }),
    el("div", { class: "host-bar-slot" }));
  return card;
}

async function fillCard(card, h) {
  const state = card.querySelector(".host-state");
  const counts = card.querySelector(".host-counts");
  try {
    const st = await api("/api/hosts/" + h.id + "/status");
    hostStat[h.id] = st;
    renderTabs();
    const ports = st.zones.reduce((a, z) => a + z.ports_perm.length, 0);
    const services = st.zones.reduce((a, z) => a + z.services_perm.length, 0);
    state.replaceChildren(
      pill(st.firewalld.running ? "firewalld работает" : "firewalld остановлен", st.firewalld.running ? "ok" : "off"),
      pill("SELinux: " + st.selinux.runtime, selTone(st.selinux.runtime)));
    counts.replaceChildren(
      tile("port", ports, "портов", "blue"),
      tile("service", services, "служб", "blue"),
      tile("zone", st.zones.length, "зон", "blue"),
      st.pending.length ? tile("clock", st.pending.length, "ожидают", "warn") : "");
    card.querySelector(".host-bar-slot").replaceChildren(stackBar(st.zones));
  } catch (e) {
    hostStat[h.id] = "err";
    renderTabs();
    state.replaceChildren(pill("недоступен", "bad"));
    counts.replaceChildren(el("span", { class: "muted small" }, e.message));
  }
}

async function hostsView() {
  const grid = el("div", { class: "grid" });
  const keys = el("div", { class: "keyslot" });
  const kpis = el("div", { class: "kpis", id: "overview-kpis" });
  $app.replaceChildren(
    el("section", { class: "bar" },
      el("div", null, el("h1", null, "Хосты"), el("p", { class: "muted", id: "hosts-sub" }, "Загрузка списка…")),
      el("button", { class: "primary", onclick: addDialog }, icon("plus"), "Добавить хост")),
    kpis, grid, keys);
  const d = await api("/api/hosts").catch((e) => { toast(e.message, true); return null; });
  if (!d) return;
  document.getElementById("hosts-sub").textContent = d.hosts.length ? tc(d.hosts.length, " на связи проверяются") : T("Хостов пока нет");
  if (!d.hosts.length) grid.append(el("div", { class: "card empty" }, icon("server", "ico big"),
    el("p", null, "Хостов пока нет. Сначала установите агент на хост — см. раздел «Справка».")));
  const cards = d.hosts.map(hostCard);
  grid.replaceChildren(...cards);
  const paintKpis = () => {
    const sts = Object.values(hostStat).filter((s) => s && s !== "err");
    const ports = sts.reduce((a, s) => a + s.zones.reduce((b, z) => b + z.ports_perm.length, 0), 0);
    const services = sts.reduce((a, s) => a + s.zones.reduce((b, z) => b + z.services_perm.length, 0), 0);
    const pend = sts.reduce((a, s) => a + s.pending.length, 0);
    kpis.replaceChildren(
      stat("server", d.hosts.length, "хостов"),
      stat("port", sts.length ? ports : "—", "открытых портов"),
      stat("service", sts.length ? services : "—", "служб"),
      stat("clock", sts.length ? pend : "—", "ожидают изменений"));
  };
  paintKpis();
  act("Опрашиваю хосты", [{ l: "Подключаюсь к хостам", ms: 800 }, { l: "Читаю состояние firewalld", ms: 1200 }],
    Promise.all(d.hosts.map((h, i) => fillCard(cards[i], h)))).then(paintKpis, () => {});
  keys.append(await keyBlock());
}

async function keyBlock() {
  return el("div", { class: "card install-cta" },
    el("div", { class: "card-h" }, icon("terminal"), el("h3", null, "Установка агента на хост")),
    el("p", { class: "muted" }, "Команда установки формируется по параметрам хоста — без терминала на панели."),
    el("button", { class: "primary", onclick: () => (location.hash = "#/help/agent") }, icon("book"), "Открыть инструкцию"));
}

// Команда установки: параметры хоста из полей + одноразовый токен регистрации от панели.
// Используется и в диалоге «Новый хост», и в разделе «Справка».
const shq = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";

function installCommand(p, info, token, remove) {
  const env = ["ZASLON_PANEL=" + shq(p.panel)];
  if (info.ca_sha256) env.push("ZASLON_CA_SHA256=" + shq(info.ca_sha256));
  if (remove) env.push("ZASLON_REMOVE=1");
  else {
    env.push("ZASLON_PANEL_KEY=" + shq(info.key));
    env.push("ZASLON_AGENT_SHA256=" + shq(info.agent_sha256));
  }
  env.push("ZASLON_USER=" + shq(p.user));
  if (!remove && token) env.push("ZASLON_ENROLL=" + shq(token));
  // скрипт скачивается, его сумма сверяется с командой, и только потом запускается
  const get = (info.ca_sha256 ? "curl -fsSk " : "curl -fsS ") + shq(p.panel + "/dl/zaslon-install.sh") +
    " -o zaslon-install.sh";
  return get + " && echo " + shq(info.install_sha256 + "  zaslon-install.sh") + " | sha256sum -c - && sudo " +
    env.join(" \\\n  ") + " sh zaslon-install.sh; rm -f zaslon-install.sh";
}

function checkParams(p) {
  if (!/^https?:\/\/[^\s'"]+$/.test(p.panel || "")) return T("Адрес панели должен начинаться с http:// или https://");
  if (!/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/.test(p.address || "")) return T("Адрес хоста: имя или IP без пробелов");
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(p.user || "")) return T("Пользователь: латиница, цифры, _ и -");
  const port = Number(p.port);
  if (!(port >= 1 && port <= 65535)) return T("Порт SSH — число от 1 до 65535");
  return "";
}

function copyButton(pre) {
  return el("button", { class: "small", type: "button", onclick: async () => {
    try {
      await navigator.clipboard.writeText(pre.textContent);
      toast("Скопировано");
    } catch (e) {
      toast("Не удалось скопировать — выделите текст и скопируйте вручную", true);
    }
  } }, icon("copy"), "Скопировать");
}

// read() возвращает {panel, name, address, user, port}; update() пересобирает команду
function installCmdBox(read) {
  const cmd = el("pre", { class: "code cmd" }, T("Укажите адрес хоста — команда появится здесь"));
  const remCmd = el("pre", { class: "code cmd" }, "…");
  const warn = el("p", { class: "err small" });
  let info = null, last = "", seq = 0;
  async function update() {
    const p = read();
    const key = JSON.stringify(p);
    if (key === last) return;
    last = key;
    const my = ++seq;
    warn.textContent = "";
    if (!p.address) { cmd.textContent = T("Укажите адрес хоста — команда появится здесь"); remCmd.textContent = "…"; return; }
    const problem = checkParams(p);
    if (problem) { warn.textContent = problem; cmd.textContent = "…"; return; }
    cmd.textContent = "…";
    try {
      if (!info) info = await api("/api/install-info");
      if (!info.key) throw new Error("Ключ панели не создан. Перезапустите панель.");
      const token = (await api("/api/enroll/token", { method: "POST", body: p })).token;
      if (my !== seq) return;
      cmd.textContent = installCommand(p, info, token, false);
      remCmd.textContent = installCommand(p, info, "", true);
    } catch (e) {
      if (my === seq) { warn.textContent = e.message; cmd.textContent = "…"; last = ""; }
    }
  }
  const node = el("div", { class: "install-box" },
    el("div", { class: "cmd-head" }, el("h3", null, "Команда установки"), copyButton(cmd)),
    warn,
    cmd,
    el("p", { class: "small muted" }, "Выполните на хосте от root. Когда установка завершится, хост появится в панели сам."),
    el("div", { class: "cmd-head" }, el("h3", null, "Команда удаления агента"), copyButton(remCmd)),
    remCmd);
  return { node, update };
}

function addDialog() {
  const err = el("p", { class: "err" });
  const force = el("input", { type: "checkbox", name: "force" });
  const name = el("input", { name: "name", placeholder: "homeserver" });
  const address = el("input", { name: "address", required: true, placeholder: "192.168.1.55" });
  const user = el("input", { name: "user", value: "sec_fw-admin" });
  const port = el("input", { name: "port", value: "22", type: "number" });
  const known = new Set();   // адреса, которые уже были в панели: их появление не ждём
  let timer = 0, poll = 0;
  const box = installCmdBox(() => ({
    panel: location.origin, name: name.value.trim(), address: address.value.trim(),
    user: user.value.trim() || "sec_fw-admin", port: port.value.trim() || "22" }));
  const schedule = () => { clearTimeout(timer); timer = setTimeout(box.update, 500); };
  [name, address, user, port].forEach((i) => i.addEventListener("input", schedule));
  const form = el("form", { class: "card dialog wide" },
    el("h2", null, "Новый хост"),
    el("p", { class: "small" }, el("a", { href: "#/help/agent" }, "Как установить агент")),
    el("label", null, "Имя", name),
    el("label", null, "Адрес (имя или IP)", address),
    el("label", null, "Пользователь SSH", user),
    el("label", null, "Порт SSH", port),
    box.node,
    el("label", { class: "switch-row" }, el("span", null, "Добавить, даже если хост не отвечает"), switchEl(force)),
    err,
    el("div", { class: "actions" },
      el("button", { type: "button", onclick: () => close() }, "Закрыть"),
      el("button", { class: "primary", type: "submit" }, "Проверить и добавить")));
  const overlay = el("div", { class: "overlay" }, form);
  function close() { clearInterval(poll); overlay.remove(); }

  // пока диалог открыт, ждём появления хоста: его регистрирует скрипт на хосте
  api("/api/hosts").then((d) => d.hosts.forEach((h) => known.add(h.address))).catch(() => {});
  poll = setInterval(async () => {
    if (!document.body.contains(overlay)) return close();
    const a = address.value.trim();
    if (!a || known.has(a)) return;
    try {
      const d = await api("/api/hosts");
      const h = d.hosts.find((x) => x.address === a);
      if (h) {
        close();
        toast("Хост зарегистрирован в панели");
        location.hash = "#/h/" + h.id;
      }
    } catch (e) { /* сеть недоступна — попробуем ещё раз */ }
  }, 3000);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    try {
      const d = await act("Добавляю хост", [{ l: "Проверяю SSH-связь", ms: 1500 }, { l: "Запускаю агент", ms: 1500 }, { l: "Сохраняю", ms: 200 }],
        api("/api/hosts", { method: "POST", body: {
          name: name.value, address: address.value, user: user.value,
          port: port.value, force: force.checked } }));
      close();
      toast(d.status ? "Хост добавлен" : "Хост добавлен без проверки связи");
      location.hash = "#/h/" + d.host.id;
    } catch (ex) {
      err.textContent = ex.message;
    }
  });
  document.body.append(overlay);
  box.update();
}

// ---------- хост ----------

function selTone(mode) {
  return mode === "enforcing" ? "ok" : mode === "permissive" ? "warn" : mode === "disabled" ? "off" : "bad";
}

function switchEl(input) {
  return el("label", { class: "switch" }, input, el("span", { class: "track" }, el("span", { class: "thumb" })));
}

const PALETTE = ["#0a84ff", "#30d158", "#ff9f0a", "#ff453a", "#8e8e93", "#bf5af2"];

function tile(iconName, value, label, tone = "") {
  return el("span", { class: "mini " + tone }, icon(iconName), el("b", null, String(value)), el("span", null, label));
}

// полоса открытых портов по зонам: доля каждой зоны + легенда
function stackBar(zones) {
  const segs = zones.map((z, i) => ({ name: z.name, n: z.ports_perm.length, c: PALETTE[i % PALETTE.length] }))
    .filter((s) => s.n > 0);
  const total = segs.reduce((a, s) => a + s.n, 0);
  if (!total) return el("p", { class: "muted small" }, "Открытых портов нет");
  return el("div", { class: "stack-wrap" },
    el("div", { class: "stack" }, segs.map((s) => el("i", { style: "width:" + (s.n / total * 100).toFixed(1) + "%;background:" + s.c, title: s.name + ": " + s.n }))),
    el("div", { class: "legend" }, segs.map((s) => el("span", null, el("i", { style: "background:" + s.c }), s.name + " · " + s.n))));
}

function stat(iconName, value, label) {
  return el("div", { class: "stat" },
    el("span", { class: "stat-ico" }, icon(iconName)),
    el("div", null, el("b", null, String(value)), el("span", { class: "muted" }, label)));
}

async function hostView(hid, tab) {
  const title = el("h1", null, "…");
  const sub = el("p", { class: "muted" }, " ");
  const kpi = el("div", { class: "kpis" });
  const portBar = el("div", { class: "portbar" });
  const pills = el("div", { class: "pills" });
  const nav = el("nav", { class: "subnav" });
  const content = el("div", { class: "content" }, el("p", { class: "muted" }, "Подключаюсь к хосту…"));
  const pending = el("div", { id: "pending" });
  $app.replaceChildren(
    el("section", { class: "bar host-bar" },
      el("div", null, title, sub, pills),
      el("div", { class: "host-actions" },
        el("button", { onclick: () => (location.hash = "#/") }, "К списку"),
        el("button", { class: "danger", onclick: () => deleteHost(hid, title.textContent) }, icon("trash"), "Удалить хост"))),
    kpi,
    portBar,
    pending,
    nav,
    content);
  pendingPanel(hid, pending);
  timers.push(setInterval(() => pendingPanel(hid, pending), 5000));
  timers.push(setInterval(tickRings, 1000));
  let st;
  try {
    st = await act("Подключаюсь к хосту", [
      { l: "SSH-соединение", ms: 900 }, { l: "Читаю зоны firewalld", ms: 1200 }, { l: "Читаю SELinux", ms: 400 }],
      api("/api/hosts/" + hid + "/status"));
  } catch (e) {
    hostStat[hid] = "err";
    renderTabs();
    nav.replaceChildren(...navItems(hid, tab, null));
    content.replaceChildren(el("p", { class: "err" }, tc("Хост недоступен: ") + T(e.message)));
    return;
  }
  hostStat[hid] = st;
  renderTabs();
  const ports = st.zones.reduce((a, z) => a + z.ports_perm.length, 0);
  const services = st.zones.reduce((a, z) => a + z.services_perm.length, 0);
  const rich = st.zones.reduce((a, z) => a + z.rich.length, 0);
  title.textContent = st.host;
  sub.textContent = tc("Зона по умолчанию: ", st.default_zone || "—");
  pills.replaceChildren(
    pill(st.firewalld.running ? "firewalld работает" : "firewalld остановлен", st.firewalld.running ? "ok" : "off"),
    pill(tc("автозапуск ", st.firewalld.enabled ? "вкл." : "выкл."), st.firewalld.enabled ? "ok" : "off"),
    pill("SELinux: " + st.selinux.runtime, selTone(st.selinux.runtime)),
    st.selinux.config !== st.selinux.runtime && st.selinux.config !== "unknown"
      ? pill(tc("в конфиге: ", st.selinux.config), "warn") : "");
  nav.replaceChildren(...navItems(hid, tab, st));
  portBar.replaceChildren(el("div", { class: "card" }, el("div", { class: "card-h" }, icon("port"), el("h3", null, "Открытые порты по зонам")), stackBar(st.zones)));
  kpi.replaceChildren(
    stat("zone", st.zones.length, "зон"),
    stat("port", ports, "открытых портов"),
    stat("service", services, "служб"),
    stat("rule", rich, "богатых правил"));
  content.replaceChildren();
  if (tab === "selinux") selinuxTab(hid, st, content);
  else if (tab === "audit") auditTab(content, st.host);
  else firewallTab(hid, st, content);
}

function navItems(hid, tab, st) {
  const tone = st ? (st.firewalld.running ? "ok" : "off") : "off";
  const sel = st ? st.selinux.runtime : "unknown";
  const pend = st ? st.pending.length : 0;
  const ports = st ? st.zones.reduce((a, z) => a + z.ports_perm.length, 0) : 0;
  const items = [
    ["firewall", "Файрвол", tone, ports],
    ["selinux", "SELinux", st ? selTone(sel) : "off", null],
    ["audit", "Журнал", pend ? "warn" : "ok", pend || null],
  ];
  return items.map(([k, label, dotTone, n]) => el("a", { href: "#/h/" + hid + "/" + k, class: k === tab ? "on" : "" },
    el("i", { class: "dot " + dotTone }), label,
    n !== null ? el("span", { class: "tab-n" }, String(n)) : null));
}

async function deleteHost(hid, name) {
  if (!(await ask(tc("Удалить хост ", name, " из панели? На самом хосте ничего не меняется."),
    { title: "Удалить хост?", ok: "Удалить", cancel: "Отмена", danger: true }))) return;
  try {
    await api("/api/hosts/" + hid, { method: "DELETE" });
    toast("Хост удалён");
    location.hash = "#/";
  } catch (e) { toast(e.message, true); }
}

// незавершённые изменения: круговой таймер и кнопки
async function pendingPanel(hid, box) {
  const d = await api("/api/hosts/" + hid + "/tx").catch(() => null);
  if (!d) return;
  const sig = JSON.stringify(d.pending);
  if (box.dataset.sig === sig) return;
  box.dataset.sig = sig;
  box.replaceChildren(...d.pending.map((tx) => {
    const left = Math.max(0, Math.round(tx.expires - Date.now() / 1000));
    const total = tx.timeout || 120;
    return el("div", { class: "card warn pending", dataset: { exp: tx.expires, total: total } },
      ring(left, total),
      el("div", { class: "grow" },
        el("b", null, tx.summary),
        el("p", { class: "muted" }, "Откатится автоматически, если не подтвердить. Осталось ", el("span", { class: "left" }, left + " с"), ".")),
      el("div", { class: "actions" },
        el("button", { class: "danger", onclick: () => txAct(hid, tx.id, "rollback", "Откатываю…") }, icon("x"), "Откатить"),
        el("button", { class: "primary", onclick: () => txAct(hid, tx.id, "confirm", "Подтверждаю…") }, icon("check"), "Оставить")));
  }));
}

function ring(left, total) {
  const r = 16, c = 2 * Math.PI * r;
  const f = Math.max(0, Math.min(1, left / total));
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("class", "ring"); s.setAttribute("viewBox", "0 0 40 40");
  const bg = document.createElementNS(SVGNS, "circle");
  bg.setAttribute("cx", 20); bg.setAttribute("cy", 20); bg.setAttribute("r", r); bg.setAttribute("class", "ring-bg");
  const fg = document.createElementNS(SVGNS, "circle");
  fg.setAttribute("cx", 20); fg.setAttribute("cy", 20); fg.setAttribute("r", r); fg.setAttribute("class", "ring-fg");
  fg.setAttribute("stroke-dasharray", c); fg.setAttribute("stroke-dashoffset", c * (1 - f));
  s.append(bg, fg);
  return s;
}

function tickRings() {
  document.querySelectorAll(".pending").forEach((card) => {
    const exp = Number(card.dataset.exp);
    const total = Number(card.dataset.total);
    const left = Math.max(0, Math.round(exp - Date.now() / 1000));
    const span = card.querySelector(".left");
    if (span) span.textContent = left + " с";
    const fg = card.querySelector(".ring-fg");
    const c = 2 * Math.PI * 16;
    if (fg) fg.setAttribute("stroke-dashoffset", c * (1 - Math.max(0, Math.min(1, left / total))));
  });
}

async function txAct(hid, tid, act_, label) {
  try {
    await act(label.replace("…", ""), [{ l: label, ms: 700 }],
      api("/api/hosts/" + hid + "/tx/" + tid + "/" + act_, { method: "POST", body: {} }));
    toast(act_ === "confirm" ? "Изменение оставлено" : "Изменение откатено");
  } catch (e) { toast(e.message, true); }
  hostView(hid, currentTab());
}

function currentTab() {
  const m = location.hash.match(/\/(\w+)$/);
  return m ? m[1] : "firewall";
}

function firewallTab(hid, st, content) {
  const zoneNames = st.zones.map((z) => z.name);
  const zoneSel = (val) => el("select", { name: "zone" },
    st.zones.map((z) => el("option", { value: z.name, selected: z.name === val }, z.name + (z.default ? " (по умолч.)" : ""))));

  // firewalld: переключатели
  const onRun = el("input", { type: "checkbox", checked: st.firewalld.running });
  const onEn = el("input", { type: "checkbox", checked: st.firewalld.enabled });
  onRun.addEventListener("change", () => fwToggle(hid, st, "running", onRun));
  onEn.addEventListener("change", () => fwToggle(hid, st, "enabled", onEn));
  const fwCard = el("div", { class: "card" },
    el("div", { class: "card-h" }, icon("shield"), el("h3", null, "firewalld")),
    el("div", { class: "row-sw" }, el("div", null, el("b", null, "Работает"), el("p", { class: "muted small" }, "Без работающего firewalld правила не действуют")), switchEl(onRun)),
    el("div", { class: "row-sw" }, el("div", null, el("b", null, "Автозапуск"), el("p", { class: "muted small" }, "Запускать после перезагрузки")), switchEl(onEn)));

  // порт
  const port = el("input", { name: "port", placeholder: "8080 или 8000-8010", required: true });
  const proto = segmented([["tcp", "TCP"], ["udp", "UDP"]], "tcp");
  const timeout = el("input", { name: "timeout", type: "number", value: "120", min: "0", max: "900" });
  const zsel = zoneSel(st.zones.find((z) => z.default)?.name || zoneNames[0]);
  const portForm = el("form", { class: "card" },
    el("div", { class: "card-h" }, icon("port"), el("h3", null, "Порт")),
    el("div", { class: "row" },
      el("label", null, "Зона", zsel),
      el("label", null, "Порт", port),
      el("label", null, "Протокол", proto.node)),
    el("div", { class: "row" }, el("label", null, "Откат через, с", timeout), el("p", { class: "muted small grow" }, "0 — без таймера отката")),
    el("div", { class: "actions" },
      el("button", { class: "danger", type: "submit", name: "add", value: "0" }, icon("x"), "Закрыть"),
      el("button", { class: "primary", type: "submit", name: "add", value: "1" }, icon("port"), "Открыть")));
  portForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const add = e.submitter && e.submitter.value === "1";
    portAct(hid, zsel.value, port.value.trim(), add, proto.value(), Number(timeout.value));
  });

  // службы
  const svcZone = zoneSel(zsel.value);
  const svc = el("input", { name: "service", placeholder: "http, https, ssh…", required: true });
  const svcForm = el("form", { class: "card" },
    el("div", { class: "card-h" }, icon("service"), el("h3", null, "Службы")),
    el("div", { class: "row" }, el("label", null, "Зона", svcZone), el("label", null, "Служба", svc)),
    el("div", { class: "actions" }, el("button", { class: "primary", type: "submit" }, icon("plus"), "Добавить службу")));
  svcForm.addEventListener("submit", (e) => {
    e.preventDefault();
    svcAct(hid, svcZone.value, svc.value.trim(), true);
  });

  const zones = st.zones.map((z) => {
    const total = z.ports_perm.length + z.services_perm.length + z.interfaces.length;
    return el("div", { class: "card zone" },
      el("div", { class: "card-h" },
        icon("zone"), el("h3", null, z.name),
        z.default ? badge("по умолчанию", "ok") : null,
        el("span", { class: "grow" }),
        badge(total + " эл.", total ? "" : "muted")),
      el("div", { class: "zsec" }, el("span", { class: "zlabel" }, icon("port"), "Порты"),
        z.ports_perm.length ? el("div", { class: "chips" }, z.ports_perm.map((p) => {
          const [port, pr] = p.split("/");
          return el("span", { class: "chip" }, p, el("button", { class: "x", title: "Закрыть порт", onclick: () => portAct(hid, z.name, port, false, pr) }, "×"));
        })) : el("span", { class: "muted small" }, "нет")),
      el("div", { class: "zsec" }, el("span", { class: "zlabel" }, icon("service"), "Службы"),
        z.services_perm.length ? el("div", { class: "chips" }, z.services_perm.map((s) =>
          el("span", { class: "chip" }, s, el("button", { class: "x", title: "Убрать службу", onclick: () => svcAct(hid, z.name, s, false) }, "×")))) :
        el("span", { class: "muted small" }, "нет")),
      el("div", { class: "zsec" }, el("span", { class: "zlabel" }, icon("iface"), "Интерфейсы"),
        z.interfaces.length ? el("div", { class: "chips" }, z.interfaces.map((i) => el("span", { class: "chip ghost" }, i))) :
        el("span", { class: "muted small" }, "нет")),
      z.rich.length ? el("details", { class: "zsec" }, el("summary", null, icon("rule"), z.rich.length + " богатых правил"),
        el("pre", { class: "mono" }, z.rich.join("\n"))) : null);
  });

  content.replaceChildren(
    el("div", { class: "grid2" }, fwCard, portForm),
    svcForm,
    el("h2", { class: "section" }, "Зоны"),
    el("div", { class: "grid" }, zones));
}

function segmented(opts, value) {
  let current = value;
  const btns = opts.map(([v, t]) => {
    const b = el("button", { type: "button", class: v === current ? "seg on" : "seg", onclick: () => {
      current = v;
      btns.forEach((x) => x.className = "seg" + (x.dataset.v === current ? " on" : ""));
    } }, t);
    b.dataset.v = v;
    return b;
  });
  const node = el("div", { class: "segmented" }, btns);
  return { node, value: () => current };
}

async function fwToggle(hid, st, key, box) {
  const running = key === "running" ? box.checked : st.firewalld.running;
  const enabled = key === "enabled" ? box.checked : st.firewalld.enabled;
  if (!running && !(await ask(T("Остановить firewalld? Без него правила не действуют. Изменение откатится через 120 с, если не подтвердите."),
    { title: "Остановить firewalld?", ok: "Остановить", cancel: "Отмена", danger: true }))) {
    box.checked = true;
    return;
  }
  try {
    await act("Применяю firewalld", [{ l: "Отправляю изменение", ms: 800 }, { l: "Перезапускаю службу", ms: 1500 }],
      api("/api/hosts/" + hid + "/firewalld", { method: "POST", body: { running, enabled, timeout: 120 } }));
    toast("Изменение применено — подтвердите или дождитесь отката");
  } catch (e) { toast(e.message, true); }
  hostView(hid, "firewall");
}

async function portAct(hid, zone, port, add, proto = "tcp", timeout = 120) {
  try {
    await act(add ? "Открываю порт" : "Закрываю порт",
      [{ l: "Проверяю правило", ms: 400 }, { l: "Применяю в runtime", ms: 700 }, { l: "Сохраняю постоянное правило", ms: 900 }],
      api("/api/hosts/" + hid + "/port", { method: "POST", body: { zone, port, proto, add, timeout } }));
    toast(add ? "Порт открыт" : "Порт закрыт");
  } catch (e) { toast(e.message, true); }
  hostView(hid, "firewall");
}

async function svcAct(hid, zone, service, add) {
  try {
    await act(add ? "Добавляю службу" : "Убираю службу",
      [{ l: "Применяю правило", ms: 700 }, { l: "Сохраняю", ms: 600 }],
      api("/api/hosts/" + hid + "/service", { method: "POST", body: { zone, service, add, timeout: 120 } }));
    toast(add ? "Служба добавлена" : "Служба удалена");
  } catch (e) { toast(e.message, true); }
  hostView(hid, "firewall");
}

function selinuxTab(hid, st, content) {
  const modes = [["enforcing", "Enforcing", "ok"], ["permissive", "Permissive", "warn"], ["disabled", "Disabled", "off"]];
  let chosen = st.selinux.config !== "unknown" ? st.selinux.config : st.selinux.runtime;
  const apply = el("button", { class: "primary", disabled: true }, icon("check"), "Применить");
  const segs = modes.map(([v, t, tone]) => {
    const b = el("button", { type: "button", class: "seg " + tone + (v === chosen ? " on" : ""),
      onclick: () => {
        chosen = v;
        segs.forEach((x) => x.dataset.v === v ? x.classList.add("on") : x.classList.remove("on"));
        apply.disabled = chosen === (st.selinux.config !== "unknown" ? st.selinux.config : st.selinux.runtime) && chosen === st.selinux.runtime;
      } }, el("i", { class: "dot " + tone }), t);
    b.dataset.v = v;
    return b;
  });
  apply.addEventListener("click", async () => {
    try {
      const d = await act("Меняю режим SELinux", [{ l: "Пишу конфигурацию", ms: 800 }, { l: "Применяю режим", ms: 700 }],
        api("/api/hosts/" + hid + "/selinux/mode", { method: "POST", body: { mode: chosen, timeout: 120 } }));
      toast(d.reboot_required ? "Нужна перезагрузка хоста, чтобы режим вступил в силу" : "Режим SELinux изменён");
    } catch (e) { toast(e.message, true); }
    hostView(hid, "selinux");
  });
  const modeCard = el("div", { class: "card" },
    el("div", { class: "card-h" }, icon("shield"), el("h3", null, "Режим SELinux")),
    el("p", { class: "muted small" }, tc("Сейчас: ", st.selinux.runtime, ". В конфигурации: ", st.selinux.config, ".")),
    el("div", { class: "segmented wide" }, segs),
    el("div", { class: "actions" }, apply));

  const persist = el("input", { type: "checkbox", checked: true });
  const search = el("input", { type: "search", placeholder: "Поиск по имени", class: "search" });
  const counter = el("span", { class: "badge muted" }, "…");
  const list = el("div", { class: "bools" }, el("p", { class: "muted" }, "Загрузка булевых опций…"));
  const boolCard = el("div", { class: "card" },
    el("div", { class: "card-h" }, icon("bolt"), el("h3", null, "Булевы опции"), el("span", { class: "grow" }), counter),
    el("div", { class: "row-sw" }, el("span", null, "Сохранять после перезагрузки"), switchEl(persist)),
    el("div", { class: "searchrow" }, icon("search", "ico muted"), search),
    list);
  content.replaceChildren(el("div", { class: "grid2" }, modeCard, boolCard));

  api("/api/hosts/" + hid + "/selinux/booleans").then((d) => {
    const draw = () => {
      const q = search.value.trim().toLowerCase();
      const items = d.items.filter((i) => !q || i.name.includes(q));
      counter.textContent = tc(d.items.filter((i) => i.value).length, " вкл. из ", d.items.length);
      list.replaceChildren(...items.map((i) => {
        const cb = el("input", { type: "checkbox", checked: i.value });
        cb.addEventListener("change", async () => {
          try {
            await act(tc("Меняю ", i.name), [{ l: "Применяю булеву опцию", ms: 600 }],
              api("/api/hosts/" + hid + "/selinux/bool", { method: "POST",
                body: { name: i.name, value: cb.checked, persistent: persist.checked, timeout: 120 } }));
            toast(i.name + " = " + (cb.checked ? "on" : "off"));
          } catch (e) { cb.checked = !cb.checked; toast(e.message, true); }
          i.value = cb.checked;
          counter.textContent = tc(d.items.filter((x) => x.value).length, " вкл. из ", d.items.length);
        });
        return el("div", { class: "brow" + (i.value ? " on" : "") }, el("span", { class: "mono" }, i.name), switchEl(cb));
      }));
    };
    search.addEventListener("input", draw);
    draw();
  }).catch((e) => list.replaceChildren(el("p", { class: "err" }, e.message)));
}

async function auditTab(content, hostName) {
  const d = await act("Загружаю журнал", [{ l: "Читаю записи", ms: 300 }], api("/api/audit")).catch((e) => { toast(e.message, true); return null; });
  if (!d) return;
  const items = d.items.filter((i) => i.host === hostName);
  content.replaceChildren(auditTable(items));
}

// подписи для записей, сделанных до обновления (без текста в журнале)
const LEGACY_OPS = {
  host_add: "Добавлен хост", host_remove: "Удалён хост",
  tx_confirm: "Изменение оставлено", tx_rollback: "Изменение откатено",
  port_change: "Изменение порта", service_change: "Изменение службы",
  firewalld_set: "Изменение firewalld", selinux_mode: "Смена режима SELinux",
  selinux_bool: "Булева опция SELinux", admin_password: "Пароль панели изменён",
};

// текст журнала собирается из операции и её аргументов — на выбранном языке
function auditText(i) {
  const a = i.args || {};
  const on = (v) => (v ? T("вкл.") : T("выкл."));
  switch (i.op) {
    case "port_change":
      return [a.add === false ? T("Закрыть порт") : T("Открыть порт"), (a.port || "") + "/" + (a.proto || "tcp"),
        T("в зоне"), a.zone || ""].join(" ");
    case "service_change":
      return [a.add === false ? T("Убрать службу") : T("Добавить службу"), a.service || "", T("в зоне"), a.zone || ""].join(" ");
    case "firewalld_set":
      return T("Изменение firewalld") + ": " + (a.running ? T("работает") : T("остановлен")) + ", " +
        T("автозапуск") + " " + on(a.enabled);
    case "selinux_mode":
      return T("Смена режима SELinux") + ": " + (a.mode || "");
    case "selinux_bool":
      return T("Булева опция SELinux") + " " + (a.name || "") + ": " + on(a.value);
    case "tx_confirm": return T("Изменение оставлено");
    case "tx_rollback": return T("Изменение откатено");
    case "host_add": return T("Добавлен хост") + " " + (i.host || "");
    case "host_remove": return T("Удалён хост") + " " + (i.host || "");
    case "admin_password": return T("Пароль панели изменён");
    default: return T(i.message || LEGACY_OPS[i.op] || i.op);
  }
}

function auditTable(items) {
  if (!items.length) return el("div", { class: "card empty" }, icon("clock", "ico big"), el("p", null, "Записей пока нет"));
  const when = (ts) => ts ? ts.slice(8, 10) + "." + ts.slice(5, 7) + " " + ts.slice(11, 19) : "";
  return el("div", { class: "card table-wrap" }, el("table", { class: "audit" },
    el("thead", null, el("tr", null, el("th", null, "Когда"), el("th", null, "Хост"), el("th", null, "Что произошло"), el("th", null, "Итог"))),
    el("tbody", null, items.map((i) => el("tr", null,
      el("td", { class: "when" }, when(i.ts)),
      el("td", null, el("span", { class: "host-tag" }, i.host || "—")),
      el("td", null, el("div", { class: "what" }, auditText(i)),
        i.who && i.who !== "panel" ? el("div", { class: "muted small" }, tc("источник: ", i.who)) : null),
      el("td", null, i.ok
        ? badge("выполнено", "ok")
        : el("span", null, badge("ошибка", "bad"), el("div", { class: "muted small" }, i.error || ""))))))));
}

async function auditView() {
  $app.replaceChildren(el("h1", null, "Журнал действий"), el("p", { class: "muted" }, "Загрузка…"));
  const d = await act("Загружаю журнал", [{ l: "Читаю записи", ms: 300 }], api("/api/audit")).catch((e) => { toast(e.message, true); return null; });
  if (!d) return;
  $app.replaceChildren(el("section", { class: "bar" }, el("h1", null, "Журнал действий")), auditTable(d.items));
}

// ---------- тема и язык ----------

function paintChrome() {
  const L = getLang();
  const th = getTheme();
  document.querySelectorAll("[data-lang]").forEach((b) => b.classList.toggle("on", b.dataset.lang === L));
  const tb = document.getElementById("btn-theme");
  if (tb) {
    tb.replaceChildren(icon(th === "light" ? "moon" : "sun", "ico"));
    tb.setAttribute("title", T(th === "light" ? "Тёмная тема" : "Светлая тема"));
  }
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("on", location.hash.startsWith(a.dataset.nav)));
}

function initChrome() {
  document.getElementById("btn-logout").addEventListener("click", async () => {
    // сессия отзывается на сервере: cookie из браузера больше не подойдёт, даже если его кто-то сохранил
    try {
      await fetch("/api/logout", { method: "POST", headers: { "X-Zaslon": "1" }, credentials: "same-origin" });
    } catch (e) { /* сеть недоступна: всё равно уходим на страницу входа */ }
    location.replace("/login.html");
  });
  document.getElementById("btn-theme").addEventListener("click", () => {
    setTheme(getTheme() === "light" ? "dark" : "light");
    paintChrome();
  });
  document.querySelectorAll("[data-lang]").forEach((b) => b.addEventListener("click", () => {
    setLang(b.dataset.lang);
    route();
  }));
  applyStatic();
  paintChrome();
}

// ---------- справка ----------

function exampleBox(ex) {
  return el("div", { class: "example" }, el("b", null, ex.title), el("p", null, ex.text));
}

function agentInstaller() {
  const panel = el("input", { name: "panel", value: location.origin });
  const user = el("input", { name: "user", value: "sec_fw-admin" });
  const hname = el("input", { name: "hname", placeholder: "homeserver" });
  const haddr = el("input", { name: "haddr", placeholder: "192.168.1.56" });
  const port = el("input", { name: "port", value: "22", type: "number" });
  const box = installCmdBox(() => ({
    panel: panel.value.trim().replace(/\/+$/, ""), name: hname.value.trim(), address: haddr.value.trim(),
    user: user.value.trim() || "sec_fw-admin", port: port.value.trim() || "22" }));
  let timer = 0;
  const schedule = () => { clearTimeout(timer); timer = setTimeout(box.update, 500); };
  [panel, user, hname, haddr, port].forEach((i) => i.addEventListener("input", schedule));
  box.update();
  return el("div", { class: "installer" },
    el("div", { class: "grid2" },
      el("label", null, "Адрес панели для хоста", panel),
      el("label", null, "Пользователь на хосте", user),
      el("label", null, "Имя хоста", hname),
      el("label", null, "Адрес хоста", haddr),
      el("label", null, "Порт SSH", port)),
    box.node);
}

function helpSection(s) {
  const kids = [el("h2", null, s.title)];
  (s.paras || []).forEach((p) => kids.push(el("p", null, p)));
  if (s.steps) kids.push(el("ol", { class: "steps" }, s.steps.map((x) => el("li", null, x))));
  if (s.id === "agent") kids.push(agentInstaller());
  if (s.example) kids.push(exampleBox(s.example));
  if (s.removal) kids.push(el("p", { class: "muted small" }, s.removal));
  return el("section", { class: "card help-sec", id: "help-" + s.id }, kids);
}

function helpView(anchor) {
  const H = HELP[getLang()];
  $app.replaceChildren(
    el("section", { class: "bar" }, el("div", null, el("h1", null, H.title), el("p", { class: "muted" }, H.lead))),
    el("div", { class: "help" },
      el("nav", { class: "toc card" }, H.sections.map((s) => el("a", { href: "#/help/" + s.id }, s.title))),
      el("div", { class: "help-body" },
        H.sections.map(helpSection),
        el("section", { class: "card help-sec", id: "help-faq" },
          el("h2", null, getLang() === "en" ? "Common problems" : "Частые проблемы"),
          H.faq.map(([q, a]) => el("div", { class: "faq" }, el("b", null, q), el("p", { class: "muted" }, a)))))));
  if (anchor) {
    const node = document.getElementById("help-" + anchor);
    if (node) node.scrollIntoView({ block: "start" });
  }
}

// ---------- администрирование ----------

async function adminView() {
  const info = await api("/api/admin").catch((e) => { toast(e.message, true); return {}; });
  const inst = await api("/api/install-info").catch(() => ({}));
  const cur = el("input", { name: "current", type: "password", autocomplete: "current-password", required: true });
  const nw = el("input", { name: "new", type: "password", autocomplete: "new-password", required: true, minlength: 8 });
  const rep = el("input", { name: "repeat", type: "password", autocomplete: "new-password", required: true, minlength: 8 });
  const err = el("p", { class: "err small" });
  const submit = el("button", { class: "primary", type: "submit" }, "Сменить пароль");
  const form = el("form", {
    class: "pw-form",
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      if (nw.value !== rep.value) { err.textContent = T("Пароли не совпадают"); return; }
      if (nw.value.length < 8) { err.textContent = T("Пароль должен быть не короче 8 символов"); return; }
      submit.disabled = true;
      try {
        await api("/api/admin/password", { method: "POST", body: { current: cur.value, new: nw.value } });
        toast("Пароль изменён");
        form.reset();
        adminView();
      } catch (ex) {
        err.textContent = T(ex.message);
      } finally {
        submit.disabled = false;
      }
    } },
    el("label", null, "Текущий пароль", cur),
    el("label", null, "Новый пароль", nw),
    el("label", null, "Повторите новый пароль", rep),
    err,
    el("p", { class: "muted small" }, "Минимум 8 символов. Смена пароля закрывает все остальные сессии."),
    el("div", { class: "actions" }, submit));
  const row = (k, v) => [el("dt", null, k), el("dd", null, v)];
  $app.replaceChildren(
    el("section", { class: "bar" }, el("div", null, el("h1", null, "Администрирование"),
      el("p", { class: "muted" }, "Пароль входа в панель и сведения о программе."))),
    el("div", { class: "grid2" },
      el("div", { class: "card" }, el("div", { class: "card-h" }, icon("key"), el("h3", null, "Пароль панели")),
        el("p", { class: "muted small" }, "Пароль сохраняется в data/admin.json как хэш. Пока его не меняли здесь, действует пароль из .env."),
        form),
      el("div", { class: "card" }, el("div", { class: "card-h" }, icon("server"), el("h3", null, "Сведения о панели")),
        el("dl", { class: "kv" },
          row("Логин", info.login || "—"),
          row("Источник пароля", info.source === "интерфейс" ? T("интерфейс") : ".env"),
          row("Версия панели", "1.3"),
          row("Контрольная сумма агента", inst.agent_sha256 || "—")))));
}

window.addEventListener("hashchange", route);
initChrome();
route();
