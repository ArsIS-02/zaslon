// Small DOM / API helpers — no framework.

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else if (k === "html") el.innerHTML = v;
      else if (v === true) el.setAttribute(k, "");
      else el.setAttribute(k, v);
    }
  }
  add(el, kids);
  return el;
}

function add(el, kids) {
  for (const k of kids) {
    if (k === null || k === undefined || k === false) continue;
    if (Array.isArray(k)) add(el, k);
    else if (k instanceof Node) el.appendChild(k);
    else el.appendChild(document.createTextNode(String(k)));
  }
}

export const svg = (path, cls = "i") => {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("class", cls);
  s.innerHTML = path;
  return s;
};

export const ICON = {
  refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16zM14 6l4 4"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  doc: '<path d="M6 3h9l4 4v14H6zM14 3v5h5M9 13h7M9 17h7"/>',
  down: '<path d="M12 4v12M6 11l6 6 6-6M5 20h14"/>',
  check: '<path d="M5 12l5 5L20 7"/>',
  undo: '<path d="M9 14L4 9l5-5M4 9h10a6 6 0 0 1 0 12h-3"/>',
  plug: '<path d="M9 7V3M15 7V3M6 7h12v4a6 6 0 0 1-12 0zM12 17v4"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M15 8l2 2"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  play: '<path d="M7 4l13 8-13 8z"/>',
  queue: '<path d="M4 6h16M4 12h16M4 18h10"/>',
};

export async function api(path, opts = {}) {
  const o = { method: opts.method || "GET", headers: { "X-Zaslon": "1" } };
  if (opts.body !== undefined) {
    o.body = JSON.stringify(opts.body);
    o.headers["Content-Type"] = "application/json";
  }
  let r;
  try {
    r = await fetch(path, o);
  } catch (e) {
    throw Object.assign(new Error("Панель недоступна: " + e.message), { kind: "network" });
  }
  let d = null;
  try { d = await r.json(); } catch { /* not json */ }
  if (!r.ok || (d && d.ok === false && !opts.allowFail)) {
    const e = new Error((d && d.error) || `HTTP ${r.status}`);
    e.kind = d && d.kind; e.detail = d && d.detail; e.data = d; e.status = r.status;
    throw e;
  }
  return d;
}

export function toast(msg, kind = "") {
  const t = h("div", { class: "toast " + kind }, msg);
  document.getElementById("toasts").appendChild(t);
  setTimeout(() => t.remove(), kind === "err" ? 9000 : 4500);
}

export function modal({ title, body, foot, wide = false, onClose }) {
  const root = document.getElementById("modal-root");
  const close = () => { bg.remove(); document.removeEventListener("keydown", esc); onClose && onClose(); };
  const esc = (e) => { if (e.key === "Escape") close(); };
  const bg = h("div", { class: "modal-bg", onmousedown: (e) => { if (e.target === bg) close(); } },
    h("div", { class: "modal" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true" },
      h("div", { class: "hd" }, h("h2", null, title),
        h("button", { class: "btn ghost icon x", title: "Закрыть", onclick: close }, svg(ICON.x))),
      h("div", { class: "bd" }, body),
      foot ? h("div", { class: "ft" }, typeof foot === "function" ? foot(close) : foot) : null));
  root.appendChild(bg);
  document.addEventListener("keydown", esc);
  const f = bg.querySelector("input,select,textarea");
  if (f) setTimeout(() => f.focus(), 30);
  return { close, el: bg };
}

export function confirmDlg(title, text, { ok = "Да", danger = false } = {}) {
  return new Promise((res) => {
    let done = false;
    const m = modal({
      title, body: h("div", null, text),
      foot: (close) => [
        h("button", { class: "btn ghost", onclick: () => { close(); } }, "Отмена"),
        h("button", { class: "btn " + (danger ? "danger" : "primary"), onclick: () => { done = true; close(); } }, ok),
      ],
      onClose: () => res(done),
    });
    return m;
  });
}

export function plural(n, one, few, many) {
  n = Math.abs(n) % 100;
  const n1 = n % 10;
  if (n > 10 && n < 20) return many;
  if (n1 > 1 && n1 < 5) return few;
  if (n1 === 1) return one;
  return many;
}

export function ago(t) {
  if (!t) return "никогда";
  const s = Math.max(0, Math.round(Date.now() / 1000 - t));
  if (s < 50) return "только что";
  if (s < 3600) return `${Math.round(s / 60)} мин назад`;
  if (s < 86400) return `${Math.round(s / 3600)} ч назад`;
  return new Date(t * 1000).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function dt(t) {
  return t ? new Date(t * 1000).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
}

export function chips(items, opts = {}) {
  if (!items || !items.length) return h("span", { class: "dim" }, opts.empty || "—");
  return h("span", { class: "pill-list" }, items.map((x) => h("span", { class: "chip" + (opts.cls ? " " + opts.cls : "") }, x)));
}

export function field(label, input, cls = "") {
  return h("label", { class: "f " + cls }, label, input);
}

export function debounce(fn, ms = 200) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

export function busy(btn, on = true) {
  if (!btn) return;
  if (on) {
    btn._html = btn.innerHTML;
    btn.disabled = true;
    btn.prepend(h("span", { class: "spin" }));
  } else {
    btn.disabled = false;
    if (btn._html !== undefined) btn.innerHTML = btn._html;
  }
}
