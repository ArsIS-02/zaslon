import { h, svg, ICON, api, toast, modal, confirmDlg, plural, ago, dt, field, busy, debounce } from "./util.js";
import { S, host, go, render, refreshHost, getView, enqueue, isQueued, queued, hostDialog, tile, txAction, auditTable, osName } from "./app.js";
import { describe, key } from "./ops.js";

const SUBS = [
  ["summary", "Сводка"], ["ports", "Порты"], ["zones", "Зоны"], ["iptables", "iptables"], ["nftables", "nftables"],
  ["selinux", "SELinux"], ["fail2ban", "fail2ban"], ["history", "Журнал"],
];
const STATUS = {
  open: ["открыт · слушает", "open"], stale: ["никто не слушает", "stale"], blocked: ["закрыт firewall", "blocked"],
  docker: ["Docker в обход зон", "docker"], exposed: ["без firewall", "exposed"], unknown: ["—", "unknown"],
};
const ui = (hid, k, def) => { S.ui[hid] = S.ui[hid] || {}; if (!(k in S.ui[hid])) S.ui[hid][k] = def; return S.ui[hid][k]; };
const setUi = (hid, k, v) => { S.ui[hid][k] = v; render(); };

export async function renderHost(root, hid, sub) {
  const x = host(hid);
  const head = h("div", { class: "page-head" });
  root.appendChild(head);
  const nav = h("div", { class: "subnav" });
  root.appendChild(nav);
  const body = h("div");
  root.appendChild(body);
  let v = S.views[hid];
  if (!v) {
    body.appendChild(h("div", { class: "loading" }, h("span", { class: "spin" }), "Получаю состояние хоста…"));
    try {
      v = await getView(hid, false);
    } catch (e) {
      S.errors[hid] = { error: e.message, kind: e.kind, detail: e.detail };
    }
    if (location.hash.indexOf(hid) < 0) return;  // ушли на другую вкладку
    body.innerHTML = "";
  }
  fillHead(head, x, v);
  for (const [k, label] of SUBS) {
    let n = null;
    if (v && k === "ports") n = v.ports.filter((r) => !r.ephemeral).length;
    if (v && k === "summary" && v.findings.length) n = v.findings.length;
    nav.appendChild(h("button", { class: sub === k ? "active" : "", onclick: () => go(hid, k) }, label, n !== null ? h("span", { class: "n" }, n) : null));
  }
  const er = S.errors[hid];
  if (er) {
    body.appendChild(h("div", { class: "err-box" }, h("b", null, "Не удалось опросить хост. "), er.error,
      er.detail ? h("div", { class: "k" }, er.detail) : null,
      v ? h("div", { class: "dim small mt" }, "Ниже — последнее сохранённое состояние от " + dt(v.state._collected || v.state.time)) : null));
  }
  if (!v) {
    body.appendChild(h("div", { class: "card" }, h("div", { class: "empty" }, h("h3", null, "Состояние хоста не получено"),
      h("p", null, "Проверьте, что хост подготовлен скриптом zaslon-provision.sh и ключ панели лежит в data/keys/."),
      h("div", { class: "row-flex", style: { justifyContent: "center" } },
        h("button", { class: "btn", onclick: () => hostDialog(x) }, svg(ICON.edit), "Настройки хоста"),
        h("button", { class: "btn primary", onclick: (e) => refreshHost(hid, e.currentTarget) }, svg(ICON.refresh), "Повторить")))));
    return;
  }
  const f = { summary: vSummary, ports: vPorts, zones: vZones, iptables: vIptables, nftables: vNft, selinux: vSelinux,
    fail2ban: vF2b, history: vHistory }[sub] || vSummary;
  f(body, hid, v);
}

function fillHead(head, x, v) {
  const s = v && v.summary;
  head.append(
    h("div", null,
      h("h1", null, x.name),
      h("div", { class: "sub" },
        h("span", { class: "mono" }, x.address + (x.port && x.port !== 22 ? ":" + x.port : "")),
        s ? h("span", null, "·", " ", osName(s.os)) : null,
        s && (s.model || s.arch) ? h("span", null, "·", " ", s.model || s.arch) : null,
        x.role ? h("span", { class: "tag" }, x.role) : null,
        s && s.demo ? h("span", { class: "tag warn" }, "демо") : null,
        s ? h("span", { class: "dim" }, "· обновлено " + ago(v.state._collected || s.time)) : null)),
    h("div", { class: "actions" },
      h("button", { class: "btn ghost", onclick: () => hostDialog(x) }, svg(ICON.edit), "Хост"),
      v ? reportMenu(x) : null,
      h("button", { class: "btn primary", onclick: (e) => refreshHost(x.id, e.currentTarget) }, svg(ICON.refresh), "Обновить")));
}

function reportMenu(x) {
  return h("button", { class: "btn", onclick: () => modal({
    title: `Отчёт по ${x.name}`,
    body: h("div", null,
      h("p", { class: "muted" }, "Отчёт строится по последнему собранному состоянию: firewalld, порты, iptables и nftables, SELinux, fail2ban, SSH и изменения через панель. Перед формированием стоит нажать «Обновить»."),
      h("div", { class: "row-flex" },
        h("a", { class: "btn", href: `/api/hosts/${x.id}/report.html`, target: "_blank" }, svg(ICON.eye), "Открыть HTML"),
        h("a", { class: "btn", href: `/api/hosts/${x.id}/report.html?download=1` }, svg(ICON.down), "Скачать HTML"),
        h("button", { class: "btn primary", onclick: async (e) => {
          busy(e.currentTarget);
          try {
            const r = await fetch(`/api/hosts/${x.id}/report.pdf`, { headers: { "X-Zaslon": "1" } });
            if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.error || r.status); }
            const b = await r.blob();
            const a = h("a", { href: URL.createObjectURL(b), download: (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "zaslon.pdf" });
            document.body.appendChild(a); a.click(); a.remove();
          } catch (er) { toast("PDF: " + er.message, "err"); }
          busy(e.currentTarget, false);
        } }, svg(ICON.down), "Скачать PDF"))),
  }) }, svg(ICON.doc), "Отчёт");
}

// =================================================================== summary
function vSummary(root, hid, v) {
  const s = v.summary, st = v.state;
  const fw = st.firewalld || {};
  root.appendChild(h("div", { class: "tiles" },
    tile("firewalld", s.firewalld === "running" ? "работает" : "выключен", fw.running ? `зона по умолчанию ${s.default_zone}` : "трафик не фильтруется", s.firewalld === "running" ? "ok" : "bad"),
    tile("Открыто в зонах", s.open_ports, `портов · служб ${s.open_services}`),
    tile("Слушает в сети", s.listening, "сокетов на внешних адресах"),
    tile("Без отклика", s.stale, "открыто, никто не слушает", s.stale ? "warn" : ""),
    tile("Docker в обход", s.docker_published, "опубликованных портов", s.docker_published ? "warn" : ""),
    tile("SELinux", s.selinux, "в конфиге: " + ((st.selinux || {}).config_mode || "—"), s.selinux === "Enforcing" ? "ok" : s.selinux === "Permissive" ? "warn" : "bad"),
    tile("fail2ban", s.fail2ban === "active" ? "работает" : "выключен", `в бане: ${s.banned}`, s.fail2ban === "active" ? "ok" : "warn")));
  // ports composition bar
  const cnt = {};
  v.ports.filter((r) => !r.ephemeral).forEach((r) => { cnt[r.status] = (cnt[r.status] || 0) + 1; });
  const tot = Object.values(cnt).reduce((a, b) => a + b, 0) || 1;
  const col = { open: "var(--ok)", stale: "var(--warn)", blocked: "var(--info)", docker: "var(--dock)", exposed: "var(--bad)" };
  root.appendChild(h("div", { class: "card mb" }, h("div", { class: "bd" },
    h("div", { class: "row-flex", style: { justifyContent: "space-between", marginBottom: "8px" } }, h("b", null, "Сетевые порты"),
      h("a", { href: `#/h/${hid}/ports` }, "подробно →")),
    h("div", { class: "bar", style: { height: "10px" } }, Object.entries(cnt).map(([k, n]) => h("i", { style: { width: (100 * n / tot) + "%", background: col[k] }, title: `${STATUS[k][0]}: ${n}` }))),
    h("div", { class: "legend" }, Object.entries(cnt).map(([k, n]) => h("span", null, h("i", { style: { background: col[k] } }), `${STATUS[k][0]} — ${n}`))))));

  const grid = h("div", { class: "grid g2" });
  root.appendChild(grid);
  // findings
  const fc = h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Замечания"), h("span", { class: "muted" }, v.findings.length)));
  const fb = h("div", { class: "bd flush" });
  if (!v.findings.length) fb.appendChild(h("div", { class: "empty" }, "Замечаний нет"));
  for (const f of v.findings) {
    fb.appendChild(h("div", { class: "finding" },
      h("div", null, h("span", { class: "sev " + f.severity }, { high: "высок.", medium: "средн.", low: "низк.", info: "инфо" }[f.severity]),
        h("div", { class: "area" }, f.area)),
      h("div", null, h("div", { class: "t" }, f.title), f.detail ? h("div", { class: "d" }, f.detail) : null),
      findingAction(hid, v, f)));
  }
  fc.appendChild(fb);
  grid.appendChild(fc);
  // host facts
  const facts = st.facts || {};
  const right = h("div", { class: "grid" });
  right.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Хост")), h("div", { class: "bd" },
    h("dl", { class: "kv" },
      h("dt", null, "Имя хоста"), h("dd", null, facts.hostname || "—"),
      h("dt", null, "Система"), h("dd", null, facts.os || "—"),
      h("dt", null, "Ядро"), h("dd", { class: "mono" }, `${facts.kernel || "—"} ${facts.arch || ""}`),
      facts.model ? [h("dt", null, "Модель"), h("dd", null, facts.model)] : null,
      h("dt", null, "Адреса"), h("dd", null, (facts.addresses || []).filter((a) => !/^(br-|docker|virbr)/.test(a.ifname)).map((a) => h("div", { class: "mono" }, `${a.ifname}  ${a.addr}/${a.prefix}`))),
      h("dt", null, "firewalld"), h("dd", null, fw.running ? `${fw.version || ""} · бэкенд ${(fw.conf || {}).FirewallBackend || "nftables"} · автозапуск: ${fw.enabled}` : `не работает (автозапуск: ${fw.enabled || "—"})`),
      h("dt", null, "iptables"), h("dd", { class: "mono" }, (st.iptables || {}).version || "—"),
      h("dt", null, "Службы"), h("dd", null, [["Docker", (st.misc || {}).docker], ["Cockpit", (st.misc || {}).cockpit], ["NetworkManager", (st.misc || {}).networkmanager]]
        .map(([n, s2]) => h("span", { class: "tag " + (s2 === "active" ? "ok" : ""), style: { marginRight: "4px" } }, `${n}: ${s2 || "—"}`))),
      x_desc(host(hid))))));
  const pi = st.peer_info;
  if (pi) {
    right.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Доступ панели к хосту")), h("div", { class: "bd" },
      h("div", { class: "note " + (pi.ssh_allowed ? "ok" : "bad") }, pi.reason || ""),
      h("div", { class: "dim small" }, `Панель подключается с адреса ${st.peer || "?"}; трафик попадает в зону ${pi.zone || "?"} (${pi.why || ""}). Перед каждым изменением helper проверяет, что SSH для панели останется открытым.`))));
  }
  grid.appendChild(right);
}

function x_desc(x) {
  if (!x || !(x.description || x.location)) return null;
  return [h("dt", null, "Описание"), h("dd", null, [x.location, x.description].filter(Boolean).join(" · "))];
}

function findingAction(hid, v, f) {
  const a = f.action;
  if (!a) return h("span");
  const btn = (label, fn, cls = "") => h("button", { class: "btn sm " + cls, onclick: fn }, label);
  switch (a.kind) {
    case "start-firewalld": return btn("Включить…", () => enqueue(hid, { op: "unit", unit: "firewalld", action: "start" }, { op: "unit", unit: "firewalld", action: "enable" }), "primary");
    case "enable-firewalld": return btn("В автозапуск", () => enqueue(hid, { op: "unit", unit: "firewalld", action: "enable" }));
    case "close-stale": return btn("Разобрать…", () => staleDialog(hid, v));
    case "drift": return btn("Показать", () => go(hid, "zones"));
    case "log-denied": return btn("Включить unicast", () => enqueue(hid, { op: "log-denied", value: "unicast" }));
    case "selinux-enforce": return btn("Enforcing…", () => enqueue(hid, { op: "selinux-enforce", value: "1" }, { op: "selinux-config", value: "enforcing" }));
    case "f2b": return btn("Показать", () => go(hid, "fail2ban"));
    default: return h("span");
  }
}

function staleDialog(hid, v) {
  const rows = v.ports.filter((r) => r.status === "stale");
  const checks = [];
  const list = h("table", { class: "tbl" }, h("thead", null, h("tr", null, h("th", null, ""), h("th", null, "Порт"), h("th", null, "Назначение"), h("th", null, "Как открыт"))),
    h("tbody", null, rows.map((r) => {
      const byPort = r.allowed.filter((a) => a.via === "port");
      const cb = h("input", { type: "checkbox", checked: byPort.length > 0, disabled: !byPort.length });
      if (byPort.length) checks.push([cb, r, byPort]);
      return h("tr", null, h("td", null, cb), h("td", { class: "mono" }, `${r.port}/${r.proto}`), h("td", null, r.hint || "—"),
        h("td", { class: "small" }, r.allowed.map((a) => `${a.zone}: ${a.via === "service" ? "служба " + a.item : a.via === "range" ? "диапазон " + a.item : a.item}`).join(", ")));
    })));
  modal({
    title: "Открыто, но никто не слушает", wide: true,
    body: h("div", null,
      h("div", { class: "note" }, "На этих портах сейчас нет ни одной службы. Часто это остатки старых установок. Перед закрытием подумайте о службах, которые запускаются не всегда (резервное копирование, временные контейнеры)."),
      h("div", { class: "tbl-wrap", style: { maxHeight: "50vh" } }, list),
      h("div", { class: "dim small mt" }, "Порты, открытые через службу или диапазон, закрываются на вкладке «Зоны».")),
    foot: (close) => [
      h("button", { class: "btn ghost", onclick: close }, "Отмена"),
      h("button", { class: "btn primary", onclick: () => {
        const ops = [];
        for (const [cb, r, by] of checks) if (cb.checked) for (const a of by) ops.push({ op: "port", action: "remove", zone: a.zone, port: a.item.split("/")[0], proto: a.item.split("/")[1] || r.proto });
        if (ops.length) enqueue(hid, ...ops);
        close();
        toast(`В очередь добавлено: ${ops.length}`, "ok");
      } }, "Добавить в очередь"),
    ],
  });
}

// =================================================================== ports
function vPorts(root, hid, v) {
  const fw = v.state.firewalld || {};
  const filt = ui(hid, "pfilter", "all");
  const eph = ui(hid, "peph", false);
  const q = ui(hid, "pq", "");
  const rows = v.ports.filter((r) => eph || !r.ephemeral);
  const counts = {};
  rows.forEach((r) => { counts[r.status] = (counts[r.status] || 0) + 1; });
  const extZones = Object.values(fw.zones || {}).filter((z) => z.active || z.default).map((z) => z.name);
  const card = h("div", { class: "card" });
  // add form
  const pIn = h("input", { type: "text", placeholder: "порт или 8000-8010", style: { width: "150px" } });
  const prIn = h("select", null, ["tcp", "udp", "sctp"].map((p) => h("option", null, p)));
  const zIn = h("select", null, extZones.map((z) => h("option", { selected: z === fw.default_zone }, z)));
  const perm = h("input", { type: "checkbox", checked: true });
  const toolbar = h("div", { class: "toolbar" },
    h("div", { class: "filters" },
      [["all", "Все", rows.length], ["open", "Открыт · слушает"], ["stale", "Никто не слушает"], ["blocked", "Закрыт firewall"], ["docker", "Docker"], ["exposed", "Без firewall"]]
        .filter(([k]) => k === "all" || counts[k])
        .map(([k, l, n]) => h("button", { class: "fbtn" + (filt === k ? " on" : ""), onclick: () => setUi(hid, "pfilter", k) }, l, h("span", { class: "c" }, n ?? counts[k])))),
    h("label", { class: "chk small" }, h("input", { type: "checkbox", checked: eph, onchange: (e) => setUi(hid, "peph", e.target.checked) }), "временные UDP"),
    h("input", { type: "search", placeholder: "поиск: порт, процесс…", value: q, style: { marginLeft: "auto", width: "200px" },
      oninput: debounce((e) => { S.ui[hid].pq = e.target.value; const tb = document.getElementById("ports-tbody"); if (tb) tb.replaceWith(portsBody(hid, v, rows)); }, 150) }));
  card.appendChild(toolbar);
  if (fw.running) {
    card.appendChild(h("div", { class: "toolbar" },
      h("span", { class: "muted" }, "Открыть порт:"), pIn, prIn, h("span", { class: "muted" }, "в зоне"), zIn,
      h("label", { class: "chk small" }, perm, "постоянно"),
      h("button", { class: "btn sm", onclick: () => {
        const p = pIn.value.trim();
        if (!/^\d{1,5}(-\d{1,5})?$/.test(p)) { toast("Порт: число или диапазон 8000-8010", "err"); return; }
        enqueue(hid, { op: "port", action: "add", zone: zIn.value, port: p, proto: prIn.value, ...(perm.checked ? {} : { permanent: false }) });
        pIn.value = "";
      } }, svg(ICON.plus), "В очередь")));
  }
  card.appendChild(h("div", { class: "bd flush tbl-wrap" }, h("table", { class: "tbl" },
    h("thead", null, h("tr", null, ["Порт", "Назначение", "Разрешён в firewall", "Слушает", "Docker", "Итог", ""].map((t) => h("th", null, t)))),
    portsBody(hid, v, rows))));
  root.appendChild(card);
  root.appendChild(h("div", { class: "note mt" },
    h("b", null, "Как читать таблицу. "), "«Разрешён в firewall» — порт открыт в зоне, смотрящей в сеть (портом, службой или диапазоном). «Слушает» — процесс принимает соединения на внешнем адресе. ",
    h("b", null, "Docker в обход зон"), " — порт опубликован контейнером (DNAT): он доступен из сети, даже если его нет в зоне. Ограничить такой порт можно привязкой к 127.0.0.1 в docker-compose или правилом в политике зоны docker."));
}

function portsBody(hid, v, rows) {
  const filt = ui(hid, "pfilter", "all");
  const q = (ui(hid, "pq", "") || "").toLowerCase();
  const tb = h("tbody", { id: "ports-tbody" });
  const list = rows.filter((r) => (filt === "all" || r.status === filt) &&
    (!q || `${r.port}/${r.proto} ${r.hint} ${(r.processes || []).join(" ")} ${r.allowed.map((a) => a.item).join(" ")} ${r.docker.map((d) => d.to).join(" ")}`.toLowerCase().includes(q)));
  if (!list.length) tb.appendChild(h("tr", null, h("td", { colspan: 7, class: "dim", style: { textAlign: "center", padding: "24px" } }, "Ничего не найдено")));
  for (const r of list) {
    const [lbl, cls] = STATUS[r.status] || STATUS.unknown;
    const qd = isQueued(hid, (o) => o.op === "port" && `${o.port}` === `${r.port}` && (o.proto || "tcp") === r.proto);
    const acts = h("td", { class: "acts" });
    const fwRun = (v.state.firewalld || {}).running;
    if (fwRun) {
      for (const a of r.allowed) {
        if (a.via === "port") acts.appendChild(h("button", { class: "btn sm ghost", title: `Закрыть ${a.item} в зоне ${a.zone}`, onclick: () => enqueue(hid, { op: "port", action: "remove", zone: a.zone, port: a.item.split("/")[0], proto: a.item.split("/")[1] }) }, "Закрыть"));
        else if (a.via === "service") acts.appendChild(h("button", { class: "btn sm ghost", title: `Убрать службу ${a.item} из зоны ${a.zone}`, onclick: () => enqueue(hid, { op: "service", action: "remove", zone: a.zone, service: a.item }) }, "Убрать " + a.item));
      }
      if (!r.allowed.length && r.status === "blocked") acts.appendChild(h("button", { class: "btn sm ghost", onclick: () => enqueue(hid, { op: "port", action: "add", zone: (v.state.firewalld || {}).default_zone, port: String(r.port), proto: r.proto }) }, "Открыть"));
    }
    tb.appendChild(h("tr", { class: qd ? "queued" : "" },
      h("td", { class: "mono nowrap" }, `${r.port}/${r.proto}`),
      h("td", null, r.hint || h("span", { class: "dim" }, "—")),
      h("td", null, r.allowed.length ? r.allowed.map((a) => h("div", { class: "small" }, h("span", { class: "dim" }, a.zone + ": "), a.via === "service" ? h("span", { class: "chip svc" }, a.item) : h("span", { class: "chip" }, a.item))) : h("span", { class: "dim" }, "—")),
      h("td", null, r.processes && r.processes.length ? h("div", null, r.processes.join(", "), h("div", { class: "dim small mono" }, [...new Set(r.listen.map((l) => l.addr))].join(" "))) : h("span", { class: "dim" }, "—")),
      h("td", { class: "mono small" }, r.docker.length ? r.docker.map((d) => h("div", null, "→ " + d.to)) : h("span", { class: "dim" }, "—")),
      h("td", null, h("span", { class: "st " + cls }, lbl), qd ? h("div", { class: "small", style: { color: "var(--accent)" } }, "в очереди") : null),
      acts));
  }
  return tb;
}

// =================================================================== zones
function vZones(root, hid, v) {
  const fw = v.state.firewalld || {};
  if (!fw.running) {
    root.appendChild(h("div", { class: "card" }, h("div", { class: "empty" },
      h("h3", null, "firewalld не запущен"),
      h("p", null, "Сейчас хост не фильтрует входящий трафик (кроме правил Docker). При запуске firewalld применит зону по умолчанию — обычно public со службами ssh, mdns и dhcpv6-client."),
      h("p", { class: "dim small" }, "Запуск идёт с таймером отката: если панель потеряет доступ, firewalld будет остановлен автоматически."),
      h("button", { class: "btn primary", onclick: () => enqueue(hid, { op: "unit", unit: "firewalld", action: "start" }, { op: "unit", unit: "firewalld", action: "enable" }) }, svg(ICON.play), "Запустить и включить автозапуск"))));
    return;
  }
  const zones = Object.values(fw.zones || {}).sort((a, b) => (b.default - a.default) || (b.active - a.active) || a.name.localeCompare(b.name));
  let cur = ui(hid, "zone", fw.default_zone);
  if (!fw.zones[cur]) cur = fw.default_zone;
  const layer = ui(hid, "zlayer", "both");
  const grid = h("div", { class: "grid side" });
  const left = h("div", { class: "grid", style: { alignContent: "start" } });
  left.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h3", null, "Зоны")),
    h("div", { class: "zlist" }, zones.map((z) => h("button", { class: z.name === cur ? "active" : "", onclick: () => setUi(hid, "zone", z.name) },
      h("span", { class: "dot " + (z.active ? "ok" : "") }), z.name,
      h("span", { class: "z-meta" }, z.default ? "по умолч." : z.active ? `${(z.interfaces || []).length + (z.sources || []).length} привяз.` : ""))))));
  // global settings
  const dz = h("select", null, zones.map((z) => h("option", { selected: z.name === fw.default_zone }, z.name)));
  const ld = h("select", null, ["off", "unicast", "broadcast", "multicast", "all"].map((x) => h("option", { selected: x === fw.log_denied }, x)));
  left.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h3", null, "firewalld")), h("div", { class: "bd" },
    h("div", { class: "grid", style: { gap: "10px" } },
      field("Зона по умолчанию", h("div", { class: "row-flex" }, dz, h("button", { class: "btn sm", onclick: () => dz.value !== fw.default_zone && enqueue(hid, { op: "default-zone", zone: dz.value }) }, "Задать"))),
      field("Журналировать отказы (LogDenied)", h("div", { class: "row-flex" }, ld, h("button", { class: "btn sm", onclick: () => ld.value !== fw.log_denied && enqueue(hid, { op: "log-denied", value: ld.value }) }, "Задать"))),
      field("Изменения применять", h("div", { class: "seg", style: { display: "flex" } },
        [["both", "постоянно"], ["runtime", "до перезагрузки"]].map(([k, l]) => h("button", { class: layer === k ? "on" : "", style: { flex: 1 }, onclick: () => setUi(hid, "zlayer", k) }, l)))),
      h("div", { class: "dim small" }, `firewalld ${fw.version || ""}, бэкенд ${(fw.conf || {}).FirewallBackend || "nftables"}`)))));
  grid.appendChild(left);
  const z = fw.zones[cur];
  const right = h("div", { class: "grid", style: { alignContent: "start" } });
  right.appendChild(zoneCard(hid, v, z, layer));
  if ((fw.drift || []).length) right.appendChild(driftCard(hid, fw.drift));
  if (Object.keys(fw.policies || {}).length) right.appendChild(policiesCard(fw.policies));
  grid.appendChild(right);
  root.appendChild(grid);
}

function L(layer) { return layer === "runtime" ? { permanent: false } : {}; }

function chipList(hid, items, mkOp, opts = {}) {
  const wrap = h("div", { class: "pill-list" });
  for (const it of items || []) {
    const op = mkOp(it, "remove");
    const k = key(op);
    const qd = isQueued(hid, (o) => key(o) === k);
    wrap.appendChild(h("span", { class: "chip" + (opts.svc ? " svc" : "") + (qd ? " del" : "") + (opts.cls ? " " + opts.cls(it) : ""), title: opts.title ? opts.title(it) : "" },
      it, opts.hint && opts.hint(it) ? h("span", { class: "hint" }, opts.hint(it)) : null,
      h("button", { title: "Убрать", onclick: () => enqueue(hid, op) }, "×")));
  }
  for (const o of queued(hid)) if (opts.match && opts.match(o)) wrap.appendChild(h("span", { class: "chip new" + (opts.svc ? " svc" : "") }, opts.label(o)));
  if (!wrap.children.length) wrap.appendChild(h("span", { class: "dim" }, "—"));
  return wrap;
}

function zoneCard(hid, v, z, layer) {
  const fw = v.state.firewalld;
  const cat = fw.services_catalog || {};
  const lay = L(layer);
  const zn = z.name;
  const bd = h("div", { class: "bd" });
  const row = (k, ...content) => h("div", { class: "zrow" }, h("div", { class: "k" }, k), h("div", null, ...content));
  const ext = (z.interfaces || []).some((i) => !/^(docker|br-|virbr|veth)/.test(i)) || (z.sources || []).length || z.default;
  // target
  const tg = h("select", null, ["default", "ACCEPT", "DROP", "%%REJECT%%"].map((t) => h("option", { selected: t === z.target }, t)));
  bd.appendChild(row("Политика (target)", h("div", { class: "row-flex" }, tg,
    h("button", { class: "btn sm", onclick: () => tg.value !== z.target && enqueue(hid, { op: "target", zone: zn, target: tg.value }) }, "Задать"),
    h("span", { class: "dim small" }, "default — отклонять всё, что не разрешено; ACCEPT — пропускать всё"))));
  // interfaces
  const ifNames = [...new Set((v.state.facts.addresses || []).map((a) => a.ifname))];
  const ifIn = h("input", { type: "text", placeholder: "интерфейс", list: "dl-if-" + hid, style: { width: "130px" } });
  bd.appendChild(row("Интерфейсы", chipList(hid, z.interfaces, (i, a) => ({ op: "interface", action: a, zone: zn, interface: i, ...lay }),
    { match: (o) => o.op === "interface" && o.zone === zn && o.action !== "remove", label: (o) => o.interface }),
  h("div", { class: "form-row mt" }, ifIn, h("datalist", { id: "dl-if-" + hid }, ifNames.map((i) => h("option", { value: i }))),
    h("button", { class: "btn sm", onclick: () => ifIn.value && enqueue(hid, { op: "interface", action: "change", zone: zn, interface: ifIn.value.trim(), ...lay }) }, "Перенести в эту зону"))));
  // sources
  const srcIn = h("input", { type: "text", placeholder: "192.168.1.0/24", style: { width: "160px" } });
  bd.appendChild(row("Источники", chipList(hid, z.sources, (s, a) => ({ op: "source", action: a, zone: zn, source: s, ...lay }),
    { match: (o) => o.op === "source" && o.zone === zn && o.action === "add", label: (o) => o.source }),
  h("div", { class: "form-row mt" }, srcIn, h("button", { class: "btn sm", onclick: () => srcIn.value && enqueue(hid, { op: "source", action: "add", zone: zn, source: srcIn.value.trim(), ...lay }) }, svg(ICON.plus), "Добавить")),
  h("div", { class: "dim small" }, "Трафик с этих адресов обрабатывается этой зоной, независимо от интерфейса.")));
  // services
  const svIn = h("input", { type: "text", placeholder: "служба (ssh, https…)", list: "dl-svc-" + hid, style: { width: "200px" } });
  bd.appendChild(row("Службы", chipList(hid, z.services, (s, a) => ({ op: "service", action: a, zone: zn, service: s, ...lay }),
    { svc: true, hint: (s) => (cat[s] ? cat[s].ports.join(" ") : ""), match: (o) => o.op === "service" && o.zone === zn && o.action === "add", label: (o) => o.service }),
  h("div", { class: "form-row mt" }, svIn,
    h("datalist", { id: "dl-svc-" + hid }, Object.entries(cat).map(([k, s]) => h("option", { value: k }, `${s.short} — ${s.ports.join(" ")}`))),
    h("button", { class: "btn sm", onclick: () => {
      const s = svIn.value.trim();
      if (!s) return;
      if (Object.keys(cat).length && !cat[s]) { toast(`Службы ${s} нет в каталоге firewalld этого хоста`, "err"); return; }
      enqueue(hid, { op: "service", action: "add", zone: zn, service: s, ...lay });
    } }, svg(ICON.plus), "Добавить"))));
  // ports
  const pIn = h("input", { type: "text", placeholder: "порт / 8000-8010", style: { width: "160px" } });
  const prIn = h("select", null, ["tcp", "udp", "sctp"].map((p) => h("option", null, p)));
  const sortedPorts = (z.ports || []).slice().sort((a, b) => parseInt(a) - parseInt(b) || a.localeCompare(b));
  bd.appendChild(row(`Порты (${(z.ports || []).length})`, chipList(hid, sortedPorts, (p, a) => ({ op: "port", action: a, zone: zn, port: p.split("/")[0], proto: p.split("/")[1], ...lay }),
    { match: (o) => o.op === "port" && o.zone === zn && o.action === "add", label: (o) => `${o.port}/${o.proto}`, title: (p) => portTitle(v, p), cls: (p) => portCls(v, p) }),
  h("div", { class: "legend" }, h("span", null, h("i", { style: { background: "var(--warn)" } }), "никто не слушает"), h("span", null, h("i", { style: { background: "var(--dock)" } }), "занят Docker"), h("span", { class: "dim" }, "наведите на порт — увидите процесс")),
  h("div", { class: "form-row mt" }, pIn, prIn, h("button", { class: "btn sm", onclick: () => {
    if (!/^\d{1,5}(-\d{1,5})?$/.test(pIn.value.trim())) { toast("Порт: число или диапазон", "err"); return; }
    enqueue(hid, { op: "port", action: "add", zone: zn, port: pIn.value.trim(), proto: prIn.value, ...lay }); pIn.value = "";
  } }, svg(ICON.plus), "Добавить"))));
  // protocols
  if ((z.protocols || []).length) bd.appendChild(row("Протоколы", chipList(hid, z.protocols, (p, a) => ({ op: "protocol", action: a, zone: zn, protocol: p, ...lay }), {})));
  // masquerade
  const mq = h("label", { class: "switch" }, h("input", { type: "checkbox", checked: !!z.masquerade, onchange: (e) => enqueue(hid, { op: "masquerade", action: e.target.checked ? "add" : "remove", zone: zn, ...lay }) }), h("span"));
  bd.appendChild(row("Маскарадинг (NAT)", h("div", { class: "row-flex" }, mq, h("span", { class: "dim small" }, "подмена адреса для исходящего трафика — нужна, если хост работает как роутер"))));
  // forward ports
  const fp = { port: h("input", { type: "text", placeholder: "порт", style: { width: "80px" } }), proto: h("select", null, ["tcp", "udp"].map((p) => h("option", null, p))),
    toport: h("input", { type: "text", placeholder: "на порт", style: { width: "80px" } }), toaddr: h("input", { type: "text", placeholder: "на адрес (необяз.)", style: { width: "150px" } }) };
  bd.appendChild(row("Проброс портов", chipList(hid, z.forward_ports, (s, a) => {
    const m = Object.fromEntries(s.split(":").map((kv) => kv.split("=")));
    return { op: "forward-port", action: a, zone: zn, port: m.port, proto: m.proto, toport: m.toport || undefined, toaddr: m.toaddr || undefined, ...lay };
  }, { match: (o) => o.op === "forward-port" && o.zone === zn && o.action === "add", label: (o) => `${o.port}/${o.proto}→${o.toaddr || ""}:${o.toport || ""}` }),
  h("div", { class: "form-row mt" }, fp.port, fp.proto, fp.toport, fp.toaddr, h("button", { class: "btn sm", onclick: () => {
    if (!fp.port.value || (!fp.toport.value && !fp.toaddr.value)) { toast("Нужен порт и порт/адрес назначения", "err"); return; }
    enqueue(hid, { op: "forward-port", action: "add", zone: zn, port: fp.port.value.trim(), proto: fp.proto.value, toport: fp.toport.value.trim() || undefined, toaddr: fp.toaddr.value.trim() || undefined, ...lay });
  } }, svg(ICON.plus), "Добавить"))));
  // icmp
  const icIn = h("select", null, h("option", { value: "" }, "тип ICMP…"), (fw.icmptypes || []).map((t) => h("option", null, t)));
  bd.appendChild(row("Блокировка ICMP", chipList(hid, z.icmp_blocks, (t, a) => ({ op: "icmp-block", action: a, zone: zn, icmptype: t, ...lay }),
    { match: (o) => o.op === "icmp-block" && o.zone === zn && o.action === "add", label: (o) => o.icmptype }),
  h("div", { class: "form-row mt" }, icIn, h("button", { class: "btn sm", onclick: () => icIn.value && enqueue(hid, { op: "icmp-block", action: "add", zone: zn, icmptype: icIn.value, ...lay }) }, svg(ICON.plus), "Блокировать"))));
  // rich rules
  bd.appendChild(row("Rich rules", h("div", null,
    (z.rich_rules || []).map((r) => {
      const op = { op: "rich", action: "remove", zone: zn, rule: r, ...lay };
      const qd = isQueued(hid, (o) => o.op === "rich" && o.rule === r && o.action === "remove");
      return h("div", { class: "rich", style: qd ? { opacity: .5, textDecoration: "line-through" } : {} }, h("code", null, r), h("button", { class: "btn sm ghost", onclick: () => enqueue(hid, op) }, svg(ICON.x)));
    }),
    queued(hid).filter((o) => o.op === "rich" && o.zone === zn && o.action === "add").map((o) => h("div", { class: "rich" }, h("code", { style: { color: "var(--accent)" } }, "+ " + o.rule))),
    !(z.rich_rules || []).length ? h("div", { class: "dim" }, "—") : null,
    h("button", { class: "btn sm mt", onclick: () => richDialog(hid, zn, lay, Object.keys(cat)) }, svg(ICON.plus), "Добавить правило…"))));
  return h("div", { class: "card" },
    h("div", { class: "hd" }, h("h2", null, "Зона ", zn),
      z.default ? h("span", { class: "tag acc" }, "по умолчанию") : null, z.active ? h("span", { class: "tag ok" }, "активна") : h("span", { class: "tag" }, "не используется"),
      ext ? h("span", { class: "tag warn", title: "привязана к физическому интерфейсу или источникам" }, "смотрит в сеть") : null,
      h("div", { class: "r" }, !z.default ? h("button", { class: "btn sm ghost", onclick: () => enqueue(hid, { op: "default-zone", zone: zn }) }, "Сделать зоной по умолчанию") : null)),
    bd);
}

function portCls(v, p) {
  const [port, proto] = p.split("/");
  const r = v.ports.find((x) => `${x.port}` === port && x.proto === proto);
  return r ? (r.status === "stale" ? "stale" : r.status === "docker" ? "dock" : "") : "";
}

function portTitle(v, p) {
  const [port, proto] = p.split("/");
  const r = v.ports.find((x) => `${x.port}` === port && x.proto === proto);
  if (!r) return "";
  return `${STATUS[r.status][0]}${r.processes && r.processes.length ? " — " + r.processes.join(", ") : ""}`;
}

function richDialog(hid, zn, lay, services) {
  const b = {
    family: h("select", null, h("option", { value: "ipv4" }, "IPv4"), h("option", { value: "ipv6" }, "IPv6"), h("option", { value: "" }, "обе")),
    src: h("input", { type: "text", placeholder: "192.168.1.0/24 (пусто — любой)" }),
    not: h("input", { type: "checkbox" }),
    kind: h("select", null, h("option", { value: "service" }, "служба"), h("option", { value: "port" }, "порт"), h("option", { value: "all" }, "весь трафик")),
    svc: h("input", { type: "text", list: "dl-rsvc", placeholder: "ssh" }),
    port: h("input", { type: "text", placeholder: "8080" }),
    proto: h("select", null, h("option", null, "tcp"), h("option", null, "udp")),
    action: h("select", null, h("option", { value: "accept" }, "accept — разрешить"), h("option", { value: "reject" }, "reject — отклонить"), h("option", { value: "drop" }, "drop — отбросить")),
    log: h("input", { type: "checkbox" }),
  };
  const txt = h("textarea", { rows: 3, style: { width: "100%" } });
  const fSvc = field("Служба", b.svc), fPort = field("Порт", b.port), fProto = field("Протокол", b.proto);
  const warnAll = h("div", { class: "note warn", hidden: true }, "Правило без службы и порта касается всего трафика от источника.");
  const build = () => {
    fSvc.hidden = b.kind.value !== "service"; fPort.hidden = fProto.hidden = b.kind.value !== "port";
    warnAll.hidden = b.kind.value !== "all";
    let r = "rule";
    if (b.family.value) r += ` family="${b.family.value}"`;
    if (b.src.value.trim()) r += ` source${b.not.checked ? " NOT" : ""} address="${b.src.value.trim()}"`;
    if (b.kind.value === "service" && b.svc.value.trim()) r += ` service name="${b.svc.value.trim()}"`;
    if (b.kind.value === "port" && b.port.value.trim()) r += ` port port="${b.port.value.trim()}" protocol="${b.proto.value}"`;
    if (b.log.checked) r += ` log prefix="zaslon-${b.action.value} " level="info"`;
    r += " " + b.action.value;
    txt.value = r;
  };
  Object.values(b).forEach((el) => el.addEventListener("input", build));
  Object.values(b).forEach((el) => el.addEventListener("change", build));
  build();
  modal({
    title: `Rich rule для зоны ${zn}`, wide: true,
    body: h("div", null,
      h("div", { class: "form-grid" },
        field("Семейство", b.family), field("Источник", b.src),
        h("label", { class: "chk" }, b.not, "кроме этого источника (NOT)"), h("span"),
        field("Что", b.kind), h("div", { class: "row-flex", style: { alignItems: "flex-end" } }, fSvc, fPort, fProto),
        field("Действие", b.action), h("label", { class: "chk", style: { alignSelf: "end" } }, b.log, "журналировать")),
      h("datalist", { id: "dl-rsvc" }, services.map((s) => h("option", { value: s }))),
      warnAll,
      h("div", { class: "mt" }, field("Правило (можно отредактировать вручную)", txt)),
      h("div", { class: "note" }, "Пример: разрешить SSH только из домашней сети — источник 192.168.1.0/24, служба ssh, accept; затем убрать службу ssh из зоны.")),
    foot: (close) => [h("button", { class: "btn ghost", onclick: close }, "Отмена"),
      h("button", { class: "btn primary", onclick: () => {
        if (!txt.value.trim().startsWith("rule")) { toast("Правило должно начинаться с rule", "err"); return; }
        if ((b.kind.value === "service" && !b.svc.value.trim()) || (b.kind.value === "port" && !b.port.value.trim())) { toast(b.kind.value === "service" ? "Укажите службу" : "Укажите порт", "err"); return; }
        enqueue(hid, { op: "rich", action: "add", zone: zn, rule: txt.value.trim(), ...lay }); close(); } }, "В очередь")],
  });
}

function driftCard(hid, drift) {
  const kindOp = { ports: "port", services: "service", sources: "source", rich_rules: "rich", forward_ports: "forward-port", icmp_blocks: "icmp-block", protocols: "protocol" };
  const mk = (d, action, layer) => {
    const op = kindOp[d.kind];
    if (!op) return null;
    const base = { op, action, zone: d.zone, ...(layer === "runtime" ? { permanent: false } : { runtime: false }) };
    if (op === "port") return { ...base, port: d.value.split("/")[0], proto: d.value.split("/")[1] };
    if (op === "service") return { ...base, service: d.value };
    if (op === "source") return { ...base, source: d.value };
    if (op === "rich") return { ...base, rule: d.value };
    if (op === "icmp-block") return { ...base, icmptype: d.value };
    if (op === "protocol") return { ...base, protocol: d.value };
    return null;
  };
  return h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Текущие и сохранённые правила расходятся"), h("span", { class: "muted" }, drift.length)),
    h("div", { class: "bd flush" }, h("div", { class: "note warn", style: { margin: "10px 14px" } }, "«Только сейчас» пропадёт после перезагрузки или firewall-cmd --reload. «Только сохранено» появится после перезагрузки."),
      h("table", { class: "tbl" }, h("thead", null, h("tr", null, h("th", null, "Зона"), h("th", null, "Что"), h("th", null, "Значение"), h("th", null, "Где"), h("th", null, ""))),
        h("tbody", null, drift.map((d) => {
          const rt = d.where === "runtime-only";
          const keep = mk(d, "add", rt ? "permanent" : "runtime"), drop = mk(d, "remove", rt ? "runtime" : "permanent");
          return h("tr", null, h("td", null, d.zone), h("td", null, d.kind), h("td", { class: "mono" }, d.value),
            h("td", null, rt ? h("span", { class: "tag warn" }, "только сейчас") : d.where === "permanent-only" ? h("span", { class: "tag acc" }, "только сохранено") : d.where),
            h("td", { class: "acts" }, keep ? h("button", { class: "btn sm", onclick: () => enqueue(hid, keep) }, rt ? "Сохранить" : "Применить сейчас") : null,
              drop ? h("button", { class: "btn sm ghost", onclick: () => enqueue(hid, drop) }, "Убрать") : null));
        })))));
}

function policiesCard(pol) {
  return h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Политики (между зонами)"), h("span", { class: "muted" }, "только просмотр")),
    h("div", { class: "bd flush" }, h("table", { class: "tbl" }, h("thead", null, h("tr", null, ["Политика", "Приоритет", "target", "Откуда → куда", "Разрешено"].map((t) => h("th", null, t)))),
      h("tbody", null, Object.values(pol).map((p) => h("tr", null, h("td", null, p.name, p.active ? h("span", { class: "tag ok", style: { marginLeft: "6px" } }, "активна") : null),
        h("td", null, p.priority), h("td", null, p.target), h("td", { class: "small" }, `${(p.ingress_zones || []).join(" ")} → ${(p.egress_zones || []).join(" ")}`),
        h("td", null, [...(p.services || []), ...(p.ports || [])].map((x) => h("span", { class: "chip" }, x)), (p.rich_rules || []).map((r) => h("div", { class: "mono small dim" }, r)))))))));
}

// =================================================================== iptables
function vIptables(root, hid, v) {
  const ipt = v.state.iptables || {};
  const fam = ui(hid, "ifam", "ipv4");
  const rawTabs = ((ipt[fam] || {}).tables) || {};
  const tabs = Object.fromEntries(["filter", "nat", "mangle", "raw", "security"].filter((t) => rawTabs[t]).map((t) => [t, rawTabs[t]])
    .concat(Object.entries(rawTabs).filter(([t]) => !["filter", "nat", "mangle", "raw", "security"].includes(t))));
  let tbl = ui(hid, "itbl", "filter");
  if (!tabs[tbl]) tbl = Object.keys(tabs)[0];
  const showRaw = ui(hid, "iraw", false);
  root.appendChild(h("div", { class: "note mb" }, h("b", null, "iptables здесь работает поверх nftables "), `(${ipt.version || "iptables-nft"}). `,
    "Почти все правила создаёт Docker — их панель показывает, но менять не даёт. Свои постоянные правила лучше задавать через зоны firewalld, rich rules или прямые правила (direct) ниже: они переживут перезагрузку. Удаление правила здесь действует только до перезагрузки — например, чтобы снять блокировку, поставленную Wazuh."));
  const bar = h("div", { class: "row-flex mb" },
    h("div", { class: "seg" }, ["ipv4", "ipv6"].map((f) => h("button", { class: fam === f ? "on" : "", onclick: () => setUi(hid, "ifam", f) }, f === "ipv4" ? "IPv4" : "IPv6"))),
    h("div", { class: "seg" }, Object.keys(tabs).map((t) => h("button", { class: tbl === t ? "on" : "", onclick: () => setUi(hid, "itbl", t) }, t, h("span", { class: "dim" }, " " + tabs[t].rules.length)))),
    h("label", { class: "chk", style: { marginLeft: "auto" } }, h("input", { type: "checkbox", checked: showRaw, onchange: (e) => setUi(hid, "iraw", e.target.checked) }), "показать iptables-save"));
  root.appendChild(bar);
  if (showRaw) {
    root.appendChild(h("div", { class: "card mb" }, h("div", { class: "hd" }, h("h3", null, `${fam === "ipv4" ? "iptables" : "ip6tables"}-save -c`)), h("pre", { class: "code" }, (ipt[fam] || {}).text || "")));
  }
  if (!tbl) {
    root.appendChild(h("div", { class: "card" }, h("div", { class: "empty" }, "Правил нет")));
  } else {
    const t = tabs[tbl];
    for (const [ch, info] of Object.entries(t.chains)) {
      const rules = t.rules.filter((r) => r.chain === ch);
      const managed = managedBy(ch);
      root.appendChild(h("div", { class: "card chain" },
        h("div", { class: "hd" }, h("h3", { class: "mono" }, ch), h("span", { class: "pol muted" }, `политика ${info.policy}`),
          managed ? h("span", { class: "tag" }, managed) : null,
          h("div", { class: "r muted small" }, `${rules.length} ${plural(rules.length, "правило", "правила", "правил")}`, info.packets ? ` · ${fmtN(info.packets)} пакетов` : "")),
        rules.length ? h("div", { class: "bd flush" }, h("table", { class: "tbl" }, h("tbody", null, rules.map((r, i) => {
          const jm = (r.rule.match(/ -[jg] (\S+)/) || [])[1] || "";
          const dockerish = managed || managedBy(jm) || /docker|br-[0-9a-f]{6}|virbr/.test(r.rule);
          const qd = isQueued(hid, (o) => o.op === "iptables" && o.rule === r.rule && o.table === tbl);
          return h("tr", { class: qd ? "queued" : "" }, h("td", { class: "num dim", style: { width: "36px" } }, i + 1), h("td", null, fmtRule(r.rule)),
            h("td", { class: "num dim small nowrap", style: { width: "120px" } }, r.packets != null ? `${fmtN(r.packets)} / ${fmtB(r.bytes)}` : ""),
            h("td", { class: "acts", style: { width: "70px" } }, dockerish ? null : h("button", { class: "btn sm ghost", title: "Удалить до перезагрузки", onclick: () => enqueue(hid, { op: "iptables", action: "delete", family: fam, table: tbl, rule: r.rule }) }, svg(ICON.trash))));
        })))) : h("div", { class: "bd dim small" }, "правил нет")));
    }
  }
  // direct rules
  const fw = v.state.firewalld || {};
  if (fw.running) {
    const d = { family: h("select", null, h("option", null, "ipv4"), h("option", null, "ipv6")), table: h("select", null, ["filter", "nat", "mangle", "raw"].map((x) => h("option", null, x))),
      chain: h("input", { type: "text", value: "INPUT", style: { width: "110px" } }), priority: h("input", { type: "number", value: 0, style: { width: "70px" } }),
      args: h("input", { type: "text", placeholder: "-s 203.0.113.5 -j DROP", style: { width: "280px" } }) };
    const perm = new Set(fw.direct_rules_permanent || []);
    const all = [...new Set([...(fw.direct_rules || []), ...(fw.direct_rules_permanent || [])])];
    root.appendChild(h("div", { class: "card mt" }, h("div", { class: "hd" }, h("h2", null, "Прямые правила firewalld (direct)"), h("span", { class: "muted" }, "сохраняются в /etc/firewalld/direct.xml")),
      h("div", { class: "bd" },
        all.length ? h("table", { class: "tbl mb" }, h("tbody", null, all.map((r) => {
          const p = r.split(" ");
          return h("tr", null, h("td", { class: "mono small" }, r), h("td", null, perm.has(r) ? h("span", { class: "tag" }, "постоянное") : h("span", { class: "tag warn" }, "только сейчас")),
            h("td", { class: "acts" }, h("button", { class: "btn sm ghost", onclick: () => enqueue(hid, { op: "direct", action: "remove", family: p[0], table: p[1], chain: p[2], priority: +p[3], args: p.slice(4).join(" ") }) }, svg(ICON.trash))));
        }))) : h("div", { class: "dim mb" }, "Прямых правил нет."),
        h("div", { class: "form-row" }, field("Семейство", d.family), field("Таблица", d.table), field("Цепочка", d.chain), field("Приоритет", d.priority), field("Аргументы iptables", d.args),
          h("button", { class: "btn sm", onclick: () => { if (!d.args.value.trim()) return; enqueue(hid, { op: "direct", action: "add", family: d.family.value, table: d.table.value, chain: d.chain.value.trim(), priority: +d.priority.value, args: d.args.value.trim() }); } }, svg(ICON.plus), "В очередь")))));
  }
}

function managedBy(ch) {
  if (/^DOCKER/.test(ch)) return "Docker";
  if (/^LIBVIRT/.test(ch)) return "libvirt";
  if (/^kesl/i.test(ch)) return "Kaspersky";
  if (/^(f2b-|fail2ban)/.test(ch)) return "fail2ban";
  if (/^(CNI|KUBE|cali|flannel|NETAVARK)/.test(ch)) return "контейнеры";
  return null;
}

function fmtRule(rule) {
  const el = h("span", { class: "rule" });
  const toks = rule.replace(/^-A \S+\s*/, "").split(/(\s+)/);
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t === "-j" || t === "-g") {
      el.append(h("span", { class: "opt" }, t), toks[i + 1] || "");
      const tg = toks[i + 2];
      if (tg) el.append(h("span", { class: "tgt " + tg }, tg));
      i += 2;
    } else if (/^-/.test(t) || /^!$/.test(t)) el.append(h("span", { class: "opt" }, t));
    else el.append(t);
  }
  return el;
}
const fmtN = (n) => (n >= 1e6 ? (n / 1e6).toFixed(1) + " млн" : n >= 1e3 ? (n / 1e3).toFixed(1) + " тыс" : String(n || 0));
const fmtB = (b) => (b >= 1 << 30 ? (b / (1 << 30)).toFixed(1) + " ГБ" : b >= 1 << 20 ? (b / (1 << 20)).toFixed(1) + " МБ" : b >= 1024 ? (b / 1024).toFixed(0) + " КБ" : (b || 0) + " Б");

// =================================================================== nftables
function vNft(root, hid, v) {
  const nft = v.state.nftables || {};
  root.appendChild(h("div", { class: "note mb" }, "Таблицы nftables на этих хостах создают firewalld (inet firewalld) и iptables-nft (ip/ip6 filter, nat, …) — то есть Docker. Редактировать их напрямую не нужно: изменения делаются через firewalld, а таблицы iptables-nft перезапишутся при перезапуске Docker. Здесь — просмотр."));
  const sel = ui(hid, "ntab", null);
  const grid = h("div", { class: "grid side" });
  grid.appendChild(h("div", { class: "card", style: { alignSelf: "start" } }, h("div", { class: "hd" }, h("h3", null, "Таблицы"), h("span", { class: "muted small" }, nft.version || "")),
    h("div", { class: "zlist" }, (nft.tables || []).map((t) => h("button", { class: sel === `${t.family} ${t.name}` ? "active" : "", onclick: () => setUi(hid, "ntab", `${t.family} ${t.name}`) },
      h("span", { class: "mono" }, `${t.family} ${t.name}`), h("span", { class: "z-meta" }, `${t.rules ?? "?"} · ${t.managed_by || ""}`))))));
  const right = h("div", { class: "card" });
  if (!sel) right.appendChild(h("div", { class: "empty" }, "Выберите таблицу слева"));
  else {
    const [fam, name] = sel.split(" ");
    right.appendChild(h("div", { class: "hd" }, h("h3", { class: "mono" }, `table ${sel}`)));
    const pre = h("pre", { class: "code" }, "загрузка…");
    right.appendChild(pre);
    const cacheKey = `nft:${sel}`;
    if (S.ui[hid][cacheKey]) pre.textContent = S.ui[hid][cacheKey];
    else api(`/api/hosts/${hid}/nft/${fam}/${name}`).then((d) => { S.ui[hid][cacheKey] = d.text || d.error || ""; pre.textContent = S.ui[hid][cacheKey]; })
      .catch((e) => { pre.textContent = "Ошибка: " + e.message; });
  }
  grid.appendChild(right);
  root.appendChild(grid);
}

// =================================================================== SELinux
function vSelinux(root, hid, v) {
  const se = v.state.selinux || {};
  if (se.tools === false) {
    root.appendChild(h("div", { class: "card" }, h("div", { class: "empty" }, h("h3", null, "SELinux не установлен"), h("p", null, "На хосте нет утилит SELinux (libselinux-utils, policycoreutils)."))));
    return;
  }
  const mode = se.mode;
  const top = h("div", { class: "grid g2 mb" });
  const cfg = h("select", null, ["enforcing", "permissive", "disabled"].map((m) => h("option", { selected: m === se.config_mode }, m)));
  top.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Режим")), h("div", { class: "bd" },
    h("dl", { class: "kv" },
      h("dt", null, "Сейчас"), h("dd", null, mode === "Disabled" ? h("span", { class: "tag bad" }, "Disabled") :
        h("div", { class: "seg" }, ["Enforcing", "Permissive"].map((m) => h("button", { class: mode === m ? "on" : "", onclick: () => mode !== m && enqueue(hid, { op: "selinux-enforce", value: m === "Enforcing" ? "1" : "0" }) }, m)))),
      h("dt", null, "После перезагрузки"), h("dd", null, h("div", { class: "row-flex" }, cfg, h("button", { class: "btn sm", onclick: () => cfg.value !== se.config_mode && enqueue(hid, { op: "selinux-config", value: cfg.value }) }, "Задать"))),
      h("dt", null, "Политика"), h("dd", null, se.policy || "—"),
      h("dt", null, "semanage"), h("dd", null, se.semanage ? "есть" : "нет (policycoreutils-python-utils)")),
    mode === "Disabled" ? h("div", { class: "note warn mt" }, "SELinux выключен. Чтобы включить: задайте режим permissive «после перезагрузки», перезагрузите хост (файлы будут заново размечены — это долго), проверьте журнал отказов и только потом переходите на enforcing. На Raspberry Pi сначала убедитесь, что ядро собрано с поддержкой SELinux.") : null,
    mode === "Permissive" ? h("div", { class: "note warn mt" }, "Permissive: нарушения журналируются, но не блокируются.") : null)));
  const avc = se.avc_today || [];
  top.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Отказы за сегодня"), h("span", { class: "muted" }, avc.length),
    h("div", { class: "r" }, h("button", { class: "btn sm", onclick: (e) => loadAvc(hid, e.currentTarget) }, "За неделю…"))),
    h("div", { class: "bd flush tbl-wrap", style: { maxHeight: "260px" } }, avc.length ? avcTable(avc.slice(-50).reverse()) : h("div", { class: "empty" }, mode === "Disabled" ? "SELinux выключен" : "Отказов нет"))));
  root.appendChild(top);
  if (mode === "Disabled") return;
  const grid = h("div", { class: "grid g2" });
  // booleans
  const bq = ui(hid, "bq", ""), bOnly = ui(hid, "bonly", true);
  const local = new Set(se.booleans_local || []);
  const bools = (se.booleans || []).filter((b) => (!bOnly || local.has(b.name) || (b.default !== null && b.state !== b.default) || isQueued(hid, (o) => o.op === "sebool" && o.name === b.name)) &&
    (!bq || (b.name + " " + b.description).toLowerCase().includes(bq.toLowerCase())));
  const btb = h("tbody", null, bools.slice(0, 300).map((b) => {
    const qo = queued(hid).find((o) => o.op === "sebool" && o.name === b.name);
    const st = qo ? qo.value === "on" : b.state;
    return h("tr", null, h("td", null, h("div", { class: "mono" }, b.name), h("div", { class: "dim small" }, b.description)),
      h("td", { class: "small dim nowrap" }, b.default === null || b.default === undefined ? "" : "по умолч. " + (b.default ? "вкл" : "выкл")),
      h("td", { class: "acts" }, h("label", { class: "switch" + (qo ? " queued" : "") }, h("input", { type: "checkbox", checked: st, onchange: (e) => enqueue(hid, { op: "sebool", name: b.name, value: e.target.checked ? "on" : "off", persist: true }) }), h("span"))));
  }));
  grid.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Переключатели (booleans)"), h("span", { class: "muted" }, `${(se.booleans || []).length}`)),
    h("div", { class: "toolbar" }, h("input", { type: "search", placeholder: "поиск: httpd, samba…", value: bq, style: { flex: 1 }, onchange: (e) => setUi(hid, "bq", e.target.value) }),
      h("label", { class: "chk small" }, h("input", { type: "checkbox", checked: bOnly, onchange: (e) => setUi(hid, "bonly", e.target.checked) }), "только изменённые")),
    h("div", { class: "bd flush tbl-wrap", style: { maxHeight: "480px" } }, h("table", { class: "tbl" }, btb)),
    bools.length > 300 ? h("div", { class: "bd dim small" }, `показано 300 из ${bools.length} — уточните поиск`) : null));
  // ports
  const pt = { type: h("input", { type: "text", list: "dl-setypes-" + hid, placeholder: "http_port_t", style: { width: "170px" } }), proto: h("select", null, ["tcp", "udp"].map((p) => h("option", null, p))), port: h("input", { type: "text", placeholder: "8585", style: { width: "90px" } }) };
  const lk = h("input", { type: "text", placeholder: "какой тип у порта? 8080", style: { width: "200px" } });
  const lkRes = h("div", { class: "small mt" });
  lk.addEventListener("input", () => {
    const p = parseInt(lk.value, 10);
    lkRes.innerHTML = "";
    if (!p) return;
    const hits = (se.ports || []).filter((x) => x.ports.some((r) => { const [a, b] = r.split("-").map(Number); return p >= a && p <= (b || a); }));
    lkRes.append(hits.length ? hits.map((x) => h("div", null, h("span", { class: "mono" }, x.type), ` (${x.proto}) — ${x.ports.join(", ")}`)) : h("span", { class: "dim" }, "порт не размечен — используется тип по умолчанию (unreserved/reserved)"));
  });
  const pl = se.ports_local || [];
  grid.appendChild(h("div", { class: "grid", style: { alignContent: "start" } },
    h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Метки портов"), h("span", { class: "muted" }, "локальные изменения")),
      h("div", { class: "bd" },
        pl.length ? h("table", { class: "tbl mb" }, h("tbody", null, pl.flatMap((x) => x.ports.map((p) => h("tr", null, h("td", { class: "mono" }, x.type), h("td", null, x.proto), h("td", { class: "mono" }, p),
          h("td", { class: "acts" }, h("button", { class: "btn sm ghost", onclick: () => enqueue(hid, { op: "seport", action: "delete", type: x.type, proto: x.proto, port: p }) }, svg(ICON.trash)))))))) : h("div", { class: "dim mb" }, "Локальных меток нет."),
        queued(hid).filter((o) => o.op === "seport" && o.action === "add").map((o) => h("div", { class: "chip new" }, `+ ${o.port}/${o.proto} ${o.type}`)),
        h("div", { class: "form-row" }, pt.type, pt.proto, pt.port, h("datalist", { id: "dl-setypes-" + hid }, [...new Set((se.ports || []).map((x) => x.type))].map((t) => h("option", { value: t }))),
          h("button", { class: "btn sm", onclick: () => { if (!/_t$/.test(pt.type.value) || !/^\d+(-\d+)?$/.test(pt.port.value)) { toast("Тип оканчивается на _t, порт — число", "err"); return; } enqueue(hid, { op: "seport", action: "add", type: pt.type.value.trim(), proto: pt.proto.value, port: pt.port.value.trim() }); } }, svg(ICON.plus), "Пометить")),
        h("div", { class: "dim small mt" }, "Нужно, когда служба слушает нестандартный порт: например, веб-сервер на 8585 — пометить как http_port_t."),
        h("div", { class: "section-title" }, "Поиск"), lk, lkRes)),
    se.fcontext_local && se.fcontext_local.length ? h("div", { class: "card" }, h("div", { class: "hd" }, h("h3", null, "Локальные контексты файлов")), h("pre", { class: "code" }, se.fcontext_local.join("\n"))) : null,
    se.permissive_domains && se.permissive_domains.length ? h("div", { class: "card" }, h("div", { class: "hd" }, h("h3", null, "Домены в permissive")), h("div", { class: "bd" }, se.permissive_domains.map((d) => h("span", { class: "chip" }, d)))) : null));
  root.appendChild(grid);
}

function avcTable(list) {
  return h("table", { class: "tbl" }, h("thead", null, h("tr", null, ["Время", "Процесс", "Запрет", "Объект", "Контексты"].map((t) => h("th", null, t)))),
    h("tbody", null, list.map((a) => h("tr", null, h("td", { class: "nowrap small" }, a.time || ""), h("td", null, a.comm || "?"),
      h("td", { class: "mono small" }, (a.perms || []).join(" ")), h("td", { class: "small" }, `${a.tclass || ""} ${a.name || a.path || a.dest || ""}`),
      h("td", { class: "mono small dim" }, `${(a.scontext || "").split(":")[2] || ""} → ${(a.tcontext || "").split(":")[2] || ""}`)))));
}

async function loadAvc(hid, btn) {
  busy(btn);
  try {
    const d = await api(`/api/hosts/${hid}/avc?since=this-week`);
    modal({ title: `Отказы SELinux за неделю: ${d.events.length}`, wide: true, body: d.events.length ? h("div", { class: "tbl-wrap" }, avcTable(d.events.slice().reverse())) : h("div", { class: "empty" }, "Отказов нет") });
  } catch (e) { toast(e.message, "err"); }
  busy(btn, false);
}

// =================================================================== fail2ban
function vF2b(root, hid, v) {
  const f = v.state.fail2ban || {};
  if (!f.active) {
    root.appendChild(h("div", { class: "card" }, h("div", { class: "empty" }, h("h3", null, f.installed === false ? "fail2ban не установлен" : "fail2ban не запущен"),
      h("p", null, "Перебор паролей SSH ничем не ограничен. Установка: dnf install fail2ban; затем включите jail sshd."))));
    return;
  }
  root.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Jails"), h("span", { class: "muted" }, (f.jails || []).length)),
    h("div", { class: "bd flush" }, h("table", { class: "tbl" }, h("thead", null, h("tr", null, ["Jail", "Неудачных сейчас", "Всего банов", "В бане", "Исключения (ignoreip)"].map((t) => h("th", null, t)))),
      h("tbody", null, (f.jails || []).map((j) => h("tr", null, h("td", null, h("b", null, j.name)), h("td", { class: "num" }, j.currently_failed ?? "—"), h("td", { class: "num" }, j.total_banned ?? "—"),
        h("td", null, (j.banned || []).length ? (j.banned || []).map((ip) => {
          const qd = isQueued(hid, (o) => o.op === "f2b-unban" && o.ip === ip);
          return h("span", { class: "chip" + (qd ? " del" : "") }, ip, h("button", { title: "Снять бан", onclick: () => enqueue(hid, { op: "f2b-unban", ip }) }, "×"));
        }) : h("span", { class: "dim" }, "никого")),
        h("td", null, (j.ignoreip || []).map((x) => h("span", { class: "chip" }, x)))))))),
    h("div", { class: "bd dim small" }, "Адреса панели и вашего Mac добавлены в ignoreip скриптом zaslon-provision.sh.")));
}

// =================================================================== history
async function vHistory(root, hid, v) {
  const pend = S.pending[hid] || [];
  if (pend.length) {
    root.appendChild(h("div", { class: "card mb" }, h("div", { class: "hd" }, h("h2", null, "Ждут подтверждения")),
      h("div", { class: "bd" }, pend.map((p) => h("div", { class: "row-flex" }, h("span", { class: "mono" }, p.id), h("span", { class: "muted" }, p.note || ""),
        h("span", { class: "spacer" }), h("button", { class: "btn sm danger", onclick: () => txAction(hid, p.id, "rollback") }, "Откатить"), h("button", { class: "btn sm primary", onclick: () => txAction(hid, p.id, "confirm") }, "Подтвердить"))))));
  }
  const box = h("div", { class: "grid" }, h("div", { class: "loading" }, h("span", { class: "spin" }), "Загрузка журнала…"));
  root.appendChild(box);
  try {
    const d = await api(`/api/hosts/${hid}/history`);
    box.innerHTML = "";
    const st = { confirmed: ["подтверждено", "ok"], pending: ["ждёт", "warn"], rolled_back: ["откачено", "warn"], failed: ["не применено", "bad"], applying: ["применяется", ""] };
    box.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Транзакции на хосте"), h("span", { class: "muted" }, "из /var/lib/zaslon/tx")),
      h("div", { class: "bd flush tbl-wrap" }, d.remote && d.remote.length ? h("table", { class: "tbl" }, h("thead", null, h("tr", null, ["Когда", "Статус", "Что сделано", "Комментарий"].map((t) => h("th", null, t)))),
        h("tbody", null, d.remote.map((t) => h("tr", null, h("td", { class: "nowrap" }, dt(t.created)), h("td", null, h("span", { class: "tag " + (st[t.status] || ["", ""])[1] }, (st[t.status] || [t.status])[0]), t.rolled_back_by ? h("div", { class: "dim small" }, t.rolled_back_by === "timer" ? "по таймеру" : "вручную") : null),
          h("td", { class: "small" }, (t.results || []).map((r) => h("div", { class: r.ok ? "" : "muted" }, r.text)), t.error ? h("div", { style: { color: "var(--bad)" } }, t.error) : null),
          h("td", { class: "small muted" }, t.note || ""))))) : h("div", { class: "empty" }, d.remote_error ? "Журнал хоста недоступен: " + d.remote_error : "Изменений ещё не было"))));
    box.appendChild(h("div", { class: "card" }, h("div", { class: "hd" }, h("h2", null, "Действия в панели")), h("div", { class: "bd flush tbl-wrap" }, auditTable(d.local))));
  } catch (e) {
    box.innerHTML = "";
    box.appendChild(h("div", { class: "err-box" }, e.message));
  }
}
