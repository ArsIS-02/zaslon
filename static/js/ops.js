// Human-readable descriptions of change operations + queue helpers.

const LAYER = (o) => (o.permanent === false ? " — только до перезагрузки" : o.runtime === false ? " — только в сохранённой конфигурации" : "");
const Z = (o) => (o.zone ? ` в зоне ${o.zone}` : "");

export function describe(o) {
  const add = o.action === "add";
  switch (o.op) {
    case "port": return `${add ? "Открыть" : "Закрыть"} порт ${o.port}/${o.proto || "tcp"}${Z(o)}${LAYER(o)}`;
    case "service": return `${add ? "Разрешить" : "Убрать"} службу ${o.service}${Z(o)}${LAYER(o)}`;
    case "source": return `${add ? "Привязать" : "Отвязать"} источник ${o.source}${add ? " к зоне " + o.zone : " от зоны " + o.zone}${LAYER(o)}`;
    case "rich": return `${add ? "Добавить" : "Удалить"} rich rule${Z(o)}: ${o.rule}${LAYER(o)}`;
    case "forward-port": return `${add ? "Добавить" : "Удалить"} проброс ${o.port}/${o.proto || "tcp"} → ${o.toaddr || ""}${o.toport ? ":" + o.toport : ""}${Z(o)}${LAYER(o)}`;
    case "icmp-block": return `${add ? "Блокировать" : "Разблокировать"} ICMP ${o.icmptype}${Z(o)}${LAYER(o)}`;
    case "protocol": return `${add ? "Разрешить" : "Убрать"} протокол ${o.protocol}${Z(o)}${LAYER(o)}`;
    case "masquerade": return `${add ? "Включить" : "Выключить"} маскарадинг${Z(o)}${LAYER(o)}`;
    case "interface": return `Интерфейс ${o.interface} → зона ${o.zone}${LAYER(o)}`;
    case "target": return `Политика зоны ${o.zone} по умолчанию: ${o.target} (с перезагрузкой правил firewalld)`;
    case "default-zone": return `Зона по умолчанию → ${o.zone}`;
    case "log-denied": return `Журналировать отброшенные пакеты: ${o.value}`;
    case "unit": return { start: "Запустить", stop: "Остановить", enable: "Включить автозапуск", disable: "Выключить автозапуск" }[o.action] + ` ${o.unit}`;
    case "direct": return `${add ? "Добавить" : "Удалить"} прямое правило: ${o.family || "ipv4"} ${o.table || "filter"} ${o.chain} ${o.priority || 0} ${o.args}${LAYER(o)}`;
    case "iptables": return `${o.action === "delete" ? "Удалить" : "Добавить"} правило ${o.family === "ipv6" ? "ip6tables" : "iptables"} -t ${o.table}: ${o.rule} — до перезагрузки`;
    case "selinux-enforce": return `SELinux сейчас: ${String(o.value) === "1" ? "Enforcing" : "Permissive"} (до перезагрузки)`;
    case "selinux-config": return `SELinux после перезагрузки: ${o.value}`;
    case "sebool": return `Переключатель ${o.name} → ${o.value === "on" ? "вкл" : "выкл"}${o.persist === false ? " (до перезагрузки)" : ""}`;
    case "seport": return `${o.action === "add" ? "Пометить" : "Снять метку"} порт ${o.port}/${o.proto || "tcp"} ${o.action === "add" ? "как" : ""} ${o.type}`;
    case "f2b-unban": return `fail2ban: снять бан с ${o.ip}`;
    default: return JSON.stringify(o);
  }
}

export function risky(o) {
  if (["interface", "target", "default-zone", "unit", "direct", "iptables", "source"].includes(o.op)) return true;
  if (["port", "service"].includes(o.op) && o.action === "remove") return true;
  if (o.op === "rich" && /\b(drop|reject)\b/.test(o.rule || "")) return true;
  if (o.op === "selinux-enforce" && String(o.value) === "1") return true;
  return false;
}

export function touchesSSH(o) {
  return (o.op === "service" && o.service === "ssh" && o.action === "remove") ||
    (o.op === "port" && String(o.port) === "22" && o.action === "remove") ||
    (o.op === "unit" && o.unit === "firewalld" && o.action === "start") ||
    o.op === "target" || o.op === "default-zone" || o.op === "interface";
}

const KEYS = ["op", "action", "zone", "port", "proto", "service", "source", "rule", "icmptype", "protocol", "interface",
  "target", "value", "unit", "family", "table", "chain", "priority", "args", "name", "type", "ip", "toport", "toaddr", "runtime", "permanent", "persist"];

export function key(o) {
  return KEYS.map((k) => (o[k] === undefined ? "" : String(o[k]))).join("|");
}

const OPP = { add: "remove", remove: "add", start: "stop", stop: "start", enable: "disable", disable: "enable", delete: "add" };

export function inverseKey(o) {
  if (["port", "service", "source", "rich", "forward-port", "icmp-block", "protocol", "masquerade", "direct"].includes(o.op)) {
    return key({ ...o, action: OPP[o.action] });
  }
  if (o.op === "unit") return key({ ...o, action: OPP[o.action] });
  if (o.op === "seport") return key({ ...o, action: o.action === "add" ? "delete" : "add" });
  return null;
}

export function riskText(o) {
  if (touchesSSH(o)) return "затрагивает SSH";
  if (["port", "service"].includes(o.op) && o.action === "remove") return "закрывает доступ";
  if (o.op === "iptables") return "до перезагрузки";
  if (o.op === "rich" && /\b(drop|reject)\b/.test(o.rule || "")) return "блокирует трафик";
  if (o.op === "rich" && !/(service|port|protocol|icmp|forward|source-port)/.test(o.rule || "") && /accept/.test(o.rule || "")) return "разрешает всё";
  if (risky(o)) return "рискованно";
  return "";
}
