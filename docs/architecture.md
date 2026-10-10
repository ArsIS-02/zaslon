# Устройство

```
браузер ──HTTP──▶ панель (Starlette, Docker) ──ssh sec_fw-admin──▶ zaslon-ssh ──sudo──▶ zaslon-helper ──▶ firewall-cmd, iptables, nft,
                    │  app/transport.py              (принудительная команда)          (root, JSON)       semanage, setsebool, fail2ban-client
                    │  app/analysis.py — порты, Docker, замечания
                    │  app/report.py   — HTML/PDF
                    └─ /data: хосты, состояние, журнал, ключ, known_hosts
```

## Панель

| Модуль | Что делает |
|---|---|
| `app/main.py` | HTTP API, вход по паролю, защита от CSRF, блокировка «один запрос на хост за раз» |
| `app/transport.py` | вызов helper через системный `ssh` (ControlMaster для повторных запросов, новое соединение для подтверждения); демо-транспорт |
| `app/analysis.py` | «смотрящие в сеть» зоны, таблица портов, опубликованные Docker порты, замечания, сводка |
| `app/report.py` | отчёт A4 (шрифты встроены) и PDF через `chromium --headless --print-to-pdf` |
| `app/store.py` | JSON-файлы в `/data`, журнал действий |
| `static/` | интерфейс: `app.js` (вкладки, обзор, очередь, применение), `host.js` (разделы хоста), `ops.js` (описания операций) |

Каждая команда helper вызывается так:

```
ssh -i /data/keys/zaslon_ed25519 -o BatchMode=yes … sec_fw-admin@<хост> \
    sudo -n /usr/local/libexec/zaslon/zaslon-helper <подкоманда> --peer "${SSH_CLIENT%% *}"
```

`zaslon-ssh` разбирает эту строку, отбрасывает присланный `--peer` и подставляет настоящий адрес из `SSH_CLIENT`.

## API панели

Все ответы — JSON. Изменяющие запросы требуют заголовок `X-Zaslon: 1`.

| Метод и путь | Назначение |
|---|---|
| `GET /api/hosts` | список хостов со сводками |
| `POST /api/hosts` | добавить хост `{name, address, port, user, role, location, tags, description}` |
| `PUT /api/hosts/{id}` · `DELETE /api/hosts/{id}` | изменить · удалить |
| `POST /api/hosts/refresh` | опросить все хосты |
| `GET /api/hosts/{id}/state[?refresh=1]` | состояние хоста + порты, замечания, сводка |
| `POST /api/hosts/{id}/test` | проверить подключение (версия helper) |
| `DELETE /api/hosts/{id}/hostkey` | сбросить отпечаток SSH |
| `GET /api/hosts/{id}/nft/{family}/{table}` | текст таблицы nftables |
| `GET /api/hosts/{id}/avc?since=today\|this-week\|…` | отказы SELinux |
| `GET /api/hosts/{id}/history` | транзакции на хосте и журнал панели |
| `POST /api/hosts/{id}/apply` | `{ops: [...], rollback: 60, auto_confirm: true, note: ""}` |
| `POST /api/hosts/{id}/tx/{tx}/confirm` · `/rollback` | подтвердить · откатить |
| `GET /api/hosts/{id}/report.html[?download=1]` · `report.pdf` | отчёт |
| `GET/PUT /api/settings` · `GET /api/audit` | настройки · журнал действий |
| `GET /healthz` | проверка живости (без пароля) |

## zaslon-helper

Подкоманды: `version`, `collect`, `nft-table FAMILY NAME`, `avc --since …`, `apply` (JSON на stdin), `confirm ID`, `rollback ID`, `pending`, `history`. Ответ — одна строка JSON.

### collect

Возвращает: `facts` (ОС, ядро, модель, адреса), `firewalld` (зоны runtime и permanent, политики, ipset, direct, каталог служб из XML, расхождения), `iptables` (`iptables-save -c` по таблицам), `nftables` (таблицы и кто их создал), `listening` (`ss -tulpn`), `selinux` (режимы, booleans, метки портов, локальные контексты, permissive-домены, AVC за день), `fail2ban` (jails, баны, ignoreip), `sshd` (ключевые параметры `sshd -T`), `peer_info` (в какую зону попадает панель и разрешён ли ей SSH), `pending` (неподтверждённые транзакции).

### Операции `apply`

У firewalld-операций есть `"runtime"` и `"permanent"` (по умолчанию обе `true`); `zone` по умолчанию — зона по умолчанию.

| `op` | Поля | Действие |
|---|---|---|
| `port` | `action` add/remove, `port` (`8080` или `8000-8010`), `proto` | порт в зоне |
| `service` | `action`, `service` | служба в зоне |
| `source` | `action`, `source` (адрес/сеть или `ipset:имя`) | привязка источника к зоне |
| `rich` | `action`, `rule` | rich rule |
| `forward-port` | `action`, `port`, `proto`, `toport`, `toaddr` | проброс порта |
| `icmp-block` | `action`, `icmptype` | блокировка ICMP |
| `protocol` | `action`, `protocol` | протокол в зоне |
| `masquerade` | `action`, `zone` | маскарадинг |
| `interface` | `action` add/change/remove, `interface` | интерфейс в зоне |
| `target` | `zone`, `target` (default/ACCEPT/DROP/%%REJECT%%) | политика зоны; перечитывает firewalld и перезапускает fail2ban |
| `default-zone` | `zone` | зона по умолчанию |
| `log-denied` | `value` (off/unicast/broadcast/multicast/all) | журнал отброшенных пакетов |
| `unit` | `unit` (firewalld/fail2ban), `action` start/stop/enable/disable | служба |
| `direct` | `action`, `family`, `table`, `chain`, `priority`, `args` | прямое правило firewalld |
| `iptables` | `action` delete/insert/append, `family`, `table`, `rule` (`-A ЦЕПОЧКА …`) | правило iptables до перезагрузки |
| `selinux-enforce` | `value` `1`/`0` | Enforcing/Permissive сейчас |
| `selinux-config` | `value` enforcing/permissive/disabled | режим после перезагрузки |
| `sebool` | `name`, `value` on/off, `persist` | переключатель |
| `seport` | `action` add/delete, `type`, `proto`, `port` | метка порта |
| `f2b-unban` | `ip` | снять бан |

### Транзакция

```json
{"id": "20261010014016-6aa4d2", "status": "pending", "deadline": 1791577341,
 "results": [{"op": 0, "ok": true, "text": "runtime: --remove-port 25/tcp (зона public)"}],
 "inverse": [{"op": "port", "action": "add", "zone": "public", "port": "25", "proto": "tcp", "runtime": true, "permanent": false}],
 "guard": {"ssh_allowed": true, "reason": "зона public (interface enp3s0): служба ssh"}}
```

Статусы: `applying` → `pending` → `confirmed` | `rolled_back`; при ошибке — `failed` (всё возвращено; если откат прошёл не полностью — `undo_incomplete`, и `rollback ID` можно повторить). Файлы — `/var/lib/zaslon/tx/<id>.json` и копия `/etc/firewalld` — `<id>-firewalld.tgz`; хранится около 60 последних. Таймер — `zaslon-rb-<id>.timer`.

## Демо-режим

`ZASLON_DEMO=1` или флажок у хоста: состояние берётся из `app/demo/<адрес>.json`, изменения имитируются в памяти и откатываются по таймеру так же, как настоящие. Демо-данные строит `tools/make_demo.py` (вымышленная сеть `10.42.0.0/24`).
