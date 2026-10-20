// Тексты справки на русском и английском. Разделы выводятся в порядке массива.
export const HELP = {
  ru: {
    title: "Справка",
    lead: "ZaSlon управляет firewalld, портами, службами и SELinux на хостах РЕД ОС — всё из браузера, без терминала на хосте после установки агента.",
    sections: [
      {
        id: "start", title: "С чего начать",
        paras: [
          "Порядок работы простой: установите агент на хост командой из раздела «Установка агента», добавьте хост в панели, затем меняйте порты, службы и режимы на странице хоста.",
          "Каждое изменение сначала применяется с таймером отката. Если вы не подтвердите его за указанное время, оно откатится само — это защита от случайной блокировки.",
        ],
      },
      {
        id: "agent", title: "Установка агента на хост",
        paras: [
          "Агент — небольшой скрипт на python3, который ставится на хост один раз. Панель подключается к хосту по SSH своим ключом. Пользователь sec_fw-admin может запустить через sudo только агент: без пароля и без командной оболочки.",
          "Требования: РЕД ОС, python3, curl, sshd на порту 22, доступ с панели к хосту по SSH. Без firewalld агент установится, но панель сообщит, что правила не действуют.",
        ],
        steps: [
          "Укажите адрес панели так, как его видит хост (например https://zaslon.apps.monitoring.test). Если панель на HTTPS с внутренним сертификатом, команда сама загрузит и проверит сертификат.",
          "Укажите имя и адрес хоста — они понадобятся, чтобы потом добавить хост в панели.",
          "Скопируйте команду и выполните её на хосте от root (или через sudo).",
          "Дождитесь строки «ZaSlon: агент установлен, хост зарегистрирован в панели». Хост появится в списке сам — ничего добавлять вручную не нужно.",
        ],
        example: {
          title: "Пример",
          text: "Хост homeserver, адрес 192.168.1.56. Команда установит агент, создаст пользователя sec_fw-admin и проверит связь с панелью.",
        },
        removal: "Удаление: команда «Удалить агент» снимает агент, пользователя sec_fw-admin и правило sudo. Таймеры откатов, которые ещё не сработали, при необходимости остановите вручную.",
      },
      {
        id: "hosts", title: "Хосты",
        paras: [
          "«Добавить хост» проверяет связь с хостом. Если хост временно недоступен, его можно добавить без проверки. «Удалить хост» убирает хост только из панели — на самом хосте ничего не меняется.",
          "Точки статуса: зелёная — firewalld работает; серая — остановлен; красная — хост недоступен; синяя — идёт проверка; жёлтая с цифрой — есть изменения, ожидающие подтверждения.",
        ],
      },
      {
        id: "ports", title: "Порты",
        paras: [
          "Откройте страницу хоста, блок «Порт»: выберите зону, укажите порт или диапазон, протокол TCP или UDP и время отката. Изменение действует сразу и сохраняется после перезагрузки.",
          "Пока изменение не подтверждено, внизу справа идёт обратный отсчёт. «Оставить» подтверждает, «Откатить» отменяет.",
        ],
        example: {
          title: "Пример: открыть порт 8080/tcp на 2 минуты",
          text: "Зона: public · Порт: 8080 · Протокол: TCP · Откат через: 120 с → «Открыть». Если за 2 минуты нажать «Оставить», порт останется открытым; если нет — закроется сам.",
        },
      },
      {
        id: "services", title: "Службы",
        paras: [
          "Службы — готовые наборы портов, например http, https или ssh. Добавляются и убираются так же, как порты, крестиком в списке зоны.",
        ],
        example: {
          title: "Пример: разрешить https в зоне public",
          text: "Зона: public → поле «Служба»: https → «Добавить службу».",
        },
      },
      {
        id: "firewalld", title: "firewalld",
        paras: [
          "Переключатели «Работает» и «Автозапуск» запускают и останавливают firewalld. Без работающего firewalld правила не действуют, поэтому остановка тоже откатывается по таймеру.",
        ],
        example: {
          title: "Пример: временно остановить firewalld для диагностики",
          text: "Выключите «Работает» и подтвердите изменение в течение времени отката. Если не подтвердить, firewalld снова запустится сам.",
        },
      },
      {
        id: "selinux", title: "SELinux",
        paras: [
          "Режимы: enforcing — правила действуют; permissive — только журнал нарушений; disabled — выключен, для смены нужна перезагрузка хоста.",
          "Булевы опции — переключатели поведения служб, например httpd_can_network_connect. Опцию можно сохранить после перезагрузки.",
        ],
        example: {
          title: "Пример: разрешить веб-серверу подключаться к сети",
          text: "SELinux → булевы опции → поиск «httpd_can_network_connect» → включить и отметить «Сохранять после перезагрузки».",
        },
      },
      {
        id: "log", title: "Журнал",
        paras: [
          "Журнал показывает каждое действие: когда, на каком хосте, что сделано и с каким результатом. Ошибки выводятся с причиной. Журнал хранится в панели.",
        ],
      },
      {
        id: "admin", title: "Администрирование, тема и язык",
        paras: [
          "Пароль меняется в разделе «Администрирование»: текущий пароль, новый (не короче 8 символов) и его повтор. Смена пароля закрывает все остальные сессии.",
          "Тема переключается кнопкой в шапке: тёмная по умолчанию или светлая. Язык — переключателем RU / EN; выбор запоминается в этом браузере.",
        ],
      },
    ],
    faq: [
      ["Хост недоступен", "Проверьте адрес и порт SSH, что sshd запущен и панель видит хост. Если агент уже стоял, но связи нет, переустановите его командой из раздела «Установка агента»."],
      ["Контрольная сумма агента не совпала", "Файл агента на панели изменился после того, как вы скопировали команду. Скопируйте команду заново."],
      ["firewalld не запущен", "Включите «Работает» на странице хоста — тогда изменения портов и служб снова станут доступны."],
      ["Изменение не осталось после подтверждения", "Проверьте журнал: там должна быть запись «выполнено». Если изменение откатилось по таймеру, его нужно сделать заново и подтвердить."],
    ],
  },
  en: {
    title: "Help",
    lead: "ZaSlon manages firewalld, ports, services and SELinux on RED OS hosts — all from the browser. After the agent is installed, you do not need a terminal on the host.",
    sections: [
      {
        id: "start", title: "Getting started",
        paras: [
          "The workflow is simple: install the agent on a host with the command from “Install agent”, add the host in the panel, then change ports, services and modes on the host page.",
          "Every change is applied with a rollback timer. If you do not confirm it in time, it rolls back by itself — protection against locking yourself out.",
        ],
      },
      {
        id: "agent", title: "Installing the agent on a host",
        paras: [
          "The agent is a small python3 script installed once on the host. The panel connects to the host over SSH with its own key. The sec_fw-admin user may run only the agent through sudo — no password and no shell.",
          "Requirements: RED OS, python3, curl, sshd on port 22, SSH access from the panel to the host. Without firewalld the agent still installs, but the panel will report that rules do not apply.",
        ],
        steps: [
          "Enter the panel address as the host sees it (for example https://zaslon.apps.monitoring.test).",
          "Enter the host name and address — you will need them to add the host in the panel.",
          "Copy the command and run it on the host as root (or with sudo).",
          "Wait for the line “ZaSlon: agent installed, host registered in the panel”. The host appears in the list by itself — nothing needs to be added by hand.",
        ],
        example: {
          title: "Example",
          text: "Host homeserver, address 192.168.1.56. The command installs the agent, creates the sec_fw-admin user and checks the connection to the panel.",
        },
        removal: "Removal: the “Remove agent” command deletes the agent, the sec_fw-admin user and the sudo rule. Rollback timers that have not fired yet can be stopped manually if needed.",
      },
      {
        id: "hosts", title: "Hosts",
        paras: [
          "“Add host” checks the connection. If the host is temporarily unreachable, you can add it without the check. “Remove host” only removes it from the panel — nothing changes on the host itself.",
          "Status dots: green — firewalld running; grey — stopped; red — host unreachable; blue — checking; yellow with a number — changes waiting for confirmation.",
        ],
      },
      {
        id: "ports", title: "Ports",
        paras: [
          "Open the host page, the “Port” block: choose a zone, enter a port or range, TCP or UDP, and the rollback time. The change applies immediately and survives a reboot.",
          "While a change is unconfirmed, a countdown runs at the bottom right. “Keep” confirms it, “Roll back” cancels it.",
        ],
        example: {
          title: "Example: open port 8080/tcp for 2 minutes",
          text: "Zone: public · Port: 8080 · Protocol: TCP · Roll back after: 120 s → “Open”. If you press “Keep” within 2 minutes, the port stays open; otherwise it closes by itself.",
        },
      },
      {
        id: "services", title: "Services",
        paras: [
          "Services are ready-made port sets, such as http, https or ssh. Add and remove them the same way as ports, with the cross in the zone list.",
        ],
        example: {
          title: "Example: allow https in zone public",
          text: "Zone: public → “Service” field: https → “Add service”.",
        },
      },
      {
        id: "firewalld", title: "firewalld",
        paras: [
          "The “Running” and “Autostart” switches start and stop firewalld. Without a running firewalld rules do not apply, so stopping it is also protected by a rollback timer.",
        ],
        example: {
          title: "Example: stop firewalld temporarily for diagnostics",
          text: "Turn “Running” off and confirm within the rollback time. If you do not confirm, firewalld starts again by itself.",
        },
      },
      {
        id: "selinux", title: "SELinux",
        paras: [
          "Modes: enforcing — rules apply; permissive — only logs violations; disabled — off, a host reboot is needed to switch to it.",
          "Booleans are switches for service behaviour, for example httpd_can_network_connect. A boolean can be kept after a reboot.",
        ],
        example: {
          title: "Example: allow the web server to connect to the network",
          text: "SELinux → booleans → search “httpd_can_network_connect” → turn it on and tick “Keep after reboot”.",
        },
      },
      {
        id: "log", title: "Log",
        paras: [
          "The log shows every action: when, on which host, what was done and the result. Errors include the reason. The log is kept by the panel.",
        ],
      },
      {
        id: "admin", title: "Administration, theme and language",
        paras: [
          "The password is changed in “Administration”: current password, new one (at least 8 characters) and its repeat. Changing it signs out all other sessions.",
          "The theme switches with the button in the header: dark by default, or light. The language switches with RU / EN; the choice is remembered in this browser.",
        ],
      },
    ],
    faq: [
      ["Host is unreachable", "Check the address and SSH port, that sshd is running and that the panel can reach the host. If the agent was installed but the connection fails, reinstall it with the command from “Install agent”."],
      ["Agent checksum does not match", "The agent file on the panel changed after you copied the command. Copy the command again."],
      ["firewalld is not running", "Turn “Running” on on the host page — then port and service changes are available again."],
      ["A change did not stay after confirmation", "Check the log: there should be a “done” entry. If the change rolled back by the timer, make it again and confirm."],
    ],
  },
};
