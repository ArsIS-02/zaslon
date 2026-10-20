#!/bin/sh
# ZaSlon — установка агента на хост РЕД ОС одной командой. Команду формирует панель (форма «Новый хост»
# и раздел «Справка»). Что делает:
#   1. если панель работает по HTTPS с внутренним сертификатом — проверяет его отпечаток и ставит в доверенные
#      (старый сертификат панели заменяется новым);
#   2. скачивает агент и setup-host.sh, проверяет контрольную сумму агента;
#   3. ставит агент и ключ панели (setup-host.sh);
#   4. регистрирует хост в панели по одноразовому токену — хост появляется в списке сам.
# Переменные (их задаёт команда из панели):
#   ZASLON_PANEL         адрес панели (обязательно)
#   ZASLON_PANEL_KEY     публичный ключ панели (обязательно, кроме удаления)
#   ZASLON_CA_SHA256     отпечаток корневого сертификата панели (SHA-256 от DER)
#   ZASLON_AGENT_SHA256  контрольная сумма агента
#   ZASLON_USER          пользователь на хосте (по умолчанию sec_fw-admin)
#   ZASLON_ENROLL        одноразовый токен регистрации (без него хост нужно добавить вручную)
#   ZASLON_REMOVE=1      удалить агент и пользователя
set -eu
die() { echo "ZaSlon: $*" >&2; exit 1; }  # сообщения на русском; English: see README

[ "$(id -u)" = 0 ] || die "запустите от root (sudo) / run as root (sudo)"
PANEL="${ZASLON_PANEL:-}"
[ -n "$PANEL" ] || die "не задан ZASLON_PANEL (адрес панели)"
command -v curl >/dev/null 2>&1 || die "нужен curl"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ANCHORS=/etc/pki/ca-trust/source/anchors
ANCHOR="$ANCHORS/zaslon-panel-ca.crt"
CAFILE=""

if [ -n "${ZASLON_CA_SHA256:-}" ]; then
  # Сертификат панели ещё не доверен системой, поэтому этот запрос идёт без проверки цепочки.
  # Доверие задаёт отпечаток из команды: сертификат с другим отпечатком не используется.
  curl -fsSk "$PANEL/dl/ca.crt" -o "$TMP/ca.crt" || die "не удалось скачать сертификат панели с $PANEL"
  got=$(openssl x509 -in "$TMP/ca.crt" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
  [ "$got" = "$ZASLON_CA_SHA256" ] || die "отпечаток сертификата панели не совпал (ожидался $ZASLON_CA_SHA256, получен $got). Возможна подмена — установка остановлена."
  CAFILE="$TMP/ca.crt"
  if [ -d "$ANCHORS" ]; then
    if [ -f "$ANCHOR" ] && cmp -s "$CAFILE" "$ANCHOR"; then
      echo "ZaSlon: сертификат панели уже установлен / panel certificate already installed"
    else
      # старые сертификаты ZaSlon (другой отпечаток или другое имя файла) убираем, новый кладём на их место
      for old in "$ANCHORS"/zaslon-*.crt; do
        [ -f "$old" ] || continue
        [ "$old" = "$ANCHOR" ] || { echo "ZaSlon: удаляю старый сертификат $old"; rm -f "$old"; }
      done
      [ -f "$ANCHOR" ] && echo "ZaSlon: заменяю сертификат панели на новый / replacing the panel certificate"
      install -m 0644 -o root -g root "$CAFILE" "$ANCHOR"
      update-ca-trust >/dev/null 2>&1 || echo "ZaSlon: не удалось обновить хранилище сертификатов (update-ca-trust)" >&2
      echo "ZaSlon: сертификат панели установлен / panel certificate installed"
    fi
  else
    echo "ZaSlon: нет каталога $ANCHORS — системное хранилище не менялось; загрузки идут с проверкой по этому сертификату" >&2
  fi
fi

fetch() {  # загрузка с проверкой: по сертификату панели, если он известен
  if [ -n "$CAFILE" ]; then curl -fsSL --cacert "$CAFILE" "$@"; else curl -fsSL "$@"; fi
}
fetch "$PANEL/dl/setup-host.sh" -o "$TMP/setup-host.sh" || die "не удалось скачать setup-host.sh с $PANEL"
fetch "$PANEL/dl/zaslon-agent" -o "$TMP/zaslon-agent" || die "не удалось скачать агент с $PANEL"

if [ -n "${ZASLON_AGENT_SHA256:-}" ]; then
  got=$(sha256sum "$TMP/zaslon-agent" | cut -d' ' -f1)
  [ "$got" = "$ZASLON_AGENT_SHA256" ] || die "контрольная сумма агента не совпала (ожидалась $ZASLON_AGENT_SHA256, получена $got)"
fi

if [ "${ZASLON_REMOVE:-}" = 1 ]; then
  bash "$TMP/setup-host.sh" --remove
  exit 0
fi

[ -n "${ZASLON_PANEL_KEY:-}" ] || die "не задан ZASLON_PANEL_KEY (публичный ключ панели)"
bash "$TMP/setup-host.sh" "$ZASLON_PANEL_KEY"

if [ -n "${ZASLON_ENROLL:-}" ]; then
  case "$ZASLON_ENROLL" in *[!A-Za-z0-9_-]*) die "неверный токен регистрации";; esac
  printf '{"token":"%s"}' "$ZASLON_ENROLL" > "$TMP/enroll.json"
  if [ -n "$CAFILE" ]; then
    resp=$(curl -sS --cacert "$CAFILE" -H 'Content-Type: application/json' -H 'X-Zaslon: 1' \
      --data @"$TMP/enroll.json" "$PANEL/api/enroll") || die "нет связи с панелью для регистрации хоста"
  else
    resp=$(curl -sS -H 'Content-Type: application/json' -H 'X-Zaslon: 1' \
      --data @"$TMP/enroll.json" "$PANEL/api/enroll") || die "нет связи с панелью для регистрации хоста"
  fi
  case "$resp" in
    *'"ok":true'*|*'"ok": true'*)
      echo "ZaSlon: агент установлен, хост зарегистрирован в панели / agent installed, host registered in the panel." ;;
    *)
      die "агент установлен, но панель не зарегистрировала хост: $resp" ;;
  esac
  exit 0
fi
echo "ZaSlon: агент установлен / agent installed. Добавьте хост в панели (имя, адрес, пользователь ${ZASLON_USER:-sec_fw-admin}) / add the host in the panel."
