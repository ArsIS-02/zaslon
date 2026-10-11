# ZaSlon — панель управления firewalld / iptables / SELinux для хостов РЕД ОС
# Готовые образы для linux/amd64 и linux/arm64: ghcr.io/arsis-02/zaslon (см. README).
# Сборка на месте — под архитектуру хоста (Raspberry Pi — linux/arm64, ПК — linux/amd64).
FROM python:3.12-slim

# openssh-client — подключение к хостам; chromium — PDF-отчёты (WITH_PDF=0, чтобы собрать образ меньше)
ARG WITH_PDF=1
# пользователь в образе: ssh требует запись о нём в /etc/passwd. Готовый образ собран с 1000;
# при запуске от другого UID запись добавляет docker/entrypoint.sh (nss_wrapper)
ARG ZASLON_UID=1000
ARG ZASLON_GID=1000
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client libnss-wrapper tzdata fonts-dejavu-core \
    $( [ "$WITH_PDF" = "1" ] && echo chromium ) \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ZASLON_DATA=/data \
    HOME=/data \
    ZASLON_CHROMIUM=/usr/bin/chromium

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
COPY host ./host
COPY docker/entrypoint.sh /usr/local/bin/zaslon-entrypoint
# файлы могут прийти с правами 0600 (например, скопированные с Mac) — контейнер работает не от root
RUN chmod -R a+rX /app && chmod 755 /usr/local/bin/zaslon-entrypoint

RUN (getent group "$ZASLON_GID" >/dev/null || groupadd -g "$ZASLON_GID" zaslon) \
 && (getent passwd "$ZASLON_UID" >/dev/null || useradd -u "$ZASLON_UID" -g "$ZASLON_GID" -d /data -M -s /usr/sbin/nologin zaslon) \
 && mkdir -p /data && chmod 0777 /data
VOLUME ["/data"]
EXPOSE 8585

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8585/healthz', timeout=4)" || exit 1

LABEL org.opencontainers.image.title="ZaSlon" \
      org.opencontainers.image.description="Веб-панель firewalld, iptables и SELinux для хостов РЕД ОС" \
      org.opencontainers.image.source="https://github.com/ArsIS-02/zaslon" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/usr/local/bin/zaslon-entrypoint"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8585", "--timeout-keep-alive", "30"]
