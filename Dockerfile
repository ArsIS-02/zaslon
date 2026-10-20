# ZaSlon — панель управления firewalld, портами и SELinux на хостах РЕД ОС.
FROM python:3.12-slim
LABEL org.opencontainers.image.version="1.3" org.opencontainers.image.title="ZaSlon"

ARG ZASLON_UID=1000
ARG ZASLON_GID=1000
# openssh-client — подключение к хостам (ssh-keygen создаёт ключ панели)
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client libnss-wrapper tzdata \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ZASLON_DATA=/data \
    HOME=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY panel ./panel
COPY static ./static
COPY host ./host
COPY docker/entrypoint.sh /usr/local/bin/zaslon-entrypoint
RUN chmod -R a+rX /app && chmod 755 /usr/local/bin/zaslon-entrypoint

RUN (getent group "$ZASLON_GID" >/dev/null || groupadd -g "$ZASLON_GID" zaslon) \
 && (getent passwd "$ZASLON_UID" >/dev/null || useradd -u "$ZASLON_UID" -g "$ZASLON_GID" -d /data -M -s /usr/sbin/nologin zaslon) \
 && mkdir -p /data && chmod 0777 /data
VOLUME ["/data"]
EXPOSE 8585

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8585/healthz', timeout=4)" || exit 1

ENTRYPOINT ["/usr/local/bin/zaslon-entrypoint"]
CMD ["uvicorn", "panel.app:app", "--host", "0.0.0.0", "--port", "8585", "--timeout-keep-alive", "30"]
