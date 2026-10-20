"""Связь панели с хостом: ssh с ключом панели и одной командой — агентом. Shell не используется."""
import json
import os
import re
import subprocess

AGENT_CMD = "sudo -n /usr/local/libexec/zaslon/agent"
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class AgentError(Exception):
    def __init__(self, msg, kind="error", status=409):
        super().__init__(msg)
        self.kind = kind
        self.status = status


def key_path(data):
    return os.path.join(data, "keys", "zaslon_ed25519")


def ssh_argv(host, data):
    kh = os.path.join(data, "known_hosts")
    return ["ssh", "-i", key_path(data), "-p", str(host.get("port", 22)),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + kh,
            "-o", "IdentitiesOnly=yes", "-o", "LogLevel=ERROR",
            # одно SSH-соединение на хост на несколько минут: повторные вызовы быстрые
            "-o", "ControlMaster=auto", "-o", "ControlPersist=300",
            "-o", "ControlPath=/tmp/zaslon-ssh-%C",
            "%s@%s" % (host["user"], host["address"])]


def call(host, data, op, args=None, timeout=60):
    """Возвращает dict ответа агента или поднимает AgentError."""
    payload = json.dumps({"op": op, "args": args or {}})
    try:
        p = subprocess.run(ssh_argv(host, data) + [AGENT_CMD], input=payload, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, universal_newlines=True)
    except subprocess.TimeoutExpired:
        raise AgentError("Хост %s не ответил за %d с" % (host["address"], timeout), "timeout", 502)
    except FileNotFoundError:
        raise AgentError("В образе нет ssh (openssh-client)", "missing_tool", 500)
    if p.returncode == 255:
        err = (p.stderr or "").strip().splitlines()
        raise AgentError("Нет связи с %s по SSH: %s" % (host["address"], err[-1] if err else "ошибка"),
                         "ssh", 502)
    lines = [l for l in (p.stdout or "").splitlines() if l.strip()]
    try:
        res = json.loads(lines[-1])
    except (IndexError, ValueError):
        err = (p.stderr or "").strip()
        raise AgentError("Агент на %s вернул непонятный ответ%s" % (host["address"], ": " + err if err else ""),
                         "agent", 502)
    if not res.get("ok"):
        kind = res.get("kind", "error")
        status = {"validation": 400, "not_found": 404, "auth": 403, "missing_tool": 502,
                  "timeout": 502}.get(kind, 409)
        raise AgentError(res.get("error", "Ошибка агента"), kind, status)
    return res


def valid_host(address, user, port):
    if not HOST_RE.match(address or ""):
        return "Адрес: имя или IP без пробелов"
    if not USER_RE.match(user or ""):
        return "Пользователь SSH: латиница, цифры, _ и -"
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "Порт SSH — число"
    if not 1 <= p <= 65535:
        return "Порт SSH вне диапазона"
    return None
