"""Отправка журнала в Graylog: формат GELF, части UDP, уровни и поля. Запуск: python3 tests/test_gelf.py"""
import json
import os
import socket
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from panel import gelf  # noqa: E402


def recv_all(sock, wait=1.0):
    """Собирает сообщения GELF из датаграмм, в том числе из частей."""
    sock.settimeout(wait)
    parts, out = {}, []
    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            return out
        if data[:2] == b"\x1e\x0f":
            mid, seq, cnt = data[2:10], data[10], data[11]
            parts.setdefault(mid, {})[seq] = data[12:]
            if len(parts[mid]) == cnt:
                got = parts.pop(mid)
                out.append(json.loads(zlib.decompress(b"".join(got[i] for i in range(cnt)))))
        else:
            out.append(json.loads(zlib.decompress(data)))


def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    return s


def test_message_format():
    m = gelf.message("x", {"zs_ok": False, "zs_args": {"a": 1}, "empty": "", "id": "1", "zs-op": "port"}, "zaslon", 4, 10.0)
    assert m["version"] == "1.1" and m["host"] == "zaslon" and m["level"] == 4 and m["timestamp"] == 10.0
    assert m["_zs_ok"] == "false" and m["_zs_args"] == '{"a": 1}' and "_empty" not in m
    assert m["_f_id"] == "1" and m["_zs_op"] == "port"


def test_levels_and_fields():
    assert gelf.level_for({"op": "login_failed", "ok": False}) == 4
    assert gelf.level_for({"op": "selinux_mode", "ok": True, "args": {"mode": "permissive"}}) == 4
    assert gelf.level_for({"op": "selinux_mode", "ok": True, "args": {"mode": "enforcing"}}) == 5
    assert gelf.level_for({"op": "firewalld_set", "ok": True, "args": {"running": False}}) == 4
    assert gelf.level_for({"op": "port_change", "ok": True}) == 5
    assert gelf.level_for({"op": "login", "ok": True}) == 6
    f = gelf.fields_for({"op": "port_change", "who": "panel", "host": "srv", "ok": True, "tx": "t1",
                         "args": {"zone": "public", "port": "8080", "id": "t1"}}, "10.0.0.5")
    assert f["zs_op"] == "port_change" and f["zs_host_address"] == "10.0.0.5" and f["zs_arg_zone"] == "public"
    assert f["zs_arg_tx_id"] == "t1" and f["homelab_app"] == "zaslon"


def test_sender_udp_and_chunks():
    s = udp()
    snd = gelf.Sender("127.0.0.1", s.getsockname()[1], "udp", "zaslon-test")
    snd.submit("короткое", {"zs_op": "test"}, 6)
    big = os.urandom(30000).hex()                       # не сжимается: уйдёт частями
    snd.submit("большое", {"zs_op": "big", "blob": big}, 6)
    snd.flush()
    msgs = recv_all(s)
    assert [m["short_message"] for m in msgs] == ["короткое", "большое"], msgs
    assert msgs[1]["_blob"] == big and msgs[0]["host"] == "zaslon-test"
    assert snd.status["sent"] == 2 and snd.status["errors"] == 0


def test_sender_errors_do_not_raise():
    snd = gelf.Sender("127.0.0.1", 9, "tcp")            # на порту 9 никто не слушает
    snd.submit("x", {}, 6)
    snd.flush()
    assert snd.status["errors"] == 1 and snd.status["last_error"]


def test_from_env():
    assert gelf.Sender.from_env({}) is None
    s = gelf.Sender.from_env({"ZASLON_GELF_HOST": "gl", "ZASLON_GELF_PORT": "12206", "ZASLON_GELF_PROTO": "TCP"})
    assert (s.host, s.port, s.proto, s.source) == ("gl", 12206, "tcp", "zaslon")


if __name__ == "__main__":
    failed = 0
    for name, fn in [(k, v) for k, v in list(globals().items()) if k.startswith("test_")]:
        try:
            fn()
            print("ok   ", name)
        except Exception as e:  # noqa
            failed += 1
            print("FAIL ", name, "->", repr(e))
    print("%d failed" % failed)
    sys.exit(1 if failed else 0)
