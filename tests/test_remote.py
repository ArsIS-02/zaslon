"""Регрессионные проверки формирования SSH-команды панели."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from panel.remote import ssh_argv  # noqa: E402


def test_ssh_does_not_leave_background_control_master():
    argv = ssh_argv({"address": "host.example", "user": "redos", "port": 22}, "/tmp/zaslon-test")
    options = dict(argv[i + 1].split("=", 1) for i in range(len(argv) - 1) if argv[i] == "-o")
    assert options["ControlMaster"] == "no"
    assert options["ControlPersist"] == "no"
    assert "ControlPath" not in options
    assert not any(os.path.basename(arg).startswith("zaslon-ssh-") for arg in argv)


def test_connect_address_overrides_only_ssh_target():
    host = {"address": "192.0.2.10", "connect_address": "host.containers.internal",
            "user": "redos", "port": 22}
    argv = ssh_argv(host, "/tmp/zaslon-test")
    assert argv[-1] == "redos@host.containers.internal"
    assert host["address"] == "192.0.2.10"


if __name__ == "__main__":
    test_ssh_does_not_leave_background_control_master()
    test_connect_address_overrides_only_ssh_target()
    print("test_remote: OK")
