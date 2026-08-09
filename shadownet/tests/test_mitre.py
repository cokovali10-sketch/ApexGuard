import pytest

from shadownet.mitre.mapper import MITREMapper


def test_classify_scanning():
    m = MITREMapper()
    assert m.classify("nmap -sV 10.0.0.0/24") == "T1046"
    assert m.classify("masscan -p1-65535 10.0.0.5") == "T1046"


def test_classify_sudo_escalation():
    m = MITREMapper()
    assert m.classify("sudo -l") == "T1548.003"
    assert m.classify("su - root") == "T1548.003"


def test_classify_credential_discovery():
    m = MITREMapper()
    assert m.classify("cat /etc/shadow") == "T1082"
    assert m.classify("getent passwd") == "T1082"


def test_classify_persistence():
    m = MITREMapper()
    assert m.classify("crontab -l") == "T1053.003"
    assert m.classify("ssh-keygen -t rsa") == "T1098.004"


def test_classify_defense_evasion():
    m = MITREMapper()
    assert m.classify("history -c && unset HISTFILE") == "T1070.003"
    assert m.classify("iptables -F") == "T1562.004"


def test_classify_container_escape():
    m = MITREMapper()
    assert m.classify("nsenter --target 1 --mount --uts --ipc --pid /bin/bash") == "T1611"
    assert m.classify("docker exec -it webapp /bin/sh") == "T1611"


def test_classify_unknown():
    m = MITREMapper()
    assert m.classify("whoami") is None
    assert m.classify("echo hello world") is None


def test_stats_tracking():
    m = MITREMapper()
    m.classify("nmap -sS 10.0.0.1")
    m.classify("nmap -sS 10.0.0.2")
    m.classify("sudo -l")
    stats = m.stats()
    assert stats.get("T1046") == 2
    assert stats.get("T1548.003") == 1
