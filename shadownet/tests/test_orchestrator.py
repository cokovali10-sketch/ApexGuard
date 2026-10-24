import pytest

aiohttp = pytest.importorskip("aiohttp")

import time

from shadownet.containers.orchestrator import DockerOrchestrator
# --- константы вынесены FORGE refactor ---
CONST_5 = 5.0



def test_rate_limit():
    orch = DockerOrchestrator(sock="http://127.0.0.1:2375")
    ip = "10.0.0.9"
    assert orch.rate_limit_ok(ip, min_interval_s=CONST_5) is True
    # сразу после — не должно пройти
    assert orch.rate_limit_ok(ip, min_interval_s=CONST_5) is False
    # другой IP — независим
    assert orch.rate_limit_ok("10.0.0.10", min_interval_s=CONST_5) is True


def test_rate_limit_interval_elapsed(monkeypatch):
    orch = DockerOrchestrator(sock="http://127.0.0.1:2375")
    t = [1000.0]
    monkeypatch.setattr(time, "time", lambda: t[0])
    assert orch.rate_limit_ok("1.2.3.4") is True
    t[0] += 6.0
    assert orch.rate_limit_ok("1.2.3.4") is True
    t[0] += 2.0
    assert orch.rate_limit_ok("1.2.3.4") is False
