import asyncio

import pytest

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import web

from shadownet.events.bus import AegisBus
from shadownet.web.api import ShadowNetAPI


def _client():
    bus = AegisBus()  # локальный лог, без сети
    api = ShadowNetAPI(bus)
    return bus, api.app()


async def _start(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


def test_healthz():
    bus, app = _client()

    async def run():
        runner, base = await _start(app)
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(base + "/healthz") as resp:
                    assert resp.status == 200
                    return await resp.json()
        finally:
            await runner.cleanup()

    assert asyncio.run(run())["status"] == "ok"


def test_create_and_list_honeypots():
    bus, app = _client()

    async def run():
        runner, base = await _start(app)
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(base + "/honeypots", json={"services": ["SSH"]}) as resp:
                    assert resp.status == 201
                    created = await resp.json()
                    assert created["honeypot_id"]
                async with s.get(base + "/honeypots") as resp:
                    listing = await resp.json()
                    assert len(listing) == 1
                    assert listing[0]["status"] == "RUNNING"
        finally:
            await runner.cleanup()

    asyncio.run(run())


def test_bad_request():
    bus, app = _client()

    async def run():
        runner, base = await _start(app)
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(base + "/honeypots", data=b"not json") as resp:
                    assert resp.status == 400
        finally:
            await runner.cleanup()

    asyncio.run(run())


def test_metrics():
    bus, app = _client()

    async def run():
        runner, base = await _start(app)
        try:
            async with aiohttp.ClientSession() as s:
                await s.post(base + "/honeypots", json={"services": ["SSH"]})
                async with s.get(base + "/metrics") as resp:
                    text = await resp.text()
                    assert "shadownet_honeypots_active 1" in text
        finally:
            await runner.cleanup()

    asyncio.run(run())


def test_emit_anomaly_event_shape(tmp_path):
    bus = AegisBus()
    captured = []
    bus._append_local = captured.append
    asyncio.run(bus.emit_anomaly("T1090", "HIGH", {"honeypot_id": "h1", "src_ip": "1.2.3.4"}))
    assert len(captured) == 1
    ev = captured[0]
    assert ev["source"] == "SHADOWNET"
    assert ev["type"] == "ANOMALY"
    assert ev["severity"] == "HIGH"
    assert ev["mitre_technique"] == "T1090"
    assert ev["context"]["honeypot_id"] == "h1"
