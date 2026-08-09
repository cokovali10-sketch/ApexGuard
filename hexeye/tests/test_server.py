import asyncio
import subprocess
import tempfile
from pathlib import Path

import pytest

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import web

import hexeye.server as hx
from hexeye.analyzer import analyze


@pytest.fixture(scope="module")
def sample_elf():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "go.mod").write_text("module sample\n\ngo 1.21\n")
        (d / "main.go").write_text('package main\nfunc main() { println("hi") }\n')
        out = d / "a.out"
        r = subprocess.run(["go", "build", "-o", str(out), "."], cwd=d, capture_output=True)
        if r.returncode != 0 or not out.read_bytes().startswith(b"\x7fELF"):
            pytest.skip("cannot build sample ELF")
        return str(out)


def test_report_shape(sample_elf):
    rep = analyze(sample_elf)
    j = hx._report_to_json(rep)
    assert set(j) >= {"sha256", "format", "headers", "secrets", "dangerous_calls", "candidate_vulns", "json_report"}
    assert j["format"] == "elf"
    assert len(j["sha256"]) == 64


def test_analyze_endpoint(sample_elf):
    async def run():
        app = hx.build_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(f"http://127.0.0.1:{port}/analyze", json={"path": sample_elf}) as resp:
                    assert resp.status == 200
                    body = await resp.json()
                    assert body["format"] == "elf"
                async with s.get(f"http://127.0.0.1:{port}/healthz") as resp:
                    assert resp.status == 200
                async with s.get(f"http://127.0.0.1:{port}/metrics") as resp:
                    text = await resp.text()
                    assert "hexeye_analyzed_total 1" in text
        finally:
            await runner.cleanup()

    asyncio.run(run())


def test_analyze_missing_file():
    async def run():
        app = hx.build_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(f"http://127.0.0.1:{port}/analyze", json={"path": "/nope"}) as resp:
                    assert resp.status == 404
                async with s.post(f"http://127.0.0.1:{port}/analyze", data=b"bad") as resp:
                    assert resp.status == 400
        finally:
            await runner.cleanup()

    asyncio.run(run())
