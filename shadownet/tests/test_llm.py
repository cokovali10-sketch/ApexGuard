import asyncio

import pytest

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import web

from shadownet.llm.client import OllamaClient, SYSTEM_PROMPT


def test_generate_payload_and_headers():
    seen = {}

    async def handler(request):
        seen["path"] = request.path
        body = await request.json()
        seen["body"] = body
        assert body["stream"] is False
        assert body["model"] == "qwen2.5:7b"
        assert body["system"] == SYSTEM_PROMPT
        assert "num_predict" in body["options"]
        assert body["options"]["temperature"] == 0.2
        return web.json_response({"response": "out"})

    async def run():
        app = web.Application()
        app.router.add_post("/api/generate", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            client = OllamaClient(base_url=f"http://127.0.0.1:{port}")
            out = await client.generate("ls -la")
            await client.close()
            return out
        finally:
            await runner.cleanup()

    assert asyncio.run(run()) == "out"
    assert seen["path"] == "/api/generate"
