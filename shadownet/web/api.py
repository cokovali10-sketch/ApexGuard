#!/usr/bin/env python3
"""ShadowNet — HTTP API (интеграция с ApexCore).

Эндпоинты:
  POST /honeypots   {services: [...], llm_model, network} → {honeypot_id, status}
  GET  /honeypots   список активных ловушек
  GET  /healthz     liveness
  GET  /metrics     Prometheus-совместимые счётчики

Отдельный aiohttp web-сервер поверх honeypot-процесса. Не требует Docker:
управление контейнерами опционально (передаётся orchestrator).
"""
import logging
import uuid
from datetime import datetime, timezone

import aiohttp
from aiohttp import web

from shadownet.events.bus import AegisBus

log = logging.getLogger("shadownet.web")


class ShadowNetAPI:
    def __init__(self, bus: AegisBus, orch=None, registry=None):
        self.bus = bus
        self.orch = orch
        self.registry = registry
        self._honeypots: dict[str, dict] = {}
        self._spawned = 0
        self._failed = 0

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_post("/honeypots", self.spawn_honeypot)
        app.router.add_get("/honeypots", self.list_honeypots)
        app.router.add_get("/healthz", self.healthz)
        app.router.add_get("/metrics", self.metrics)
        return app

    async def spawn_honeypot(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "bad request"}, status=400)

        services = body.get("services") or ["SSH"]
        llm_model = body.get("llm_model", "qwen2.5:7b")
        hid = str(uuid.uuid4())
        self._honeypots[hid] = {
            "id": hid,
            "services": services,
            "llm_model": llm_model,
            "status": "RUNNING",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._spawned += 1

        await self.bus.emit_anomaly(
            "T1090", severity="INFO",
            context={"honeypot_id": hid, "services": ",".join(services), "src_ip": "api"},
        )
        return web.json_response({"honeypot_id": hid, "status": "RUNNING"}, status=201)

    async def list_honeypots(self, _request: web.Request) -> web.Response:
        return web.json_response(list(self._honeypots.values()))

    async def healthz(self, _request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def metrics(self, _request: web.Request) -> web.Response:
        text = (
            f"shadownet_honeypots_active {len(self._honeypots)}\n"
            f"shadownet_honeypots_spawned {self._spawned}\n"
            f"shadownet_honeypots_failed {self._failed}\n"
        )
        return web.Response(text=text, content_type="text/plain; version=0.0.4")


async def run_api(api: ShadowNetAPI, host: str, port: int) -> None:
    """Запуск web-сервера в том же event loop, что и SSH-honeypot."""
    runner = web.AppRunner(api.app())
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    log.info("ShadowNet HTTP API listening on %s:%d", host, port)
