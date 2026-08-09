#!/usr/bin/env python3
# ShadowNet — шина событий (AegisBus client).
# Публикация ThreatEvent в реальном времени через WebSocket в ApexConsole,
# дублирование в очередь NATS (опционально) и локальный лог.
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp

log = logging.getLogger("shadownet.bus")


def _new_uuid() -> uuid.UUID:
    """uuid7 где доступен (Python ≥3.12), иначе uuid4."""
    gen = getattr(uuid, "uuid7", None)
    if gen is not None:
        return gen()
    return uuid.uuid4()

# Локальный лог — fallback, если WS недоступен.
LOCAL_LOG = Path("shadownet_events.jsonl")


class AegisBus:
    """Отправляет события honeypot в центральную шину (WebSocket) + локальный лог."""

    def __init__(self, ws_url: str | None = None, nats_url: str | None = None):
        self.ws_url = ws_url          # wss://console:8443/ws/events
        self.nats_url = nats_url      # nats://127.0.0.1:4222 (не реализовано)
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._session: aiohttp.ClientSession | None = None
        self._lock = asyncio.Lock()

    async def _ensure(self):
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        if self.ws_url and (self._ws is None or self._ws.closed):
            try:
                self._ws = await self._session.ws_connect(self.ws_url, heartbeat=30)
            except Exception as e:
                log.debug("ws connect failed: %s", e)
                self._ws = None

    def _event(self, event_type: str, severity: str, mitre: str | None,
               context: dict[str, Any]) -> dict:
        return {
            "event_id": str(_new_uuid()),
            "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "source": "SHADOWNET",
            "type": event_type,
            "severity": severity.upper(),
            "mitre_technique": mitre,
            "context": context,
        }

    async def emit_honey_cmd(self, cmd: str, ttp: str | None, src_ip: str):
        ev = self._event("HONEY_CMD", "LOW", ttp, {"command": cmd, "src_ip": src_ip})
        await self._publish(ev)
        log.info("[%s] %s %s", src_ip, ttp or "-", cmd)

    async def emit_anomaly(self, ttp: str, severity: str, context: dict):
        ev = self._event("ANOMALY", severity, ttp, context)
        await self._publish(ev)
        log.warning("[%s] %s", context.get("src_ip"), ttp)

    async def _publish(self, ev: dict):
        async with self._lock:
            try:
                await self._ensure()
                if self._ws:
                    await self._ws.send_json(ev)
            except Exception as e:
                log.debug("bus unavailable: %s", e)
            # локальный лог-файл без блокировки event loop
            await asyncio.to_thread(self._append_local, ev)

    def _append_local(self, ev: dict) -> None:
        try:
            with LOCAL_LOG.open("a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except OSError:
            pass

    async def close(self):
        if self._ws:
            await self._ws.close()
        if self._session:
            await self._session.close()
