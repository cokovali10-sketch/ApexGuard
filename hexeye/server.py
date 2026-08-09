#!/usr/bin/env python3
"""HexEye — HTTP API (интеграция с ApexCore).

Эндпоинты:
  POST /analyze   {path: "/opt/samples/sample"} → AnalysisReport (JSON)
  GET  /healthz   liveness
  GET  /metrics   Prometheus-совместимые счётчики

Анализ: см. analyzer.py (ELF/PE, секреты, call-graph, BOF/UAF-эвристики).
"""
import argparse
import asyncio
import json
import logging
from dataclasses import asdict
from pathlib import Path

from aiohttp import web

from hexeye.analyzer import analyze

log = logging.getLogger("hexeye.api")

analyzed_total = 0
analyzed_failed = 0


def _report_to_json(rep) -> dict:
    """Адаптация HexEyeReport к shape AnalysisReport из proto."""
    d = asdict(rep)
    return {
        "sha256": d["sha256"],
        "format": d["format"],
        "headers": d["headers"],
        "secrets": d["secrets"],
        "dangerous_calls": [{"sink": s, "callers": c} for s, c in d["dangerous_calls"]],
        "candidate_vulns": d["candidate_vulns"],
        "json_report": json.dumps(d),
    }


async def analyze_handler(request: web.Request) -> web.Response:
    global analyzed_total, analyzed_failed
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "bad request"}, status=400)

    path = (body.get("path") or "").strip()
    if not path or not Path(path).is_file():
        return web.json_response({"error": f"file not found: {path}"}, status=404)

    try:
        rep = await asyncio.to_thread(analyze, path)
        analyzed_total += 1
        return web.json_response(_report_to_json(rep))
    except Exception as e:  # noqa: BLE001
        analyzed_failed += 1
        log.exception("analyze failed")
        return web.json_response({"error": str(e)}, status=500)


async def healthz(_request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def metrics(_request: web.Request) -> web.Response:
    text = (
        f"hexeye_analyzed_total {analyzed_total}\n"
        f"hexeye_analyzed_failed {analyzed_failed}\n"
    )
    return web.Response(text=text, content_type="text/plain; version=0.0.4")


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/analyze", analyze_handler)
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/metrics", metrics)
    return app


def main():
    ap = argparse.ArgumentParser(description="HexEye HTTP analysis service")
    ap.add_argument("--listen", default="0.0.0.0:9092")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)
    host, port = args.listen.rsplit(":", 1)
    log.info("HexEye API listening on %s:%s", host, port)
    web.run_app(build_app(), host=host, port=int(port), print=False)


if __name__ == "__main__":
    main()
