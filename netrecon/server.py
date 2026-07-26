from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from .models import ReconResult, ScanOptions
from .renderer import to_json

LOGGER = logging.getLogger(__name__)


class NetReconAPIHandler(BaseHTTPRequestHandler):
    server: ApiServer  # type: ignore[override]

    def log_message(self, fmt: str, *args: Any) -> None:
        LOGGER.info(fmt, *args)

    def _send_json(self, data: dict, status: int = 200) -> None:
        payload = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        match self.path:
            case "/api/v1/status":
                self._handle_status()
            case "/api/v1/results":
                self._handle_results()
            case _:
                self._send_json({"error": "Not found", "endpoints": ["/api/v1/status", "/api/v1/scan", "/api/v1/results"]}, 404)

    def do_POST(self) -> None:
        match self.path:
            case "/api/v1/scan":
                self._handle_scan()
            case _:
                self._send_json({"error": "Not found"}, 404)

    def _handle_status(self) -> None:
        self._send_json({
            "status": "running" if self.server._scan_in_progress else "idle",
            "cycle": self.server._cycle_count,
            "last_scan": self.server._last_scan_time,
            "uptime_seconds": (datetime.now(timezone.utc) - self.server._started).total_seconds(),
        })

    def _handle_scan(self) -> None:
        if self.server._scan_in_progress:
            self._send_json({"error": "Scan already in progress"}, 409)
            return
        self._send_json({"message": "Scan started"}, 202)
        threading.Thread(target=self.server._run_scan, daemon=True).start()

    def _handle_results(self) -> None:
        result = self.server._last_result
        if result is None:
            self._send_json({"error": "No results available yet"}, 404)
            return
        self._send_json(json.loads(to_json(result, pretty=False)))


class ApiServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8088, options: ScanOptions | None = None, orchestrator: Any = None):
        self.host = host
        self.port = port
        self.options = options or ScanOptions(target="localhost")
        self.orchestrator = orchestrator
        self._last_result: ReconResult | None = None
        self._last_scan_time: str | None = None
        self._scan_in_progress = False
        self._cycle_count = 0
        self._started = datetime.now(timezone.utc)
        self._httpd: HTTPServer | None = None

    def _run_scan(self) -> None:
        if self._scan_in_progress:
            LOGGER.warning("Scan already in progress, skipping.")
            return
        self._scan_in_progress = True
        self._cycle_count += 1
        LOGGER.info("API scan cycle #%s starting...", self._cycle_count)
        try:
            if self.orchestrator:
                result = self.orchestrator.run(self.options)
                self._last_result = result
                self._last_scan_time = datetime.now(timezone.utc).isoformat()
                LOGGER.info("API scan cycle #%s complete.", self._cycle_count)
        except Exception as exc:
            LOGGER.exception("API scan cycle #%s failed: %s", self._cycle_count, exc)
        finally:
            self._scan_in_progress = False

    def serve_forever(self) -> None:
        self._httpd = HTTPServer((self.host, self.port), NetReconAPIHandler)
        self._httpd.server = self  # type: ignore[attr-defined]
        LOGGER.info("REST API server starting on http://%s:%s", self.host, self.port)
        print(f"NetRecon API server running at http://{self.host}:{self.port}")
        print("Endpoints:")
        print("  GET  /api/v1/status   - Server status")
        print("  POST /api/v1/scan     - Trigger a new scan")
        print("  GET  /api/v1/results  - Latest scan results")
        try:
            self._httpd.serve_forever()
        except KeyboardInterrupt:
            self.shutdown()

    def shutdown(self) -> None:
        LOGGER.info("Shutting down API server...")
        if self._httpd:
            self._httpd.shutdown()
