from __future__ import annotations

import json
import logging
import os
import secrets
import ssl
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from .models import ReconResult, ScanOptions
from .renderer import to_json

LOGGER = logging.getLogger(__name__)

API_TOKEN_ENV = "NETRECON_API_TOKEN"
RATE_LIMIT_MAX_PER_MINUTE = 3
SCAN_COOLDOWN_SECONDS = 30
ALLOWED_ORIGINS = frozenset({"http://127.0.0.1:8088", "http://localhost:8088"})


class NetReconAPIHandler(BaseHTTPRequestHandler):
    server: ApiServer  # type: ignore[override]

    def log_message(self, fmt: str, *args: Any) -> None:
        LOGGER.info(fmt, *args)

    def _check_auth(self) -> bool:
        expected = os.environ.get(API_TOKEN_ENV)
        if not expected:
            return False
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        return secrets.compare_digest(header[7:].strip(), expected)

    def _cors_origin(self) -> str:
        origin = self.headers.get("Origin", "")
        return origin if origin in ALLOWED_ORIGINS else "null"

    def _send_json(self, data: dict, status: int = 200) -> None:
        payload = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        if not self._check_auth():
            self._send_json({"error": "Unauthorized"}, 401)
            return
        match self.path:
            case "/api/v1/status":
                self._handle_status()
            case "/api/v1/results":
                self._handle_results()
            case _:
                self._send_json({"error": "Not found", "endpoints": ["/api/v1/status", "/api/v1/scan", "/api/v1/results"]}, 404)

    def do_POST(self) -> None:
        if not self._check_auth():
            self._send_json({"error": "Unauthorized"}, 401)
            return
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
        client_ip = self.client_address[0]
        if self.server._is_rate_limited(client_ip):
            self._send_json({"error": "Rate limited. Try again later."}, 429)
            return
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
        raw = json.loads(to_json(result, pretty=False))
        raw.pop("warnings", None)
        raw.pop("errors", None)
        self._send_json(raw)


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
        self._last_scan_start: float = 0.0
        self._request_counts: dict[str, list[float]] = defaultdict(list)

    def _is_rate_limited(self, client_ip: str) -> bool:
        now = time.time()
        if now - self._last_scan_start < SCAN_COOLDOWN_SECONDS:
            return True
        self._request_counts[client_ip] = [
            t for t in self._request_counts[client_ip] if now - t < 60
        ]
        if len(self._request_counts[client_ip]) >= RATE_LIMIT_MAX_PER_MINUTE:
            return True
        self._request_counts[client_ip].append(now)
        return False

    def _run_scan(self) -> None:
        if self._scan_in_progress:
            LOGGER.warning("Scan already in progress, skipping.")
            return
        self._scan_in_progress = True
        self._cycle_count += 1
        self._last_scan_start = time.time()
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
        if not os.environ.get(API_TOKEN_ENV):
            print(f"ERROR: {API_TOKEN_ENV} environment variable is not set.")
            print(f"Set it with: export {API_TOKEN_ENV}=$(python3 -c \"import secrets; print(secrets.token_urlsafe(32))\")")
            return
        self._httpd = HTTPServer((self.host, self.port), NetReconAPIHandler)
        self._httpd.server = self  # type: ignore[attr-defined]
        self._apply_tls()
        LOGGER.info("REST API server starting on %s://%s:%s", "https" if self._tls_enabled else "http", self.host, self.port)
        protocol = "https" if self._tls_enabled else "http"
        print(f"NetRecon API server running at {protocol}://{self.host}:{self.port}")
        print("Endpoints:")
        print("  GET  /api/v1/status   - Server status")
        print("  POST /api/v1/scan     - Trigger a new scan")
        print("  GET  /api/v1/results  - Latest scan results")
        try:
            self._httpd.serve_forever()
        except KeyboardInterrupt:
            self.shutdown()

    def _apply_tls(self) -> None:
        self._tls_enabled = False
        cert_file = os.environ.get("NETRECON_CERT_FILE")
        key_file = os.environ.get("NETRECON_KEY_FILE")
        if cert_file and key_file:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert_file, key_file)
                self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
                self._tls_enabled = True
                LOGGER.info("TLS enabled.")
            except Exception as exc:
                LOGGER.warning("Failed to configure TLS: %s", exc)
        else:
            LOGGER.info("TLS not configured — set NETRECON_CERT_FILE and NETRECON_KEY_FILE to enable.")

    def shutdown(self) -> None:
        LOGGER.info("Shutting down API server...")
        if self._httpd:
            self._httpd.shutdown()
