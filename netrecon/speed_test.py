from __future__ import annotations

import logging

from .models import SpeedTestResult

LOGGER = logging.getLogger(__name__)


class SpeedTester:
    """Internet speed measurement using speedtest-cli."""

    def run(self) -> tuple[SpeedTestResult | None, list[str]]:
        """Execute download/upload/ping speed test."""
        warnings: list[str] = []

        try:
            import speedtest  # type: ignore[import-not-found]
        except ModuleNotFoundError:
            warnings.append("speedtest-cli is not installed. Install with: pip install speedtest-cli")
            return None, warnings

        def _execute_client(client: object) -> SpeedTestResult:
            best_server = client.get_best_server()
            download_mbps = round(client.download() / 1_000_000, 2)
            upload_mbps = round(client.upload() / 1_000_000, 2)
            ping_ms = round(float(best_server.get("latency", client.results.ping)), 2)
            return SpeedTestResult(
                download_mbps=download_mbps,
                upload_mbps=upload_mbps,
                ping_ms=ping_ms,
                server_name=best_server.get("name"),
                server_country=best_server.get("country"),
            )

        last_error: Exception | None = None
        for secure_mode in (True, False):
            try:
                client = speedtest.Speedtest(secure=secure_mode)
            except TypeError:
                if not secure_mode:
                    continue
                client = speedtest.Speedtest()

            try:
                result = _execute_client(client)
                return result, warnings
            except Exception as exc:  # noqa: BLE001 - external library behavior is variable.
                last_error = exc
                if secure_mode and "403" in str(exc):
                    LOGGER.info("Speed test secure mode received 403, retrying with insecure mode.")
                    continue
                break

        try:
            if last_error is None:
                raise RuntimeError("Speed test failed without a specific error.")
            raise last_error
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Speed test failed: %s", exc)
            warnings.append(f"Speed test failed: {exc}")
            return None, warnings
