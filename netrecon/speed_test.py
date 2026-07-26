from __future__ import annotations

import logging
import threading

from .models import SpeedTestResult

LOGGER = logging.getLogger(__name__)

_SPEEDTEST_TIMEOUT = 120


class SpeedTester:

    def __init__(self, timeout_seconds: int = _SPEEDTEST_TIMEOUT) -> None:
        self.timeout_seconds = max(30, timeout_seconds)

    def run(self) -> tuple[SpeedTestResult | None, list[str]]:
        warnings: list[str] = []

        try:
            import speedtest  # type: ignore[import-not-found]
        except ModuleNotFoundError:
            warnings.append("speedtest-cli is not installed. Install with: pip install speedtest-cli")
            return None, warnings

        result_container: list[SpeedTestResult | None] = [None]
        error_container: list[Exception | None] = [None]

        def _execute(client: object) -> None:
            try:
                best_server = client.get_best_server()
                download_mbps = round(client.download() / 1_000_000, 2)
                upload_mbps = round(client.upload() / 1_000_000, 2)
                ping_ms = round(float(best_server.get("latency", client.results.ping)), 2)
                result_container[0] = SpeedTestResult(
                    download_mbps=download_mbps,
                    upload_mbps=upload_mbps,
                    ping_ms=ping_ms,
                    server_name=best_server.get("name"),
                    server_country=best_server.get("country"),
                )
            except Exception as exc:  # noqa: BLE001
                error_container[0] = exc

        def _run_with_timeout() -> None:
            last_error: Exception | None = None
            for secure_mode in (True, False):
                try:
                    st = speedtest.Speedtest(secure=secure_mode)
                except TypeError:
                    if not secure_mode:
                        last_error = last_error or TypeError("Speedtest() constructor failed")
                        break
                    try:
                        st = speedtest.Speedtest()
                    except Exception as exc:
                        last_error = exc
                        break

                _execute(st)
                if result_container[0] is not None:
                    return
                last_error = error_container[0]
                if secure_mode and last_error and "403" in str(last_error):
                    LOGGER.info("Speed test secure mode received 403, retrying with insecure mode.")
                    continue
                break

            if last_error is None:
                last_error = RuntimeError("Speed test failed without a specific error.")
            error_container[0] = last_error

        thread = threading.Thread(target=_run_with_timeout, daemon=True)
        thread.start()
        thread.join(timeout=self.timeout_seconds)

        if thread.is_alive():
            warnings.append(f"Speed test timed out after {self.timeout_seconds}s.")
            return None, warnings

        if error_container[0]:
            LOGGER.warning("Speed test failed: %s", error_container[0])
            warnings.append(f"Speed test failed: {error_container[0]}")
            return None, warnings

        return result_container[0], warnings
