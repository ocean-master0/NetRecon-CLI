from __future__ import annotations

import asyncio
import logging
import time
from typing import Iterable

from .async_utils import run_async
from .banner import BannerGrabber
from .models import BannerResult, PortScanResult

LOGGER = logging.getLogger(__name__)


class PortScanner:
    """Asynchronous TCP port scanner with optional banner grabbing."""

    def __init__(
        self,
        common_ports: list[int] | None = None,
        risky_ports: list[int] | None = None,
        timeout: float = 0.5,
        max_workers: int = 300,
        stealth_mode: bool = False,
    ) -> None:
        self.common_ports = sorted(set(common_ports or [20, 21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]))
        self.risky_ports = sorted(set(risky_ports or [21, 23, 25, 445, 3389, 5900]))
        self.timeout = timeout
        self.max_workers = max(1, max_workers)
        self.stealth_mode = stealth_mode
        self.banner_grabber = BannerGrabber(timeout=max(1.0, timeout * 2))

    @staticmethod
    def parse_port_range(port_range: str) -> list[int]:
        """Parse CLI range input like `1-1000` and return concrete port list."""
        if "-" not in port_range:
            raise ValueError("Port range must use format START-END (example: 1-1000).")

        start_text, end_text = [part.strip() for part in port_range.split("-", maxsplit=1)]
        try:
            start_port = int(start_text)
            end_port = int(end_text)
        except ValueError as exc:
            raise ValueError("Port range values must be integers.") from exc

        if start_port < 1 or end_port > 65535:
            raise ValueError("Port range must stay within 1-65535.")
        if start_port > end_port:
            raise ValueError("Port range start must be <= end.")

        return list(range(start_port, end_port + 1))

    async def _scan_single_port(self, target: str, port: int) -> tuple[int, str]:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=self.timeout)
        except ConnectionRefusedError:
            return port, "closed"
        except asyncio.TimeoutError:
            return port, "filtered"
        except OSError:
            return port, "filtered"

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return port, "open"

    async def scan_ports_async(
        self,
        target: str,
        ports: Iterable[int],
        *,
        grab_banners: bool = True,
        stealth_mode: bool | None = None,
    ) -> PortScanResult:
        """Scan provided ports asynchronously and optionally grab service banners."""
        import random
        port_list = sorted(set(int(port) for port in ports))
        is_stealth = self.stealth_mode if stealth_mode is None else stealth_mode
        if is_stealth:
            random.shuffle(port_list)

        started = time.perf_counter()
        semaphore = asyncio.Semaphore(min(self.max_workers, max(1, len(port_list))))
        open_ports: list[int] = []
        closed_ports: list[int] = []
        filtered_ports: list[int] = []
        banners: list[BannerResult] = []

        async def _scan(port: int) -> tuple[int, str]:
            async with semaphore:
                if is_stealth:
                    await asyncio.sleep(random.uniform(0.01, 0.05))
                return await self._scan_single_port(target, port)

        tasks = [asyncio.create_task(_scan(port)) for port in port_list]
        for task in asyncio.as_completed(tasks):
            port, status = await task
            if status == "open":
                open_ports.append(port)
            elif status == "closed":
                closed_ports.append(port)
            else:
                filtered_ports.append(port)

        open_ports.sort()
        closed_ports.sort()
        filtered_ports.sort()

        if grab_banners and open_ports:
            banner_tasks = [asyncio.create_task(self.banner_grabber.grab_banner_async(target, port)) for port in open_ports]
            for task in asyncio.as_completed(banner_tasks):
                try:
                    banners.append(await task)
                except OSError as exc:
                    LOGGER.debug("Banner grab failed: %s", exc)

        banners.sort(key=lambda item: item.port)
        duration = time.perf_counter() - started
        risky_open_ports = sorted(port for port in open_ports if port in self.risky_ports)

        return PortScanResult(
            target=target,
            scanned_ports=port_list,
            open_ports=open_ports,
            closed_ports=closed_ports,
            filtered_ports=filtered_ports,
            duration_seconds=round(duration, 4),
            risky_open_ports=risky_open_ports,
            banners=banners,
        )

    def scan_ports(
        self,
        target: str,
        ports: Iterable[int],
        *,
        grab_banners: bool = True,
    ) -> PortScanResult:
        """Synchronous wrapper for async scanner."""
        return run_async(self.scan_ports_async(target=target, ports=ports, grab_banners=grab_banners))

    def scan_common_ports(self, target: str, *, grab_banners: bool = True) -> PortScanResult:
        """Scan common ports configured in `common_ports`."""
        return self.scan_ports(target=target, ports=self.common_ports, grab_banners=grab_banners)

    def scan_custom_range(self, target: str, port_range: str, *, grab_banners: bool = True) -> PortScanResult:
        """Scan a custom CLI range string such as `1-1000`."""
        ports = self.parse_port_range(port_range)
        return self.scan_ports(target=target, ports=ports, grab_banners=grab_banners)
