from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import time

from .async_utils import run_async
from .models import LanHost, LanScanResult

MAC_PATTERN = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")
IP_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


class LANScanner:
    """Local network scanner for active host discovery."""

    def __init__(self, timeout_ms: int = 800, max_workers: int = 256) -> None:
        self.timeout_ms = max(100, timeout_ms)
        self.max_workers = max(1, max_workers)

    async def scan_async(self, cidr: str) -> LanScanResult:
        started = time.perf_counter()
        warnings: list[str] = []

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            return LanScanResult(cidr=cidr, warnings=[f"Invalid CIDR: {exc}"])

        hosts = [str(host) for host in network.hosts()]
        if not hosts:
            return LanScanResult(cidr=cidr, warnings=["No host addresses found in CIDR."])

        if len(hosts) > 1024:
            warnings.append("Large network detected; limiting to first 1024 hosts for safety.")
            hosts = hosts[:1024]

        semaphore = asyncio.Semaphore(self.max_workers)

        async def _probe(ip_value: str) -> str | None:
            async with semaphore:
                alive = await self._ping_host(ip_value)
                return ip_value if alive else None

        tasks = [asyncio.create_task(_probe(host)) for host in hosts]
        active_ips: list[str] = []
        for task in asyncio.as_completed(tasks):
            active = await task
            if active:
                active_ips.append(active)
        active_ips.sort(key=lambda item: tuple(int(part) for part in item.split(".")))

        mac_map = await asyncio.to_thread(self._read_arp_table)
        lan_hosts: list[LanHost] = []
        for ip_value in active_ips:
            hostname = await asyncio.to_thread(self._reverse_lookup, ip_value)
            lan_hosts.append(
                LanHost(
                    ip=ip_value,
                    hostname=hostname,
                    mac_address=mac_map.get(ip_value),
                    vendor=None,
                )
            )

        duration = round(time.perf_counter() - started, 4)
        return LanScanResult(cidr=cidr, active_hosts=lan_hosts, duration_seconds=duration, warnings=warnings)

    def scan(self, cidr: str) -> LanScanResult:
        """Synchronous wrapper for async LAN scan."""
        return run_async(self.scan_async(cidr))

    async def _ping_host(self, ip_value: str) -> bool:
        system_name = platform.system()
        if system_name == "Windows":
            command = ["ping", "-n", "1", "-w", str(self.timeout_ms), ip_value]
        elif system_name == "Darwin":
            command = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout_ms / 1000))), ip_value]
        else:
            command = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout_ms / 1000))), ip_value]

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=max(2, int(self.timeout_ms / 1000) + 1))
            return proc.returncode == 0
        except (OSError, asyncio.TimeoutError):
            return False

    @staticmethod
    def _read_arp_table() -> dict[str, str]:
        system_name = platform.system()
        command = ["arp", "-a"] if system_name == "Windows" else ["arp", "-an"]
        try:
            result = asyncio.run(_run_subprocess(command))
        except Exception:  # noqa: BLE001
            return {}
        output = result or ""

        mapping: dict[str, str] = {}
        for line in output.splitlines():
            ip_match = IP_PATTERN.search(line)
            mac_match = MAC_PATTERN.search(line)
            if not ip_match or not mac_match:
                continue
            mapping[ip_match.group(1)] = mac_match.group(0).lower().replace("-", ":")
        return mapping

    @staticmethod
    def _reverse_lookup(ip_value: str) -> str | None:
        try:
            host, _, _ = socket.gethostbyaddr(ip_value)
            return host
        except (socket.herror, socket.gaierror, OSError):
            return None


async def _run_subprocess(command: list[str]) -> str:
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    return stdout.decode("utf-8", errors="ignore")
