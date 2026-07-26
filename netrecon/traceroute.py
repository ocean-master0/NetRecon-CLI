from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import subprocess
from typing import Awaitable, Callable

from .async_utils import run_async
from .models import TracerouteHop, TracerouteResult

IP_PATTERN = re.compile(r"([0-9a-fA-F:.]+)")
LATENCY_PATTERN = re.compile(r"(\d+(?:\.\d+)?)\s*ms", flags=re.IGNORECASE)


class TracerouteScanner:
    """Cross-platform traceroute scanner with optional hop enrichment."""

    def __init__(
        self,
        max_hops: int = 30,
        timeout_ms: int = 2000,
        enrich_hop: Callable[[str], Awaitable[tuple[str | None, str | None]]] | None = None,
    ) -> None:
        self.max_hops = max(1, max_hops)
        self.timeout_ms = max(100, timeout_ms)
        self.enrich_hop = enrich_hop

    async def trace_async(
        self,
        target: str,
        *,
        advanced: bool = False,
    ) -> TracerouteResult:
        """Run traceroute and optionally enrich hops with ASN/geo data."""
        hops, method, warnings = await asyncio.to_thread(self._run_traceroute_blocking, target)
        result = TracerouteResult(target=target, method=method, hops=hops, warnings=warnings)

        if advanced and self.enrich_hop:
            await self._enrich_hops(result)

        return result

    def trace(self, target: str, *, advanced: bool = False) -> TracerouteResult:
        """Synchronous wrapper for async traceroute."""
        return run_async(self.trace_async(target, advanced=advanced))

    def _run_traceroute_blocking(self, target: str) -> tuple[list[TracerouteHop], str, list[str]]:
        warnings: list[str] = []
        command = self._system_traceroute_command(target)
        if command:
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=max(5, int(self.max_hops * (self.timeout_ms / 1000 + 1))),
                    check=False,
                )
                output = (result.stdout or "") + "\n" + (result.stderr or "")
                hops = self._parse_traceroute_output(output)
                if hops:
                    return hops, "system-traceroute", warnings
                warnings.append("Traceroute command returned no parseable hops.")
            except (OSError, subprocess.TimeoutExpired) as exc:
                warnings.append(f"Traceroute command failed: {exc}")
        else:
            warnings.append("No traceroute command available for this platform.")

        fallback_hops = self._fallback_ttl_ping(target)
        if fallback_hops:
            warnings.append("Using TTL ping fallback mode.")
            return fallback_hops, "ping-ttl-fallback", warnings

        warnings.append("Unable to determine traceroute path.")
        return [], "unavailable", warnings

    @staticmethod
    def _system_traceroute_command(target: str) -> list[str] | None:
        system_name = platform.system()
        if system_name == "Windows":
            return ["tracert", "-d", target]
        if system_name in {"Linux", "Darwin"}:
            return ["traceroute", "-n", target]
        return None

    def _fallback_ttl_ping(self, target: str) -> list[TracerouteHop]:
        hops: list[TracerouteHop] = []
        system_name = platform.system()
        timeout_seconds = max(1, int(self.timeout_ms / 1000))

        target_ip = self._resolve_target_ip_sync(target)

        for hop_number in range(1, self.max_hops + 1):
            if system_name == "Windows":
                command = ["ping", "-n", "1", "-w", str(self.timeout_ms), "-i", str(hop_number), target]
            else:
                command = ["ping", "-c", "1", "-W", str(timeout_seconds), "-t", str(hop_number), target]

            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds + 2, check=False)
            except (OSError, subprocess.TimeoutExpired):
                hops.append(TracerouteHop(hop=hop_number, ip=None, latency_ms=None))
                continue

            line_text = (result.stdout or "") + "\n" + (result.stderr or "")
            hop_ip = self._extract_ip(line_text)
            latency = self._extract_latency(line_text)
            hops.append(TracerouteHop(hop=hop_number, ip=hop_ip, latency_ms=latency))

            if hop_ip and target_ip and hop_ip == target_ip:
                break
            if "ttl expired" not in line_text.lower() and "time to live exceeded" not in line_text.lower():
                if result.returncode == 0:
                    break
        return hops

    @staticmethod
    def _resolve_target_ip_sync(target: str) -> str | None:
        try:
            infos = socket.getaddrinfo(target, None, family=0, type=0, proto=0, flags=0)
        except OSError:
            return None
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            ip_value = str(sockaddr[0]).strip()
            try:
                ipaddress.ip_address(ip_value)
            except ValueError:
                continue
            return ip_value
        return None

    def _parse_traceroute_output(self, text: str) -> list[TracerouteHop]:
        hops: list[TracerouteHop] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if not match:
                continue

            hop_number = int(match.group(1))
            rest = match.group(2)
            if rest.lower().startswith("request timed out") or rest.startswith("*"):
                hops.append(TracerouteHop(hop=hop_number, ip=None, latency_ms=None))
                continue

            hop_ip = self._extract_ip(rest)
            latency = self._extract_latency(rest)
            hops.append(TracerouteHop(hop=hop_number, ip=hop_ip, latency_ms=latency))
        return hops

    @staticmethod
    def _extract_ip(text: str) -> str | None:
        for token in IP_PATTERN.findall(text):
            cleaned = token.strip("[](),")
            try:
                ipaddress.ip_address(cleaned)
                return cleaned
            except ValueError:
                continue
        return None

    @staticmethod
    def _extract_latency(text: str) -> float | None:
        match = LATENCY_PATTERN.search(text)
        if not match:
            return None
        try:
            return float(match.group(1))
        except ValueError:
            return None

    async def _enrich_hops(self, result: TracerouteResult) -> None:
        enrich_tasks: list[tuple[TracerouteHop, asyncio.Task[tuple[str | None, str | None]]]] = []
        for hop in result.hops:
            if hop.ip:
                enrich_tasks.append((hop, asyncio.create_task(self.enrich_hop(hop.ip))))

        for hop, task in enrich_tasks:
            try:
                asn, geo = await task
            except Exception:  # noqa: BLE001
                continue
            hop.asn = asn
            hop.geo = geo
