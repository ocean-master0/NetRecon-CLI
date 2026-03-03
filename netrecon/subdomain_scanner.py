from __future__ import annotations

import asyncio
import ipaddress
import time

from .async_utils import run_async
from .models import SubdomainRecord, SubdomainScanResult


class SubdomainScanner:
    """Asynchronous subdomain enumeration with DNS resolution."""

    def __init__(self, wordlist: list[str], max_workers: int = 200) -> None:
        self.wordlist = sorted(set(word.strip().lower() for word in wordlist if word.strip()))
        self.max_workers = max(1, max_workers)

    async def _resolve_subdomain(self, fqdn: str) -> SubdomainRecord | None:
        started = time.perf_counter()
        loop = asyncio.get_running_loop()
        try:
            answers = await loop.getaddrinfo(fqdn, None, family=0, type=0, proto=0, flags=0)
        except OSError:
            return None

        for answer in answers:
            sockaddr = answer[4]
            if not sockaddr:
                continue
            ip_value = str(sockaddr[0]).strip()
            try:
                ipaddress.ip_address(ip_value)
            except ValueError:
                continue

            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            return SubdomainRecord(host=fqdn, ip=ip_value, response_ms=duration_ms)
        return None

    async def scan_async(self, domain: str) -> SubdomainScanResult:
        """Scan domain using configured common subdomain list."""
        started = time.perf_counter()
        warnings: list[str] = []
        records: list[SubdomainRecord] = []

        semaphore = asyncio.Semaphore(self.max_workers)

        async def _scan_word(word: str) -> SubdomainRecord | None:
            host = f"{word}.{domain}"
            async with semaphore:
                return await self._resolve_subdomain(host)

        tasks = [asyncio.create_task(_scan_word(word)) for word in self.wordlist]
        for task in asyncio.as_completed(tasks):
            try:
                record = await task
            except OSError as exc:
                warnings.append(str(exc))
                continue
            if record:
                records.append(record)

        records.sort(key=lambda item: item.host)
        duration = round(time.perf_counter() - started, 4)
        return SubdomainScanResult(
            domain=domain,
            scanned_count=len(self.wordlist),
            active_hosts=records,
            duration_seconds=duration,
            warnings=warnings,
        )

    def scan(self, domain: str) -> SubdomainScanResult:
        """Synchronous wrapper for async scan."""
        return run_async(self.scan_async(domain))
