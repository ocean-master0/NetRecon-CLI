from __future__ import annotations

import asyncio
import ipaddress
import json
import secrets
import time
from typing import Any

from .async_utils import run_async
from .models import SubdomainRecord, SubdomainScanResult


class SubdomainScanner:
    def __init__(self, wordlist: list[str], max_workers: int = 200) -> None:
        self.wordlist = sorted(set(word.strip().lower() for word in wordlist if word.strip()))
        self.max_workers = max(1, max_workers)
        self._session: Any | None = None

    @property
    async def session(self) -> Any:
        if self._session is None:
            import aiohttp
            self._session = aiohttp.ClientSession(
                headers={"User-Agent": "NetRecon/2.0"},
                timeout=aiohttp.ClientTimeout(total=15),
            )
        return self._session

    async def _close_session(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

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

    async def _detect_wildcard(self, domain: str) -> tuple[bool, str | None]:
        random_label = secrets.token_hex(8)
        fqdn = f"{random_label}.{domain}"
        record = await self._resolve_subdomain(fqdn)
        if record:
            return True, record.ip
        return False, None

    async def _crt_sh_subdomains(self, domain: str) -> set[str]:
        try:
            sess = await self.session
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with sess.get(url) as resp:
                if resp.status != 200:
                    return set()
                text = await resp.text()
                entries = json.loads(text)
                names: set[str] = set()
                for entry in entries:
                    name: str = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n.endswith(f".{domain}") and n != f"*.{domain}":
                            names.add(n)
                return names
        except Exception:
            return set()

    async def _http_probe(self, host: str, timeout: float = 3.0) -> tuple[int | None, float | None]:
        started = time.perf_counter()
        for port in (80, 443):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
                scheme = "https" if port == 443 else "http"
                req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                writer.write(req.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(256), timeout=timeout)
                first_line = data.decode("utf-8", errors="ignore").splitlines()[0] if data else ""
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                elapsed = round((time.perf_counter() - started) * 1000, 2)
                if "200" in first_line or "301" in first_line or "302" in first_line or "403" in first_line:
                    return port, elapsed
                return port, elapsed
            except (asyncio.TimeoutError, OSError):
                continue
        return None, None

    async def scan_async(self, domain: str, *, stealth_mode: bool = False, enable_crt: bool = True, enable_http_probe: bool = False) -> SubdomainScanResult:
        started = time.perf_counter()
        warnings: list[str] = []
        records: list[SubdomainRecord] = []

        wildcard_detected, wildcard_ip = await self._detect_wildcard(domain)
        if wildcard_detected:
            warnings.append(f"Wildcard DNS detected (resolves to {wildcard_ip}). Results may include false positives.")

        crt_names: set[str] = set()
        if enable_crt:
            crt_names = await self._crt_sh_subdomains(domain)

        all_names = set(self.wordlist)
        if crt_names:
            all_names.update(crt_names)

        semaphore = asyncio.Semaphore(self.max_workers)

        async def _scan_word(word: str) -> SubdomainRecord | None:
            host = f"{word}.{domain}" if "." not in word else word
            async with semaphore:
                if stealth_mode:
                    await asyncio.sleep(0.05)
                return await self._resolve_subdomain(host)

        tasks = [asyncio.create_task(_scan_word(word)) for word in all_names]
        for task in asyncio.as_completed(tasks):
            try:
                record = await task
            except OSError as exc:
                warnings.append(str(exc))
                continue
            if record:
                if enable_http_probe:
                    probe_port, probe_ms = await self._http_probe(record.ip)
                    record = SubdomainRecord(
                        host=record.host,
                        ip=record.ip,
                        response_ms=record.response_ms,
                        http_status=probe_port,
                        http_response_ms=probe_ms,
                    )
                records.append(record)

        records = [r for r in records if isinstance(r, SubdomainRecord)]
        records.sort(key=lambda item: item.host)
        duration = round(time.perf_counter() - started, 4)
        await self._close_session()
        return SubdomainScanResult(
            domain=domain,
            scanned_count=len(all_names),
            active_hosts=records,
            duration_seconds=duration,
            wildcard_detected=wildcard_detected,
            wildcard_ip=wildcard_ip,
            crt_sh_count=len(crt_names),
            warnings=warnings,
        )

    def scan(self, domain: str) -> SubdomainScanResult:
        return run_async(self.scan_async(domain))
