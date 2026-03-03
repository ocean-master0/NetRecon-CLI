from __future__ import annotations

import asyncio
import ipaddress
import logging
import platform
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import requests

from .async_utils import run_async
from .models import ExternalIPInfo

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Provider:
    name: str
    url: str
    parser: Callable[[dict[str, Any]], ExternalIPInfo | None]


class IPScanner:
    """IP intelligence scanner with asynchronous external provider lookup."""

    def __init__(
        self,
        request_timeout_seconds: float = 8.0,
        external_workers: int = 3,
    ) -> None:
        self.request_timeout_seconds = request_timeout_seconds
        self.external_workers = max(1, external_workers)
        self.headers = {"User-Agent": "netrecon-cli/2.0"}
        self.providers: tuple[_Provider, ...] = (
            _Provider("ipinfo", "https://ipinfo.io/json", self._parse_ipinfo),
            _Provider("ipapi", "https://ipapi.co/json/", self._parse_ipapi),
            _Provider("ipwhois", "https://ipwho.is/", self._parse_ipwhois),
        )

    @staticmethod
    def _is_valid_ip(value: str | None) -> bool:
        if not value:
            return False
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def _as_float(value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _parse_ipinfo(self, data: dict[str, Any]) -> ExternalIPInfo | None:
        ip_value = data.get("ip")
        if not self._is_valid_ip(ip_value):
            return None

        lat: float | None = None
        lon: float | None = None
        location = data.get("loc")
        if isinstance(location, str) and "," in location:
            parts = [part.strip() for part in location.split(",", maxsplit=1)]
            lat = self._as_float(parts[0])
            lon = self._as_float(parts[1])

        return ExternalIPInfo(
            ip=ip_value,
            city=data.get("city"),
            region=data.get("region"),
            country=data.get("country"),
            latitude=lat,
            longitude=lon,
            organization=data.get("org"),
            isp=data.get("org"),
            postal=data.get("postal"),
            timezone=data.get("timezone"),
            source="ipinfo",
            raw=data,
        )

    def _parse_ipapi(self, data: dict[str, Any]) -> ExternalIPInfo | None:
        ip_value = data.get("ip")
        if not self._is_valid_ip(ip_value):
            return None

        return ExternalIPInfo(
            ip=ip_value,
            city=data.get("city"),
            region=data.get("region"),
            country=data.get("country_name") or data.get("country"),
            latitude=self._as_float(data.get("latitude")),
            longitude=self._as_float(data.get("longitude")),
            organization=data.get("org"),
            isp=data.get("org"),
            postal=data.get("postal"),
            timezone=data.get("timezone"),
            source="ipapi",
            raw=data,
        )

    def _parse_ipwhois(self, data: dict[str, Any]) -> ExternalIPInfo | None:
        ip_value = data.get("ip")
        if not self._is_valid_ip(ip_value):
            return None

        connection = data.get("connection") if isinstance(data.get("connection"), dict) else {}
        security = data.get("security") if isinstance(data.get("security"), dict) else {}
        org_value = connection.get("org") or connection.get("isp")

        return ExternalIPInfo(
            ip=ip_value,
            city=data.get("city"),
            region=data.get("region"),
            country=data.get("country_code") or data.get("country"),
            latitude=self._as_float(data.get("latitude")),
            longitude=self._as_float(data.get("longitude")),
            organization=org_value,
            isp=connection.get("isp") or org_value,
            postal=data.get("postal"),
            timezone=data.get("timezone", {}).get("id")
            if isinstance(data.get("timezone"), dict)
            else data.get("timezone"),
            source="ipwhois",
            proxy_detected=bool(security.get("proxy")) if security else None,
            vpn_detected=bool(security.get("vpn")) if security else None,
            raw=data,
        )

    async def _fetch_provider(self, session: Any, provider: _Provider) -> tuple[str, ExternalIPInfo | None]:
        async with session.get(provider.url, headers=self.headers) as response:
            response.raise_for_status()
            payload = await response.json()
            if not isinstance(payload, dict):
                raise ValueError("Provider response is not a JSON object.")
            return provider.name, provider.parser(payload)

    async def lookup_external_ip_async(self) -> tuple[ExternalIPInfo | None, list[str]]:
        """
        Lookup external IP data by querying providers concurrently.

        First provider that returns valid data wins.
        """
        warnings: list[str] = []
        try:
            import aiohttp
        except ModuleNotFoundError:
            return self.lookup_external_ip_sync_fallback()

        timeout = aiohttp.ClientTimeout(total=self.request_timeout_seconds)
        connector = aiohttp.TCPConnector(limit=self.external_workers)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = [asyncio.create_task(self._fetch_provider(session, provider)) for provider in self.providers]

            for task in asyncio.as_completed(tasks):
                try:
                    provider_name, result = await task
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                    warnings.append(f"provider lookup failed: {exc}")
                    continue

                if result is None:
                    warnings.append(f"{provider_name} returned invalid IP details.")
                    continue

                for other_task in tasks:
                    if other_task is not task and not other_task.done():
                        other_task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                LOGGER.info("External IP data resolved from provider: %s", provider_name)
                return result, warnings

            warnings.append("All external IP providers failed.")
            return None, warnings

    def lookup_external_ip_sync_fallback(self) -> tuple[ExternalIPInfo | None, list[str]]:
        warnings: list[str] = []
        session = requests.Session()
        for provider in self.providers:
            try:
                response = session.get(
                    provider.url,
                    timeout=self.request_timeout_seconds,
                    headers=self.headers,
                )
                response.raise_for_status()
                payload = response.json()
            except (requests.RequestException, ValueError) as exc:
                warnings.append(f"{provider.name} lookup failed: {exc}")
                continue
            if not isinstance(payload, dict):
                warnings.append(f"{provider.name} returned non-object JSON payload.")
                continue

            parsed = provider.parser(payload)
            if parsed:
                return parsed, warnings
            warnings.append(f"{provider.name} returned invalid IP details.")

        warnings.append("All external IP providers failed.")
        return None, warnings

    def lookup_external_ip(self) -> tuple[ExternalIPInfo | None, list[str]]:
        """Synchronous wrapper around asynchronous external lookup."""
        return run_async(self.lookup_external_ip_async())

    async def enrich_ip_async(self, ip_value: str) -> tuple[str | None, str | None]:
        """Lookup ASN and coarse geo for a public IP using ipwho.is."""
        if not self._is_valid_ip(ip_value):
            return None, None
        try:
            import aiohttp
        except ModuleNotFoundError:
            return None, None

        timeout = aiohttp.ClientTimeout(total=self.request_timeout_seconds)
        url = f"https://ipwho.is/{ip_value}"
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=self.headers) as response:
                    response.raise_for_status()
                    payload = await response.json()
        except Exception:
            return None, None

        if not isinstance(payload, dict):
            return None, None
        connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
        asn = connection.get("asn")
        city = payload.get("city")
        country = payload.get("country")
        geo = ", ".join(part for part in [city, country] if isinstance(part, str) and part.strip()) or None
        return str(asn) if asn else None, geo

    def collect_local_ips(self) -> list[str]:
        """Collect unique local IPv4/IPv6 addresses."""
        addresses: set[str] = set()

        try:
            for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_UNSPEC, socket.SOCK_STREAM):
                sockaddr = item[4]
                if not sockaddr:
                    continue
                ip_value = str(sockaddr[0]).strip()
                if self._is_valid_ip(ip_value):
                    addresses.add(ip_value)
        except socket.gaierror as exc:
            LOGGER.warning("getaddrinfo lookup failed: %s", exc)

        if not addresses:
            try:
                _, _, fallback_ips = socket.gethostbyname_ex(socket.gethostname())
            except socket.gaierror:
                fallback_ips = []
            for ip_value in fallback_ips:
                if self._is_valid_ip(ip_value):
                    addresses.add(ip_value)

        return sorted(addresses, key=lambda item: (":" in item, item))

    def reverse_dns_lookup(self, ip_value: str) -> tuple[str | None, str | None]:
        """Resolve reverse DNS hostname for a given IP address."""
        if not self._is_valid_ip(ip_value):
            return None, "Reverse DNS skipped because IP is invalid."

        try:
            host, _, _ = socket.gethostbyaddr(ip_value)
            return host, None
        except (socket.herror, socket.gaierror, OSError) as exc:
            return None, f"Reverse DNS lookup failed: {exc}"

    @staticmethod
    def build_geo_map_url(external_info: ExternalIPInfo | None) -> str | None:
        if external_info is None or external_info.coordinates is None:
            return None
        return f"https://www.google.com/maps?q={external_info.coordinates}"

    @staticmethod
    def export_geo_map_html(map_url: str, path: str | Path) -> Path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        html = (
            "<!doctype html>\n"
            "<html lang='en'>\n"
            "<head><meta charset='utf-8'><title>NetRecon Geo Map</title></head>\n"
            "<body>\n"
            "<h1>NetRecon Geo Map</h1>\n"
            f"<p><a href='{map_url}' target='_blank' rel='noopener noreferrer'>{map_url}</a></p>\n"
            f"<iframe src='{map_url}&output=embed' width='100%' height='600' loading='lazy'></iframe>\n"
            "</body>\n"
            "</html>\n"
        )
        output_path.write_text(html, encoding="utf-8")
        return output_path

    @staticmethod
    def _interface_commands() -> list[list[str]]:
        system_name = platform.system()
        if system_name == "Windows":
            return [["ipconfig", "/all"]]
        if system_name == "Linux":
            return [["ip", "addr", "show"], ["ifconfig", "-a"]]
        if system_name == "Darwin":
            return [["ifconfig"]]
        return []

    def collect_network_interfaces(self) -> tuple[str | None, str | None]:
        commands = self._interface_commands()
        if not commands:
            return None, f"Network interface scan is unsupported on {platform.system()}."

        errors: list[str] = []
        for command in commands:
            label = " ".join(command)
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=False)
            except FileNotFoundError:
                errors.append(f"{command[0]} not found.")
                continue
            except OSError as exc:
                errors.append(f"{label} failed: {exc}")
                continue

            output = (result.stdout or "").strip()
            if output:
                return f"$ {label}\n{output}", None

            stderr = (result.stderr or "").strip()
            if stderr:
                errors.append(f"{label} error: {stderr}")
            else:
                errors.append(f"{label} exited with code {result.returncode}.")

        return None, " ".join(errors) if errors else "No network interface output available."
