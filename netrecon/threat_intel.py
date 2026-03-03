from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from .async_utils import fetch_json, run_async
from .models import ThreatIntelResult


class ThreatIntelChecker:
    """Threat intelligence integration for AbuseIPDB, VirusTotal, and optional Shodan."""

    def __init__(
        self,
        api_keys: dict[str, str] | None = None,
        timeout_seconds: float = 8.0,
        rate_limit_sleep: float = 0.25,
    ) -> None:
        self.api_keys = {k.lower(): v for k, v in (api_keys or {}).items()}
        self.timeout_seconds = timeout_seconds
        self.rate_limit_sleep = max(0.0, rate_limit_sleep)

    async def check_ip_async(self, ip_value: str) -> ThreatIntelResult:
        """Run available threat intel sources for an IP address."""
        result = ThreatIntelResult(ip=ip_value)
        if not self._is_valid_ip(ip_value):
            result.warnings.append("Threat check skipped due to invalid IP.")
            return result

        checks: list[asyncio.Task[tuple[str, dict[str, Any] | None, str | None]]] = []
        if self.api_keys.get("abuseipdb"):
            checks.append(asyncio.create_task(self._check_abuseipdb(ip_value)))

        if self.api_keys.get("virustotal"):
            checks.append(asyncio.create_task(self._check_virustotal(ip_value)))

        if self.api_keys.get("shodan"):
            checks.append(asyncio.create_task(self._check_shodan(ip_value)))

        if not checks:
            result.source_details["status"] = {
                "state": "skipped",
                "reason": "No threat intelligence API keys configured.",
            }
            return result

        for task in asyncio.as_completed(checks):
            source, payload, warning = await task
            if warning:
                result.warnings.append(f"{source}: {warning}")
                continue
            if payload is None:
                continue
            result.source_details[source] = payload

        self._aggregate(result)
        return result

    def check_ip(self, ip_value: str) -> ThreatIntelResult:
        """Synchronous wrapper for asynchronous threat checks."""
        return run_async(self.check_ip_async(ip_value))

    async def _check_abuseipdb(self, ip_value: str) -> tuple[str, dict[str, Any] | None, str | None]:
        api_key = self.api_keys.get("abuseipdb")
        if not api_key:
            return "abuseipdb", None, "missing key"
        await asyncio.sleep(self.rate_limit_sleep)
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_value}&maxAgeInDays=90"
        headers = {"Key": api_key, "Accept": "application/json"}
        try:
            payload = await fetch_json(url, headers=headers, timeout_seconds=self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001
            return "abuseipdb", None, str(exc)
        return "abuseipdb", payload, None

    async def _check_virustotal(self, ip_value: str) -> tuple[str, dict[str, Any] | None, str | None]:
        api_key = self.api_keys.get("virustotal")
        if not api_key:
            return "virustotal", None, "missing key"
        await asyncio.sleep(self.rate_limit_sleep)
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_value}"
        headers = {"x-apikey": api_key}
        try:
            payload = await fetch_json(url, headers=headers, timeout_seconds=self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001
            return "virustotal", None, str(exc)
        return "virustotal", payload, None

    async def _check_shodan(self, ip_value: str) -> tuple[str, dict[str, Any] | None, str | None]:
        api_key = self.api_keys.get("shodan")
        if not api_key:
            return "shodan", None, "missing key"
        await asyncio.sleep(self.rate_limit_sleep)
        url = f"https://api.shodan.io/shodan/host/{ip_value}?key={api_key}"
        try:
            payload = await fetch_json(url, timeout_seconds=self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001
            return "shodan", None, str(exc)
        return "shodan", payload, None

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def _aggregate(result: ThreatIntelResult) -> None:
        abuse_data = result.source_details.get("abuseipdb", {})
        if isinstance(abuse_data, dict):
            data = abuse_data.get("data") if isinstance(abuse_data.get("data"), dict) else {}
            score = data.get("abuseConfidenceScore")
            reports = data.get("totalReports")
            if isinstance(score, (int, float)):
                result.malicious_score = max(result.malicious_score, int(score))
            if isinstance(reports, int):
                result.spam_reports += max(0, reports)

        vt_data = result.source_details.get("virustotal", {})
        if isinstance(vt_data, dict):
            data = vt_data.get("data") if isinstance(vt_data.get("data"), dict) else {}
            attributes = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
            stats = attributes.get("last_analysis_stats") if isinstance(attributes.get("last_analysis_stats"), dict) else {}
            malicious = int(stats.get("malicious", 0)) if isinstance(stats.get("malicious"), (int, float)) else 0
            suspicious = int(stats.get("suspicious", 0)) if isinstance(stats.get("suspicious"), (int, float)) else 0
            result.blacklist_count += malicious + suspicious
            result.malicious_score = max(result.malicious_score, min(100, (malicious + suspicious) * 10))

        shodan_data = result.source_details.get("shodan", {})
        if isinstance(shodan_data, dict):
            vulns = shodan_data.get("vulns")
            if isinstance(vulns, dict):
                result.known_vulnerabilities = sorted(str(key) for key in vulns.keys())
                result.blacklist_count += len(result.known_vulnerabilities)

        if result.blacklist_count > 0 and result.malicious_score < 20:
            result.malicious_score = min(100, result.blacklist_count * 5)
