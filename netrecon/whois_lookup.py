from __future__ import annotations

import logging
import re
import socket
from typing import Any

from .models import WhoisResult

LOGGER = logging.getLogger(__name__)

EMAIL_PATTERN = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
ASN_PATTERN = re.compile(r"\bAS\d+\b", flags=re.IGNORECASE)
REFERRAL_PATTERN = re.compile(r"^(?:refer|whois):\s*(\S+)", flags=re.IGNORECASE | re.MULTILINE)


class WhoisLookup:
    """WHOIS lookup service with python-whois primary and raw TCP fallback."""

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = timeout_seconds

    def lookup(self, query: str) -> tuple[WhoisResult | None, list[str]]:
        """Run WHOIS lookup and return normalized result plus warnings."""
        warnings: list[str] = []

        primary_result = self._lookup_with_python_whois(query)
        if primary_result is not None:
            return primary_result, warnings

        try:
            raw_result = self._lookup_raw_whois(query)
        except OSError as exc:
            warnings.append(f"Raw WHOIS lookup failed: {exc}")
            return None, warnings

        if raw_result is None:
            warnings.append("WHOIS lookup did not return useful metadata.")
            return None, warnings
        return raw_result, warnings

    def _lookup_with_python_whois(self, query: str) -> WhoisResult | None:
        try:
            import whois  # type: ignore[import-not-found]
        except ModuleNotFoundError:
            LOGGER.info("python-whois package is not installed.")
            return None

        try:
            data = whois.whois(query)
        except Exception as exc:  # noqa: BLE001 - external library may raise varied exceptions.
            LOGGER.warning("python-whois lookup failed for %s: %s", query, exc)
            return None

        record = self._coerce_mapping(data)
        raw_text = str(data)
        asn = self._extract_text(record, ["asn", "originas", "origin", "asnumber"])
        if asn is None:
            match = ASN_PATTERN.search(raw_text)
            asn = match.group(0).upper() if match else None

        organization = self._extract_text(record, ["org", "organization", "name", "orgname"])
        isp = self._extract_text(record, ["isp", "owner", "registrar", "netname"]) or organization

        abuse_contact = self._extract_abuse_contact(
            self._extract_list(record, ["emails", "email", "abuse_contact", "abuse_email"]),
            raw_text,
        )

        return WhoisResult(
            query=query,
            asn=asn,
            isp=isp,
            organization=organization,
            abuse_contact=abuse_contact,
            source="python_whois",
            raw_text=raw_text[:12000],
        )

    @staticmethod
    def _coerce_mapping(data: Any) -> dict[str, Any]:
        if isinstance(data, dict):
            return data
        if hasattr(data, "items"):
            try:
                return dict(data.items())  # type: ignore[arg-type]
            except Exception:  # noqa: BLE001
                return {}
        return {}

    @staticmethod
    def _extract_text(data: dict[str, Any], keys: list[str]) -> str | None:
        for key in keys:
            if key not in data:
                continue
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        return item.strip()
        return None

    @staticmethod
    def _extract_list(data: dict[str, Any], keys: list[str]) -> list[str]:
        values: list[str] = []
        for key in keys:
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                values.append(value.strip())
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        values.append(item.strip())
        return values

    @staticmethod
    def _extract_abuse_contact(candidates: list[str], raw_text: str) -> str | None:
        for candidate in candidates:
            if "abuse" in candidate.lower():
                return candidate
        if candidates:
            return candidates[0]

        for line in raw_text.splitlines():
            if "abuse" not in line.lower():
                continue
            email = EMAIL_PATTERN.search(line)
            if email:
                return email.group(1)
        return None

    def _lookup_raw_whois(self, query: str) -> WhoisResult | None:
        root_output = self._query_whois_server("whois.iana.org", query)
        referral_match = REFERRAL_PATTERN.search(root_output)
        referral_server = referral_match.group(1).strip() if referral_match else None

        raw_output = root_output
        if referral_server:
            try:
                raw_output = self._query_whois_server(referral_server, query)
            except OSError:
                raw_output = root_output

        asn = self._extract_raw_field(raw_output, ["originas", "origin", "aut-num", "asn", "asnumber"])
        if asn is None:
            match = ASN_PATTERN.search(raw_output)
            asn = match.group(0).upper() if match else None

        organization = self._extract_raw_field(
            raw_output,
            ["orgname", "organization", "org-name", "owner", "descr", "netname"],
        )
        abuse_contact = self._extract_raw_abuse(raw_output)

        if not any([asn, organization, abuse_contact]):
            return None

        return WhoisResult(
            query=query,
            asn=asn,
            isp=organization,
            organization=organization,
            abuse_contact=abuse_contact,
            source=f"raw_whois:{referral_server or 'whois.iana.org'}",
            raw_text=raw_output[:12000],
        )

    def _query_whois_server(self, server: str, query: str) -> str:
        with socket.create_connection((server, 43), timeout=self.timeout_seconds) as sock:
            sock.settimeout(self.timeout_seconds)
            payload = f"{query}\r\n".encode("utf-8", errors="ignore")
            sock.sendall(payload)

            chunks: list[bytes] = []
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
            except socket.timeout:
                pass

        return b"".join(chunks).decode("utf-8", errors="ignore")

    @staticmethod
    def _extract_raw_field(raw_text: str, field_names: list[str]) -> str | None:
        for line in raw_text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", maxsplit=1)
            if key.strip().lower() in field_names:
                value = value.strip()
                if value:
                    return value
        return None

    @staticmethod
    def _extract_raw_abuse(raw_text: str) -> str | None:
        for line in raw_text.splitlines():
            if "abuse" not in line.lower():
                continue
            match = EMAIL_PATTERN.search(line)
            if match:
                return match.group(1)
        return None
