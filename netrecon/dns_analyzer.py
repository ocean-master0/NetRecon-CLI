from __future__ import annotations

import logging
import socket

from .models import DNSAnalysisResult

LOGGER = logging.getLogger(__name__)


class DNSAnalyzer:
    """DNS record analyzer with SPF/DMARC/DNSSEC checks."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def analyze(self, hostname: str) -> DNSAnalysisResult:
        warnings: list[str] = []

        try:
            import dns.exception  # type: ignore[import-not-found]
            import dns.resolver  # type: ignore[import-not-found]
        except ModuleNotFoundError:
            warnings.append("dnspython is required for DNS analyzer.")
            return DNSAnalysisResult(hostname=hostname, warnings=warnings)

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        def _resolve(record_type: str) -> list[str]:
            try:
                answers = resolver.resolve(hostname, record_type)
            except dns.resolver.NoAnswer:
                return []
            except dns.resolver.NXDOMAIN:
                message = f"DNS host not found: {hostname}"
                if message not in warnings:
                    warnings.append(message)
                return []
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                warnings.append(f"{record_type} lookup failed: {exc}")
                return []
            except Exception as exc:  # noqa: BLE001 - dnspython exception family is broad.
                warnings.append(f"{record_type} lookup failed: {exc}")
                return []

            values: list[str] = []
            for answer in answers:
                text = str(answer).strip().rstrip(".")
                if record_type == "MX":
                    parts = text.split()
                    text = parts[-1] if parts else text
                values.append(text)
            return sorted(set(values))

        a_records = _resolve("A")
        aaaa_records = _resolve("AAAA")
        mx_records = _resolve("MX")
        txt_records = _resolve("TXT")
        ns_records = _resolve("NS")
        cname_records = _resolve("CNAME")

        spf_present = any("v=spf1" in record.lower() for record in txt_records)
        dmarc_present = self._check_dmarc(resolver, hostname, warnings)
        dnssec_enabled = self._check_dnssec(resolver, hostname, warnings)

        return DNSAnalysisResult(
            hostname=hostname,
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            txt_records=txt_records,
            ns_records=ns_records,
            cname_records=cname_records,
            spf_present=spf_present,
            dmarc_present=dmarc_present,
            dnssec_enabled=dnssec_enabled,
            warnings=warnings,
        )

    def reverse_lookup(self, ip_value: str) -> tuple[str | None, str | None]:
        """Resolve reverse DNS for a given IP."""
        try:
            host, _, _ = socket.gethostbyaddr(ip_value)
            return host, None
        except (socket.herror, socket.gaierror, OSError) as exc:
            return None, f"Reverse lookup failed: {exc}"

    @staticmethod
    def _check_dmarc(resolver: object, hostname: str, warnings: list[str]) -> bool:
        try:
            import dns.exception  # type: ignore[import-not-found]
            import dns.resolver  # type: ignore[import-not-found]
        except ModuleNotFoundError:
            return False

        dmarc_host = f"_dmarc.{hostname}"
        try:
            answers = resolver.resolve(dmarc_host, "TXT")  # type: ignore[attr-defined]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            warnings.append(f"DMARC lookup failed: {exc}")
            return False
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"DMARC lookup failed: {exc}")
            return False

        for answer in answers:
            text = str(answer).strip().strip('"')
            if "v=dmarc1" in text.lower():
                return True
        return False

    @staticmethod
    def _check_dnssec(resolver: object, hostname: str, warnings: list[str]) -> bool:
        try:
            import dns.exception  # type: ignore[import-not-found]
            import dns.resolver  # type: ignore[import-not-found]
        except ModuleNotFoundError:
            return False

        try:
            answers = resolver.resolve(hostname, "DNSKEY")  # type: ignore[attr-defined]
            return bool(list(answers))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            warnings.append(f"DNSSEC check failed: {exc}")
            return False
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"DNSSEC check failed: {exc}")
            return False
