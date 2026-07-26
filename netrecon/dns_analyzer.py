from __future__ import annotations

import logging
import socket

from .models import DNSAnalysisResult

LOGGER = logging.getLogger(__name__)


class DNSAnalyzer:
    """DNS record analyzer with SPF/DMARC/DNSSEC checks."""

    COMMON_SRV_SERVICES = [
        "_sip._tcp", "_sip._udp", "_sips._tcp",
        "_ldap._tcp", "_ldaps._tcp",
        "_xmpp-client._tcp", "_xmpp-server._tcp",
        "_imap._tcp", "_imaps._tcp",
        "_pop3._tcp", "_pop3s._tcp",
        "_caldav._tcp", "_caldavs._tcp",
        "_carddav._tcp", "_carddavs._tcp",
        "_jabber._tcp", "_jabber._udp",
        "_stun._tcp", "_stun._udp",
        "_turn._tcp", "_turn._udp",
        "_matrix._tcp",
    ]

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    @staticmethod
    def _walk_parents(hostname: str) -> list[str]:
        parts = hostname.split(".")
        return [".".join(parts[i:]) for i in range(1, len(parts) - 1)]

    def analyze(self, hostname: str) -> DNSAnalysisResult:
        warnings: list[str] = []

        try:
            import dns.exception
            import dns.resolver
        except ModuleNotFoundError:
            warnings.append("dnspython is required for DNS analyzer.")
            return DNSAnalysisResult(hostname=hostname, warnings=warnings)

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        def _resolve(record_type: str, target: str | None = None) -> list[str]:
            qname = target or hostname
            try:
                answers = resolver.resolve(qname, record_type)
            except dns.resolver.NoAnswer:
                return []
            except dns.resolver.NXDOMAIN:
                message = f"DNS host not found: {qname}"
                if message not in warnings:
                    warnings.append(message)
                return []
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                warnings.append(f"{record_type} lookup failed: {exc}")
                return []
            except Exception as exc:
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

        def _resolve_single(record_type: str, target: str | None = None) -> str | None:
            vals = _resolve(record_type, target)
            return vals[0] if vals else None

        a_records = _resolve("A")
        aaaa_records = _resolve("AAAA")
        mx_records = _resolve("MX")
        txt_records = _resolve("TXT")
        ns_records = _resolve("NS")
        cname_records = _resolve("CNAME")
        soa_record = _resolve_single("SOA")

        srv_records: list[str] = []
        for service in self.COMMON_SRV_SERVICES:
            vals = _resolve("SRV", f"{service}.{hostname}")
            if vals:
                srv_records.extend(vals)

        caa_records = _resolve("CAA")
        tlsa_records: list[str] = []
        for prefix in ("_443._tcp", "_25._tcp", "_853._tcp"):
            vals = _resolve("TLSA", f"{prefix}.{hostname}")
            if vals:
                tlsa_records.extend(vals)

        spf_present = any("v=spf1" in record.lower() for record in txt_records)
        spf_source = hostname if spf_present else ""

        dmarc_present = self._check_dmarc(resolver, hostname, warnings)
        dmarc_source = hostname if dmarc_present else ""

        dnssec_enabled, dnssec_source = self._check_dnssec(resolver, hostname, warnings)

        for parent in self._walk_parents(hostname):
            if not spf_present:
                parent_txt = _resolve("TXT", parent)
                spf_present = any("v=spf1" in record.lower() for record in parent_txt)
                spf_source = f"{parent} (inherited)" if spf_present else ""
            if not dmarc_present:
                dmarc_present = self._check_dmarc(resolver, parent, warnings)
                dmarc_source = f"{parent} (inherited)" if dmarc_present else ""
            if spf_present and dmarc_present and dnssec_enabled:
                break

        return DNSAnalysisResult(
            hostname=hostname,
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            txt_records=txt_records,
            ns_records=ns_records,
            cname_records=cname_records,
            soa_record=soa_record,
            srv_records=srv_records,
            caa_records=caa_records,
            tlsa_records=tlsa_records,
            spf_present=spf_present,
            spf_source=spf_source,
            dmarc_present=dmarc_present,
            dmarc_source=dmarc_source,
            dnssec_enabled=dnssec_enabled,
            dnssec_source=dnssec_source,
            warnings=warnings,
        )

    def reverse_lookup(self, ip_value: str) -> tuple[str | None, str | None]:
        try:
            host, _, _ = socket.gethostbyaddr(ip_value)
            return host, None
        except (socket.herror, socket.gaierror, OSError) as exc:
            return None, f"Reverse lookup failed: {exc}"

    def axfr(self, hostname: str) -> tuple[list[str], list[str]]:
        warnings: list[str] = []
        records: list[str] = []
        try:
            import dns.exception
            import dns.resolver
            import dns.zone
        except ModuleNotFoundError:
            warnings.append("dnspython is required for DNS AXFR.")
            return records, warnings

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        try:
            ns_answers = resolver.resolve(hostname, "NS")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            warnings.append("AXFR skipped: no NS records found.")
            return records, warnings
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            warnings.append(f"AXFR NS lookup failed: {exc}")
            return records, warnings
        except Exception as exc:
            warnings.append(f"AXFR NS lookup failed: {exc}")
            return records, warnings

        for ns_answer in ns_answers:
            ns_host = str(ns_answer).strip().rstrip(".")
            try:
                axfr_answer = dns.zone.from_xfr(dns.query.xfr(ns_host, hostname, lifetime=self.timeout))
                for name, node in axfr_answer.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(f"{name} {rdataset.rdtype} {rdata}")
                if records:
                    break
            except (dns.exception.FormError, dns.exception.Timeout, dns.query.BadResponse):
                continue
            except Exception:
                continue

        if not records:
            warnings.append("AXFR failed on all nameservers (zone transfer likely denied).")
        return records, warnings

    @staticmethod
    def _check_dmarc(resolver: object, hostname: str, warnings: list[str]) -> bool:
        try:
            import dns.exception
            import dns.resolver
        except ModuleNotFoundError:
            return False

        dmarc_host = f"_dmarc.{hostname}"
        try:
            answers = resolver.resolve(dmarc_host, "TXT")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            warnings.append(f"DMARC lookup failed: {exc}")
            return False
        except Exception as exc:
            warnings.append(f"DMARC lookup failed: {exc}")
            return False

        for answer in answers:
            text = str(answer).strip().strip('"')
            if "v=dmarc1" in text.lower():
                return True
        return False

    @staticmethod
    def _check_dnssec(resolver: object, hostname: str, warnings: list[str]) -> tuple[bool, str]:
        try:
            import dns.exception
            import dns.resolver
        except ModuleNotFoundError:
            return (False, "")

        def _has_dnskey(qname: str) -> bool:
            try:
                answers = resolver.resolve(qname, "DNSKEY")
                return bool(list(answers))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return False
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                return False
            except Exception:
                return False

        def _has_ns(qname: str) -> bool:
            try:
                answers = resolver.resolve(qname, "NS")
                return bool(list(answers))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return False
            except Exception:
                return False

        if _has_dnskey(hostname):
            return (True, hostname)

        parts = hostname.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if not _has_dnskey(parent):
                continue
            same_zone = True
            for j in range(1, i):
                intermediate = ".".join(parts[j:])
                if _has_ns(intermediate):
                    same_zone = False
                    break
            if same_zone:
                return (True, f"{parent} (inherited)")
            break

        return (False, "")
