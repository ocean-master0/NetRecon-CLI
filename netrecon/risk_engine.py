from __future__ import annotations

from .models import (
    DNSAnalysisResult,
    FirewallDetectionResult,
    PortScanResult,
    RiskAssessment,
    ThreatIntelResult,
    WhoisResult,
)

SUSPICIOUS_ASN_KEYWORDS = [
    "hosting",
    "datacenter",
    "vps",
    "anonymous",
    "proxy",
    "vpn",
]


class RiskScoringEngine:
    """Weighted scoring engine for consolidated recon risk assessment."""

    def score(
        self,
        *,
        port_scan: PortScanResult | None = None,
        threat_intel: ThreatIntelResult | None = None,
        dns_analysis: DNSAnalysisResult | None = None,
        whois_result: WhoisResult | None = None,
        firewall: FirewallDetectionResult | None = None,
        proxy_detected: bool = False,
        vpn_detected: bool = False,
    ) -> RiskAssessment:
        score = 0
        factors: list[str] = []

        if port_scan:
            risky_ports = len(port_scan.risky_open_ports)
            if risky_ports:
                port_score = min(30, risky_ports * 8)
                score += port_score
                factors.append(f"Risky open ports contribution: +{port_score}")

            if port_scan.filtered_count > 0 and len(port_scan.scanned_ports) >= 20:
                score += 5
                factors.append("Significant filtered ports detected: +5")

        if proxy_detected:
            score += 15
            factors.append("Proxy indicator detected: +15")
        if vpn_detected:
            score += 10
            factors.append("VPN indicator detected: +10")

        if whois_result:
            org_text = " ".join(part.lower() for part in [whois_result.organization or "", whois_result.isp or ""])
            if any(keyword in org_text for keyword in SUSPICIOUS_ASN_KEYWORDS):
                score += 10
                factors.append("Suspicious ASN/organization pattern: +10")

        if threat_intel:
            if threat_intel.blacklist_count:
                add = min(25, threat_intel.blacklist_count * 3)
                score += add
                factors.append(f"Blacklist presence contribution: +{add}")

            if threat_intel.malicious_score:
                add = min(30, int(threat_intel.malicious_score * 0.3))
                score += add
                factors.append(f"Threat malicious score contribution: +{add}")

            if threat_intel.spam_reports:
                add = min(10, int(threat_intel.spam_reports / 10))
                score += add
                factors.append(f"Spam reports contribution: +{add}")

            if threat_intel.known_vulnerabilities:
                add = min(15, len(threat_intel.known_vulnerabilities) * 3)
                score += add
                factors.append(f"Known vulnerabilities contribution: +{add}")

        if dns_analysis:
            if not dns_analysis.spf_present:
                score += 8
                factors.append("SPF missing: +8")
            if not dns_analysis.dmarc_present:
                score += 8
                factors.append("DMARC missing: +8")
            if not dns_analysis.dnssec_enabled:
                score += 5
                factors.append("DNSSEC not detected: +5")

        if firewall and firewall.likely_firewall:
            score += 4
            factors.append("Firewall/filtering anomalies detected: +4")

        score = max(0, min(100, score))
        level = self._level(score)
        return RiskAssessment(score=score, level=level, factors=factors)

    @staticmethod
    def _level(score: int) -> str:
        if score < 25:
            return "Low"
        if score < 50:
            return "Medium"
        if score < 75:
            return "High"
        return "Critical"
