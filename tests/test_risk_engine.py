import unittest

from netrecon.models import DNSAnalysisResult, FirewallDetectionResult, PortScanResult, ThreatIntelResult, WhoisResult
from netrecon.risk_engine import RiskScoringEngine


class RiskEngineTests(unittest.TestCase):
    def test_score_high(self):
        engine = RiskScoringEngine()
        port_scan = PortScanResult(
            target="8.8.8.8",
            scanned_ports=[21, 22, 445],
            open_ports=[21, 445],
            closed_ports=[22],
            filtered_ports=[],
            risky_open_ports=[21, 445],
        )
        threat = ThreatIntelResult(ip="8.8.8.8", malicious_score=80, blacklist_count=5, spam_reports=50)
        dns = DNSAnalysisResult(hostname="example.com", spf_present=False, dmarc_present=False, dnssec_enabled=False)
        whois = WhoisResult(query="8.8.8.8", organization="Proxy Hosting")
        firewall = FirewallDetectionResult(likely_firewall=True, filtered_ratio=0.5)
        result = engine.score(
            port_scan=port_scan,
            threat_intel=threat,
            dns_analysis=dns,
            whois_result=whois,
            firewall=firewall,
            proxy_detected=True,
            vpn_detected=True,
        )
        self.assertGreaterEqual(result.score, 50)
        self.assertIn(result.level, {"High", "Critical"})


if __name__ == "__main__":
    unittest.main()
