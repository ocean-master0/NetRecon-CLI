import asyncio
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, MagicMock

from netrecon.config import AppConfig
from netrecon.models import (
    DNSAnalysisResult,
    ExternalIPInfo,
    PortScanResult,
    RiskAssessment,
    ScanOptions,
    SecurityCheckResult,
    ThreatIntelResult,
    TracerouteResult,
)
from netrecon.orchestrator import NetReconOrchestrator


class OrchestratorTests(unittest.TestCase):
    def test_passive_mode_skips_aggressive_tasks(self):
        config = AppConfig()
        orchestrator = NetReconOrchestrator(config=config)
        orchestrator.ip_scanner.collect_local_ips = MagicMock(return_value=["192.168.1.10"])
        orchestrator.ip_scanner.lookup_external_ip_async = AsyncMock(return_value=(None, []))

        options = ScanOptions(mode="passive", scan_common_ports=True, traceroute_target="8.8.8.8", sniff=True)
        result = asyncio.run(orchestrator.run_async(options))
        self.assertTrue(any("skipped in passive mode" in warning.lower() for warning in result.warnings))

    def test_active_flow_with_mocks(self):
        config = AppConfig()
        orchestrator = NetReconOrchestrator(config=config)
        orchestrator.ip_scanner.collect_local_ips = MagicMock(return_value=["192.168.1.10"])
        orchestrator.ip_scanner.lookup_external_ip_async = AsyncMock(
            return_value=(ExternalIPInfo(ip="8.8.8.8"), [])
        )
        orchestrator.ip_scanner.reverse_dns_lookup = MagicMock(return_value=("dns.google", None))
        orchestrator.ip_scanner.build_geo_map_url = MagicMock(return_value="https://maps.example")
        orchestrator.port_scanner.scan_ports_async = AsyncMock(
            return_value=PortScanResult(
                target="8.8.8.8",
                scanned_ports=[80, 443],
                open_ports=[443],
                closed_ports=[80],
                filtered_ports=[],
                risky_open_ports=[],
            )
        )
        orchestrator.dns_analyzer.analyze = MagicMock(return_value=DNSAnalysisResult(hostname="example.com"))
        orchestrator.traceroute_scanner.trace_async = AsyncMock(
            return_value=TracerouteResult(target="8.8.8.8", method="test", hops=[])
        )
        orchestrator.threat_checker.check_ip_async = AsyncMock(
            return_value=ThreatIntelResult(ip="8.8.8.8", malicious_score=10)
        )
        orchestrator.security_checker.evaluate = MagicMock(
            return_value=SecurityCheckResult(
                input_ip="8.8.8.8",
                classification="Public",
                is_private=False,
                is_public=True,
                suspected_vpn=False,
                suspected_proxy=False,
            )
        )
        orchestrator.risk_engine.score = MagicMock(return_value=RiskAssessment(score=20, level="Low"))
        orchestrator.html_report_builder.generate = MagicMock(return_value=Path("report.html"))

        options = ScanOptions(
            mode="active",
            external_lookup=True,
            target="8.8.8.8",
            scan_common_ports=True,
            dns_host="example.com",
            traceroute_target="8.8.8.8",
            run_threat_check=True,
            security_check=True,
            html_report_path="report.html",
        )
        result = asyncio.run(orchestrator.run_async(options))
        self.assertEqual(result.external_info.ip, "8.8.8.8")
        self.assertEqual(result.port_scan.open_ports, [443])
        self.assertEqual(result.risk_assessment.score, 20)


if __name__ == "__main__":
    unittest.main()
