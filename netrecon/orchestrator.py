from __future__ import annotations

import asyncio
import logging
import socket
from datetime import datetime, timezone

from .async_utils import run_async
from .config import AppConfig
from .dns_analyzer import DNSAnalyzer
from .html_report import HTMLReportBuilder
from .ip_scanner import IPScanner
from .lan_scanner import LANScanner
from .models import ReconResult, ScanOptions
from .port_scanner import PortScanner
from .risk_engine import RiskScoringEngine
from .security_checks import SecurityChecker
from .sniffer import PacketSniffer
from .speed_test import SpeedTester
from .subdomain_scanner import SubdomainScanner
from .threat_intel import ThreatIntelChecker
from .traceroute import TracerouteScanner
from .whois_lookup import WhoisLookup

LOGGER = logging.getLogger(__name__)


class NetReconOrchestrator:
    """Coordinates all module scans and builds a single result object."""

    def __init__(
        self,
        config: AppConfig,
        ip_scanner: IPScanner | None = None,
        port_scanner: PortScanner | None = None,
        whois_lookup: WhoisLookup | None = None,
        speed_tester: SpeedTester | None = None,
        dns_analyzer: DNSAnalyzer | None = None,
        security_checker: SecurityChecker | None = None,
        traceroute_scanner: TracerouteScanner | None = None,
        subdomain_scanner: SubdomainScanner | None = None,
        threat_checker: ThreatIntelChecker | None = None,
        risk_engine: RiskScoringEngine | None = None,
        lan_scanner: LANScanner | None = None,
        sniffer: PacketSniffer | None = None,
        html_report_builder: HTMLReportBuilder | None = None,
    ) -> None:
        self.config = config
        self.ip_scanner = ip_scanner or IPScanner(
            request_timeout_seconds=config.request_timeout_seconds,
            external_workers=config.external_workers,
        )
        self.port_scanner = port_scanner or PortScanner(
            common_ports=config.common_ports,
            risky_ports=config.risky_ports,
            timeout=config.connect_timeout,
            max_workers=config.port_scan_workers,
        )
        self.whois_lookup = whois_lookup or WhoisLookup()
        self.speed_tester = speed_tester or SpeedTester()
        self.dns_analyzer = dns_analyzer or DNSAnalyzer(timeout=config.request_timeout_seconds)
        self.security_checker = security_checker or SecurityChecker(risky_ports=config.risky_ports)
        self.traceroute_scanner = traceroute_scanner or TracerouteScanner(
            max_hops=config.traceroute_max_hops,
            timeout_ms=config.traceroute_timeout_ms,
            enrich_hop=self.ip_scanner.enrich_ip_async,
        )
        self.subdomain_scanner = subdomain_scanner or SubdomainScanner(
            wordlist=config.subdomain_wordlist,
            max_workers=config.subdomain_workers,
        )
        self.threat_checker = threat_checker or ThreatIntelChecker(
            api_keys=config.api_keys,
            timeout_seconds=config.request_timeout_seconds,
        )
        self.risk_engine = risk_engine or RiskScoringEngine()
        self.lan_scanner = lan_scanner or LANScanner(timeout_ms=config.lan_scan_timeout_ms)
        self.sniffer = sniffer or PacketSniffer()
        self.html_report_builder = html_report_builder or HTMLReportBuilder()

    def run(self, options: ScanOptions) -> ReconResult:
        """Synchronous wrapper to execute async orchestrator."""
        return run_async(self.run_async(options))

    async def run_async(self, options: ScanOptions) -> ReconResult:
        """Execute requested scan options and return aggregated recon output."""
        result = ReconResult(
            timestamp=datetime.now(timezone.utc).astimezone().isoformat(),
            hostname=socket.gethostname(),
            mode=options.mode,
        )

        LOGGER.info("Starting NetRecon scan with options: %s", options)
        result.local_ips = self.ip_scanner.collect_local_ips()
        if not result.local_ips:
            result.warnings.append("No local IP addresses detected.")

        if options.external_lookup:
            external_info, external_warnings = await self.ip_scanner.lookup_external_ip_async()
            result.external_info = external_info
            result.warnings.extend(external_warnings)

            if external_info:
                reverse_dns, reverse_warning = self.ip_scanner.reverse_dns_lookup(external_info.ip)
                result.reverse_dns = reverse_dns
                if reverse_warning:
                    result.warnings.append(reverse_warning)
                result.geo_map_url = self.ip_scanner.build_geo_map_url(external_info)

        if options.include_interfaces:
            interface_output, interface_warning = await asyncio.to_thread(self.ip_scanner.collect_network_interfaces)
            result.interface_details = interface_output
            if interface_warning:
                result.warnings.append(interface_warning)

        scan_target = self._resolve_target(options, result)
        passive_mode = options.mode == "passive"

        if options.scan_common_ports or options.scan_port_range:
            if passive_mode:
                result.warnings.append("Port scan skipped in passive mode.")
            elif scan_target:
                result.port_scan = await self._run_port_scan(scan_target, options)
            else:
                result.warnings.append("Port scan skipped because no valid target was available.")

        if options.traceroute_target:
            if passive_mode:
                result.warnings.append("Traceroute skipped in passive mode.")
            else:
                result.traceroute = await self.traceroute_scanner.trace_async(
                    options.traceroute_target,
                    advanced=options.traceroute_advanced,
                )
                result.warnings.extend(result.traceroute.warnings)

        if options.subdomain_target:
            result.subdomains = await self.subdomain_scanner.scan_async(options.subdomain_target)
            result.warnings.extend(result.subdomains.warnings)

        if options.run_whois:
            whois_target = self._resolve_whois_target(options, result)
            if whois_target:
                whois_result, whois_warnings = await asyncio.to_thread(self.whois_lookup.lookup, whois_target)
                result.whois = whois_result
                result.warnings.extend(whois_warnings)
            else:
                result.warnings.append("WHOIS lookup skipped because target was not resolved.")

        if options.dns_host:
            result.dns = await asyncio.to_thread(self.dns_analyzer.analyze, options.dns_host)
            result.warnings.extend(result.dns.warnings)

        if options.run_speedtest:
            if passive_mode:
                result.warnings.append("Speed test skipped in passive mode.")
            else:
                speed_result, speed_warnings = await asyncio.to_thread(self.speed_tester.run)
                result.speed_test = speed_result
                result.warnings.extend(speed_warnings)

        if options.lan_scan_cidr:
            if passive_mode:
                result.warnings.append("LAN scan skipped in passive mode.")
            else:
                result.lan_scan = await self.lan_scanner.scan_async(options.lan_scan_cidr)
                result.warnings.extend(result.lan_scan.warnings)

        if options.sniff:
            if passive_mode:
                result.warnings.append("Packet sniffing skipped in passive mode.")
            else:
                result.sniffer = await asyncio.to_thread(
                    self.sniffer.capture,
                    limit=options.sniff_limit,
                    timeout=options.sniff_timeout,
                )
                result.warnings.extend(result.sniffer.warnings)

        if options.run_threat_check:
            threat_ip = self._resolve_threat_ip(options, result)
            if threat_ip:
                result.threat_intel = await self.threat_checker.check_ip_async(threat_ip)
                result.warnings.extend(result.threat_intel.warnings)
            else:
                result.warnings.append("Threat check skipped because no IP target was available.")

        if options.security_check:
            security_ip = self._resolve_security_ip(options, result)
            open_ports = result.port_scan.open_ports if result.port_scan else []
            result.security = self.security_checker.evaluate(
                ip_value=security_ip,
                external_info=result.external_info,
                reverse_dns=result.reverse_dns,
                whois_result=result.whois,
                open_ports=open_ports,
                port_scan=result.port_scan,
                traceroute=result.traceroute,
            )

        result.risk_assessment = self.risk_engine.score(
            port_scan=result.port_scan,
            threat_intel=result.threat_intel,
            dns_analysis=result.dns,
            whois_result=result.whois,
            firewall=result.security.firewall if result.security else None,
            proxy_detected=bool(result.external_info and result.external_info.proxy_detected),
            vpn_detected=bool(result.external_info and result.external_info.vpn_detected),
        )

        if options.geo_html_path:
            if result.geo_map_url:
                try:
                    path = self.ip_scanner.export_geo_map_html(result.geo_map_url, options.geo_html_path)
                    result.geo_map_html_path = str(path)
                except OSError as exc:
                    result.errors.append(f"Geo map HTML export failed: {exc}")
            else:
                result.warnings.append("Geo map HTML export skipped because coordinates are unavailable.")

        if options.html_report_path:
            try:
                html_path = await asyncio.to_thread(self.html_report_builder.generate, result, options.html_report_path)
                result.html_report_path = str(html_path)
            except OSError as exc:
                result.errors.append(f"HTML report export failed: {exc}")

        LOGGER.info(
            "NetRecon scan complete with %s warnings and %s errors.",
            len(result.warnings),
            len(result.errors),
        )
        return result

    async def _run_port_scan(self, target: str, options: ScanOptions):
        ports: set[int] = set()
        if options.scan_common_ports:
            ports.update(self.config.common_ports)
        if options.scan_port_range:
            ports.update(self.port_scanner.parse_port_range(options.scan_port_range))
        if not ports:
            return None
        return await self.port_scanner.scan_ports_async(target=target, ports=sorted(ports), grab_banners=True)

    @staticmethod
    def _resolve_target(options: ScanOptions, result: ReconResult) -> str | None:
        if options.target:
            return options.target
        if result.external_info:
            return result.external_info.ip
        if result.local_ips:
            return result.local_ips[0]
        return None

    @staticmethod
    def _resolve_whois_target(options: ScanOptions, result: ReconResult) -> str | None:
        if options.whois_target:
            return options.whois_target
        if options.target:
            return options.target
        if result.external_info:
            return result.external_info.ip
        return None

    @staticmethod
    def _resolve_security_ip(options: ScanOptions, result: ReconResult) -> str | None:
        if result.external_info:
            return result.external_info.ip
        if options.target:
            return options.target
        if result.local_ips:
            return result.local_ips[0]
        return None

    @staticmethod
    def _resolve_threat_ip(options: ScanOptions, result: ReconResult) -> str | None:
        if result.external_info:
            return result.external_info.ip
        if options.target:
            return options.target
        return None
