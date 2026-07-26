from __future__ import annotations

import asyncio
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path

from .async_utils import run_async
from .config import AppConfig
from .cve_lookup import CveLookup
from .dns_analyzer import DNSAnalyzer
from .geoip import GeoIpLookup
from .ssl_grabber import SslGrabber
from .ssh_enum import SshEnumerator
from .html_report import HTMLReportBuilder
from .ip_scanner import IPScanner
from .lan_scanner import LANScanner
from .models import DNSAnalysisResult, OsFingerprintResult, PluginResult, ReconResult, ScanOptions
from .plugin_registry import PluginRegistry
from .port_scanner import PortScanner
from .risk_engine import RiskScoringEngine
from .security_checks import SecurityChecker
from .sniffer import PacketSniffer
from .speed_test import SpeedTester
from .os_fingerprint import fingerprint_os_async
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
        status_callback: object = None,
    ) -> None:
        self.config = config
        self._status = status_callback
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
        self.speed_tester = speed_tester or SpeedTester(timeout_seconds=60)
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

    def _set_status(self, message: str) -> None:
        LOGGER.info(message)
        if self._status is not None:
            try:
                self._status(message)
            except Exception as exc:
                LOGGER.debug("Status update failed (non-fatal): %s", exc)

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

        self._set_status("Collecting local IP addresses...")
        result.local_ips = self.ip_scanner.collect_local_ips()
        if not result.local_ips:
            result.warnings.append("No local IP addresses detected.")

        phase1_coros = []
        if options.external_lookup:
            phase1_coros.append(self._run_external_lookup(result))
        if options.include_interfaces:
            phase1_coros.append(self._run_interfaces(result))

        if phase1_coros:
            await asyncio.gather(*phase1_coros)

        passive_mode = options.mode == "passive"
        scan_target = self._resolve_target(options, result)

        phase2_coros = []
        if passive_mode:
            self._add_passive_skips(result, options)
        else:
            if options.scan_common_ports or options.scan_port_range:
                if scan_target:
                    phase2_coros.append(self._run_port_scan_task(result, scan_target, options))
                else:
                    result.warnings.append("Port scan skipped because no valid target was available.")
            if options.traceroute_target:
                phase2_coros.append(self._run_traceroute_task(result, options))
            if options.subdomain_target:
                phase2_coros.append(self._run_subdomain_task(result, options))
            if options.run_speedtest:
                phase2_coros.append(self._run_speedtest_task(result))
            if options.lan_scan_cidr:
                phase2_coros.append(self._run_lan_scan_task(result, options))
            if options.sniff:
                phase2_coros.append(self._run_sniff_task(result, options))
        if options.os_fingerprint_target:
            phase2_coros.append(self._run_os_fingerprint_task(result, options))
        if options.cve_target:
            phase2_coros.append(self._run_cve_lookup_task(result, options))
        if options.ssl_enum_target:
            phase2_coros.append(self._run_ssl_task(result, options))
        if options.ssh_enum_target:
            phase2_coros.append(self._run_ssh_task(result, options))
        if options.geoip_db_path:
            phase2_coros.append(self._run_geoip_task(result, options))
        if options.plugin_dir or options.list_plugins:
            phase2_coros.append(self._run_plugins_task(result, options))

        whois_task = self._run_whois_task(result, options)
        dns_task = self._run_dns_task(result, options)

        all_parallel = [t for t in [*phase2_coros, whois_task, dns_task] if t is not None]
        if all_parallel:
            await asyncio.gather(*all_parallel)

        if options.run_threat_check:
            self._set_status("Checking threat intelligence...")
            threat_ip = self._resolve_threat_ip(options, result)
            if threat_ip:
                result.threat_intel = await self.threat_checker.check_ip_async(threat_ip)
                result.warnings.extend(result.threat_intel.warnings)
            else:
                result.warnings.append("Threat check skipped because no IP target was available.")

        if options.security_check:
            self._set_status("Running security checks...")
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

    async def _run_external_lookup(self, result: ReconResult) -> None:
        self._set_status("Looking up external IP information...")
        external_info, external_warnings = await self.ip_scanner.lookup_external_ip_async()
        result.external_info = external_info
        result.warnings.extend(external_warnings)
        if external_info:
            reverse_dns, reverse_warning = self.ip_scanner.reverse_dns_lookup(external_info.ip)
            result.reverse_dns = reverse_dns
            if reverse_warning:
                result.warnings.append(reverse_warning)
            result.geo_map_url = self.ip_scanner.build_geo_map_url(external_info)

    async def _run_interfaces(self, result: ReconResult) -> None:
        self._set_status("Collecting network interface details...")
        interface_output, interface_warning = await asyncio.to_thread(self.ip_scanner.collect_network_interfaces)
        result.interface_details = interface_output
        if interface_warning:
            result.warnings.append(interface_warning)

    async def _run_port_scan_task(self, result: ReconResult, scan_target: str, options: ScanOptions) -> None:
        self._set_status("Scanning ports...")
        result.port_scan = await self._run_port_scan(scan_target, options)

    async def _run_traceroute_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Running traceroute...")
        result.traceroute = await self.traceroute_scanner.trace_async(
            options.traceroute_target,
            advanced=options.traceroute_advanced,
        )
        result.warnings.extend(result.traceroute.warnings)

    async def _run_subdomain_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Scanning subdomains...")
        scanner = self.subdomain_scanner
        if options.subdomain_wordlist_path:
            try:
                words = Path(options.subdomain_wordlist_path).read_text(encoding="utf-8").splitlines()
                words = [w.strip().lower() for w in words if w.strip()]
                if words:
                    scanner = SubdomainScanner(wordlist=words, max_workers=self.config.subdomain_workers)
            except OSError as exc:
                result.warnings.append(f"Failed to read wordlist file: {exc}")
        result.subdomains = await scanner.scan_async(options.subdomain_target, stealth_mode=options.stealth_mode)
        result.warnings.extend(result.subdomains.warnings)

    async def _run_whois_task(self, result: ReconResult, options: ScanOptions) -> None:
        if not options.run_whois:
            return
        self._set_status("Running WHOIS lookup...")
        whois_target = self._resolve_whois_target(options, result)
        if whois_target:
            whois_result, whois_warnings = await asyncio.to_thread(self.whois_lookup.lookup, whois_target)
            result.whois = whois_result
            result.warnings.extend(whois_warnings)
        else:
            result.warnings.append("WHOIS lookup skipped because target was not resolved.")

    async def _run_dns_task(self, result: ReconResult, options: ScanOptions) -> None:
        if options.dns_host:
            self._set_status("Analyzing DNS records...")
            result.dns = await asyncio.to_thread(self.dns_analyzer.analyze, options.dns_host)
            result.warnings.extend(result.dns.warnings)
        if options.dns_axfr_target:
            self._set_status("Attempting DNS zone transfer (AXFR)...")
            axfr_records, axfr_warnings = await asyncio.to_thread(self.dns_analyzer.axfr, options.dns_axfr_target)
            result.warnings.extend(axfr_warnings)
            if result.dns is None:
                result.dns = DNSAnalysisResult(hostname=options.dns_axfr_target)
            result.dns.axfr_records = axfr_records

    async def _run_speedtest_task(self, result: ReconResult) -> None:
        self._set_status("Running speed test (may take a minute)...")
        speed_result, speed_warnings = await asyncio.to_thread(self.speed_tester.run)
        result.speed_test = speed_result
        result.warnings.extend(speed_warnings)

    async def _run_lan_scan_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Scanning LAN...")
        result.lan_scan = await self.lan_scanner.scan_async(options.lan_scan_cidr)
        result.warnings.extend(result.lan_scan.warnings)

    async def _run_sniff_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Capturing packets (sniffer)...")
        result.sniffer = await asyncio.to_thread(
            self.sniffer.capture,
            limit=options.sniff_limit,
            timeout=options.sniff_timeout,
            filter_bpf=options.sniff_filter,
            pcap_path=options.pcap_path,
        )
        result.warnings.extend(result.sniffer.warnings)

    async def _run_os_fingerprint_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Fingerprinting target OS...")
        banner_window = None
        if result.port_scan and result.port_scan.banners:
            for banner in result.port_scan.banners:
                if banner.port in (80, 443, 8080):
                    banner_window = 65535
                    break
        result.os_fingerprint = await fingerprint_os_async(options.os_fingerprint_target, banner_window)

    async def _run_plugins_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Running plugins...")
        registry = PluginRegistry()
        registry.discover_entry_points()
        if options.plugin_dir:
            registry.discover_directory(options.plugin_dir)
        if registry.count == 0:
            if options.plugin_dir:
                result.warnings.append(f"No plugins found in '{options.plugin_dir}' or entry points.")
            elif options.list_plugins:
                result.warnings.append("No plugins discovered via entry points or directory.")
            return
        for plugin in registry._plugins.values():
            try:
                result = await asyncio.to_thread(plugin.run, options, result)
                result.plugin_results.append(PluginResult(
                    plugin_name=plugin.name,
                    plugin_version=plugin.version,
                ))
            except Exception as exc:
                result.warnings.append(f"Plugin '{plugin.name}' failed: {exc}")

    async def _run_geoip_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Running offline GeoIP lookup...")
        geoip = GeoIpLookup(db_path=options.geoip_db_path)
        ips: set[str] = set()
        if result.external_info:
            ips.add(result.external_info.ip)
        if result.local_ips:
            ips.update(result.local_ips)
        if options.target:
            ips.add(options.target)
        for ip in sorted(ips):
            result.geoip_result = await asyncio.to_thread(geoip.lookup, ip)
            break

    async def _run_ssl_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Grabbing SSL/TLS certificate...")
        grabber = SslGrabber()
        result.ssl_cert = await asyncio.to_thread(grabber.grab, options.ssl_enum_target, options.ssl_enum_port)
        result.warnings.extend(result.ssl_cert.warnings)

    async def _run_ssh_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Enumerating SSH server...")
        enump = SshEnumerator()
        result.ssh_enum = await asyncio.to_thread(enump.enumerate, options.ssh_enum_target, options.ssh_enum_port)
        result.warnings.extend(result.ssh_enum.warnings)

    async def _run_cve_lookup_task(self, result: ReconResult, options: ScanOptions) -> None:
        self._set_status("Looking up CVEs...")
        api_key = self.config.api_keys.get("nvd", "")
        lookup = CveLookup(api_key=api_key if api_key else None)
        cve_result = await lookup.lookup(options.cve_target, options.cve_version)
        if result.cve_results is None:
            result.cve_results = []
        result.cve_results.append(cve_result)
        result.warnings.extend(cve_result.warnings)

    @staticmethod
    def _add_passive_skips(result: ReconResult, options: ScanOptions) -> None:
        if options.scan_common_ports or options.scan_port_range:
            result.warnings.append("Port scan skipped in passive mode.")
        if options.traceroute_target:
            result.warnings.append("Traceroute skipped in passive mode.")
        if options.run_speedtest:
            result.warnings.append("Speed test skipped in passive mode.")
        if options.lan_scan_cidr:
            result.warnings.append("LAN scan skipped in passive mode.")
        if options.sniff:
            result.warnings.append("Packet sniffing skipped in passive mode.")

    async def _run_port_scan(self, target: str, options: ScanOptions):
        ports: set[int] = set()
        if options.scan_common_ports:
            ports.update(self.config.common_ports)
        if options.scan_port_range:
            ports.update(self.port_scanner.parse_port_range(options.scan_port_range))
        if not ports:
            return None
        return await self.port_scanner.scan_ports_async(
            target=target, ports=sorted(ports), grab_banners=True, stealth_mode=options.stealth_mode,
        )

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
