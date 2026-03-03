from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from rich.console import Console

from .config import AppConfig, ConfigLoader
from .logging_utils import setup_logging
from .models import ScanOptions
from .orchestrator import NetReconOrchestrator
from .port_scanner import PortScanner
from .renderer import render_rich, save_json_report, to_json

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for NetRecon commands."""
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="Professional network reconnaissance and security analysis CLI.",
    )
    parser.add_argument("--target", help="Target host/IP for scan modules.")
    parser.add_argument("--mode", choices=["passive", "active"], help="Scan mode: passive or active.")

    parser.add_argument("--external", action="store_true", dest="external", help="Enable external IP lookup.")
    parser.add_argument("--no-external", action="store_false", dest="external", help="Disable external IP lookup.")

    parser.add_argument("--interfaces", action="store_true", dest="interfaces", help="Include interface details.")
    parser.add_argument("--no-interfaces", action="store_false", dest="interfaces", help="Skip interface details.")

    parser.add_argument("--scan-common-ports", action="store_true", help="Scan predefined common TCP ports.")
    parser.add_argument(
        "--scan-ports",
        nargs="?",
        const="default",
        metavar="RANGE",
        help="Scan custom range (example: 1-1000). Use without value to use config default.",
    )

    parser.add_argument("--traceroute", metavar="TARGET", help="Run traceroute for the provided target.")
    parser.add_argument(
        "--traceroute-advanced",
        action="store_true",
        help="Enable traceroute hop geolocation and ASN enrichment.",
    )

    parser.add_argument("--subdomain", metavar="DOMAIN", help="Run subdomain scanner for the given domain.")
    parser.add_argument("--dns", metavar="HOST", help="Run DNS analyzer for hostname.")

    parser.add_argument("--whois", action="store_true", help="Run WHOIS lookup.")
    parser.add_argument("--whois-target", help="WHOIS target override (domain/IP).")

    parser.add_argument("--speedtest", action="store_true", help="Run internet speed test.")
    parser.add_argument("--threat-check", action="store_true", dest="threat_check", help="Run threat intelligence lookup.")

    parser.add_argument(
        "--security-check",
        action="store_true",
        dest="security_check",
        help="Run security classification and firewall checks.",
    )
    parser.add_argument(
        "--no-security-check",
        action="store_false",
        dest="security_check",
        help="Disable security checks even if enabled in config.",
    )

    parser.add_argument("--lan-scan", metavar="CIDR", help="Run LAN active host scan (example: 192.168.1.0/24).")
    parser.add_argument("--sniff", action="store_true", help="Run packet sniffer (advanced mode).")
    parser.add_argument("--sniff-limit", type=int, help="Packet capture limit for sniffer.")
    parser.add_argument("--sniff-timeout", type=int, help="Sniffer timeout in seconds.")

    parser.add_argument("--geo-html", metavar="PATH", help="Export Google Maps geo result to HTML.")
    parser.add_argument(
        "--html-report",
        nargs="?",
        const="default",
        metavar="PATH",
        help="Generate dashboard HTML report (default: report.html).",
    )

    parser.add_argument("--json", action="store_true", dest="json_output", help="Print JSON output to stdout.")
    parser.add_argument(
        "--save-json",
        nargs="?",
        const="",
        metavar="PATH",
        help="Save JSON report to disk. Default path is reports/netrecon_report_<timestamp>.json",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable Rich colorized output.")

    parser.add_argument("--config", default="config.json", help="Path to config.json file.")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity.")
    parser.add_argument("--log-file", help="Log file path override.")

    parser.set_defaults(external=None, interfaces=None, security_check=None)
    return parser


def resolve_scan_options(args: argparse.Namespace, config: AppConfig) -> ScanOptions:
    """Merge CLI arguments with config defaults and validate values."""
    mode = (args.mode or config.mode).lower()
    if mode not in {"passive", "active"}:
        raise ValueError("Mode must be either passive or active.")

    external_lookup = config.external_lookup if args.external is None else args.external
    include_interfaces = config.interfaces if args.interfaces is None else args.interfaces
    security_check = config.security_mode if args.security_check is None else args.security_check
    run_threat_check = bool(args.threat_check or config.threat_check)

    scan_port_range: str | None
    if args.scan_ports == "default":
        scan_port_range = config.default_port_range
    else:
        scan_port_range = args.scan_ports

    if scan_port_range:
        PortScanner.parse_port_range(scan_port_range)

    if args.lan_scan:
        try:
            ipaddress.ip_network(args.lan_scan, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid LAN scan CIDR: {exc}") from exc

    run_whois = bool(args.whois or args.whois_target)
    sniff_limit = args.sniff_limit if args.sniff_limit is not None else config.sniff_default_limit
    sniff_timeout = args.sniff_timeout if args.sniff_timeout is not None else config.sniff_default_timeout
    if sniff_limit <= 0 or sniff_timeout <= 0:
        raise ValueError("Sniffer limit and timeout must be positive integers.")

    html_report_path = _resolve_html_report_path(args.html_report, config.html_report_default)

    return ScanOptions(
        target=args.target,
        mode=mode,
        external_lookup=external_lookup,
        include_interfaces=include_interfaces,
        scan_common_ports=bool(args.scan_common_ports),
        scan_port_range=scan_port_range,
        run_whois=run_whois,
        whois_target=args.whois_target,
        run_speedtest=bool(args.speedtest),
        dns_host=args.dns,
        security_check=security_check,
        geo_html_path=args.geo_html,
        traceroute_target=args.traceroute,
        traceroute_advanced=bool(args.traceroute_advanced),
        subdomain_target=args.subdomain,
        run_threat_check=run_threat_check,
        html_report_path=html_report_path,
        lan_scan_cidr=args.lan_scan,
        sniff=bool(args.sniff),
        sniff_limit=sniff_limit,
        sniff_timeout=sniff_timeout,
    )


def _resolve_html_report_path(argument: str | None, default_path: str) -> str | None:
    if argument is None:
        return None
    if argument == "default":
        return default_path
    if argument.strip():
        return argument.strip()
    return default_path


def _resolve_json_save_path(save_json_arg: str | None) -> Path | None:
    if save_json_arg is None:
        return None
    if save_json_arg.strip():
        return Path(save_json_arg)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("reports") / f"netrecon_report_{timestamp}.json"


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    config = ConfigLoader(args.config).load()
    log_level = args.log_level or config.log_level
    log_file = args.log_file or config.log_file
    setup_logging(level=log_level, log_file=log_file)

    try:
        options = resolve_scan_options(args, config)
    except ValueError as exc:
        parser.error(str(exc))

    orchestrator = NetReconOrchestrator(config=config)
    console = Console(no_color=args.no_color)

    try:
        if args.json_output:
            result = orchestrator.run(options)
        else:
            with console.status("Running NetRecon modules...", spinner="dots"):
                result = orchestrator.run(options)
    except Exception as exc:  # noqa: BLE001 - top-level safeguard.
        LOGGER.exception("Fatal scan error")
        if args.json_output:
            _safe_print_json(to_json_error(str(exc)))
        else:
            console.print(f"[red]Fatal error:[/red] {exc}")
        return 1

    if args.json_output:
        _safe_print_json(to_json(result, pretty=True))
    else:
        render_rich(console, result)

    save_path = _resolve_json_save_path(args.save_json)
    if save_path is not None:
        try:
            written_path = save_json_report(result, save_path)
        except OSError as exc:
            LOGGER.error("Failed to save JSON report: %s", exc)
            if args.json_output:
                print(to_json_error(f"Failed to save JSON report: {exc}"), file=sys.stderr)
            else:
                console.print(f"[red]Failed to save JSON report:[/red] {exc}")
            return 1
        else:
            if not args.json_output:
                console.print(f"[green]JSON report saved:[/green] {written_path}")

    return 1 if result.errors else 0


def to_json_error(message: str) -> str:
    return json.dumps({"error": message}, ensure_ascii=False)


def _safe_print_json(payload: str) -> None:
    try:
        print(payload)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(payload.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
