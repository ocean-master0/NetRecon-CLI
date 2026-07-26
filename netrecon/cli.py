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
from .models import ReconResult, ScanOptions
from .monitor import ContinuousMonitor, format_deltas, has_changes
from .orchestrator import NetReconOrchestrator
from .server import ApiServer
from .tui_app import NetReconTuiApp
from .port_scanner import PortScanner
from .renderer import render_rich, save_csv_report, save_json_report, to_json

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for NetRecon commands."""
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="Professional network reconnaissance and security analysis CLI.",
    )
    parser.add_argument("-t", "--target", help="Target host/IP for scan modules.")
    parser.add_argument("-m", "--mode", choices=["passive", "active"], help="Scan mode: passive or active.")

    parser.add_argument("--external", action="store_true", dest="external", help="Enable external IP lookup.")
    parser.add_argument("--no-external", action="store_false", dest="external", help="Disable external IP lookup.")

    parser.add_argument("--interfaces", action="store_true", dest="interfaces", help="Include interface details.")
    parser.add_argument("--no-interfaces", action="store_false", dest="interfaces", help="Skip interface details.")

    parser.add_argument("-s", "--stealth", action="store_true", dest="stealth_mode", help="Stealth mode: adds jitter/delay between probes to reduce detection.")
    parser.add_argument("--scan-common-ports", action="store_true", dest="scan_common_ports", help="Scan predefined common TCP ports.")
    parser.add_argument("--no-scan-common-ports", action="store_false", dest="scan_common_ports", help="Skip scanning common TCP ports.")
    parser.add_argument(
        "-p", "--scan-ports",
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

    parser.add_argument("-d", "--subdomain", metavar="DOMAIN", help="Run subdomain scanner for the given domain.")
    parser.add_argument("--subdomain-wordlist", metavar="FILE", help="Path to custom subdomain wordlist file (one word per line).")
    parser.add_argument("--dns", metavar="HOST", help="Run DNS analyzer for hostname.")
    parser.add_argument("--dns-axfr", metavar="DOMAIN", help="Attempt DNS zone transfer (AXFR) for domain.")
    parser.add_argument("--os-fingerprint", metavar="HOST", help="Run OS fingerprinting on target host.")
    parser.add_argument("--cve-lookup", metavar="PRODUCT", help="Look up CVEs for a software product (e.g. 'apache httpd').")
    parser.add_argument("--cve-version", metavar="VERSION", help="Software version for CVE lookup.")

    parser.add_argument("-w", "--whois", action="store_true", help="Run WHOIS lookup.")
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
    parser.add_argument("--sniff-filter", metavar="BPF", help="BPF filter for sniffer (e.g. 'tcp port 80').")
    parser.add_argument("--sniff-pcap", metavar="PATH", help="Save captured packets to PCAP file.")

    parser.add_argument("--geo-html", metavar="PATH", help="Export Google Maps geo result to HTML.")
    parser.add_argument(
        "-r", "--html-report",
        nargs="?",
        const="default",
        metavar="PATH",
        help="Generate dashboard HTML report (default: report.html).",
    )

    parser.add_argument("-j", "--json", action="store_true", dest="json_output", help="Print JSON output to stdout.")
    parser.add_argument(
        "--save-json",
        nargs="?",
        const="",
        metavar="PATH",
        help="Save JSON report to disk. Default path is reports/netrecon_report_<timestamp>.json",
    )
    parser.add_argument(
        "--save-csv",
        nargs="?",
        const="",
        metavar="PATH",
        help="Save CSV report to disk. Default path is reports/netrecon_report_<timestamp>.csv",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable Rich colorized output.")

    parser.add_argument("--init-config", action="store_true", help="Generate a default config.json and exit.")
    parser.add_argument("--watch", action="store_true", help="Enable continuous monitoring mode (re-scan at interval).")
    parser.add_argument("--watch-interval", type=int, default=60, metavar="SECONDS", help="Polling interval for watch mode (default: 60s).")
    parser.add_argument("--serve", action="store_true", help="Start REST API server (default port 8088).")
    parser.add_argument("--serve-host", default="127.0.0.1", help="API server bind address (default: 127.0.0.1).")
    parser.add_argument("--serve-port", type=int, default=8088, help="API server port (default: 8088).")
    parser.add_argument("--ssl-enum", metavar="HOST", help="Grab SSL/TLS certificate from host.")
    parser.add_argument("--ssl-port", type=int, default=443, help="SSL/TLS port (default: 443).")
    parser.add_argument("--ssh-enum", metavar="HOST", help="Enumerate SSH server algorithms.")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22).")
    parser.add_argument("--geoip-db", metavar="PATH", help="Path to GeoLite2 City/ASN .mmdb database.")
    parser.add_argument("--tui", action="store_true", help="Launch interactive TUI dashboard.")

    parser.add_argument("--plugin-dir", metavar="DIR", help="Plugin directory to load external modules from.")
    parser.add_argument("--list-plugins", action="store_true", help="List all discovered plugins and exit.")

    parser.add_argument("-c", "--config", default="config.json", help="Path to config.json file.")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity.")
    parser.add_argument("--log-file", help="Log file path override.")

    parser.set_defaults(external=None, interfaces=None, security_check=None)
    return parser


MAX_ARG_LENGTH = 4096

def _validate_length(value: str | None, name: str) -> None:
    if value and len(value) > MAX_ARG_LENGTH:
        raise ValueError(f"{name} exceeds maximum length of {MAX_ARG_LENGTH} characters.")


def resolve_scan_options(args: argparse.Namespace, config: AppConfig) -> ScanOptions:
    """Merge CLI arguments with config defaults and validate values."""
    for arg_name in ("target", "dns", "whois_target", "traceroute", "subdomain", "lan_scan", "geo_html"):
        _validate_length(getattr(args, arg_name.replace("-", "_"), None), arg_name)

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
    sniff_pcap = args.sniff_pcap or (config.sniff_default_pcap if hasattr(config, "sniff_default_pcap") else None)

    html_report_path = _resolve_html_report_path(args.html_report, config.html_report_default)

    return ScanOptions(
        stealth_mode=bool(args.stealth_mode),
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
        dns_axfr_target=args.dns_axfr,
        security_check=security_check,
        geo_html_path=args.geo_html,
        traceroute_target=args.traceroute,
        traceroute_advanced=bool(args.traceroute_advanced),
        subdomain_target=args.subdomain,
        subdomain_wordlist_path=args.subdomain_wordlist,
        run_threat_check=run_threat_check,
        html_report_path=html_report_path,
        lan_scan_cidr=args.lan_scan,
        sniff=bool(args.sniff),
        sniff_limit=sniff_limit,
        sniff_timeout=sniff_timeout,
        sniff_filter=args.sniff_filter,
        pcap_path=sniff_pcap,
        ssl_enum_target=args.ssl_enum,
        ssl_enum_port=args.ssl_port,
        ssh_enum_target=args.ssh_enum,
        ssh_enum_port=args.ssh_port,
        geoip_db_path=args.geoip_db,
        tui_mode=bool(args.tui),
        os_fingerprint_target=args.os_fingerprint,
        cve_target=args.cve_lookup,
        cve_version=args.cve_version,
        watch_mode=bool(args.watch),
        watch_interval=args.watch_interval,
        serve_mode=bool(args.serve),
        serve_host=args.serve_host,
        serve_port=args.serve_port,
        plugin_dir=args.plugin_dir,
        list_plugins=bool(args.list_plugins),
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


def _generate_init_config(config_path: str) -> int:
    """Write a default config.json to disk and exit."""
    from .config import AppConfig
    dest = Path(config_path)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(AppConfig().to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Default config written to: {dest}")
        return 0
    except OSError as exc:
        print(f"Failed to write config: {exc}", file=sys.stderr)
        return 1


def _resolve_csv_save_path(save_csv_arg: str | None) -> Path | None:
    if save_csv_arg is None:
        return None
    if save_csv_arg.strip():
        return Path(save_csv_arg)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("reports") / f"netrecon_report_{timestamp}.csv"


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.init_config:
        return _generate_init_config(args.config)

    config = ConfigLoader(args.config).load()
    log_level = args.log_level or config.log_level
    log_file = args.log_file or config.log_file
    setup_logging(level=log_level, log_file=log_file)

    try:
        options = resolve_scan_options(args, config)
    except ValueError as exc:
        parser.error(str(exc))

    console = Console(no_color=args.no_color)
    orchestrator = NetReconOrchestrator(config=config)

    if options.tui_mode:
        app = NetReconTuiApp(orchestrator, options)
        app.run()
        return 0

    if options.list_plugins:
        return _list_plugins(console, options)

    if options.watch_mode:
        if args.json_output:
            console.print("[yellow]JSON output is not supported in watch mode; falling back to rich output.[/yellow]")
        return _run_watch_mode(console, orchestrator, options)

    if options.serve_mode:
        server = ApiServer(
            host=options.serve_host,
            port=options.serve_port,
            options=options,
            orchestrator=orchestrator,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    try:
        if args.json_output:
            result = orchestrator.run(options)
        else:
            with console.status("Starting NetRecon scan...", spinner="dots") as status:
                orchestrator._status = status.update
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

    csv_save_path = _resolve_csv_save_path(args.save_csv)
    if csv_save_path is not None:
        try:
            written_csv = save_csv_report(result, csv_save_path)
        except OSError as exc:
            LOGGER.error("Failed to save CSV report: %s", exc)
            if args.json_output:
                print(to_json_error(f"Failed to save CSV report: {exc}"), file=sys.stderr)
            else:
                console.print(f"[red]Failed to save CSV report:[/red] {exc}")
            return 1
        else:
            if not args.json_output:
                console.print(f"[green]CSV report saved:[/green] {written_csv}")

    return 1 if result.errors else 0


def to_json_error(message: str) -> str:
    return json.dumps({"error": message}, ensure_ascii=False)


def _run_watch_mode(console: Console, orchestrator: NetReconOrchestrator, options: ScanOptions) -> int:
    def on_result(cycle: int, result: ReconResult) -> None:
        console.rule(f"[bold cyan]Cycle #{cycle}[/bold cyan]")
        render_rich(console, result)

    def on_delta(cycle: int, deltas: dict) -> None:
        console.print("\n[yellow]Changes detected:[/yellow]")
        console.print(format_deltas(deltas))
        console.print()

    monitor = ContinuousMonitor(
        orchestrator=orchestrator,
        options=options,
        interval_seconds=options.watch_interval,
        on_result=on_result,
        on_delta=on_delta,
    )
    try:
        monitor.run()
    except KeyboardInterrupt:
        pass
    return 0


def _list_plugins(console: Console, options: ScanOptions) -> int:
    registry = PluginRegistry()
    registry.discover_entry_points()
    if options.plugin_dir:
        registry.discover_directory(options.plugin_dir)
    plugins = registry.list_plugins()
    if not plugins:
        console.print("[yellow]No plugins discovered.[/yellow]")
        return 0
    from rich.table import Table
    table = Table(title="Discovered Plugins")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Description")
    for p in plugins:
        table.add_row(p["name"], p["version"], p["description"])
    console.print(table)
    return 0


def _safe_print_json(payload: str) -> None:
    try:
        print(payload)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(payload.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
