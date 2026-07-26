from __future__ import annotations

import csv
import json
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import ReconResult


def to_json(result: ReconResult, pretty: bool = True) -> str:
    """Serialize the recon result into JSON text."""
    indent = 2 if pretty else None
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)


def save_json_report(result: ReconResult, path: str | Path) -> Path:
    """Persist recon result as JSON report on disk."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(to_json(result, pretty=True), encoding="utf-8")
    return output_path


def save_csv_report(result: ReconResult, path: str | Path) -> Path:
    """Export recon result sections as CSV files."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if result.subdomains:
            writer.writerow([f"Subdomain Scan: {result.subdomains.domain}"])
            writer.writerow(["Host", "IP", "Response (ms)"])
            for record in result.subdomains.active_hosts:
                writer.writerow([record.host, record.ip, record.response_ms])
            writer.writerow([])

        if result.port_scan:
            writer.writerow([f"Port Scan: {result.port_scan.target}"])
            writer.writerow(["Port", "Service", "Banner", "Status"])
            for banner in result.port_scan.banners:
                writer.writerow([banner.port, banner.service, banner.banner or "", banner.status])
            if result.port_scan.open_ports:
                writer.writerow(["Open Ports", ", ".join(str(p) for p in result.port_scan.open_ports)])
            writer.writerow([])

        if result.lan_scan:
            writer.writerow([f"LAN Scan: {result.lan_scan.cidr}"])
            writer.writerow(["IP", "Hostname", "MAC", "Vendor"])
            for host in result.lan_scan.active_hosts:
                writer.writerow([host.ip, host.hostname or "", host.mac_address or "", host.vendor or ""])
            writer.writerow([])

        if result.dns:
            writer.writerow([f"DNS Analysis: {result.dns.hostname}"])
            writer.writerow(["Record Type", "Values"])
            writer.writerow(["A", ", ".join(result.dns.a_records)])
            writer.writerow(["AAAA", ", ".join(result.dns.aaaa_records)])
            writer.writerow(["MX", ", ".join(result.dns.mx_records)])
            writer.writerow(["TXT", ", ".join(result.dns.txt_records)])
            writer.writerow(["NS", ", ".join(result.dns.ns_records)])
            writer.writerow(["CNAME", ", ".join(result.dns.cname_records)])
            spf_csv = f"{result.dns.spf_present} ({result.dns.spf_source})" if result.dns.spf_source else str(result.dns.spf_present)
            dmarc_csv = f"{result.dns.dmarc_present} ({result.dns.dmarc_source})" if result.dns.dmarc_source else str(result.dns.dmarc_present)
            dnssec_csv = f"{result.dns.dnssec_enabled} ({result.dns.dnssec_source})" if result.dns.dnssec_source else str(result.dns.dnssec_enabled)
            writer.writerow(["SPF", spf_csv])
            writer.writerow(["DMARC", dmarc_csv])
            writer.writerow(["DNSSEC", dnssec_csv])
            if result.dns.axfr_records:
                for record in result.dns.axfr_records:
                    writer.writerow(["AXFR", record])

    return output_path


def render_rich(console: Console, result: ReconResult) -> None:
    """Render the full recon report in Rich terminal format."""
    _render_header(console, result)
    _render_summary(console, result)
    _render_local_ips(console, result)
    _render_external(console, result)
    _render_dns(console, result)
    _render_subdomains(console, result)
    _render_ports(console, result)
    _render_traceroute(console, result)
    _render_whois(console, result)
    _render_speed(console, result)
    _render_threat(console, result)
    _render_security(console, result)
    _render_risk(console, result)
    _render_lan(console, result)
    _render_os_fingerprint(console, result)
    _render_geoip(console, result)
    _render_cve(console, result)
    _render_ssl(console, result)
    _render_ssh(console, result)
    _render_sniffer(console, result)
    _render_interfaces(console, result)
    _render_warnings(console, result)


def _render_header(console: Console, result: ReconResult) -> None:
    title = Text("NetRecon CLI", style="bold cyan", justify="center")
    console.print(
        Panel(
            title,
            subtitle=f"Network Reconnaissance Toolkit ({result.mode.upper()} MODE)",
            box=box.ASCII,
            border_style="cyan",
        )
    )


def _render_summary(console: Console, result: ReconResult) -> None:
    table = Table(show_header=False, box=box.ASCII)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value")
    table.add_row("Hostname", result.hostname)
    table.add_row("Timestamp", result.timestamp)
    table.add_row("Mode", result.mode)
    table.add_row("Local IP Count", str(len(result.local_ips)))
    table.add_row("External IP", result.external_info.ip if result.external_info else "Unavailable")
    table.add_row("Warnings", str(len(result.warnings)))
    table.add_row("Errors", str(len(result.errors)))
    console.print(Panel(table, title="Summary", box=box.ASCII, border_style="blue"))


def _render_local_ips(console: Console, result: ReconResult) -> None:
    table = Table(title="Local IP Addresses", box=box.ASCII)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("IP Address")
    if not result.local_ips:
        table.add_row("-", "No local IPs detected")
    else:
        for index, ip_value in enumerate(result.local_ips, start=1):
            table.add_row(str(index), ip_value)
    console.print(table)


def _render_external(console: Console, result: ReconResult) -> None:
    table = Table(title="External IP Intelligence", box=box.ASCII)
    table.add_column("Field", style="green")
    table.add_column("Value")
    info = result.external_info
    if info is None:
        table.add_row("status", "No external data")
    else:
        table.add_row("ip", info.ip)
        table.add_row("city", info.city or "Unknown")
        table.add_row("region", info.region or "Unknown")
        table.add_row("country", info.country or "Unknown")
        table.add_row("coordinates", info.coordinates or "Unknown")
        table.add_row("organization", info.organization or "Unknown")
        table.add_row("isp", info.isp or "Unknown")
        table.add_row("timezone", info.timezone or "Unknown")
        table.add_row("source", info.source or "Unknown")
        table.add_row("reverse_dns", result.reverse_dns or "Unavailable")
        table.add_row("map_url", result.geo_map_url or "Unavailable")
        table.add_row("map_html", result.geo_map_html_path or "Not exported")
    console.print(table)


def _render_dns(console: Console, result: ReconResult) -> None:
    if result.dns is None:
        return
    table = Table(title=f"DNS Analysis ({result.dns.hostname})", box=box.ASCII)
    table.add_column("Record")
    table.add_column("Values")
    table.add_row("A", ", ".join(result.dns.a_records) or "None")
    table.add_row("AAAA", ", ".join(result.dns.aaaa_records) or "None")
    table.add_row("MX", ", ".join(result.dns.mx_records) or "None")
    table.add_row("TXT", ", ".join(result.dns.txt_records) or "None")
    table.add_row("NS", ", ".join(result.dns.ns_records) or "None")
    table.add_row("CNAME", ", ".join(result.dns.cname_records) or "None")
    table.add_row("SOA", result.dns.soa_record or "None")
    table.add_row("SRV", ", ".join(result.dns.srv_records) or "None")
    table.add_row("CAA", ", ".join(result.dns.caa_records) or "None")
    table.add_row("TLSA", ", ".join(result.dns.tlsa_records) or "None")
    spf_val = f"{result.dns.spf_present} ({result.dns.spf_source})" if result.dns.spf_source else str(result.dns.spf_present)
    dmarc_val = f"{result.dns.dmarc_present} ({result.dns.dmarc_source})" if result.dns.dmarc_source else str(result.dns.dmarc_present)
    dnssec_val = f"{result.dns.dnssec_enabled} ({result.dns.dnssec_source})" if result.dns.dnssec_source else str(result.dns.dnssec_enabled)
    table.add_row("SPF", spf_val)
    table.add_row("DMARC", dmarc_val)
    table.add_row("DNSSEC", dnssec_val)
    if result.dns.axfr_records:
        table.add_row("AXFR Records", str(len(result.dns.axfr_records)))
    console.print(table)


def _render_subdomains(console: Console, result: ReconResult) -> None:
    if result.subdomains is None:
        return
    source_label = f" (crt.sh: {result.subdomains.crt_sh_count})" if result.subdomains.crt_sh_count else ""
    table = Table(title=f"Subdomain Scan ({result.subdomains.domain}){source_label}", box=box.ASCII)
    table.add_column("Subdomain")
    table.add_column("IP")
    table.add_column("Response (ms)")
    table.add_column("HTTP")
    if not result.subdomains.active_hosts:
        table.add_row("None", "-", "-", "-")
    else:
        for record in result.subdomains.active_hosts:
            http_str = f"port {record.http_status}" if record.http_status else "-"
            table.add_row(record.host, record.ip, str(record.response_ms), http_str)
    console.print(table)


def _render_ports(console: Console, result: ReconResult) -> None:
    if result.port_scan is None:
        return
    summary = Table(title=f"Port Scan ({result.port_scan.target})", box=box.ASCII)
    summary.add_column("Metric")
    summary.add_column("Value")
    summary.add_row("Scanned", str(len(result.port_scan.scanned_ports)))
    summary.add_row("Open", ", ".join(str(port) for port in result.port_scan.open_ports) or "None")
    summary.add_row("Closed", str(result.port_scan.closed_count))
    summary.add_row("Filtered", str(result.port_scan.filtered_count))
    summary.add_row("Risky Open", ", ".join(str(port) for port in result.port_scan.risky_open_ports) or "None")
    summary.add_row("Duration (s)", str(result.port_scan.duration_seconds))
    console.print(summary)

    if result.port_scan.banners:
        banner_table = Table(title="Banner Grabbing", box=box.ASCII)
        banner_table.add_column("Port")
        banner_table.add_column("Service")
        banner_table.add_column("Version")
        banner_table.add_column("Banner")
        banner_table.add_column("Status")
        for banner in result.port_scan.banners:
            banner_table.add_row(str(banner.port), banner.service, banner.version or "-", banner.banner or "-", banner.status)
        console.print(banner_table)


def _render_traceroute(console: Console, result: ReconResult) -> None:
    if result.traceroute is None:
        return
    table = Table(title=f"Traceroute ({result.traceroute.target})", box=box.ASCII)
    table.add_column("Hop")
    table.add_column("IP")
    table.add_column("Latency (ms)")
    table.add_column("ASN")
    table.add_column("Geo")
    for hop in result.traceroute.hops:
        table.add_row(
            str(hop.hop),
            hop.ip or "*",
            str(hop.latency_ms) if hop.latency_ms is not None else "*",
            hop.asn or "-",
            hop.geo or "-",
        )
    console.print(table)


def _render_whois(console: Console, result: ReconResult) -> None:
    if result.whois is None:
        return
    table = Table(title=f"WHOIS ({result.whois.query})", box=box.ASCII)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("ASN", result.whois.asn or "Unknown")
    table.add_row("ISP", result.whois.isp or "Unknown")
    table.add_row("Organization", result.whois.organization or "Unknown")
    table.add_row("Abuse Contact", result.whois.abuse_contact or "Unknown")
    table.add_row("Source", result.whois.source or "Unknown")
    console.print(table)


def _render_speed(console: Console, result: ReconResult) -> None:
    if result.speed_test is None:
        return
    table = Table(title="Speed Test", box=box.ASCII)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Download (Mbps)", str(result.speed_test.download_mbps))
    table.add_row("Upload (Mbps)", str(result.speed_test.upload_mbps))
    table.add_row("Ping (ms)", str(result.speed_test.ping_ms))
    table.add_row("Server", result.speed_test.server_name or "Unknown")
    table.add_row("Country", result.speed_test.server_country or "Unknown")
    console.print(table)


def _render_threat(console: Console, result: ReconResult) -> None:
    if result.threat_intel is None:
        return
    table = Table(title=f"Threat Intelligence ({result.threat_intel.ip})", box=box.ASCII)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Malicious Score", str(result.threat_intel.malicious_score))
    table.add_row("Blacklist Count", str(result.threat_intel.blacklist_count))
    table.add_row("Spam Reports", str(result.threat_intel.spam_reports))
    table.add_row("Known Vulns", ", ".join(result.threat_intel.known_vulnerabilities) or "None")
    console.print(table)


def _render_security(console: Console, result: ReconResult) -> None:
    if result.security is None:
        return
    table = Table(title="Security Check", box=box.ASCII)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Classification", result.security.classification)
    table.add_row("Private", str(result.security.is_private))
    table.add_row("Public", str(result.security.is_public))
    table.add_row("Suspected VPN", str(result.security.suspected_vpn))
    table.add_row("Suspected Proxy", str(result.security.suspected_proxy))
    table.add_row("Risk Level", result.security.risk_level)
    table.add_row("Risky Ports", ", ".join(str(p) for p in result.security.risky_open_ports) or "None")
    if result.security.firewall:
        table.add_row("Firewall", str(result.security.firewall.likely_firewall))
        table.add_row("ICMP Blocked", str(result.security.firewall.icmp_blocked))
    console.print(table)

    if result.security.findings:
        content = "\n".join(f"- {line}" for line in result.security.findings)
        console.print(Panel(content, title="Security Findings", box=box.ASCII, border_style="yellow"))


def _render_risk(console: Console, result: ReconResult) -> None:
    if result.risk_assessment is None:
        return
    table = Table(title="Risk Scoring", box=box.ASCII)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Risk Score", f"{result.risk_assessment.score}/100")
    table.add_row("Risk Level", result.risk_assessment.level)
    console.print(table)

    if result.risk_assessment.factors:
        factors = "\n".join(f"- {item}" for item in result.risk_assessment.factors)
        console.print(Panel(factors, title="Risk Factors", box=box.ASCII, border_style="red"))


def _render_lan(console: Console, result: ReconResult) -> None:
    if result.lan_scan is None:
        return
    table = Table(title=f"LAN Scan ({result.lan_scan.cidr})", box=box.ASCII)
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("MAC")
    table.add_column("Vendor")
    for host in result.lan_scan.active_hosts:
        table.add_row(host.ip, host.hostname or "-", host.mac_address or "-", host.vendor or "-")
    if not result.lan_scan.active_hosts:
        table.add_row("None", "-", "-", "-")
    console.print(table)


def _render_os_fingerprint(console: Console, result: ReconResult) -> None:
    if result.os_fingerprint is None:
        return
    table = Table(title=f"OS Fingerprint ({result.os_fingerprint.host})", box=box.ASCII)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Guessed OS", result.os_fingerprint.guessed_os or "Unknown")
    table.add_row("Confidence", f"{result.os_fingerprint.confidence:.0%}" if result.os_fingerprint.confidence else "N/A")
    table.add_row("TTL Observed", str(result.os_fingerprint.ttl_observed) if result.os_fingerprint.ttl_observed else "N/A")
    if result.os_fingerprint.latency_ms is not None:
        table.add_row("Latency (ms)", str(result.os_fingerprint.latency_ms))
    console.print(table)
    if result.os_fingerprint.details:
        content = "\n".join(f"- {line}" for line in result.os_fingerprint.details)
        console.print(Panel(content, title="Fingerprint Details", box=box.ASCII, border_style="green"))


def _render_cve(console: Console, result: ReconResult) -> None:
    if not result.cve_results:
        return
    for cve_result in result.cve_results:
        table = Table(title=f"CVE Lookup: {cve_result.software} {cve_result.version or '*'}", box=box.ASCII)
        table.add_column("CVE ID")
        table.add_column("Score")
        table.add_column("Severity")
        table.add_column("Description")
        for cve in cve_result.cves[:20]:
            table.add_row(
                cve.cve_id,
                str(cve.base_score) if cve.base_score else "-",
                cve.severity or "-",
                (cve.description or "-")[:60],
            )
        if not cve_result.cves:
            table.add_row("None", "-", "-", "No CVEs found")
        console.print(table)
        if cve_result.total_found > 20:
            console.print(f"[dim]... and {cve_result.total_found - 20} more CVEs[/dim]")


def _render_sniffer(console: Console, result: ReconResult) -> None:
    if result.sniffer is None:
        return
    table = Table(title="Packet Sniffer", box=box.ASCII)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Packets Captured", str(result.sniffer.packets_captured))
    table.add_row("Suspicious Events", str(len(result.sniffer.suspicious_events)))
    console.print(table)

    if result.sniffer.suspicious_events:
        data = "\n".join(f"- {item}" for item in result.sniffer.suspicious_events)
        console.print(Panel(data, title="Sniffer Alerts", box=box.ASCII, border_style="yellow"))


def _render_interfaces(console: Console, result: ReconResult) -> None:
    if not result.interface_details:
        return
    console.print(
        Panel(
            result.interface_details,
            title="Interface Details",
            box=box.ASCII,
            border_style="magenta",
        )
    )


def _render_warnings(console: Console, result: ReconResult) -> None:
    if result.warnings:
        warning_text = "\n".join(f"- {item}" for item in result.warnings)
        console.print(Panel(warning_text, title="Warnings", box=box.ASCII, border_style="yellow"))

    if result.errors:
        error_text = "\n".join(f"- {item}" for item in result.errors)
        console.print(Panel(error_text, title="Errors", box=box.ASCII, border_style="red"))

    if result.sniffer and result.sniffer.pcap_path:
        console.print(f"[green]PCAP saved:[/green] {result.sniffer.pcap_path}")

    if result.html_report_path:
        console.print(f"[green]HTML report:[/green] {result.html_report_path}")


def _render_geoip(console: Console, result: ReconResult) -> None:
    if result.geoip_result is None:
        return
    g = result.geoip_result
    table = Table(title=f"GeoIP: {g.ip}", box=box.ASCII)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Country", g.country or "Unknown")
    table.add_row("City", g.city or "Unknown")
    if g.latitude is not None and g.longitude is not None:
        table.add_row("Coordinates", f"{g.latitude}, {g.longitude}")
    table.add_row("ASN", g.asn or "N/A")
    table.add_row("Organization", g.organization or "N/A")
    table.add_row("Source", g.source)
    console.print(table)


def _render_ssl(console: Console, result: ReconResult) -> None:
    if result.ssl_cert is None:
        return
    s = result.ssl_cert
    table = Table(title=f"SSL/TLS Certificate: {s.target}:{s.port}", box=box.ASCII)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Subject CN", s.subject_cn or "N/A")
    table.add_row("Issuer", s.issuer or "N/A")
    table.add_row("Not Before", s.not_before or "N/A")
    table.add_row("Not After", s.not_after or "N/A")
    table.add_row("Cipher", s.cipher or "N/A")
    table.add_row("Protocol", s.protocol or "N/A")
    table.add_row("Self-Signed", "Yes" if s.self_signed else "No")
    table.add_row("Expired", "Yes" if s.expired else "No")
    console.print(table)
    if s.san:
        console.print(Panel("\n".join(s.san[:20]), title="Subject Alternative Names", box=box.ASCII, border_style="green"))
    if s.warnings:
        console.print(Panel("\n".join(f"- {w}" for w in s.warnings), title="SSL Warnings", box=box.ASCII, border_style="yellow"))


def _render_ssh(console: Console, result: ReconResult) -> None:
    if result.ssh_enum is None:
        return
    s = result.ssh_enum
    table = Table(title=f"SSH Server: {s.target}:{s.port}", box=box.ASCII)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Banner", s.banner or "N/A")
    table.add_row("Software", s.software_version or "N/A")
    console.print(table)

    def _show_algo(title: str, algos: list[str]) -> None:
        if algos:
            console.print(Panel("\n".join(algos[:30]), title=title, box=box.ASCII, border_style="blue"))

    _show_algo("KEX Algorithms", s.kex_algorithms)
    _show_algo("Host Key Algorithms", s.host_key_algorithms)
    _show_algo("Encryption Algorithms", s.encryption_algorithms)
    _show_algo("MAC Algorithms", s.mac_algorithms)

    if s.warnings:
        console.print(Panel("\n".join(f"- {w}" for w in s.warnings), title="SSH Warnings", box=box.ASCII, border_style="yellow"))
