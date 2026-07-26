from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ExternalIPInfo:
    """Normalized external IP intelligence details."""

    ip: str
    city: str | None = None
    region: str | None = None
    country: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    organization: str | None = None
    isp: str | None = None
    postal: str | None = None
    timezone: str | None = None
    source: str | None = None
    proxy_detected: bool | None = None
    vpn_detected: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def coordinates(self) -> str | None:
        if self.latitude is None or self.longitude is None:
            return None
        return f"{self.latitude},{self.longitude}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BannerResult:
    """Service banner grab response for an open port."""

    port: int
    service: str
    banner: str | None = None
    version: str | None = None
    status: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PortScanResult:
    """Result object for asynchronous TCP port scanning."""

    target: str
    scanned_ports: list[int] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)
    filtered_ports: list[int] = field(default_factory=list)
    duration_seconds: float = 0.0
    risky_open_ports: list[int] = field(default_factory=list)
    banners: list[BannerResult] = field(default_factory=list)

    @property
    def closed_count(self) -> int:
        return len(self.closed_ports)

    @property
    def filtered_count(self) -> int:
        return len(self.filtered_ports)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WhoisResult:
    """WHOIS lookup data including fallback output."""

    query: str
    asn: str | None = None
    isp: str | None = None
    organization: str | None = None
    abuse_contact: str | None = None
    source: str | None = None
    raw_text: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SpeedTestResult:
    """Internet speed test metrics."""

    download_mbps: float
    upload_mbps: float
    ping_ms: float
    server_name: str | None = None
    server_country: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DNSAnalysisResult:
    """DNS records and security posture checks."""

    hostname: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    axfr_records: list[str] = field(default_factory=list)
    spf_present: bool = False
    spf_source: str = ""
    dmarc_present: bool = False
    dmarc_source: str = ""
    dnssec_enabled: bool = False
    dnssec_source: str = ""
    soa_record: str | None = None
    srv_records: list[str] = field(default_factory=list)
    caa_records: list[str] = field(default_factory=list)
    tlsa_records: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TracerouteHop:
    """Single hop details from traceroute execution."""

    hop: int
    ip: str | None = None
    latency_ms: float | None = None
    asn: str | None = None
    geo: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TracerouteResult:
    """Traceroute path output."""

    target: str
    method: str
    hops: list[TracerouteHop] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SubdomainRecord:
    """Resolved active subdomain record."""

    host: str
    ip: str
    response_ms: float
    http_status: int | None = None
    http_response_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SubdomainScanResult:
    """Subdomain scan summary with active hosts."""

    domain: str
    scanned_count: int
    active_hosts: list[SubdomainRecord] = field(default_factory=list)
    duration_seconds: float = 0.0
    wildcard_detected: bool = False
    wildcard_ip: str | None = None
    crt_sh_count: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatIntelResult:
    """Threat intelligence aggregation from AbuseIPDB/VirusTotal/Shodan."""

    ip: str
    malicious_score: int = 0
    blacklist_count: int = 0
    spam_reports: int = 0
    known_vulnerabilities: list[str] = field(default_factory=list)
    source_details: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FirewallDetectionResult:
    """Heuristic firewall/packet filtering detection output."""

    likely_firewall: bool
    icmp_blocked: bool = False
    filtered_ratio: float = 0.0
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    """Final weighted risk scoring output."""

    score: int
    level: str
    factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CveRecord:
    cve_id: str
    base_score: float | None = None
    severity: str | None = None
    description: str | None = None
    cvss_vector: str | None = None
    source: str = "nvd"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CveLookupResult:
    software: str
    version: str | None = None
    cves: list[CveRecord] = field(default_factory=list)
    total_found: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OsFingerprintResult:
    """OS fingerprinting result based on TCP/IP stack analysis."""

    host: str
    guessed_os: str | None = None
    confidence: float = 0.0
    ttl_observed: int | None = None
    latency_ms: float | None = None
    details: list[str] = field(default_factory=list)
    raw_sources: list[tuple[str | None, str | None]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityCheckResult:
    """Security posture summary for the scanned host or public IP."""

    input_ip: str | None
    classification: str
    is_private: bool | None
    is_public: bool | None
    suspected_vpn: bool
    suspected_proxy: bool
    risky_open_ports: list[int] = field(default_factory=list)
    risk_level: str = "Low"
    findings: list[str] = field(default_factory=list)
    firewall: FirewallDetectionResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LanHost:
    """Active host discovered in LAN scan."""

    ip: str
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LanScanResult:
    """LAN network discovery results."""

    cidr: str
    active_hosts: list[LanHost] = field(default_factory=list)
    duration_seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SnifferResult:
    """Packet sniffer summary and anomaly detections."""

    packets_captured: int
    suspicious_events: list[str] = field(default_factory=list)
    pcap_path: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GeoIpResult:
    """Offline GeoIP lookup result."""

    ip: str
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    organization: str | None = None
    source: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SslCertResult:
    """SSL/TLS certificate details."""

    target: str
    port: int = 443
    subject_cn: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    san: list[str] = field(default_factory=list)
    self_signed: bool = False
    expired: bool = False
    cipher: str | None = None
    protocol: str | None = None
    cert_chain_length: int | None = None
    key_algorithm: str | None = None
    key_size: int | None = None
    ocsp_must_staple: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SshEnumResult:
    """SSH server enumeration result."""

    target: str
    port: int = 22
    banner: str | None = None
    software_version: str | None = None
    kex_algorithms: list[str] = field(default_factory=list)
    host_key_algorithms: list[str] = field(default_factory=list)
    encryption_algorithms: list[str] = field(default_factory=list)
    mac_algorithms: list[str] = field(default_factory=list)
    compression_algorithms: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PluginResult:
    plugin_name: str
    plugin_version: str = "0.1.0"
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanOptions:
    """Runtime options resolved from CLI + config."""

    stealth_mode: bool = False
    target: str | None = None
    mode: str = "active"
    external_lookup: bool = True
    include_interfaces: bool = False
    scan_common_ports: bool = False
    scan_port_range: str | None = None
    run_whois: bool = False
    whois_target: str | None = None
    run_speedtest: bool = False
    dns_host: str | None = None
    dns_axfr_target: str | None = None
    security_check: bool = False
    geo_html_path: str | None = None
    traceroute_target: str | None = None
    traceroute_advanced: bool = False
    subdomain_target: str | None = None
    subdomain_wordlist_path: str | None = None
    run_threat_check: bool = False
    html_report_path: str | None = None
    lan_scan_cidr: str | None = None
    sniff: bool = False
    sniff_limit: int = 200
    sniff_timeout: int = 15
    os_fingerprint_target: str | None = None
    cve_target: str | None = None
    cve_version: str | None = None
    watch_mode: bool = False
    watch_interval: int = 60
    serve_mode: bool = False
    serve_host: str = "127.0.0.1"
    serve_port: int = 8088
    plugin_dir: str | None = None
    list_plugins: bool = False
    ssl_enum_target: str | None = None
    ssl_enum_port: int = 443
    ssh_enum_target: str | None = None
    ssh_enum_port: int = 22
    geoip_db_path: str | None = None
    pcap_path: str | None = None
    sniff_filter: str | None = None
    tui_mode: bool = False


@dataclass
class ReconResult:
    """Aggregated output for a full NetRecon scan run."""

    timestamp: str
    hostname: str
    mode: str = "active"
    local_ips: list[str] = field(default_factory=list)
    external_info: ExternalIPInfo | None = None
    reverse_dns: str | None = None
    geo_map_url: str | None = None
    geo_map_html_path: str | None = None
    interface_details: str | None = None
    port_scan: PortScanResult | None = None
    whois: WhoisResult | None = None
    speed_test: SpeedTestResult | None = None
    dns: DNSAnalysisResult | None = None
    traceroute: TracerouteResult | None = None
    subdomains: SubdomainScanResult | None = None
    threat_intel: ThreatIntelResult | None = None
    security: SecurityCheckResult | None = None
    risk_assessment: RiskAssessment | None = None
    lan_scan: LanScanResult | None = None
    sniffer: SnifferResult | None = None
    os_fingerprint: OsFingerprintResult | None = None
    cve_results: list[CveLookupResult] | None = None
    plugin_results: list[PluginResult] = field(default_factory=list)
    geoip_result: GeoIpResult | None = None
    ssl_cert: SslCertResult | None = None
    ssh_enum: SshEnumResult | None = None
    html_report_path: str | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
