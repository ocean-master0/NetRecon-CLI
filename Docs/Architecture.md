# Architecture Overview

## Project Name

**NetRecon CLI** — Modular Network Reconnaissance and Security Analysis Toolkit

---

## 1. High-Level Architecture

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                            USER / TERMINAL                              │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          CLI LAYER (cli.py)                              │
│  ┌──────────────────┐  ┌─────────────────────┐  ┌────────────────────┐  │
│  │  Argument Parser  │  │  Option Resolver    │  │  main() entrypoint │  │
│  │  (build_parser)   │  │  (resolve_options)  │  │                    │  │
│  └──────────────────┘  └─────────────────────┘  └────────────────────┘  │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    CONFIG LAYER (config.py)                              │
│  ┌──────────────────┐  ┌─────────────────────┐                          │
│  │  AppConfig        │  │  ConfigLoader       │                          │
│  │  (dataclass)      │  │  (JSON → AppConfig) │                          │
│  └──────────────────┘  └─────────────────────┘                          │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                 ORCHESTRATOR LAYER (orchestrator.py)                     │
│                  NetReconOrchestrator.run_async()                        │
│  Coordinates 13 scanning modules and aggregates into ReconResult        │
└──────────────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬───┘
               │    │    │    │    │    │    │    │    │    │    │    │
    ┌──────────┘    │    │    │    │    │    │    │    │    │    │    └──────┐
    ▼               ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼         ▼
┌────────┐ ┌──────┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌────────┐
│   IP   │ │ Port │ │B │ │DN│ │WH│ │TR│ │SU│ │TH│ │SP│ │LA│ │SN│ │Security│
│Scanner │ │Scannr│ │a │ │S │ │OI│ │AC│ │BD│ │RE│ │EE│ │N │ │IF│ │+ Risk  │
│        │ │      │ │n │ │  │ │S │ │E │ │OM│ │AT│ │D │ │  │ │F │ │Engine  │
│        │ │      │ │n │ │  │ │  │ │  │ │  │ │  │ │  │ │  │ │  │ │        │
│        │ │      │ │er│ │  │ │  │ │  │ │  │ │  │ │  │ │  │ │  │ │        │
└────────┘ └──────┘ └──┘ └──┘ └──┘ └──┘ └──┘ └──┘ └──┘ └──┘ └──┘ └────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      OUTPUT / REPORTING LAYER                           │
│  ┌─────────────────┐  ┌──────────────┐  ┌───────────────────────────┐   │
│  │  Rich Terminal   │  │  JSON Export  │  │  HTML Dashboard Report   │   │
│  │  (renderer.py)   │  │  (renderer)  │  │  (html_report.py)        │   │
│  └─────────────────┘  └──────────────┘  └───────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Layer Responsibilities

### 2.1 CLI Layer (`cli.py`)

| Component | Function | Description |
|-----------|----------|-------------|
| `build_parser()` | Argument definition | Defines 30+ CLI flags using `argparse.ArgumentParser` with mutual exclusion groups (`--external`/`--no-external`, `--interfaces`/`--no-interfaces`, `--security-check`/`--no-security-check`) |
| `resolve_scan_options()` | Option merging | Merges CLI arguments with `AppConfig` defaults. CLI flags override config values when explicitly provided. Validates port ranges, CIDR notation, and positive integer constraints |
| `main()` | Entry execution | Loads config, sets up logging, resolves options, creates orchestrator, runs scan, renders output, saves reports. Returns exit code 0 (success) or 1 (errors) |
| `to_json_error()` | Error serialization | Produces `{"error": "message"}` JSON for fatal errors in `--json` mode |

### 2.2 Config Layer (`config.py`)

| Component | Description |
|-----------|-------------|
| `AppConfig` | Dataclass with 25+ fields holding all runtime configuration with safe defaults |
| `ConfigLoader` | Reads `config.json`, validates each field with type-specific static methods (`_bool`, `_str`, `_positive_float`, `_positive_int`, `_ports_list`, `_wordlist`, `_api_keys`). Invalid values silently fall back to defaults |

### 2.3 Orchestrator Layer (`orchestrator.py`)

The `NetReconOrchestrator` is the central coordinator:

- **Constructor**: Accepts 13 optional service instances for dependency injection. Creates default instances from config when not provided
- **`run_async()`**: Executes modules in the following order:
  1. Local IP collection (always)
  2. External IP lookup (if `external_lookup` enabled)
  3. Reverse DNS and geo map URL (if external IP found)
  4. Network interfaces (if `include_interfaces` enabled)
  5. Port scan (if `scan_common_ports` or `scan_port_range`, skipped in passive mode)
  6. Traceroute (if `traceroute_target`, skipped in passive mode)
  7. Subdomain scan (if `subdomain_target`)
  8. WHOIS lookup (if `run_whois`)
  9. DNS analysis (if `dns_host`)
  10. Speed test (if `run_speedtest`, skipped in passive mode)
  11. LAN scan (if `lan_scan_cidr`, skipped in passive mode)
  12. Packet sniffer (if `sniff`, skipped in passive mode)
  13. Threat intelligence (if `run_threat_check`)
  14. Security check (if `security_check`)
  15. Risk scoring (always, uses available data)
  16. Geo HTML export (if `geo_html_path`)
  17. HTML report (if `html_report_path`)
- **Target Resolution**: Chain of priority: CLI `--target` → external IP → first local IP
- **`run()`**: Synchronous wrapper using `run_async()` for callers without an event loop

### 2.4 Output Layer

| Renderer | Format | Description |
|----------|--------|-------------|
| `renderer.py` → `render_rich()` | Terminal | 16-section Rich dashboard with tables, panels, styled text |
| `renderer.py` → `to_json()` | JSON | `dataclasses.asdict()` serialization with pretty printing |
| `renderer.py` → `save_json_report()` | JSON file | Writes JSON to disk with auto-directory creation |
| `html_report.py` → `HTMLReportBuilder.generate()` | HTML file | Self-contained HTML dashboard with Chart.js charts |

---

## 3. Module Catalog

### 3.1 Core Scanning Modules

| Module File | Class | Key Methods | Async | Dependencies |
|-------------|-------|-------------|-------|-------------|
| `ip_scanner.py` | `IPScanner` | `collect_local_ips()`, `lookup_external_ip_async()`, `reverse_dns_lookup()`, `enrich_ip_async()`, `collect_network_interfaces()`, `build_geo_map_url()`, `export_geo_map_html()` | Yes | `aiohttp`, `requests` (fallback) |
| `port_scanner.py` | `PortScanner` | `scan_ports_async()`, `scan_common_ports()`, `scan_custom_range()`, `parse_port_range()` | Yes | stdlib only |
| `banner.py` | `BannerGrabber` | `grab_banner_async()` | Yes | stdlib only |
| `dns_analyzer.py` | `DNSAnalyzer` | `analyze()`, `reverse_lookup()` | No (thread-wrapped) | `dnspython` |
| `whois_lookup.py` | `WhoisLookup` | `lookup()` | No (thread-wrapped) | `python-whois` (optional), raw TCP |
| `traceroute.py` | `TracerouteScanner` | `trace_async()`, `trace()` | Yes | system commands |
| `subdomain_scanner.py` | `SubdomainScanner` | `scan_async()`, `scan()` | Yes | stdlib only |
| `threat_intel.py` | `ThreatIntelChecker` | `check_ip_async()`, `check_ip()` | Yes | `aiohttp` |
| `speed_test.py` | `SpeedTester` | `run()` | No (thread-wrapped) | `speedtest-cli` |
| `lan_scanner.py` | `LANScanner` | `scan_async()`, `scan()` | Yes | system commands |
| `sniffer.py` | `PacketSniffer` | `capture()` | No (thread-wrapped) | `scapy` |

### 3.2 Analysis Modules

| Module File | Class | Key Methods | Description |
|-------------|-------|-------------|-------------|
| `security_checks.py` | `SecurityChecker` | `evaluate()`, `detect_firewall()` | IP classification, VPN/proxy heuristics, firewall detection |
| `risk_engine.py` | `RiskScoringEngine` | `score()` | Weighted 0-100 risk scoring with Low/Medium/High/Critical levels |

### 3.3 Infrastructure Modules

| Module File | Class/Function | Description |
|-------------|----------------|-------------|
| `async_utils.py` | `run_async()` | Runs coroutine in fresh event loop; thread fallback if loop is already running |
| `async_utils.py` | `gather_limited()` | Runs coroutine factories with semaphore-based concurrency limit |
| `async_utils.py` | `fetch_json()` | Generic async JSON HTTP GET via `aiohttp` |
| `async_utils.py` | `_install_windows_exception_filter()` | Suppresses benign `ConnectionResetError` on Windows Proactor loop |
| `config.py` | `ConfigLoader` | JSON config file loader with typed validation methods |
| `logging_utils.py` | `setup_logging()` | Initializes root logger with console + file handlers |
| `models.py` | 18 dataclasses | All data transfer objects with `to_dict()` serialization |
| `renderer.py` | 16 render functions | Rich terminal rendering for each module's output |
| `html_report.py` | `HTMLReportBuilder` | Generates HTML dashboard with Chart.js |

---

## 4. Data Model Hierarchy

```text
ReconResult (top-level aggregator)
├── local_ips: list[str]
├── external_info: ExternalIPInfo
│   └── ip, city, region, country, latitude, longitude, organization, isp,
│       postal, timezone, source, proxy_detected, vpn_detected, raw
├── reverse_dns: str
├── geo_map_url: str
├── interface_details: str
├── port_scan: PortScanResult
│   ├── target, scanned_ports, open_ports, closed_ports, filtered_ports
│   ├── duration_seconds, risky_open_ports
│   └── banners: list[BannerResult]
│       └── port, service, banner, status
├── whois: WhoisResult
│   └── query, asn, isp, organization, abuse_contact, source, raw_text
├── speed_test: SpeedTestResult
│   └── download_mbps, upload_mbps, ping_ms, server_name, server_country
├── dns: DNSAnalysisResult
│   └── hostname, a/aaaa/mx/txt/ns/cname_records, spf/dmarc/dnssec status
├── traceroute: TracerouteResult
│   ├── target, method
│   └── hops: list[TracerouteHop]
│       └── hop, ip, latency_ms, asn, geo
├── subdomains: SubdomainScanResult
│   ├── domain, scanned_count, duration_seconds
│   └── active_hosts: list[SubdomainRecord]
│       └── host, ip, response_ms
├── threat_intel: ThreatIntelResult
│   └── ip, malicious_score, blacklist_count, spam_reports,
│       known_vulnerabilities, source_details
├── security: SecurityCheckResult
│   ├── input_ip, classification, is_private, is_public,
│   │   suspected_vpn, suspected_proxy, risky_open_ports, risk_level, findings
│   └── firewall: FirewallDetectionResult
│       └── likely_firewall, icmp_blocked, filtered_ratio, reason
├── risk_assessment: RiskAssessment
│   └── score, level, factors
├── lan_scan: LanScanResult
│   ├── cidr, duration_seconds
│   └── active_hosts: list[LanHost]
│       └── ip, hostname, mac_address, vendor
├── sniffer: SnifferResult
│   └── packets_captured, suspicious_events
├── warnings: list[str]
└── errors: list[str]
```

---

## 5. Execution Flow

### 5.1 Startup Sequence

```text
main.py / python -m netrecon
    │
    ├── 1. Parse CLI arguments (build_parser → argparse.Namespace)
    ├── 2. Load config.json (ConfigLoader → AppConfig)
    ├── 3. Setup logging (setup_logging → console + file handlers)
    ├── 4. Resolve scan options (resolve_scan_options → ScanOptions)
    │       ├── Merge CLI flags with config defaults
    │       ├── Validate port ranges, CIDR, positive integers
    │       └── Determine mode (active/passive)
    ├── 5. Create orchestrator (NetReconOrchestrator with config)
    ├── 6. Execute scan (orchestrator.run → ReconResult)
    ├── 7. Render output
    │       ├── JSON mode: to_json() → stdout
    │       └── Normal mode: render_rich() → terminal
    ├── 8. Save reports (optional)
    │       ├── --save-json → save_json_report()
    │       └── --html-report → HTMLReportBuilder.generate()
    └── 9. Return exit code (0 = success, 1 = errors)
```

### 5.2 Async Execution Model

```text
orchestrator.run()
    │
    └── run_async() [via asyncio.run() or thread if loop exists]
            │
            ├── Synchronous: collect_local_ips()
            │
            ├── Async: lookup_external_ip_async()
            │   └── 3 concurrent provider tasks (first-success with cancellation)
            │
            ├── Sync→Thread: collect_network_interfaces()
            │
            ├── Async: scan_ports_async()
            │   └── Semaphore(300) → asyncio.open_connection() per port
            │       └── Async: grab_banner_async() for each open port
            │
            ├── Async: trace_async()
            │   └── Thread: system traceroute or TTL ping fallback
            │       └── Async: enrich_ip_async() per hop (advanced mode)
            │
            ├── Async: scan_async() [subdomains]
            │   └── Semaphore(200) → getaddrinfo() per subdomain
            │
            ├── Sync→Thread: whois_lookup.lookup()
            │
            ├── Sync→Thread: dns_analyzer.analyze()
            │
            ├── Sync→Thread: speed_tester.run()
            │
            ├── Async: lan_scanner.scan_async()
            │   └── Semaphore(256) → async ping per host
            │
            ├── Sync→Thread: sniffer.capture()
            │
            ├── Async: threat_checker.check_ip_async()
            │   └── Concurrent tasks per API (abuseipdb, virustotal, shodan)
            │
            ├── Sync: security_checker.evaluate()
            │
            └── Sync: risk_engine.score()
```

---

## 6. Threading and Async Model

### Async Patterns Used

| Pattern | Where Used | Purpose |
|---------|-----------|---------|
| `asyncio.open_connection()` | Port scanner, banner grabber | Non-blocking TCP connections |
| `asyncio.Semaphore` | Port scanner (300), subdomain scanner (200), LAN scanner (256) | Concurrency limiting |
| `asyncio.as_completed()` | Port scanner, external IP lookup, threat checks | Process results as they arrive |
| `asyncio.create_task()` + cancellation | External IP providers | First-success pattern |
| `asyncio.to_thread()` | WHOIS, DNS, speed test, sniffer, interfaces | Move blocking I/O off event loop |
| `asyncio.create_subprocess_exec()` | LAN scanner (ping) | Async subprocess execution |
| `aiohttp.ClientSession` | External IP lookup, threat intel APIs, hop enrichment | Async HTTP client |

### Event Loop Management (`async_utils.py`)

- `run_async()`: Creates fresh event loop via `asyncio.run()`
- If loop already running (e.g., Jupyter/tests): Falls back to running coroutine in a daemon thread
- Windows-specific: Installs exception handler to suppress benign `ConnectionResetError` from Proactor event loop transport shutdown

---

## 7. Dependency Architecture

```text
cli.py
├── config.py (AppConfig, ConfigLoader)
├── logging_utils.py (setup_logging)
├── models.py (ScanOptions)
├── orchestrator.py (NetReconOrchestrator)
├── port_scanner.py (PortScanner - for parse_port_range validation)
└── renderer.py (render_rich, save_json_report, to_json)

orchestrator.py
├── async_utils.py (run_async)
├── config.py (AppConfig)
├── dns_analyzer.py (DNSAnalyzer)
├── html_report.py (HTMLReportBuilder)
├── ip_scanner.py (IPScanner)
├── lan_scanner.py (LANScanner)
├── models.py (ReconResult, ScanOptions)
├── port_scanner.py (PortScanner)
├── risk_engine.py (RiskScoringEngine)
├── security_checks.py (SecurityChecker)
├── sniffer.py (PacketSniffer)
├── speed_test.py (SpeedTester)
├── subdomain_scanner.py (SubdomainScanner)
├── threat_intel.py (ThreatIntelChecker)
├── traceroute.py (TracerouteScanner)
└── whois_lookup.py (WhoisLookup)

port_scanner.py
└── banner.py (BannerGrabber)

ip_scanner.py
├── async_utils.py (run_async)
└── models.py (ExternalIPInfo)

threat_intel.py
└── async_utils.py (fetch_json, run_async)
```

---

## 8. External Service Dependencies

| Service | URL | Module | Purpose |
|---------|-----|--------|---------|
| ipinfo.io | `https://ipinfo.io/json` | `ip_scanner.py` | External IP provider #1 |
| ipapi.co | `https://ipapi.co/json/` | `ip_scanner.py` | External IP provider #2 |
| ipwho.is | `https://ipwho.is/` | `ip_scanner.py` | External IP provider #3 + hop enrichment |
| AbuseIPDB | `https://api.abuseipdb.com/api/v2/check` | `threat_intel.py` | IP abuse reputation (requires API key) |
| VirusTotal | `https://www.virustotal.com/api/v3/ip_addresses/{ip}` | `threat_intel.py` | IP malware analysis (requires API key) |
| Shodan | `https://api.shodan.io/shodan/host/{ip}` | `threat_intel.py` | Host vulnerability data (requires API key) |
| Google Maps | `https://www.google.com/maps?q={coordinates}` | `ip_scanner.py` | Geo map visualization |
| Chart.js CDN | `https://cdn.jsdelivr.net/npm/chart.js` | `html_report.py` | HTML report chart rendering |
| WHOIS servers | `whois.iana.org:43` + referral servers | `whois_lookup.py` | Raw WHOIS protocol queries |
| speedtest-cli | Speedtest.net servers | `speed_test.py` | Internet speed measurement |

---

## 9. Package Exports

The `netrecon` package (`__init__.py`) exports:

```python
from .models import ReconResult, ScanOptions
from .orchestrator import NetReconOrchestrator

__all__ = ["NetReconOrchestrator", "ReconResult", "ScanOptions"]
```

This allows programmatic use:

```python
from netrecon import NetReconOrchestrator, ScanOptions
from netrecon.config import AppConfig

config = AppConfig()
orchestrator = NetReconOrchestrator(config=config)
options = ScanOptions(target="8.8.8.8", scan_common_ports=True)
result = orchestrator.run(options)
print(result.to_dict())
```
