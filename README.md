# NetRecon CLI

**NetRecon CLI** is a professional, cross-platform, async-first network reconnaissance and security analysis toolkit built in Python. It provides 15+ modular scanning engines coordinated through a central orchestrator, delivering comprehensive intelligence about networks, hosts, and security posture from a single command-line interface.

---

## Feature Overview

| Module | Description | CLI Flag |
|--------|-------------|----------|
| **IP Intelligence** | Local IP detection, multi-provider external IP lookup (ipinfo, ipapi, ipwhois), reverse DNS, geo map export | `--external`, `--interfaces` |
| **Port Scanner** | Async TCP port scanning with open/closed/filtered classification | `--scan-common-ports`, `--scan-ports RANGE` |
| **Banner Grabber** | Protocol-aware service identification (SSH, HTTP, SMTP, FTP, MySQL, etc.) | Automatic on open ports |
| **DNS Analyzer** | A, AAAA, MX, TXT, NS, CNAME records + SPF/DMARC/DNSSEC verification | `--dns HOST` |
| **WHOIS Lookup** | ASN, ISP, organization, abuse contact with raw TCP fallback | `--whois`, `--whois-target` |
| **Traceroute** | Cross-platform traceroute with TTL-ping fallback and optional ASN/geo enrichment | `--traceroute TARGET`, `--traceroute-advanced` |
| **Subdomain Scanner** | Async DNS resolution of common subdomain wordlist with response timing | `--subdomain DOMAIN` |
| **Threat Intel** | AbuseIPDB, VirusTotal, Shodan API integration for IP reputation checks | `--threat-check` |
| **Security Checks** | IP classification (private/public), VPN/proxy heuristics, firewall detection | `--security-check` |
| **Risk Engine** | Weighted scoring (0-100) with Low/Medium/High/Critical severity levels | Automatic |
| **Speed Test** | Download/upload/ping measurement via speedtest-cli | `--speedtest` |
| **LAN Scanner** | CIDR-based active host discovery with hostname and MAC address resolution | `--lan-scan CIDR` |
| **Packet Sniffer** | Traffic capture with ARP spoofing, DNS poisoning, and anomaly detection | `--sniff` |
| **HTML Report** | Dashboard-style HTML report with Chart.js visualizations | `--html-report [PATH]` |
| **JSON Export** | Structured JSON output to stdout or file | `--json`, `--save-json [PATH]` |

---

## Scan Modes

- **Active Mode** (`--mode active`): Full scanning including ports, banners, traceroute, LAN scan, and packet sniffing. This is the default mode.
- **Passive Mode** (`--mode passive`): Non-aggressive intelligence gathering only. DNS, WHOIS, threat checks, and subdomain scanning are allowed. Port scanning, traceroute, LAN scan, speed test, and packet sniffing are automatically skipped with warnings.

---

## Requirements

### System Requirements

- Python **3.10+**
- Network access (for external lookups and scanning)
- Administrator/root privileges (required only for packet sniffing via `--sniff`)

### System Commands (Optional)

Some modules rely on platform-specific system commands:

| Command | Platform | Used By |
|---------|----------|---------|
| `ping` | All | LAN scanner, traceroute fallback |
| `tracert` | Windows | Traceroute module |
| `traceroute` | Linux/macOS | Traceroute module |
| `arp` | All | LAN scanner (MAC address lookup) |
| `ipconfig` | Windows | Network interface details |
| `ip addr show` / `ifconfig` | Linux/macOS | Network interface details |

### Python Dependencies

All dependencies are listed in `requirements.txt`:

| Package | Purpose |
|---------|---------|
| `aiohttp` | Async HTTP client for external IP lookup, threat intel APIs |
| `async-timeout` | Timeout management for async operations |
| `rich` | Terminal UI rendering with tables, panels, and colors |
| `requests` | Synchronous HTTP fallback for external IP lookup |
| `dnspython` | DNS record resolution (A, AAAA, MX, TXT, NS, CNAME, DNSKEY) |
| `speedtest-cli` | Internet speed measurement |
| `scapy` | Packet capture and analysis for sniffer module |
| `psutil` | System/process utilities |
| `python-whois` | WHOIS domain/IP lookup (primary method) |
| `ipwhois` | IP WHOIS data enrichment |

---

## Installation

### 1. Clone or Download the Project

```bash
git clone <repository-url>
cd NetRecon-CLI
```

### 2. Create Virtual Environment

```bash
python -m venv venv
```

### 3. Activate Virtual Environment

**Windows PowerShell:**
```powershell
venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Quick Start

### View All CLI Options

```bash
python main.py --help
```

### Basic Active Scan

```bash
python main.py --mode active --target 8.8.8.8 --external --scan-common-ports --security-check
```

### Basic Passive Recon

```bash
python main.py --mode passive --dns example.com --whois --whois-target example.com --threat-check
```

---

## Command Reference

### IP Intelligence

```bash
# External IP lookup with reverse DNS and geo map
python main.py --external

# Include network interface details (ipconfig/ifconfig output)
python main.py --external --interfaces

# Export geo location to HTML map
python main.py --external --geo-html reports/geo_map.html
```

### Port Scanning

```bash
# Scan predefined common ports (20,21,22,23,25,53,80,110,139,143,443,445,3389,8080)
python main.py --target 192.168.1.1 --scan-common-ports

# Scan custom port range
python main.py --target 192.168.1.1 --scan-ports 1-1000

# Scan using config default range (1-1024)
python main.py --target 192.168.1.1 --scan-ports

# Full port scan (use with caution)
python main.py --target 192.168.1.1 --scan-ports 1-65535
```

### DNS Analysis

```bash
# Full DNS record lookup with security checks
python main.py --dns example.com
```

### WHOIS Lookup

```bash
# WHOIS for domain
python main.py --whois --whois-target example.com

# WHOIS for IP
python main.py --whois --whois-target 8.8.8.8

# WHOIS using scan target
python main.py --target 8.8.8.8 --whois
```

### Traceroute

```bash
# Basic traceroute
python main.py --traceroute 8.8.8.8

# Advanced with ASN and geolocation per hop
python main.py --traceroute 8.8.8.8 --traceroute-advanced
```

### Subdomain Scanning

```bash
python main.py --subdomain example.com
```

### Threat Intelligence

```bash
# Requires API keys in config.json
python main.py --external --threat-check
```

### Security Check and Risk Scoring

```bash
python main.py --external --scan-common-ports --security-check
```

### Speed Test

```bash
python main.py --speedtest
```

### LAN Scanner

```bash
python main.py --mode active --lan-scan 192.168.1.0/24
```

### Packet Sniffer

```bash
# Basic sniffing (requires admin/root)
python main.py --mode active --sniff

# Custom limits
python main.py --mode active --sniff --sniff-limit 500 --sniff-timeout 30
```

### Reporting

```bash
# JSON to stdout
python main.py --json

# Save JSON to auto-named file (reports/netrecon_report_<timestamp>.json)
python main.py --save-json

# Save JSON to specific path
python main.py --save-json reports/result.json

# HTML dashboard report (default: report.html)
python main.py --html-report

# HTML dashboard to specific path
python main.py --html-report reports/netrecon_report.html

# Disable Rich colored output
python main.py --no-color
```

### Full Enterprise Scan Example

```bash
python main.py --mode active --target 8.8.8.8 --external --scan-ports 1-1000 --whois --whois-target 8.8.8.8 --dns google.com --traceroute 8.8.8.8 --traceroute-advanced --threat-check --speedtest --security-check --subdomain google.com --html-report full_report.html
```

---

## Configuration

### config.json Reference

The application loads configuration from `config.json` at startup. All fields have safe defaults if the file is missing or incomplete.

```json
{
  "mode": "active",
  "external_lookup": true,
  "interfaces": false,
  "default_port_range": "1-1024",
  "security_mode": true,
  "threat_check": false,
  "connect_timeout": 0.5,
  "request_timeout_seconds": 8.0,
  "external_workers": 3,
  "port_scan_workers": 300,
  "subdomain_workers": 200,
  "common_ports": [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080],
  "risky_ports": [21, 23, 25, 445, 3389, 5900],
  "subdomain_wordlist": ["www", "mail", "api", "dev", "staging", "beta", "admin", "portal", "vpn", "docs", "blog", "m", "ftp", "cpanel", "webmail"],
  "traceroute_max_hops": 30,
  "traceroute_timeout_ms": 2000,
  "lan_scan_timeout_ms": 800,
  "sniff_default_limit": 200,
  "sniff_default_timeout": 15,
  "html_report_default": "report.html",
  "log_level": "INFO",
  "log_file": "logs/netrecon.log",
  "api_keys": {
    "abuseipdb": "",
    "virustotal": "",
    "shodan": ""
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"active"` | Default scan mode (`active` or `passive`) |
| `external_lookup` | bool | `true` | Enable external IP lookup by default |
| `interfaces` | bool | `false` | Include network interface details by default |
| `default_port_range` | string | `"1-1024"` | Default port range when `--scan-ports` is used without a value |
| `security_mode` | bool | `true` | Enable security checks by default |
| `threat_check` | bool | `false` | Enable threat intelligence by default |
| `connect_timeout` | float | `0.5` | TCP connection timeout per port (seconds) |
| `request_timeout_seconds` | float | `8.0` | HTTP request timeout for API calls |
| `external_workers` | int | `3` | Concurrent external IP provider lookups |
| `port_scan_workers` | int | `300` | Concurrent port scan connections |
| `subdomain_workers` | int | `200` | Concurrent subdomain DNS resolutions |
| `common_ports` | list[int] | 14 ports | Predefined list for `--scan-common-ports` |
| `risky_ports` | list[int] | 6 ports | Ports flagged as security-sensitive |
| `subdomain_wordlist` | list[str] | 15 words | Common subdomain prefixes to enumerate |
| `traceroute_max_hops` | int | `30` | Maximum TTL hops for traceroute |
| `traceroute_timeout_ms` | int | `2000` | Per-hop timeout in milliseconds |
| `lan_scan_timeout_ms` | int | `800` | Ping timeout for LAN host discovery |
| `sniff_default_limit` | int | `200` | Default packet capture count |
| `sniff_default_timeout` | int | `15` | Default sniffer timeout in seconds |
| `html_report_default` | string | `"report.html"` | Default HTML report output path |
| `log_level` | string | `"INFO"` | Logging verbosity (DEBUG, INFO, WARNING, ERROR) |
| `log_file` | string | `"logs/netrecon.log"` | Log file output path |
| `api_keys` | object | `{}` | API keys for threat intelligence services |

### Custom Config File

```bash
python main.py --config /path/to/custom_config.json
```

### Logging Override

```bash
python main.py --log-level DEBUG --log-file logs/debug.log
```

---

## Threat Intelligence API Keys

Configure API keys in `config.json` under `api_keys`:

```json
{
  "api_keys": {
    "abuseipdb": "YOUR_ABUSEIPDB_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_KEY",
    "shodan": "YOUR_SHODAN_KEY"
  }
}
```

- **AbuseIPDB**: Checks IP abuse confidence score and total reports (last 90 days)
- **VirusTotal**: Checks IP analysis stats (malicious/suspicious detections)
- **Shodan**: Checks known vulnerabilities for the host

If no keys are configured, threat intelligence checks are skipped gracefully with a status message.

---

## Legacy Compatibility

The original `ip_finder.py` entrypoint is still available for backward compatibility:

```bash
python ip_finder.py
```

This prints basic local and external IP information using the `IPScanner` class. For full functionality, use `main.py`.

---

## Project Structure

```text
NetRecon CLI/
├── main.py                          # Application entrypoint (imports netrecon.cli.main)
├── ip_finder.py                     # Legacy compatibility wrapper
├── config.json                      # Runtime configuration file
├── requirements.txt                 # Python package dependencies
├── README.md                        # This file
├── PRD.md                           # Product Requirements Document
├── Architecture.md                  # Architecture overview
├── SystemDesign.md                  # System design document
├── MVP.md                           # MVP tracking and checklist
├── How_to_use_this_Program.md       # Detailed usage guide
├── logs/                            # Application log output directory
│   └── netrecon.log                 # Default log file
├── netrecon/                        # Main application package
│   ├── __init__.py                  # Exports: NetReconOrchestrator, ReconResult, ScanOptions
│   ├── __main__.py                  # Package entrypoint (python -m netrecon)
│   ├── async_utils.py               # Async runner, concurrency limiter, HTTP fetch helper
│   ├── banner.py                    # Service banner grabbing (BannerGrabber)
│   ├── cli.py                       # CLI argument parser, option resolver, main() function
│   ├── config.py                    # AppConfig dataclass and ConfigLoader from JSON
│   ├── dns_analyzer.py              # DNS record analyzer with security checks (DNSAnalyzer)
│   ├── html_report.py               # HTML dashboard report generator (HTMLReportBuilder)
│   ├── ip_scanner.py                # IP intelligence scanner (IPScanner)
│   ├── lan_scanner.py               # LAN active host discovery (LANScanner)
│   ├── logging_utils.py             # Logging setup with console + file handlers
│   ├── models.py                    # All dataclass models (18 dataclasses)
│   ├── orchestrator.py              # Central scan coordinator (NetReconOrchestrator)
│   ├── port_scanner.py              # Async TCP port scanner (PortScanner)
│   ├── renderer.py                  # Rich terminal output and JSON serialization
│   ├── risk_engine.py               # Weighted risk scoring engine (RiskScoringEngine)
│   ├── security_checks.py           # Security posture evaluator (SecurityChecker)
│   ├── sniffer.py                   # Packet capture and anomaly detection (PacketSniffer)
│   ├── speed_test.py                # Internet speed measurement (SpeedTester)
│   ├── subdomain_scanner.py         # Async subdomain enumeration (SubdomainScanner)
│   ├── threat_intel.py              # Threat intel API integration (ThreatIntelChecker)
│   ├── traceroute.py                # Cross-platform traceroute (TracerouteScanner)
│   └── whois_lookup.py              # WHOIS lookup with fallback (WhoisLookup)
└── tests/                           # Unit test suite (one test file per module)
    ├── test_async_utils.py
    ├── test_banner.py
    ├── test_cli.py
    ├── test_config.py
    ├── test_dns_analyzer.py
    ├── test_html_report.py
    ├── test_ip_scanner.py
    ├── test_lan_scanner.py
    ├── test_logging_utils.py
    ├── test_models.py
    ├── test_orchestrator.py
    ├── test_port_scanner.py
    ├── test_renderer.py
    ├── test_risk_engine.py
    ├── test_security_checks.py
    ├── test_sniffer.py
    ├── test_speed_test.py
    ├── test_subdomain_scanner.py
    ├── test_threat_intel.py
    ├── test_traceroute.py
    └── test_whois_lookup.py
```

---

## Testing

Run the full test suite:

```bash
python -m unittest discover -s tests -v
```

Run a specific test file:

```bash
python -m unittest tests.test_port_scanner -v
```

---

## Important Notes

- **Authorization**: Only scan networks and systems you have explicit permission to test.
- **Privileges**: Packet sniffing (`--sniff`) requires administrator/root privileges.
- **Rate Limits**: Aggressive scans and threat API calls may trigger rate limiting.
- **Dependencies**: Modules gracefully degrade when optional packages are missing (e.g., `scapy`, `dnspython`, `speedtest-cli`).
- **Cross-Platform**: Tested on Windows, Linux, and macOS. Platform-specific commands have automatic fallbacks.
