# NetRecon CLI

**NetRecon CLI** is a professional, cross-platform, async-first network reconnaissance and security analysis toolkit built in Python. It provides **25+ modular scanning engines** coordinated through a central orchestrator, delivering comprehensive intelligence about networks, hosts, and security posture from a single command-line interface.

---

## Feature Overview

| Module | Description | CLI Flag |
|--------|-------------|----------|
| **IP Intelligence** | Local IP detection, multi-provider external IP lookup (ipinfo, ipapi, ipwhois), reverse DNS, geo map export | `--external`, `--interfaces` |
| **GeoIP (Offline)** | Offline IP geolocation via MaxMind GeoLite2 database — no API needed | `--geoip-db PATH` |
| **Port Scanner** | Async TCP port scanning with open/closed/filtered classification | `--scan-common-ports`, `--scan-ports RANGE` |
| **Banner Grabber** | Protocol-aware service identification (SSH, HTTP, SMTP, FTP, MySQL, etc.) | Automatic on open ports |
| **OS Fingerprinting** | TTL/window-based OS guessing (Linux/Windows/Cisco/macOS) with optional Scapy | `--os-fingerprint HOST` |
| **DNS Analyzer** | A, AAAA, MX, TXT, NS, CNAME records + SPF/DMARC/DNSSEC verification | `--dns HOST` |
| **DNS Zone Transfer** | Attempt AXFR (zone transfer) on DNS servers | `--dns-axfr DOMAIN` |
| **WHOIS Lookup** | ASN, ISP, organization, abuse contact with raw TCP fallback | `--whois`, `--whois-target` |
| **Traceroute** | Cross-platform traceroute with TTL-ping fallback and optional ASN/geo enrichment | `--traceroute TARGET`, `--traceroute-advanced` |
| **Subdomain Scanner** | Async DNS resolution of common subdomain wordlist with response timing | `--subdomain DOMAIN` |
| **SSL/TLS Grabber** | Certificate info: issuer, subject, expiry, SAN, cipher, protocol | `--ssl-enum HOST` |
| **SSH Enumeration** | SSH banner, software version, KEX/hostkey/encryption/MAC algorithms | `--ssh-enum HOST` |
| **Threat Intel** | AbuseIPDB, VirusTotal, Shodan API integration for IP reputation checks | `--threat-check` |
| **Security Checks** | IP classification (private/public), VPN/proxy heuristics, firewall detection | `--security-check` |
| **Risk Engine** | Weighted scoring (0-100) with Low/Medium/High/Critical severity levels | Automatic |
| **Speed Test** | Download/upload/ping measurement via speedtest-cli | `--speedtest` |
| **LAN Scanner** | CIDR-based active host discovery with hostname and MAC address resolution | `--lan-scan CIDR` |
| **Packet Sniffer** | Traffic capture with ARP spoofing, DNS poisoning, anomaly detection | `--sniff` |
| **BPF Filter** | Berkeley Packet Filter expression for sniffer (e.g. `tcp port 80`) | `--sniff-filter BPF` |
| **PCAP Export** | Save captured packets to PCAP file for Wireshark analysis | `--sniff-pcap PATH` |
| **NVD/CVE Lookup** | Local CVE database lookup via NVD API with SQLite caching | `--cve-lookup PRODUCT --cve-version V` |
| **Continuous Monitor** | Re-scan at intervals with delta detection (new ports, hosts, IP changes) | `--watch` |
| **REST API Server** | HTTP API to trigger scans and fetch results | `--serve` |
| **Plugin System** | Load external Python modules via entry points or directory scanning | `--plugin-dir DIR`, `--list-plugins` |
| **Interactive TUI** | Textual-based terminal dashboard with scan trigger and results browser | `--tui` |
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

| Command | Platform | Used By |
|---------|----------|---------|
| `ping` | All | LAN scanner, traceroute fallback, OS fingerprinting |
| `tracert` | Windows | Traceroute module |
| `traceroute` | Linux/macOS | Traceroute module |
| `arp` | All | LAN scanner (MAC address lookup) |
| `ipconfig` | Windows | Network interface details |
| `ip addr show` / `ifconfig` | Linux/macOS | Network interface details |

### Python Dependencies

All dependencies are listed in `requirements.txt`:

| Package | Purpose | Required For |
|---------|---------|-------------|
| `aiohttp` | Async HTTP client | External IP lookup, threat intel, NVD/CVE API |
| `async-timeout` | Timeout management for async operations | All async operations |
| `rich` | Terminal UI rendering with tables, panels, and colors | All CLI output |
| `requests` | Synchronous HTTP fallback | External IP lookup |
| `dnspython` | DNS record resolution | `--dns` module |
| `speedtest-cli` | Internet speed measurement | `--speedtest` module |
| `scapy` | Packet capture and analysis | `--sniff`, OS fingerprinting (advanced) |
| `psutil` | System/process utilities | Process management |
| `python-whois` | WHOIS domain/IP lookup (primary method) | `--whois` module |
| `ipwhois` | IP WHOIS data enrichment | WHOIS data enhancement |
| `geoip2` | Offline MaxMind GeoIP database reader | `--geoip-db` module |
| `textual` | Terminal UI framework | `--tui` module |

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

### 5. (Optional) Install Package in Development Mode

```powershell
pip install -e .
netrecon --help
```

This makes the `netrecon` command globally available in the venv.

---

## Quick Start

### View All CLI Options

```bash
python -m netrecon --help
```

### Basic Active Scan

```bash
python -m netrecon --mode active --target 8.8.8.8 --external --scan-common-ports --security-check
```

### Basic Passive Recon

```bash
python -m netrecon --mode passive --dns example.com --whois --whois-target example.com --threat-check
```

---

## Command Reference

### IP Intelligence

```bash
# External IP lookup with reverse DNS and geo map
python -m netrecon --external

# Include network interface details
python -m netrecon --external --interfaces

# Export geo location to HTML map
python -m netrecon --external --geo-html reports/geo_map.html
```

### GeoIP Offline Lookup (No API Required)

Download `GeoLite2-City.mmdb` and (optionally) `GeoLite2-ASN.mmdb` from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place them in a folder:

```powershell
# Install the geoip2 library
pip install geoip2

# Lookup IP location offline
python -m netrecon --target 8.8.8.8 --geoip-db data/GeoLite2-City.mmdb
```

The module automatically finds `GeoLite2-ASN.mmdb` in the same folder as the City database.

### OS Fingerprinting

```bash
# Basic TTL-based OS guess
python -m netrecon --os-fingerprint 8.8.8.8

# With port scan (banners provide additional window-size hints)
python -m netrecon --target 192.168.1.1 --scan-common-ports --os-fingerprint 192.168.1.1
```

Guesses: Linux (TTL 64), Windows (TTL 128), Cisco (TTL 255), macOS, Solaris, FreeBSD.

### NVD/CVE Lookup

> **API Key (recommended):** Without an API key, NVD rate-limits to 5 requests per 30 seconds.
> Get a **free** key from [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
> and save it in `.env`:
> ```env
> NVD_API_KEY=your_key_here
> ```

```bash
# Look up CVEs for a software product
python -m netrecon --cve-lookup "apache httpd" --cve-version "2.4.49"
```

Results are cached locally in `cve_cache.db` (SQLite) for 24 hours.

### Port Scanning

```bash
# Scan predefined common ports
python -m netrecon --target 192.168.1.1 --scan-common-ports

# Scan custom port range
python -m netrecon --target 192.168.1.1 --scan-ports 1-1000

# Full port scan (use with caution)
python -m netrecon --target 192.168.1.1 --scan-ports 1-65535

# Stealth mode (adds jitter between probes)
python -m netrecon --target 192.168.1.1 --scan-common-ports --stealth
```

### DNS Analysis

```bash
# Full DNS record lookup with security checks
python -m netrecon --dns example.com

# DNS zone transfer attempt
python -m netrecon --dns-axfr example.com
```

### SSL/TLS Certificate Grabber

```bash
# Grab certificate (default port 443)
python -m netrecon --ssl-enum example.com

# Custom port
python -m netrecon --ssl-enum example.com --ssl-port 8443
```

Output: Subject CN, issuer, validity dates, cipher suite, TLS protocol version, SAN list, self-signed/expired status.

### SSH Server Enumeration

```bash
# Enumerate SSH server (default port 22)
python -m netrecon --ssh-enum example.com

# Custom port
python -m netrecon --ssh-enum example.com --ssh-port 2222
```

Output: Banner, software version, KEX algorithms, host key algorithms, encryption/MAC/compression algorithms.

### WHOIS Lookup

```bash
# WHOIS for domain
python -m netrecon --whois --whois-target example.com

# WHOIS for IP
python -m netrecon --whois --whois-target 8.8.8.8

# WHOIS using scan target
python -m netrecon --target 8.8.8.8 --whois
```

### Traceroute

```bash
# Basic traceroute
python -m netrecon --traceroute 8.8.8.8

# Advanced with ASN and geolocation per hop
python -m netrecon --traceroute 8.8.8.8 --traceroute-advanced
```

### Subdomain Scanning

```bash
python -m netrecon --subdomain example.com

# Custom wordlist
python -m netrecon --subdomain example.com --subdomain-wordlist my_words.txt
```

### Threat Intelligence

```bash
# Requires API keys in config.json
python -m netrecon --external --threat-check
```

### Security Check and Risk Scoring

```bash
python -m netrecon --external --scan-common-ports --security-check
```

### Speed Test

```bash
python -m netrecon --speedtest
```

### LAN Scanner

```bash
python -m netrecon --mode active --lan-scan 192.168.1.0/24
```

### Packet Sniffer with BPF Filter and PCAP Export

```bash
# Basic sniffing (requires admin/root)
python -m netrecon --mode active --sniff

# Custom limits
python -m netrecon --mode active --sniff --sniff-limit 500 --sniff-timeout 30

# BPF filter — capture only HTTP traffic
python -m netrecon --mode active --sniff --sniff-filter "tcp port 80"

# Save captured packets to PCAP for Wireshark
python -m netrecon --mode active --sniff --sniff-pcap capture.pcap

# Full example: filter + export
python -m netrecon --mode active --sniff --sniff-filter "tcp port 443" --sniff-limit 1000 --sniff-pcap https_traffic.pcap
```

### Continuous Monitoring (Watch Mode)

```bash
# Re-scan every 60 seconds (default)
python -m netrecon --target 8.8.8.8 --external --scan-common-ports --watch

# Custom interval
python -m netrecon --target 8.8.8.8 --external --watch --watch-interval 120
```

Detects and reports: new open ports, closed ports, new LAN hosts, lost LAN hosts, external IP changes.

### REST API Server

```bash
# Start API server on default 127.0.0.1:8088
python -m netrecon --serve

# Custom bind address and port
python -m netrecon --serve --serve-host 0.0.0.0 --serve-port 9090
```

Endpoints:
- `GET  /api/v1/status` — Server status, cycle count, uptime
- `POST /api/v1/scan`   — Trigger a new scan
- `GET  /api/v1/results` — Latest scan results (JSON)

### Plugin System

```bash
# List discovered plugins
python -m netrecon --list-plugins

# Load plugins from a directory
python -m netrecon --plugin-dir ./my_plugins
```

Plugins are Python classes extending `NetReconPlugin` with a `run(options, result)` method.

### Interactive TUI Dashboard

```bash
python -m netrecon --tui
```

Requires `textual` package. Provides a terminal UI with scan button, live log, and browseable results.

### Reporting

```bash
# JSON to stdout
python -m netrecon --json

# Save JSON to auto-named file
python -m netrecon --save-json

# Save JSON to specific path
python -m netrecon --save-json reports/result.json

# HTML dashboard report
python -m netrecon --html-report

# CSV report
python -m netrecon --save-csv

# Disable Rich colored output
python -m netrecon --no-color
```

### Full Enterprise Scan Example

```bash
python -m netrecon --mode active --target 8.8.8.8 --external --scan-ports 1-1000 --whois --whois-target 8.8.8.8 --dns google.com --traceroute 8.8.8.8 --traceroute-advanced --threat-check --speedtest --security-check --subdomain google.com --os-fingerprint 8.8.8.8 --ssl-enum google.com --ssh-enum example.com --cve-lookup "openssl" --cve-version "1.1.1" --geoip-db data/GeoLite2-City.mmdb --html-report full_report.html
```

---

## Configuration

### config.json Reference

The application loads configuration from `config.json` at startup. Generate a default config:

```bash
python -m netrecon --init-config
```

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
  "common_ports": [20,21,22,23,25,53,80,110,139,143,443,445,3389,8080],
  "risky_ports": [21,23,25,445,3389,5900],
  "subdomain_wordlist": ["www","mail","api","dev","staging","beta","admin","portal","vpn","docs","blog","m","ftp","cpanel","webmail"],
  "traceroute_max_hops": 30,
  "traceroute_timeout_ms": 2000,
  "lan_scan_timeout_ms": 800,
  "sniff_default_limit": 200,
  "sniff_default_timeout": 15,
  "html_report_default": "report.html",
  "log_level": "INFO",
  "log_file": "logs/netrecon.log",
  "api_keys": {
    "nvd": "",
    "abuseipdb": "",
    "virustotal": "",
    "shodan": ""
  }
}
```

### Custom Config File

```bash
python -m netrecon --config /path/to/custom_config.json
```

### Logging Override

```bash
python -m netrecon --log-level DEBUG --log-file logs/debug.log
```

---

## API Keys

Keys can be configured in `config.json` under `api_keys` or via `.env` (`.env` takes precedence):

### .env (recommended for NVD)
```env
NVD_API_KEY=your_key_here
```

### config.json
```json
{
  "api_keys": {
    "nvd": "YOUR_NVD_KEY",
    "abuseipdb": "YOUR_ABUSEIPDB_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_KEY",
    "shodan": "YOUR_SHODAN_KEY"
  }
}
```

| Key | Service | Purpose | Get It |
|-----|---------|---------|--------|
| `nvd` | NVD | CVE database lookup (faster with key) | [Request Key](https://nvd.nist.gov/developers/request-an-api-key) |
| `abuseipdb` | AbuseIPDB | IP abuse confidence score | [AbuseIPDB](https://www.abuseipdb.com/api) |
| `virustotal` | VirusTotal | Malicious/suspicious IP detections | [VirusTotal](https://www.virustotal.com/gui/join-us) |
| `shodan` | Shodan | Known host vulnerabilities | [Shodan](https://account.shodan.io/register) |

If no keys are configured, threat intelligence checks are skipped gracefully.

---

## GeoIP Database Setup

NetRecon supports **offline** IP geolocation via MaxMind GeoLite2 databases — no external API calls needed.

### Required Files

| File | Required | Provides |
|------|----------|----------|
| `GeoLite2-City.mmdb` | **Yes** | City, Country, Latitude, Longitude |
| `GeoLite2-ASN.mmdb` | Optional | AS number, Organization name |

### Setup Steps

1. Register at [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free)
2. Download `GeoLite2-City.mmdb` (GZIP) and optionally `GeoLite2-ASN.mmdb`
3. Extract and place both `.mmdb` files in a folder (e.g. `data/`)
4. Install the reader: `pip install geoip2`
5. Run:

```powershell
python -m netrecon --target 8.8.8.8 --geoip-db data/GeoLite2-City.mmdb
```

The module auto-discovers `GeoLite2-ASN.mmdb` if present in the same folder.

---

## Project Structure

```text
NetRecon CLI/
├── main.py                          # Application entrypoint
├── ip_finder.py                     # Legacy compatibility wrapper
├── config.json                      # Runtime configuration
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
├── How_to_use_this_Program.md       # Complete usage guide
├── PRD.md / Architecture.md / SystemDesign.md / MVP.md
├── data/                            # GeoIP .mmdb databases (gitignored)
├── logs/                            # Application log output
├── netrecon/                        # Main application package
│   ├── __init__.py / __main__.py
│   ├── cli.py                       # CLI parser + main() entrypoint
│   ├── orchestrator.py              # Central scan coordinator (async parallel)
│   ├── models.py                    # All dataclass models
│   ├── renderer.py                  # Rich terminal + JSON output
│   ├── config.py                    # AppConfig + ConfigLoader
│   ├── async_utils.py               # Async runner, concurrency limiter
│   ├── ip_scanner.py                # IP intelligence
│   ├── port_scanner.py              # Async TCP port scanner
│   ├── banner.py                    # Service banner grabbing
│   ├── os_fingerprint.py            # TTL/window OS guessing
│   ├── geoip.py                     # Offline GeoIP (MaxMind)
│   ├── dns_analyzer.py              # DNS record + security checks
│   ├── whois_lookup.py              # WHOIS lookup with fallback
│   ├── traceroute.py                # Cross-platform traceroute
│   ├── subdomain_scanner.py         # Async subdomain enumeration
│   ├── ssl_grabber.py               # SSL/TLS certificate grabber
│   ├── ssh_enum.py                  # SSH server algorithm enumeration
│   ├── sniffer.py                   # Packet capture + PCAP export + BPF
│   ├── threat_intel.py              # AbuseIPDB/VirusTotal/Shodan
│   ├── security_checks.py           # IP classification + firewall detection
│   ├── risk_engine.py               # Weighted risk scoring
│   ├── speed_test.py                # Internet speed measurement
│   ├── lan_scanner.py               # LAN host discovery
│   ├── cve_lookup.py                # NVD CVE database lookup
│   ├── monitor.py                   # Continuous monitoring loop
│   ├── server.py                    # REST API server
│   ├── plugin_base.py               # Plugin abstract base class
│   ├── plugin_registry.py           # Plugin discovery + loading
│   ├── tui_app.py                   # Interactive TUI dashboard
│   └── html_report.py               # HTML report builder
└── tests/                           # Unit test suite (145+ tests)
    ├── test_cli.py / test_config.py / test_models.py
    ├── test_orchestrator.py / test_renderer.py
    ├── test_async_utils.py / test_banner.py
    ├── test_ip_scanner.py / test_port_scanner.py
    ├── test_dns_analyzer.py / test_whois_lookup.py
    ├── test_traceroute.py / test_subdomain_scanner.py
    ├── test_threat_intel.py / test_security_checks.py
    ├── test_risk_engine.py / test_speed_test.py
    ├── test_lan_scanner.py / test_sniffer.py
    ├── test_os_fingerprint.py / test_cve_lookup.py
    ├── test_monitor.py / test_server.py
    ├── test_plugins.py / test_geoip.py
    ├── test_ssl_grabber.py / test_ssh_enum.py
    ├── test_tui.py / test_html_report.py
    └── test_logging_utils.py
```

---

## Testing

Run the full test suite:

```bash
python -m unittest discover -s tests -v
```

Run a specific test file:

```bash
python -m unittest tests.test_geoip -v
```

---

## Important Notes

- **Authorization**: Only scan networks and systems you have explicit permission to test.
- **Privileges**: Packet sniffing (`--sniff`) requires administrator/root privileges.
- **Rate Limits**: Aggressive scans and threat API calls may trigger rate limiting.
- **Dependencies**: All modules gracefully degrade when optional packages are missing.
- **Cross-Platform**: Tested on Windows, Linux, and macOS. Platform-specific commands have automatic fallbacks.
- **Parallel Execution**: Independent modules run concurrently for maximum performance.
