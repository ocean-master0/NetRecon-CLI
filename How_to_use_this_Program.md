# How To Use NetRecon CLI — Complete User Guide

NetRecon CLI is a professional-grade Network Reconnaissance and Security Intelligence Toolkit. This guide covers every module, every CLI flag, configuration options, and recommended workflows with detailed explanations.

---

## Table of Contents

1. [Environment Setup](#1-environment-setup)
2. [Quick Start Commands](#2-quick-start-commands)
3. [Scan Modes](#3-scan-modes)
4. [External IP Intelligence](#4-external-ip-intelligence)
5. [Port Scanning](#5-port-scanning)
6. [Banner Grabbing](#6-banner-grabbing)
7. [DNS Analysis](#7-dns-analysis)
8. [WHOIS Lookup](#8-whois-lookup)
9. [Traceroute](#9-traceroute)
10. [Subdomain Scanning](#10-subdomain-scanning)
11. [Threat Intelligence](#11-threat-intelligence)
12. [Speed Test](#12-speed-test)
13. [Security Check](#13-security-check)
14. [Risk Scoring Engine](#14-risk-scoring-engine)
15. [LAN Scanner](#15-lan-scanner)
16. [Packet Sniffer](#16-packet-sniffer)
17. [Reporting and Output](#17-reporting-and-output)
18. [Configuration Reference](#18-configuration-reference)
19. [Full Scan Examples](#19-full-scan-examples)
20. [Important Notes and Best Practices](#20-important-notes-and-best-practices)
21. [Recommended Workflow](#21-recommended-workflow)
22. [Complete CLI Flag Reference](#22-complete-cli-flag-reference)

---

## 1. Environment Setup

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment

**Windows PowerShell:**
```powershell
venv\Scripts\Activate.ps1
```

**Windows CMD:**
```cmd
venv\Scripts\activate.bat
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Verify Installation

```bash
python main.py --help
```

This should display all available CLI flags and options.

### Required Python Dependencies

| Package | Purpose | Required For |
|---------|---------|-------------|
| `aiohttp` | Async HTTP client | External IP lookup, threat intel APIs |
| `async-timeout` | Async timeout management | All async operations |
| `rich` | Terminal UI rendering | Rich CLI dashboard output |
| `requests` | Sync HTTP fallback | External IP (when aiohttp unavailable) |
| `dnspython` | DNS record resolution | `--dns` module |
| `speedtest-cli` | Speed measurement | `--speedtest` module |
| `scapy` | Packet capture | `--sniff` module |
| `psutil` | System utilities | Process management |
| `python-whois` | WHOIS lookup | `--whois` module (primary method) |
| `ipwhois` | IP WHOIS enrichment | WHOIS data enhancement |

---

## 2. Quick Start Commands

### View Help

```bash
python main.py --help
```

### Minimal Scan (Default Settings)

```bash
python main.py
```

This performs local IP detection, external IP lookup (if enabled in config), and basic security classification.

### Basic Active Scan

```bash
python main.py --mode active --target 8.8.8.8 --external --scan-common-ports --security-check
```

### Basic Passive Scan

```bash
python main.py --mode passive --dns example.com --whois --whois-target example.com
```

---

## 3. Scan Modes

NetRecon CLI has two scan modes that control which modules are allowed to execute.

### Active Mode (Default)

```bash
python main.py --mode active
```

All modules are available in active mode:
- External IP lookup
- Port scanning + banner grabbing
- DNS analysis
- WHOIS lookup
- Traceroute
- Subdomain scanning
- Threat intelligence
- Speed test
- Security checks + risk scoring
- LAN scanning
- Packet sniffing

### Passive Mode

```bash
python main.py --mode passive
```

Passive mode restricts aggressive network probing. The following modules are **automatically skipped** with warning messages:

| Skipped Module | Warning Message |
|----------------|-----------------|
| Port Scanner | "Port scan skipped in passive mode" |
| Traceroute | "Traceroute skipped in passive mode" |
| Speed Test | "Speed test skipped in passive mode" |
| LAN Scanner | "LAN scan skipped in passive mode" |
| Packet Sniffer | "Packet sniffing skipped in passive mode" |

The following modules **work in passive mode**:
- External IP lookup
- DNS analysis
- WHOIS lookup
- Subdomain scanning
- Threat intelligence
- Security checks + risk scoring

---

## 4. External IP Intelligence

### Enable External IP Lookup

```bash
python main.py --external
```

**What it does:**
- Queries 3 external IP providers concurrently (ipinfo.io, ipapi.co, ipwho.is)
- Returns the first valid response and cancels remaining requests
- Provides: IP address, city, region, country, coordinates, organization, ISP, timezone
- ipwho.is also provides VPN and proxy detection flags
- Performs reverse DNS lookup on the external IP
- Generates Google Maps URL from coordinates

### Disable External IP Lookup

```bash
python main.py --no-external
```

### Include Network Interface Details

```bash
python main.py --external --interfaces
```

Shows the output of `ipconfig /all` (Windows), `ip addr show` (Linux), or `ifconfig` (macOS).

### Export Geo Map to HTML

```bash
python main.py --external --geo-html reports/geo_map.html
```

Generates an HTML file with a Google Maps link and embedded iframe showing your IP's geolocation.

### Output Fields

| Field | Description |
|-------|-------------|
| IP | Your external/public IP address |
| City | City-level geolocation |
| Region | State/province/region |
| Country | Country code or name |
| Coordinates | Latitude,longitude |
| Organization | Network owner organization |
| ISP | Internet Service Provider |
| Timezone | IANA timezone identifier |
| Source | Which provider returned the data |
| Reverse DNS | Hostname resolved from your IP |
| Map URL | Google Maps link with coordinates |

---

## 5. Port Scanning

### Scan Predefined Common Ports

```bash
python main.py --target 192.168.1.1 --scan-common-ports
```

**Common ports scanned:** 20 (FTP-data), 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 139 (NetBIOS), 143 (IMAP), 443 (HTTPS), 445 (SMB), 3389 (RDP), 8080 (HTTP-Alt)

### Scan Custom Port Range

```bash
python main.py --target 192.168.1.1 --scan-ports 1-1000
```

### Scan Config Default Range (1-1024)

```bash
python main.py --target 192.168.1.1 --scan-ports
```

When `--scan-ports` is used without a value, it uses the `default_port_range` from `config.json` (default: `"1-1024"`).

### Full Port Scan (All 65535 Ports)

```bash
python main.py --target 192.168.1.1 --scan-ports 1-65535
```

**Warning:** Full port scans take significantly longer and may trigger firewall or IDS alerts.

### Combined Port Scan

```bash
python main.py --target 192.168.1.1 --scan-common-ports --scan-ports 8000-9000
```

Both common ports and the custom range are merged and deduplicated before scanning.

### Port State Classification

| State | Meaning | Detection |
|-------|---------|-----------|
| **Open** | Service is accepting connections | TCP connection established successfully |
| **Closed** | Port actively rejects connections | `ConnectionRefusedError` received |
| **Filtered** | No response (possibly firewalled) | `TimeoutError` or `OSError` |

### Risky Ports

The following ports are flagged as security-sensitive when found open:
- 21 (FTP) — Unencrypted file transfer
- 23 (Telnet) — Unencrypted remote access
- 25 (SMTP) — Email relay abuse potential
- 445 (SMB) — Windows file sharing vulnerabilities
- 3389 (RDP) — Remote desktop attack surface
- 5900 (VNC) — Remote desktop without encryption

### Performance

- Default concurrency: 300 simultaneous connections
- Per-port timeout: 0.5 seconds
- 1000 ports typically scanned in 2-5 seconds

---

## 6. Banner Grabbing

Banner grabbing is **automatically triggered** when port scanning finds open ports. No separate flag is needed.

### What It Detects

| Port | Protocol | Banner Method |
|------|----------|---------------|
| 21 | FTP | Sends `USER anonymous`, reads server response |
| 22 | SSH | Reads initial SSH banner (e.g., `SSH-2.0-OpenSSH_8.9`) |
| 25, 587 | SMTP | Sends `EHLO netrecon.local`, reads greeting |
| 80, 8080, 443, 8443 | HTTP | Sends `HEAD / HTTP/1.1`, extracts `Server` header |
| 110 | POP3 | Sends `EHLO netrecon.local`, reads banner |
| 143 | IMAP | Sends `EHLO netrecon.local`, reads banner |
| 3306 | MySQL | Reads initial handshake packet |
| Other | Generic | Reads up to 512 bytes from socket |

### Output Fields

| Field | Description |
|-------|-------------|
| Port | Port number |
| Service | Detected service name (ssh, http, mysql, etc.) |
| Banner | Raw banner text or server header |
| Status | `open`, `open-no-banner`, or `failed:<error>` |

---

## 7. DNS Analysis

```bash
python main.py --dns example.com
```

### Records Resolved

| Record Type | Description | Example |
|-------------|-------------|---------|
| A | IPv4 address | `93.184.216.34` |
| AAAA | IPv6 address | `2606:2800:220:1:248:1893:25c8:1946` |
| MX | Mail exchange server | `mail.example.com` |
| TXT | Text records (SPF, verification) | `"v=spf1 include:_spf.google.com ~all"` |
| NS | Name servers | `ns1.example.com` |
| CNAME | Canonical name alias | `www.example.com → example.com` |

### Security Checks

| Check | What It Verifies | Impact |
|-------|------------------|--------|
| **SPF** | Sender Policy Framework present in TXT records | Prevents email spoofing. Missing SPF adds +8 to risk score |
| **DMARC** | Domain-based Message Authentication present at `_dmarc.{domain}` | Email authentication. Missing DMARC adds +8 to risk score |
| **DNSSEC** | DNS Security Extensions enabled (DNSKEY record exists) | DNS integrity. Missing DNSSEC adds +5 to risk score |

---

## 8. WHOIS Lookup

### For Domain

```bash
python main.py --whois --whois-target example.com
```

### For IP Address

```bash
python main.py --whois --whois-target 8.8.8.8
```

### Using Scan Target

```bash
python main.py --target 8.8.8.8 --whois
```

When `--whois-target` is not specified, the WHOIS query uses the `--target` value or external IP.

### Output Fields

| Field | Description |
|-------|-------------|
| ASN | Autonomous System Number (e.g., `AS15169`) |
| ISP | Internet Service Provider name |
| Organization | Registered organization |
| Abuse Contact | Email address for abuse reports |
| Source | `python_whois` or `raw_whois:<server>` |

### How It Works

1. **Primary method**: Uses `python-whois` library for structured data extraction
2. **Fallback method**: If primary fails, connects directly to WHOIS servers via TCP port 43
   - First queries `whois.iana.org` for referral server
   - Then queries the referral server for detailed records

---

## 9. Traceroute

### Basic Traceroute

```bash
python main.py --traceroute 8.8.8.8
```

### Advanced Traceroute (with ASN and Geolocation per Hop)

```bash
python main.py --traceroute 8.8.8.8 --traceroute-advanced
```

### How It Works

1. **Primary**: Runs system traceroute command
   - Windows: `tracert -d TARGET`
   - Linux/macOS: `traceroute -n TARGET`
2. **Fallback**: If system command fails, uses TTL-based ping probing (incrementing TTL from 1 to max_hops)
3. **Advanced mode**: Each hop's IP address is enriched with ASN and geolocation data from ipwho.is API

### Output Fields per Hop

| Field | Description |
|-------|-------------|
| Hop | Hop number (1, 2, 3...) |
| IP | Router IP address (`*` if timed out) |
| Latency (ms) | Round-trip time to hop |
| ASN | Autonomous System Number (advanced mode only) |
| Geo | City, Country (advanced mode only) |

### Configuration

- Maximum hops: 30 (configurable via `traceroute_max_hops` in config.json)
- Per-hop timeout: 2000ms (configurable via `traceroute_timeout_ms`)

---

## 10. Subdomain Scanning

```bash
python main.py --subdomain example.com
```

### How It Works

1. Prepends each word from the wordlist to the target domain
2. Attempts DNS resolution for each constructed hostname
3. Records successfully resolved hosts with their IP and response time

### Default Wordlist

The following subdomains are checked by default: `admin`, `api`, `beta`, `blog`, `cpanel`, `dev`, `docs`, `ftp`, `m`, `mail`, `portal`, `staging`, `vpn`, `webmail`, `www`

### Custom Wordlist

Modify `subdomain_wordlist` in `config.json`:

```json
{
  "subdomain_wordlist": ["www", "mail", "api", "dev", "staging", "admin", "portal", "vpn", "docs", "blog", "test", "stage", "uat", "demo", "sandbox"]
}
```

### Output Fields

| Field | Description |
|-------|-------------|
| Subdomain | Full hostname (e.g., `www.example.com`) |
| IP | Resolved IP address |
| Response (ms) | DNS resolution time in milliseconds |

### Performance

- Default concurrency: 200 simultaneous DNS resolution tasks
- Configurable via `subdomain_workers` in config.json

---

## 11. Threat Intelligence

```bash
python main.py --external --threat-check
```

### Prerequisites

API keys must be configured in `config.json`:

```json
{
  "api_keys": {
    "abuseipdb": "YOUR_ABUSEIPDB_API_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "shodan": "YOUR_SHODAN_API_KEY"
  }
}
```

If no keys are configured, threat checks are skipped gracefully with a status message.

### Services Checked

| Service | What It Checks | Output |
|---------|---------------|--------|
| **AbuseIPDB** | IP abuse reports in last 90 days | Abuse confidence score (0-100), total reports |
| **VirusTotal** | IP malware analysis results | Malicious + suspicious detection count |
| **Shodan** | Host vulnerability database | List of known CVE identifiers |

### Output Fields

| Field | Description |
|-------|-------------|
| Malicious Score | Highest abuse/malware confidence (0-100) |
| Blacklist Count | Total malicious + suspicious + vulnerability detections |
| Spam Reports | Number of abuse reports from AbuseIPDB |
| Known Vulns | Comma-separated CVE identifiers from Shodan |

### How to Get API Keys

1. **AbuseIPDB**: Register at [abuseipdb.com](https://www.abuseipdb.com/)
2. **VirusTotal**: Register at [virustotal.com](https://www.virustotal.com/)
3. **Shodan**: Register at [shodan.io](https://www.shodan.io/)

---

## 12. Speed Test

```bash
python main.py --speedtest
```

### What It Measures

| Metric | Description |
|--------|-------------|
| Download (Mbps) | Download bandwidth in megabits per second |
| Upload (Mbps) | Upload bandwidth in megabits per second |
| Ping (ms) | Latency to the best available speedtest server |
| Server | Name of the test server used |
| Country | Country of the test server |

### Notes

- Uses the `speedtest-cli` library with Speedtest.net servers
- Automatically retries with insecure mode if secure connection returns 403
- Not available in passive mode
- Typical execution time: 15-30 seconds

---

## 13. Security Check

```bash
python main.py --external --scan-common-ports --security-check
```

### What It Evaluates

| Check | Description |
|-------|-------------|
| **IP Classification** | Determines if IP is Private, Public, or Special/Reserved |
| **VPN Detection** | Checks provider flags + keyword scanning in network metadata |
| **Proxy Detection** | Checks provider flags + keyword scanning for proxy/TOR indicators |
| **Hosting Detection** | Scans for datacenter/cloud keywords (AWS, Azure, DigitalOcean, etc.) |
| **Risky Port Detection** | Flags open ports 21, 23, 25, 445, 3389, 5900 |
| **Firewall Detection** | Analyzes filtered port ratios and traceroute hop patterns |

### Firewall Detection Logic

| Condition | Detection |
|-----------|-----------|
| ≥50% of scanned ports filtered | Likely firewall |
| 0 open ports but filtered responses exist | Likely firewall |
| ≥40% of traceroute hops have unknown IP | ICMP blocked, likely firewall |

### Output Fields

| Field | Description |
|-------|-------------|
| Classification | Private, Public, Special/Reserved |
| Suspected VPN | True/False |
| Suspected Proxy | True/False |
| Risky Ports | List of open risky ports |
| Risk Level | Low, Medium, High, or Critical |
| Firewall | Likely/unlikely with reason |
| Findings | Detailed list of all security observations |

### Enable/Disable

```bash
python main.py --security-check      # Enable
python main.py --no-security-check   # Disable (even if enabled in config)
```

---

## 14. Risk Scoring Engine

Risk scoring is **automatically calculated** whenever a scan runs. It aggregates findings from all modules into a single 0-100 score.

### Scoring Factors

| Factor | Points | Maximum | Source |
|--------|--------|---------|--------|
| Risky open ports | +8 per port | 30 | Port scan results |
| Significant filtered ports | +5 | 5 | Port scan (if ≥20 ports scanned) |
| Proxy indicator | +15 | 15 | External IP provider flags |
| VPN indicator | +10 | 10 | External IP provider flags |
| Suspicious ASN/organization | +10 | 10 | WHOIS hosting/datacenter keywords |
| Blacklist presence | +3 per entry | 25 | Threat intelligence |
| Threat malicious score | +0.3 × score | 30 | Threat intelligence |
| Spam reports | +1 per 10 reports | 10 | AbuseIPDB |
| Known vulnerabilities | +3 per CVE | 15 | Shodan |
| SPF missing | +8 | 8 | DNS analysis |
| DMARC missing | +8 | 8 | DNS analysis |
| DNSSEC not detected | +5 | 5 | DNS analysis |
| Firewall anomalies | +4 | 4 | Security checks |

### Severity Levels

| Level | Score Range | Interpretation |
|-------|------------|----------------|
| **Low** | 0-24 | Minimal risk indicators detected |
| **Medium** | 25-49 | Some risk factors present, review recommended |
| **High** | 50-74 | Significant risk factors detected, action needed |
| **Critical** | 75-100 | Multiple high-risk indicators, immediate attention required |

---

## 15. LAN Scanner

```bash
python main.py --mode active --lan-scan 192.168.1.0/24
```

### How It Works

1. Expands CIDR notation into individual host addresses
2. Sends ICMP ping to each host concurrently (256 workers)
3. Hosts that respond are marked as active
4. Reads ARP table for MAC address resolution
5. Performs reverse DNS for hostname lookup

### Safety Limits

- Maximum 1024 hosts per scan
- Larger networks are automatically truncated with a warning

### Output Fields

| Field | Description |
|-------|-------------|
| IP | Active host IP address |
| Hostname | Resolved hostname (if available) |
| MAC | MAC address from ARP table (if available) |

### Common CIDR Ranges

| CIDR | Hosts | Use Case |
|------|-------|----------|
| `192.168.1.0/24` | 254 | Typical home/small office |
| `10.0.0.0/24` | 254 | Corporate LAN segment |
| `172.16.0.0/24` | 254 | Private network segment |
| `192.168.0.0/16` | 65,534 | Large network (truncated to 1024) |

---

## 16. Packet Sniffer

```bash
python main.py --mode active --sniff
```

### With Custom Parameters

```bash
python main.py --mode active --sniff --sniff-limit 500 --sniff-timeout 30
```

### Requirements

- **Administrator/root privileges required** for raw socket access
- `scapy` package must be installed

### Anomaly Detection

| Anomaly | Detection Method | Alert |
|---------|-----------------|-------|
| **ARP Spoofing** | Same IP address changes MAC address in ARP replies | "Possible ARP spoofing: {IP} changed MAC {old} -> {new}" |
| **DNS Poisoning** | Single domain resolves to >3 distinct IP addresses | "Potential DNS poisoning: high answer variance for {domain}" |
| **High Traffic** | Single source sends >25% of captured packets (or >30 packets) | "High traffic anomaly detected from source {IP}" |

### Configuration

| Parameter | Default | CLI Flag |
|-----------|---------|----------|
| Packet capture limit | 200 | `--sniff-limit INT` |
| Capture timeout | 15 seconds | `--sniff-timeout INT` |

---

## 17. Reporting and Output

### Rich Terminal Output (Default)

The default output renders a full dashboard in your terminal using the `rich` library with 16 sections:

1. Header panel with "NetRecon CLI" title and scan mode
2. Summary table (hostname, timestamp, mode, IP counts)
3. Local IP addresses table
4. External IP intelligence table (12 fields)
5. DNS analysis table with security checks
6. Subdomain scan results
7. Port scan summary + banner grabbing table
8. Traceroute hop table
9. WHOIS details
10. Speed test metrics
11. Threat intelligence metrics
12. Security check results + findings
13. Risk score + factor breakdown
14. LAN scan active hosts
15. Packet sniffer metrics + alerts
16. Warnings and errors summary

### Disable Color Output

```bash
python main.py --no-color
```

### JSON Output to Terminal

```bash
python main.py --json
```

Prints the complete scan result as formatted JSON to stdout.

### Save JSON Report

```bash
# Auto-generated filename (reports/netrecon_report_YYYYMMDD_HHMMSS.json)
python main.py --save-json

# Specific file path
python main.py --save-json reports/my_report.json
```

### HTML Dashboard Report

```bash
# Default path (report.html)
python main.py --html-report

# Custom path
python main.py --html-report reports/dashboard.html
```

**HTML report includes:**
- Summary card with hostname, mode, external IP, risk score
- Risk score doughnut chart (Chart.js)
- Open ports and banners table
- Speed test bar chart (download/upload/ping)
- Threat intelligence summary
- Embedded Google Maps geolocation iframe
- Complete raw JSON data snapshot

### Geo Map HTML Export

```bash
python main.py --external --geo-html reports/geo_map.html
```

Generates a simple HTML file with a Google Maps link and embedded iframe.

---

## 18. Configuration Reference

### Config File Location

Default: `config.json` in project root.

### Custom Config File

```bash
python main.py --config /path/to/custom_config.json
```

### Logging Configuration

```bash
# Override log level
python main.py --log-level DEBUG

# Override log file path
python main.py --log-file logs/debug.log
```

### Complete config.json Reference

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

### Field Descriptions

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"active"` | Default scan mode |
| `external_lookup` | bool | `true` | Enable external IP lookup by default |
| `interfaces` | bool | `false` | Include interface details by default |
| `default_port_range` | string | `"1-1024"` | Default range for `--scan-ports` without value |
| `security_mode` | bool | `true` | Enable security checks by default |
| `threat_check` | bool | `false` | Enable threat intel by default |
| `connect_timeout` | float | `0.5` | TCP connection timeout per port (seconds) |
| `request_timeout_seconds` | float | `8.0` | HTTP API request timeout (seconds) |
| `external_workers` | int | `3` | Concurrent external IP provider count |
| `port_scan_workers` | int | `300` | Maximum concurrent port connections |
| `subdomain_workers` | int | `200` | Concurrent subdomain DNS tasks |
| `common_ports` | list | 14 ports | Ports for `--scan-common-ports` |
| `risky_ports` | list | 6 ports | Ports flagged as security-sensitive |
| `subdomain_wordlist` | list | 15 words | Subdomain prefixes to enumerate |
| `traceroute_max_hops` | int | `30` | Max TTL hops |
| `traceroute_timeout_ms` | int | `2000` | Per-hop timeout (ms) |
| `lan_scan_timeout_ms` | int | `800` | Ping timeout for LAN discovery (ms) |
| `sniff_default_limit` | int | `200` | Default packet capture count |
| `sniff_default_timeout` | int | `15` | Default sniffer timeout (seconds) |
| `html_report_default` | string | `"report.html"` | Default HTML report path |
| `log_level` | string | `"INFO"` | Log verbosity |
| `log_file` | string | `"logs/netrecon.log"` | Log file path |
| `api_keys` | object | `{}` | Threat intel API keys |

---

## 19. Full Scan Examples

### Enterprise Security Audit (Recommended)

```bash
python main.py --mode active --target 8.8.8.8 --external --scan-ports 1-1000 --whois --whois-target 8.8.8.8 --dns google.com --traceroute 8.8.8.8 --traceroute-advanced --threat-check --speedtest --security-check --subdomain google.com --html-report full_report.html
```

### Aggressive Full Scan (All Ports + LAN + Sniffer)

**Warning: Use only when authorized on your own network**

```bash
python main.py --mode active --target 192.168.1.1 --external --scan-ports 1-65535 --whois --whois-target 192.168.1.1 --dns example.com --traceroute 192.168.1.1 --traceroute-advanced --threat-check --speedtest --security-check --lan-scan 192.168.1.0/24 --sniff --sniff-limit 300 --sniff-timeout 20 --subdomain example.com --html-report aggressive_report.html
```

### Passive Intelligence Gathering

```bash
python main.py --mode passive --external --dns google.com --whois --whois-target google.com --threat-check --security-check --subdomain google.com --html-report passive_report.html
```

### Quick Port Scan with JSON Output

```bash
python main.py --target 192.168.1.1 --scan-common-ports --json
```

### Save JSON for Automation

```bash
python main.py --target 192.168.1.1 --scan-common-ports --dns example.com --save-json reports/scan_result.json
```

### Local Network Discovery

```bash
python main.py --mode active --lan-scan 192.168.1.0/24 --html-report lan_report.html
```

### DNS-Only Analysis

```bash
python main.py --dns example.com --json
```

### WHOIS + Threat Check Combination

```bash
python main.py --whois --whois-target 8.8.8.8 --threat-check --security-check
```

---

## 20. Important Notes and Best Practices

### Authorization

- **Never scan systems without explicit permission**
- Use passive mode when scanning external domains you do not own
- Use active mode only on networks and systems you are authorized to test
- Packet sniffing on networks you do not administer may be illegal

### Privileges

- Packet sniffer (`--sniff`) requires **administrator/root privileges**
- Port scanning on some systems may require elevated privileges
- LAN scanning uses ICMP ping which may require privileges on some Linux systems

### Performance Considerations

- Full port scans (1-65535) can take several minutes
- Large LAN scans are automatically limited to 1024 hosts
- Speed tests take 15-30 seconds to complete
- Traceroute with advanced enrichment adds API calls per hop

### Rate Limits

- Threat intelligence APIs have rate limits; the tool adds a 0.25-second delay between calls
- External IP providers may rate-limit frequent requests
- Aggressive port scanning may trigger IDS/IPS alerts

### Dependency Handling

- If a required package is missing, the module skips with a warning instead of crashing
- Example: Without `scapy`, the sniffer returns: "scapy is not installed. Install with: pip install scapy"
- Example: Without `dnspython`, DNS analyzer returns: "dnspython is required for DNS analyzer"

### Logging

- All scan activity is logged to `logs/netrecon.log` by default
- Use `--log-level DEBUG` for troubleshooting
- Log format: `2025-03-03 10:30:00 [INFO] netrecon.orchestrator: Starting NetRecon scan...`

---

## 21. Recommended Workflow

### For External Target Assessment

1. **Passive Recon First**: Start with passive mode to gather DNS, WHOIS, and threat data
   ```bash
   python main.py --mode passive --dns target.com --whois --whois-target target.com --threat-check
   ```

2. **DNS Analysis**: Review DNS records and email security configuration
   ```bash
   python main.py --dns target.com
   ```

3. **Subdomain Discovery**: Find active subdomains
   ```bash
   python main.py --subdomain target.com
   ```

4. **Active Scan** (if authorized): Port scanning and banner grabbing
   ```bash
   python main.py --mode active --target target.com --scan-ports 1-1000 --security-check
   ```

5. **Traceroute**: Understand network path
   ```bash
   python main.py --traceroute target.com --traceroute-advanced
   ```

6. **Generate Report**: Export findings
   ```bash
   python main.py --mode active --target target.com --external --scan-ports 1-1000 --dns target.com --whois --whois-target target.com --traceroute target.com --threat-check --security-check --html-report report.html --save-json
   ```

### For Internal Network Assessment

1. **Network Discovery**: Find active hosts
   ```bash
   python main.py --mode active --lan-scan 192.168.1.0/24
   ```

2. **Port Scan Key Hosts**: Check open ports on discovered hosts
   ```bash
   python main.py --target 192.168.1.1 --scan-common-ports --security-check
   ```

3. **Traffic Analysis** (if needed):
   ```bash
   python main.py --mode active --sniff --sniff-limit 500 --sniff-timeout 60
   ```

4. **Full Report**:
   ```bash
   python main.py --mode active --target 192.168.1.1 --scan-common-ports --lan-scan 192.168.1.0/24 --security-check --html-report internal_report.html
   ```

---

## 22. Complete CLI Flag Reference

| Flag | Type | Description |
|------|------|-------------|
| `--target HOST` | string | Target host or IP for scan modules |
| `--mode {passive,active}` | string | Scan mode selection |
| `--external` | flag | Enable external IP lookup |
| `--no-external` | flag | Disable external IP lookup |
| `--interfaces` | flag | Include network interface details |
| `--no-interfaces` | flag | Skip interface details |
| `--scan-common-ports` | flag | Scan predefined common TCP ports |
| `--scan-ports [RANGE]` | optional string | Scan custom port range or config default |
| `--traceroute TARGET` | string | Run traceroute to target |
| `--traceroute-advanced` | flag | Enable per-hop ASN/geo enrichment |
| `--subdomain DOMAIN` | string | Run subdomain scanner |
| `--dns HOST` | string | Run DNS analyzer |
| `--whois` | flag | Enable WHOIS lookup |
| `--whois-target HOST` | string | WHOIS target override |
| `--speedtest` | flag | Run internet speed test |
| `--threat-check` | flag | Run threat intelligence lookup |
| `--security-check` | flag | Enable security classification and firewall checks |
| `--no-security-check` | flag | Disable security checks |
| `--lan-scan CIDR` | string | Run LAN active host scan |
| `--sniff` | flag | Run packet sniffer |
| `--sniff-limit INT` | integer | Packet capture limit |
| `--sniff-timeout INT` | integer | Sniffer timeout in seconds |
| `--geo-html PATH` | string | Export geo map to HTML file |
| `--html-report [PATH]` | optional string | Generate HTML dashboard report |
| `--json` | flag | Print JSON output to stdout |
| `--save-json [PATH]` | optional string | Save JSON report to file |
| `--no-color` | flag | Disable Rich colored output |
| `--config PATH` | string | Path to config.json file |
| `--log-level {DEBUG,INFO,WARNING,ERROR}` | string | Logging verbosity |
| `--log-file PATH` | string | Log file path override |