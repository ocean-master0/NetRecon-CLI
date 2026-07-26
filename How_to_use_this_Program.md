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
7. [OS Fingerprinting](#7-os-fingerprinting)
8. [NVD/CVE Lookup](#8-nvdcve-lookup)
9. [GeoIP Offline Lookup](#9-geoip-offline-lookup-no-api-required)
10. [SSL/TLS Certificate Grabber](#10-ssltls-certificate-grabber)
11. [SSH Server Enumeration](#11-ssh-server-enumeration)
12. [DNS Analysis](#12-dns-analysis)
13. [WHOIS Lookup](#13-whois-lookup)
14. [Traceroute](#14-traceroute)
15. [Subdomain Scanning](#15-subdomain-scanning)
16. [Threat Intelligence](#16-threat-intelligence)
17. [Speed Test](#17-speed-test)
18. [Security Check](#18-security-check)
19. [Risk Scoring Engine](#19-risk-scoring-engine)
20. [LAN Scanner](#20-lan-scanner)
21. [Packet Sniffer with BPF and PCAP](#21-packet-sniffer-with-bpf-and-pcap)
22. [Continuous Monitoring (Watch Mode)](#22-continuous-monitoring-watch-mode)
23. [REST API Server](#23-rest-api-server)
24. [Plugin System](#24-plugin-system)
25. [Interactive TUI Dashboard](#25-interactive-tui-dashboard)
26. [Reporting and Output](#26-reporting-and-output)
27. [Configuration Reference](#27-configuration-reference)
28. [Full Scan Examples](#28-full-scan-examples)
29. [Important Notes and Best Practices](#29-important-notes-and-best-practices)
30. [Recommended Workflow](#30-recommended-workflow)
31. [Complete CLI Flag Reference](#31-complete-cli-flag-reference)

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

### (Optional) Install Package in Development Mode

```powershell
pip install -e .
netrecon --help
```

### Verify Installation

```bash
python -m netrecon --help
```

### Required Python Dependencies

| Package | Purpose | Required For |
|---------|---------|-------------|
| `aiohttp` | Async HTTP client | External IP lookup, threat intel APIs, NVD/CVE |
| `async-timeout` | Async timeout management | All async operations |
| `rich` | Terminal UI rendering | Rich CLI dashboard output |
| `requests` | Sync HTTP fallback | External IP (when aiohttp unavailable) |
| `dnspython` | DNS record resolution | `--dns` module |
| `speedtest-cli` | Speed measurement | `--speedtest` module |
| `scapy` | Packet capture and analysis | `--sniff`, OS fingerprinting (advanced) |
| `psutil` | System utilities | Process management |
| `python-whois` | WHOIS lookup | `--whois` module (primary method) |
| `ipwhois` | IP WHOIS enrichment | WHOIS data enhancement |
| `geoip2` | Offline MaxMind GeoIP reader | `--geoip-db` module |
| `textual` | Terminal UI framework | `--tui` module |

---

## 2. Quick Start Commands

### View Help

```bash
python -m netrecon --help
```

### Minimal Scan (Default Settings)

```bash
python -m netrecon
```

This performs local IP detection, external IP lookup (if enabled in config), and basic security classification.

### Basic Active Scan

```bash
python -m netrecon --mode active --target 8.8.8.8 --external --scan-common-ports --security-check
```

### Basic Passive Scan

```bash
python -m netrecon --mode passive --dns example.com --whois --whois-target example.com
```

---

## 3. Scan Modes

NetRecon CLI has two scan modes that control which modules are allowed to execute.

### Active Mode (Default)

```bash
python -m netrecon --mode active
```

All modules are available in active mode:
- External IP lookup
- Port scanning + banner grabbing
- OS fingerprinting
- NVD/CVE lookup
- GeoIP lookup
- SSL/TLS grabber
- SSH enumeration
- DNS analysis
- WHOIS lookup
- Traceroute
- Subdomain scanning
- Threat intelligence
- Speed test
- Security checks + risk scoring
- LAN scanning
- Packet sniffing (with BPF + PCAP)
- Continuous monitoring
- REST API server
- Plugin system
- TUI dashboard

### Passive Mode

```bash
python -m netrecon --mode passive
```

Passive mode restricts aggressive network probing. The following modules are **automatically skipped** with warning messages:

| Skipped Module | Warning Message |
|----------------|-----------------|
| Port Scanner | "Port scan skipped in passive mode" |
| OS Fingerprinting | "OS fingerprinting skipped in passive mode" |
| Traceroute | "Traceroute skipped in passive mode" |
| Speed Test | "Speed test skipped in passive mode" |
| LAN Scanner | "LAN scan skipped in passive mode" |
| Packet Sniffer | "Packet sniffing skipped in passive mode" |

The following modules **work in passive mode**:
- External IP lookup
- GeoIP lookup
- NVD/CVE lookup
- SSL/TLS grabber
- SSH enumeration
- DNS analysis
- WHOIS lookup
- Subdomain scanning
- Threat intelligence
- Security checks + risk scoring
- Continuous monitoring
- Plugin system
- TUI dashboard

---

## 4. External IP Intelligence

### Enable External IP Lookup

```bash
python -m netrecon --external
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
python -m netrecon --no-external
```

### Include Network Interface Details

```bash
python -m netrecon --external --interfaces
```

Shows the output of `ipconfig /all` (Windows), `ip addr show` (Linux), or `ifconfig` (macOS).

### Export Geo Map to HTML

```bash
python -m netrecon --external --geo-html reports/geo_map.html
```

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
python -m netrecon --target 192.168.1.1 --scan-common-ports
```

**Common ports scanned:** 20 (FTP-data), 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 139 (NetBIOS), 143 (IMAP), 443 (HTTPS), 445 (SMB), 3389 (RDP), 8080 (HTTP-Alt)

### Scan Custom Port Range

```bash
python -m netrecon --target 192.168.1.1 --scan-ports 1-1000
```

### Scan Config Default Range (1-1024)

```bash
python -m netrecon --target 192.168.1.1 --scan-ports
```

### Full Port Scan (All 65535 Ports)

```bash
python -m netrecon --target 192.168.1.1 --scan-ports 1-65535
```

### Combined Port Scan

```bash
python -m netrecon --target 192.168.1.1 --scan-common-ports --scan-ports 8000-9000
```

### Port State Classification

| State | Meaning | Detection |
|-------|---------|-----------|
| **Open** | Service is accepting connections | TCP connection established |
| **Closed** | Port actively rejects connections | `ConnectionRefusedError` |
| **Filtered** | No response (possibly firewalled) | `TimeoutError` or `OSError` |

### Risky Ports

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Unencrypted file transfer |
| 23 | Telnet | Unencrypted remote access |
| 25 | SMTP | Email relay abuse potential |
| 445 | SMB | Windows file sharing vulnerabilities |
| 3389 | RDP | Remote desktop attack surface |
| 5900 | VNC | Remote desktop without encryption |

### Performance

- Default concurrency: 300 simultaneous connections
- Per-port timeout: 0.5 seconds
- 1000 ports typically scanned in 2-5 seconds

### Stealth Mode

```bash
python -m netrecon --target 192.168.1.1 --scan-common-ports --stealth
```

Adds random jitter between connection probes to evade simple detection.

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

## 7. OS Fingerprinting

Guess the operating system of a remote host using TCP/IP stack fingerprinting techniques.

### Basic TTL-Based Detection

```bash
python -m netrecon --os-fingerprint 8.8.8.8
```

### With Port Scan (Better Accuracy)

```bash
python -m netrecon --target 192.168.1.1 --scan-common-ports --os-fingerprint 192.168.1.1
```

### How It Works

The module uses multiple techniques to identify the OS:

1. **TTL Analysis**: Initial TTL values from ICMP replies reveal the OS family
2. **TCP Window Size**: Initial window sizes from banner connections provide additional hints
3. **Scapy (if available)**: Sends crafted TCP probes and analyzes IP identification patterns and TCP timestamp behavior

### TTL-Based OS Guesses

| TTL Value | OS Guess |
|-----------|----------|
| 64 | Linux, macOS, Android, FreeBSD |
| 128 | Windows (NT/2000/XP/7/8/10/11) |
| 255 | Cisco IOS, Solaris, AIX |
| 60 | Some macOS versions |

### Output Fields

| Field | Description |
|-------|-------------|
| Host | Target IP address |
| TTL | Observed Time-To-Live value |
| TCP Window | TCP window size hint |
| Guess | Most likely OS (e.g., "Linux/Unix", "Windows") |
| Confidence | Confidence indicator (e.g., high/medium) |
| Method | Technique used (ttl_only / ttl_window / scapy) |

---

## 8. NVD/CVE Lookup

Query the National Vulnerability Database (NVD) for known vulnerabilities in a specific software product and version.

### Basic Lookup

```bash
python -m netrecon --cve-lookup "apache httpd" --cve-version "2.4.49"
```

### How It Works

1. Sends a request to the NVD API with the product name and version
2. Parses CVE entries matching the product
3. Returns: CVE ID, description, CVSS score, severity, publish date
4. Results are cached in `cve_cache.db` (SQLite) for 24 hours

### Output Fields

| Field | Description |
|-------|-------------|
| Product | Software product queried |
| Version | Version queried |
| CVE Count | Total matching CVEs found |
| Top CVEs | Highest-severity CVEs with descriptions |
| Cache Status | Fresh / Cached (with timestamp) |

### Notes

- Requires internet access (calls NVD API at `https://services.nvd.nist.gov`)
- First API call may take a few seconds; subsequent calls use local cache
- Rate limits apply (NVD allows ~5 requests per 30 seconds without API key)

---

## 9. GeoIP Offline Lookup (No API Required)

Perform IP geolocation entirely offline using MaxMind GeoLite2 databases. No external API calls, no latency, no rate limits.

### Database Setup

1. Register at [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free account)
2. Download `GeoLite2-City.mmdb` and optionally `GeoLite2-ASN.mmdb`
3. Extract the `.mmdb` files from the `.tar.gz` archive
4. Place them in a folder (e.g., `data/`)
5. Install the reader library:

```bash
pip install geoip2
```

### Basic Usage

```bash
python -m netrecon --target 8.8.8.8 --geoip-db data/GeoLite2-City.mmdb
```

### How It Works

The module automatically discovers `GeoLite2-ASN.mmdb` if it exists in the same folder as the City database. Both databases are loaded into memory for fast lookups.

### Output Fields

| Field | Source | Description |
|-------|--------|-------------|
| IP | Target | Queried IP address |
| City | City DB | City name |
| Country | City DB | Country name and ISO code |
| Latitude/Longitude | City DB | Geographic coordinates |
| Time Zone | City DB | IANA time zone |
| AS Number | ASN DB | Autonomous System number |
| Organization | ASN DB | Network owner organization |

### Example Output

```
Target IP: 8.8.8.8
Country:    United States (US)
City:       Mountain View
Lat/Lon:    37.4056, -122.0775
Time Zone:  America/Los_Angeles
ASN:        AS15169
Org:        Google LLC
```

---

## 10. SSL/TLS Certificate Grabber

Connect to an SSL/TLS service and retrieve the full certificate details, including issuer, subject, validity, SANs, and negotiated cipher.

### Basic Grab (Default Port 443)

```bash
python -m netrecon --ssl-enum example.com
```

### Custom Port

```bash
python -m netrecon --ssl-enum example.com --ssl-port 8443
```

### How It Works

1. Opens a TCP connection to the target host and port
2. Wraps the socket with SSL/TLS
3. Retrieves the peer certificate (`getpeercert()`)
4. Extracts all fields and performs security checks

### Output Fields

| Field | Description |
|-------|-------------|
| Subject CN | Common Name of the certificate subject |
| Issuer | Certificate issuer organization |
| Valid From | Certificate start date |
| Valid Until | Certificate expiration date |
| Serial | Certificate serial number |
| SAN | Subject Alternative Names (DNS names) |
| Cipher | Negotiated cipher suite |
| Protocol | TLS protocol version (e.g., TLSv1.3) |
| Self-Signed | True/False indicator |
| Expired | True/False indicator (checks current date) |

### Security Checks

- **Self-signed flag**: Alerts if the certificate is self-signed
- **Expiration check**: Warns if the certificate is expired
- **Cipher strength**: Reports the negotiated cipher suite

---

## 11. SSH Server Enumeration

Connect to an SSH server and enumerate its capabilities: banner, software version, and supported key exchange / encryption / MAC / compression algorithms.

### Basic Enumeration (Default Port 22)

```bash
python -m netrecon --ssh-enum example.com
```

### Custom Port

```bash
python -m netrecon --ssh-enum example.com --ssh-port 2222
```

### How It Works

1. Connects to the SSH server on the specified port
2. Reads the server's SSH banner (e.g., `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3`)
3. Initiates a key exchange and captures the server's algorithm lists from the SSH handshake
4. Closes the connection gracefully before authentication

### Output Fields

| Field | Description |
|-------|-------------|
| Banner | SSH protocol banner string |
| Software | Extracted software version (e.g., "OpenSSH_8.9") |
| Host | Target host and port |
| KEX Algorithms | Key exchange methods (e.g., curve25519-sha256, ecdh-sha2-nistp256) |
| Host Key Algorithms | Host key types (e.g., rsa-sha2-512, ssh-ed25519) |
| Encryption Algorithms | Symmetric ciphers (e.g., aes256-ctr, chacha20-poly1305) |
| MAC Algorithms | Message authentication codes (e.g., hmac-sha2-256) |
| Compression Algorithms | Compression methods (e.g., none, zlib) |

### Security Notes

- Older algorithms (e.g., `diffie-hellman-group1-sha1`, `ssh-dss`) indicate a potentially outdated server
- The module does **not** authenticate — it only reads the server's offer lists

---

## 12. DNS Analysis

```bash
python -m netrecon --dns example.com
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

## 13. WHOIS Lookup

### For Domain

```bash
python -m netrecon --whois --whois-target example.com
```

### For IP Address

```bash
python -m netrecon --whois --whois-target 8.8.8.8
```

### Using Scan Target

```bash
python -m netrecon --target 8.8.8.8 --whois
```

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
2. **Fallback method**: Connects directly to WHOIS servers via TCP port 43
   - First queries `whois.iana.org` for referral server
   - Then queries the referral server for detailed records

---

## 14. Traceroute

### Basic Traceroute

```bash
python -m netrecon --traceroute 8.8.8.8
```

### Advanced Traceroute (with ASN and Geolocation per Hop)

```bash
python -m netrecon --traceroute 8.8.8.8 --traceroute-advanced
```

### How It Works

1. **Primary**: Runs system traceroute command
   - Windows: `tracert -d TARGET`
   - Linux/macOS: `traceroute -n TARGET`
2. **Fallback**: TTL-based ping probing (incrementing TTL from 1 to max_hops)
3. **Advanced mode**: Each hop IP is enriched with ASN and geolocation from ipwho.is API

### Output Fields per Hop

| Field | Description |
|-------|-------------|
| Hop | Hop number (1, 2, 3...) |
| IP | Router IP address (`*` if timed out) |
| Latency (ms) | Round-trip time to hop |
| ASN | Autonomous System Number (advanced mode only) |
| Geo | City, Country (advanced mode only) |

---

## 15. Subdomain Scanning

```bash
python -m netrecon --subdomain example.com
```

### How It Works

1. Prepends each word from the wordlist to the target domain
2. Attempts DNS resolution for each constructed hostname
3. Records successfully resolved hosts with their IP and response time

### Default Wordlist

`admin`, `api`, `beta`, `blog`, `cpanel`, `dev`, `docs`, `ftp`, `m`, `mail`, `portal`, `staging`, `vpn`, `webmail`, `www`

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

---

## 16. Threat Intelligence

```bash
python -m netrecon --external --threat-check
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

---

## 17. Speed Test

```bash
python -m netrecon --speedtest
```

### What It Measures

| Metric | Description |
|--------|-------------|
| Download (Mbps) | Download bandwidth in megabits per second |
| Upload (Mbps) | Upload bandwidth in megabits per second |
| Ping (ms) | Latency to the best available speedtest server |
| Server | Name of the test server used |

### Notes

- Uses `speedtest-cli` library with Speedtest.net servers
- Automatically retries with insecure mode if secure connection returns 403
- Not available in passive mode
- Typical execution time: 15-30 seconds

---

## 18. Security Check

```bash
python -m netrecon --external --scan-common-ports --security-check
```

### What It Evaluates

| Check | Description |
|-------|-------------|
| **IP Classification** | Private, Public, or Special/Reserved |
| **VPN Detection** | Provider flags + keyword scanning in metadata |
| **Proxy Detection** | Provider flags + keyword scanning for proxy/TOR indicators |
| **Hosting Detection** | Datacenter/cloud keywords (AWS, Azure, DigitalOcean, etc.) |
| **Risky Port Detection** | Open ports 21, 23, 25, 445, 3389, 5900 |
| **Firewall Detection** | Filtered port ratios + traceroute hop patterns |

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

---

## 19. Risk Scoring Engine

Risk scoring is **automatically calculated** whenever a scan runs. It aggregates findings from all modules into a single 0-100 score.

### Scoring Factors

| Factor | Points | Maximum | Source |
|--------|--------|---------|--------|
| Risky open ports | +8 per port | 30 | Port scan results |
| Significant filtered ports | +5 | 5 | Port scan |
| Proxy indicator | +15 | 15 | External IP provider flags |
| VPN indicator | +10 | 10 | External IP provider flags |
| Suspicious ASN/organization | +10 | 10 | WHOIS hosting/datacenter keywords |
| Blacklist presence | +3 per entry | 25 | Threat intelligence |
| Threat malicious score | +0.3 x score | 30 | Threat intelligence |
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

## 20. LAN Scanner

```bash
python -m netrecon --mode active --lan-scan 192.168.1.0/24
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

## 21. Packet Sniffer with BPF and PCAP

### Basic Sniffing (Requires Admin/Root)

```bash
python -m netrecon --mode active --sniff
```

### Custom Limits

```bash
python -m netrecon --mode active --sniff --sniff-limit 500 --sniff-timeout 30
```

### BPF Filter — Capture Only Specific Traffic

Berkeley Packet Filter expressions let you capture only the traffic you care about:

```bash
# HTTP traffic only
python -m netrecon --mode active --sniff --sniff-filter "tcp port 80"

# HTTPS traffic only
python -m netrecon --mode active --sniff --sniff-filter "tcp port 443"

# DNS traffic only
python -m netrecon --mode active --sniff --sniff-filter "udp port 53"

# Traffic from a specific host
python -m netrecon --mode active --sniff --sniff-filter "host 192.168.1.1"

# Complex expression
python -m netrecon --mode active --sniff --sniff-filter "tcp and not port 22"
```

### PCAP Export — Save for Wireshark

```bash
# Save captured packets to a PCAP file
python -m netrecon --mode active --sniff --sniff-pcap capture.pcap

# Full example: filter + export
python -m netrecon --mode active --sniff --sniff-filter "tcp port 443" --sniff-limit 1000 --sniff-pcap https_traffic.pcap
```

The PCAP file can be opened directly in Wireshark or tcpdump for further analysis.

### Anomaly Detection

| Anomaly | Detection Method | Alert |
|---------|-----------------|-------|
| **ARP Spoofing** | Same IP changes MAC in ARP replies | "Possible ARP spoofing: {IP} changed MAC {old} -> {new}" |
| **DNS Poisoning** | Single domain resolves to >3 distinct IPs | "Potential DNS poisoning: high answer variance for {domain}" |
| **High Traffic** | Single source sends >25% of packets | "High traffic anomaly detected from source {IP}" |

### Configuration

| Parameter | Default | CLI Flag |
|-----------|---------|----------|
| Packet capture limit | 200 | `--sniff-limit INT` |
| Capture timeout | 15 seconds | `--sniff-timeout INT` |
| BPF filter | (none) | `--sniff-filter BPF` |
| PCAP export path | (none) | `--sniff-pcap PATH` |

---

## 22. Continuous Monitoring (Watch Mode)

Repeatedly scan a target at set intervals and detect changes between runs.

### Basic Watch

```bash
python -m netrecon --target 8.8.8.8 --external --scan-common-ports --watch
```

### Custom Interval

```bash
python -m netrecon --target 8.8.8.8 --external --scan-common-ports --watch --watch-interval 120
```

### Delta Detection

The watch mode detects and reports the following changes between scans:

| Change Type | Detection |
|-------------|-----------|
| New open ports | Port that was closed/filtered is now open |
| Closed ports | Port that was open is now closed/filtered |
| New LAN hosts | Host that was inactive now responds |
| Lost LAN hosts | Host that responded previously no longer responds |
| External IP change | Public IP address changed since last scan |

### Output

Each cycle prints a summary and any detected deltas. The cycle counter increments with each iteration.

---

## 23. REST API Server

Start NetRecon as an HTTP API server for integration with other tools and automation pipelines.

### Start Server

```bash
# Default: 127.0.0.1:8088
python -m netrecon --serve

# Custom bind address and port
python -m netrecon --serve --serve-host 0.0.0.0 --serve-port 9090
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/status` | Server status, cycle count, uptime |
| `POST` | `/api/v1/scan` | Trigger a new scan |
| `GET` | `/api/v1/results` | Latest scan results (JSON) |

### Example Usage

```bash
# Check server status
curl http://127.0.0.1:8088/api/v1/status

# Trigger a scan
curl -X POST http://127.0.0.1:8088/api/v1/scan

# Get latest results
curl http://127.0.0.1:8088/api/v1/results
```

### Notes

- The server runs in its own thread alongside the core orchestrator
- Results are cached in memory and returned as JSON
- The server supports graceful shutdown via Ctrl+C

---

## 24. Plugin System

Extend NetRecon with external Python modules that integrate directly into the scan pipeline.

### List Available Plugins

```bash
python -m netrecon --list-plugins
```

### Load Plugins from a Directory

```bash
python -m netrecon --plugin-dir ./my_plugins
```

### How It Works

1. Scans the specified directory for Python files
2. Imports each file and discovers classes extending `NetReconPlugin`
3. Runs the `run(options, result)` method of each plugin
4. Plugin output is merged into the scan results

### Plugin Template

```python
from netrecon.plugin_base import NetReconPlugin

class MyPlugin(NetReconPlugin):
    @property
    def name(self):
        return "my_plugin"

    @property
    def description(self):
        return "My custom plugin description"

    def run(self, options, result):
        # Your plugin logic here
        return {"my_key": "my_value"}
```

---

## 25. Interactive TUI Dashboard

A full-screen terminal UI (TUI) powered by `textual` for interactive scanning without remembering CLI flags.

### Launch TUI

```bash
python -m netrecon --tui
```

### Features

- **Scan Button**: Trigger a full scan with a single click
- **Live Log**: Real-time activity feed showing what the scanner is doing
- **Results Browser**: Browse all scan results in a structured view
- **Status Bar**: Current scan state, cycle count, and module status
- **Keyboard Navigation**: Full keyboard support for navigating panels

### Requirements

```bash
pip install textual
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `q` or `Ctrl+C` | Quit TUI |
| `Tab` | Cycle focus between panels |
| Arrow keys | Navigate within panels |

### Notes

- The TUI runs a full scan (same as default CLI scan mode)
- Results are displayed in real-time as modules complete
- Supports all modules configured in `config.json`

---

## 26. Reporting and Output

### Rich Terminal Output (Default)

The default output renders a full dashboard in your terminal using the `rich` library.

### Disable Color Output

```bash
python -m netrecon --no-color
```

### JSON Output to Terminal

```bash
python -m netrecon --json
```

### Save JSON Report

```bash
# Auto-generated filename (reports/netrecon_report_YYYYMMDD_HHMMSS.json)
python -m netrecon --save-json

# Specific file path
python -m netrecon --save-json reports/my_report.json
```

### HTML Dashboard Report

```bash
# Default path (report.html)
python -m netrecon --html-report

# Custom path
python -m netrecon --html-report reports/dashboard.html
```

**HTML report includes:**
- Summary card with hostname, mode, external IP, risk score
- Risk score doughnut chart (Chart.js)
- Open ports and banners table
- Speed test bar chart
- Threat intelligence summary
- Embedded Google Maps geolocation iframe
- Complete raw JSON data snapshot

### Geo Map HTML Export

```bash
python -m netrecon --external --geo-html reports/geo_map.html
```

### CSV Report

```bash
python -m netrecon --save-csv
```

---

## 27. Configuration Reference

### Config File Location

Default: `config.json` in project root.

### Custom Config File

```bash
python -m netrecon --config /path/to/custom_config.json
```

### Logging Configuration

```bash
python -m netrecon --log-level DEBUG
python -m netrecon --log-file logs/debug.log
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

## 28. Full Scan Examples

### Enterprise Security Audit (All Features)

```bash
python -m netrecon --mode active --target 8.8.8.8 --external --scan-ports 1-1000 --whois --whois-target 8.8.8.8 --dns google.com --traceroute 8.8.8.8 --traceroute-advanced --threat-check --speedtest --security-check --subdomain google.com --os-fingerprint 8.8.8.8 --ssl-enum google.com --ssh-enum example.com --cve-lookup "openssl" --cve-version "1.1.1" --geoip-db data/GeoLite2-City.mmdb --html-report full_report.html
```

### Aggressive Full Scan (All Ports + LAN + Sniffer + PCAP)

```bash
python -m netrecon --mode active --target 192.168.1.1 --external --scan-ports 1-65535 --whois --whois-target 192.168.1.1 --dns example.com --traceroute 192.168.1.1 --traceroute-advanced --threat-check --speedtest --security-check --lan-scan 192.168.1.0/24 --sniff --sniff-filter "tcp and not port 22" --sniff-limit 300 --sniff-timeout 20 --sniff-pcap traffic.pcap --subdomain example.com --ssl-enum example.com --os-fingerprint 192.168.1.1 --html-report aggressive_report.html
```

### Passive Intelligence Gathering

```bash
python -m netrecon --mode passive --external --dns google.com --whois --whois-target google.com --threat-check --security-check --subdomain google.com --geoip-db data/GeoLite2-City.mmdb --cve-lookup "openssl" --cve-version "3.0.0" --html-report passive_report.html
```

### Watch Mode Continuous Monitoring

```bash
python -m netrecon --target 192.168.1.1 --external --scan-common-ports --security-check --watch --watch-interval 300
```

### SSL/TLS + SSH Server Audit

```bash
python -m netrecon --ssl-enum example.com --ssl-port 443 --ssh-enum example.com --ssh-port 22 --cve-lookup "openssh" --cve-version "9.0"
```

### Traffic Capture with Wireshark Export

```bash
python -m netrecon --mode active --sniff --sniff-filter "tcp port 80 or tcp port 443" --sniff-limit 2000 --sniff-timeout 60 --sniff-pcap web_traffic.pcap
```

### REST API Server for Automation

```bash
python -m netrecon --serve --serve-host 0.0.0.0 --serve-port 8088
```

### Quick Port Scan with JSON Output

```bash
python -m netrecon --target 192.168.1.1 --scan-common-ports --json
```

### Local Network Discovery

```bash
python -m netrecon --mode active --lan-scan 192.168.1.0/24 --os-fingerprint 192.168.1.1 --html-report lan_report.html
```

### DNS-Only Analysis

```bash
python -m netrecon --dns example.com --json
```

---

## 29. Important Notes and Best Practices

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
- Watch mode runs indefinitely — use Ctrl+C to stop

### Rate Limits

- Threat intelligence APIs have rate limits; the tool adds a 0.25-second delay between calls
- External IP providers may rate-limit frequent requests
- Aggressive port scanning may trigger IDS/IPS alerts
- NVD CVE API allows approximately 5 requests per 30 seconds without API key

### Dependency Handling

- All modules gracefully degrade when optional packages are missing
- Without `scapy`: sniffer returns "scapy is not installed"
- Without `geoip2`: GeoIP module returns "geoip2 is not installed"
- Without `textual`: TUI returns "textual is not installed"
- Without `dnspython`: DNS analyzer returns "dnspython is required"

### Logging

- All scan activity is logged to `logs/netrecon.log` by default
- Use `--log-level DEBUG` for troubleshooting
- Log format: `2025-03-03 10:30:00 [INFO] netrecon.orchestrator: Starting NetRecon scan...`

---

## 30. Recommended Workflow

### For External Target Assessment

1. **Passive Recon First**:
   ```bash
   python -m netrecon --mode passive --dns target.com --whois --whois-target target.com --threat-check
   ```

2. **DNS Analysis**:
   ```bash
   python -m netrecon --dns target.com
   ```

3. **GeoIP and SSL/SSH Enumeration**:
   ```bash
   python -m netrecon --target target.com --geoip-db data/GeoLite2-City.mmdb --ssl-enum target.com --ssh-enum target.com
   ```

4. **CVE Lookup for Known Services**:
   ```bash
   python -m netrecon --cve-lookup "openssh" --cve-version "9.0"
   ```

5. **Subdomain Discovery**:
   ```bash
   python -m netrecon --subdomain target.com
   ```

6. **Active Scan** (if authorized):
   ```bash
   python -m netrecon --mode active --target target.com --scan-ports 1-1000 --os-fingerprint target.com --security-check
   ```

7. **Traceroute**:
   ```bash
   python -m netrecon --traceroute target.com --traceroute-advanced
   ```

8. **Generate Report**:
   ```bash
   python -m netrecon --mode active --target target.com --external --scan-ports 1-1000 --dns target.com --whois --whois-target target.com --traceroute target.com --threat-check --security-check --ssl-enum target.com --os-fingerprint target.com --geoip-db data/GeoLite2-City.mmdb --html-report report.html --save-json
   ```

### For Internal Network Assessment

1. **Network Discovery**:
   ```bash
   python -m netrecon --mode active --lan-scan 192.168.1.0/24
   ```

2. **Port Scan Key Hosts**:
   ```bash
   python -m netrecon --target 192.168.1.1 --scan-common-ports --os-fingerprint 192.168.1.1 --security-check
   ```

3. **Traffic Analysis**:
   ```bash
   python -m netrecon --mode active --sniff --sniff-filter "tcp port 80 or tcp port 443" --sniff-limit 500 --sniff-timeout 60 --sniff-pcap traffic.pcap
   ```

4. **Continuous Monitor**:
   ```bash
   python -m netrecon --target 192.168.1.1 --external --scan-common-ports --watch --watch-interval 120
   ```

5. **Full Report**:
   ```bash
   python -m netrecon --mode active --target 192.168.1.1 --scan-common-ports --lan-scan 192.168.1.0/24 --security-check --os-fingerprint 192.168.1.1 --html-report internal_report.html
   ```

### For API Integration

1. **Start Server**:
   ```bash
   python -m netrecon --serve --serve-host 0.0.0.0 --serve-port 8088
   ```

2. **Trigger Scan via API**:
   ```bash
   curl -X POST http://localhost:8088/api/v1/scan
   ```

3. **Retrieve Results**:
   ```bash
   curl http://localhost:8088/api/v1/results | python -m json.tool
   ```

### For Interactive Exploration

```bash
python -m netrecon --tui
```

---

## 31. Complete CLI Flag Reference

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
| `--stealth` | flag | Add jitter between port scan probes |
| `--traceroute TARGET` | string | Run traceroute to target |
| `--traceroute-advanced` | flag | Enable per-hop ASN/geo enrichment |
| `--subdomain DOMAIN` | string | Run subdomain scanner |
| `--os-fingerprint HOST` | string | Guess OS via TTL/window/Scapy |
| `--ssl-enum HOST` | string | Grab SSL/TLS certificate |
| `--ssl-port PORT` | int | SSL/TLS port (default: 443) |
| `--ssh-enum HOST` | string | Enumerate SSH server algorithms |
| `--ssh-port PORT` | int | SSH port (default: 22) |
| `--dns HOST` | string | Run DNS analyzer |
| `--dns-axfr DOMAIN` | string | Attempt DNS zone transfer |
| `--whois` | flag | Enable WHOIS lookup |
| `--whois-target HOST` | string | WHOIS target override |
| `--geoip-db PATH` | string | Path to GeoLite2-City.mmdb for offline GeoIP |
| `--cve-lookup PRODUCT` | string | Look up CVEs for a software product |
| `--cve-version VERSION` | string | Product version for CVE lookup |
| `--speedtest` | flag | Run internet speed test |
| `--threat-check` | flag | Run threat intelligence lookup |
| `--security-check` | flag | Enable security classification and firewall checks |
| `--no-security-check` | flag | Disable security checks |
| `--lan-scan CIDR` | string | Run LAN active host scan |
| `--sniff` | flag | Run packet sniffer |
| `--sniff-limit INT` | integer | Packet capture limit |
| `--sniff-timeout INT` | integer | Sniffer timeout in seconds |
| `--sniff-filter BPF` | string | Berkeley Packet Filter expression |
| `--sniff-pcap PATH` | string | Save captured packets to PCAP file |
| `--watch` | flag | Enable continuous monitoring mode |
| `--watch-interval SECONDS` | integer | Watch mode interval (default: 60) |
| `--serve` | flag | Start REST API server |
| `--serve-host HOST` | string | API server bind address (default: 127.0.0.1) |
| `--serve-port PORT` | int | API server port (default: 8088) |
| `--tui` | flag | Launch interactive TUI dashboard |
| `--plugin-dir DIR` | string | Load plugins from directory |
| `--list-plugins` | flag | List available plugins |
| `--geo-html PATH` | string | Export geo map to HTML file |
| `--html-report [PATH]` | optional string | Generate HTML dashboard report |
| `--json` | flag | Print JSON output to stdout |
| `--save-json [PATH]` | optional string | Save JSON report to file |
| `--save-csv` | flag | Save CSV report |
| `--no-color` | flag | Disable Rich colored output |
| `--config PATH` | string | Path to config.json file |
| `--init-config` | flag | Generate default config.json |
| `--log-level {DEBUG,INFO,WARNING,ERROR}` | string | Logging verbosity |
| `--log-file PATH` | string | Log file path override |
