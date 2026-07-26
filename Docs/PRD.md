# Product Requirements Document (PRD)

## Product Name

**NetRecon CLI** — Professional Network Reconnaissance and Security Analysis Toolkit

---

## 1. Objective

Build a production-ready, cross-platform, async-first network reconnaissance and security analysis command-line toolkit in Python. The tool must provide modular, independently testable scanning engines that work together through a central orchestrator to produce comprehensive network intelligence, security posture assessments, and exportable reports.

---

## 2. Target Users

| User Role | Primary Use Case |
|-----------|------------------|
| Cybersecurity Students | Learning network reconnaissance techniques in a real-world CLI tool |
| Ethical Hackers / Pen Testers | Quick reconnaissance and enumeration during security assessments |
| Network Administrators | Identifying open ports, active hosts, DNS misconfigurations on their networks |
| DevSecOps Engineers | Automated security checks integrated into CI/CD or infrastructure audits |
| SOC Analysts | IP reputation checks, threat intelligence lookups, and risk scoring |
| Portfolio Builders | Demonstrating Python, async programming, and security engineering skills |

---

## 3. Feature Requirements

### 3.1 IP Intelligence Module (`ip_scanner.py`)

**Implementation Details:**
- Collects all local IPv4/IPv6 addresses via `socket.getaddrinfo()` with `gethostbyname_ex()` fallback
- Queries **3 external IP providers** concurrently using `aiohttp`:
  - `ipinfo.io/json` — parses IP, city, region, country, coordinates from `loc` field, organization
  - `ipapi.co/json/` — parses IP, city, region, latitude/longitude, organization, timezone
  - `ipwho.is/` — parses IP, city, region, latitude/longitude, ISP, proxy/VPN detection from `security` object
- **First-success cancellation**: Once a valid provider response is received, remaining tasks are cancelled
- Synchronous fallback via `requests` when `aiohttp` is not available
- Reverse DNS via `socket.gethostbyaddr()`
- Geo map URL construction: `https://www.google.com/maps?q={lat},{lon}`
- HTML geo map export with embedded iframe
- Network interface collection via platform-specific commands (`ipconfig /all`, `ip addr show`, `ifconfig`)
- Hop enrichment function (`enrich_ip_async`) for traceroute ASN/geo lookup via `ipwho.is`

**CLI Flags:**
- `--external` / `--no-external` — Enable/disable external IP lookup
- `--interfaces` / `--no-interfaces` — Include/exclude interface details
- `--geo-html PATH` — Export geo map to HTML file

**Data Model: `ExternalIPInfo`**
- Fields: `ip`, `city`, `region`, `country`, `latitude`, `longitude`, `organization`, `isp`, `postal`, `timezone`, `source`, `proxy_detected`, `vpn_detected`, `raw`

---

### 3.2 Port Scanning and Banner Grabbing (`port_scanner.py`, `banner.py`)

**Port Scanner Implementation:**
- Uses `asyncio.open_connection()` for non-blocking TCP connection attempts
- Port state classification:
  - **Open**: Connection established successfully
  - **Closed**: `ConnectionRefusedError` received
  - **Filtered**: `asyncio.TimeoutError` or `OSError` (no response)
- Concurrency controlled via `asyncio.Semaphore` (default: 300 concurrent connections)
- Per-port timeout configurable (default: 0.5 seconds)
- Port range parser validates `START-END` format within 1-65535
- Predefined common ports: `20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080`
- Predefined risky ports: `21, 23, 25, 445, 3389, 5900`

**Banner Grabber Implementation:**
- Protocol-aware banner detection for HTTP and non-HTTP ports
- HTTP ports (`80, 81, 443, 8000, 8080, 8443`): Sends `HEAD / HTTP/1.1` request, extracts `Server` header
- SMTP/POP3/IMAP ports (`25, 110, 143, 587`): Sends `EHLO netrecon.local` to prompt banner
- FTP port (`21`): Sends `USER anonymous` to get server response
- Other ports: Reads up to 512 bytes for banner identification
- Service inference from banner content (SSH, MySQL, SMTP, HTTP, PostgreSQL patterns)
- Fallback to port-based service guessing for 14 known services

**CLI Flags:**
- `--scan-common-ports` — Scan predefined common TCP ports
- `--scan-ports [RANGE]` — Scan custom range (e.g., `1-1000`) or config default

**Data Models:**
- `PortScanResult`: target, scanned_ports, open_ports, closed_ports, filtered_ports, duration_seconds, risky_open_ports, banners
- `BannerResult`: port, service, banner, status

---

### 3.3 Traceroute Module (`traceroute.py`)

**Implementation:**
- **Primary method**: System traceroute command
  - Windows: `tracert -d TARGET`
  - Linux/macOS: `traceroute -n TARGET`
- **Fallback method**: TTL-based ping probing (increments TTL from 1 to `max_hops`)
  - Windows: `ping -n 1 -w TIMEOUT -i TTL TARGET`
  - Linux/macOS: `ping -c 1 -W TIMEOUT -t TTL TARGET`
- Output parsing extracts hop number, IP address, and latency (ms)
- **Advanced enrichment** (`--traceroute-advanced`): Each hop IP is enriched with ASN and geolocation data via `IPScanner.enrich_ip_async()` using the `ipwho.is` API
- Maximum hops configurable (default: 30)
- Per-hop timeout configurable (default: 2000ms)

**CLI Flags:**
- `--traceroute TARGET` — Run traceroute to target
- `--traceroute-advanced` — Enable ASN/geo enrichment per hop

**Data Models:**
- `TracerouteHop`: hop, ip, latency_ms, asn, geo
- `TracerouteResult`: target, method, hops, warnings

---

### 3.4 Subdomain Scanner (`subdomain_scanner.py`)

**Implementation:**
- Async DNS resolution using `asyncio.get_running_loop().getaddrinfo()`
- Prepends each word from wordlist to the target domain (e.g., `www.example.com`)
- Concurrency controlled via `asyncio.Semaphore` (default: 200 workers)
- Measures response time per resolution in milliseconds
- Default wordlist: `admin, api, beta, blog, cpanel, dev, docs, ftp, m, mail, portal, staging, vpn, webmail, www`
- Records only hosts that successfully resolve to valid IP addresses

**CLI Flags:**
- `--subdomain DOMAIN` — Run subdomain scanner

**Data Models:**
- `SubdomainRecord`: host, ip, response_ms
- `SubdomainScanResult`: domain, scanned_count, active_hosts, duration_seconds, warnings

---

### 3.5 DNS Analyzer (`dns_analyzer.py`)

**Implementation:**
- Uses `dnspython` library (`dns.resolver.Resolver`) with configurable timeout
- Resolves 6 record types: `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`
- MX records: Extracts hostname from priority-host format
- **Security checks**:
  - **SPF**: Searches TXT records for `v=spf1` string
  - **DMARC**: Resolves `_dmarc.{hostname}` TXT record, looks for `v=dmarc1`
  - **DNSSEC**: Resolves `DNSKEY` record type to verify DNSSEC is configured
- Reverse DNS lookup via `socket.gethostbyaddr()`
- Graceful handling of NXDOMAIN, timeout, and no-nameserver errors

**CLI Flags:**
- `--dns HOST` — Run DNS analysis

**Data Model: `DNSAnalysisResult`**
- Fields: hostname, a_records, aaaa_records, mx_records, txt_records, ns_records, cname_records, spf_present, dmarc_present, dnssec_enabled, warnings

---

### 3.6 WHOIS Lookup (`whois_lookup.py`)

**Implementation:**
- **Primary method**: `python-whois` library (`whois.whois()`)
  - Extracts ASN, organization, ISP, abuse contact from structured response
  - ASN extracted from field keys (`asn`, `originas`, `origin`) or regex `\bAS\d+\b` in raw text
  - Abuse contact prioritized by keyword `abuse` in email candidates
- **Fallback method**: Raw TCP WHOIS
  - Queries `whois.iana.org` on port 43 first
  - Follows referral server from `refer:` or `whois:` header
  - Parses fields: `orgname`, `organization`, `owner`, `descr`, `netname`
  - Extracts abuse email from lines containing "abuse" keyword
- Raw text truncated to 12,000 characters for storage

**CLI Flags:**
- `--whois` — Enable WHOIS lookup
- `--whois-target HOST` — Specify WHOIS target override

**Data Model: `WhoisResult`**
- Fields: query, asn, isp, organization, abuse_contact, source, raw_text

---

### 3.7 Threat Intelligence (`threat_intel.py`)

**Implementation:**
- Concurrent async API checks using `aiohttp` via `fetch_json()` helper
- Rate-limit sleep (0.25s default) between API calls
- **AbuseIPDB**: `GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90` with `Key` header
  - Extracts: `abuseConfidenceScore`, `totalReports`
- **VirusTotal**: `GET /api/v3/ip_addresses/{ip}` with `x-apikey` header
  - Extracts: `last_analysis_stats.malicious`, `last_analysis_stats.suspicious`
- **Shodan**: `GET /shodan/host/{ip}?key={key}`
  - Extracts: `vulns` dictionary (known CVEs)
- **Aggregation logic**:
  - `malicious_score`: Max of AbuseIPDB confidence score and VT detections * 10 (capped at 100)
  - `blacklist_count`: Sum of VT malicious+suspicious + Shodan vulnerability count
  - `spam_reports`: From AbuseIPDB total reports
  - `known_vulnerabilities`: Sorted list of Shodan CVE identifiers
  - Minimum score of `blacklist_count * 5` if blacklist count > 0

**CLI Flags:**
- `--threat-check` — Enable threat intelligence lookup

**Data Model: `ThreatIntelResult`**
- Fields: ip, malicious_score, blacklist_count, spam_reports, known_vulnerabilities, source_details, warnings

---

### 3.8 Security Checks (`security_checks.py`)

**Implementation:**
- **IP Classification**: Uses `ipaddress.ip_address()` to determine Private/Public/Special/Reserved
- **VPN/Proxy Detection**:
  - Checks `vpn_detected` and `proxy_detected` flags from external IP provider (ipwho.is)
  - Keyword scanning in reverse DNS, organization, and ISP fields
  - VPN keywords: `vpn`, `wireguard`, `openvpn`, `nord`, `expressvpn`, `mullvad`, `tunnel`
  - Proxy keywords: `proxy`, `socks`, `tor`, `relay`, `anonymizer`
  - Hosting keywords: `datacenter`, `hosting`, `vps`, `colo`, `cloud`, `digitalocean`, `linode`, `ovh`, `aws`, `azure`, `gcp`
- **Firewall Detection** (heuristic):
  - High filtered-port ratio (≥50% of scanned ports filtered) → likely firewall
  - Zero open ports with filtered responses present → likely firewall
  - Traceroute hops with ≥40% unknown IPs → ICMP blocked, likely firewall
- **Risk Level Calculation**:
  - Score based on: public classification (+1), VPN (+2), proxy (+2), risky ports (up to +3), firewall (+1)
  - Private classification reduces score by 1
  - Levels: Low (≤1), Medium (≤3), High (≤5), Critical (>5)

**CLI Flags:**
- `--security-check` / `--no-security-check` — Enable/disable security checks

**Data Models:**
- `SecurityCheckResult`: input_ip, classification, is_private, is_public, suspected_vpn, suspected_proxy, risky_open_ports, risk_level, findings, firewall
- `FirewallDetectionResult`: likely_firewall, icmp_blocked, filtered_ratio, reason

---

### 3.9 Risk Scoring Engine (`risk_engine.py`)

**Implementation:**
- Weighted scoring from 0 to 100 with multiple factor contributions:
  - **Risky open ports**: +8 per risky port (max +30)
  - **Significant filtered ports**: +5 if filtered count > 0 and ≥20 ports scanned
  - **Proxy indicator**: +15
  - **VPN indicator**: +10
  - **Suspicious ASN/organization**: +10 (keywords: hosting, datacenter, vps, anonymous, proxy, vpn)
  - **Blacklist presence**: +3 per blacklist entry (max +25)
  - **Threat malicious score**: +0.3 * score (max +30)
  - **Spam reports**: +1 per 10 reports (max +10)
  - **Known vulnerabilities**: +3 per CVE (max +15)
  - **SPF missing**: +8
  - **DMARC missing**: +8
  - **DNSSEC not detected**: +5
  - **Firewall anomalies**: +4
- Final score clamped to 0-100 range
- Severity levels: Low (<25), Medium (<50), High (<75), Critical (≥75)
- Factors list provides human-readable breakdown of score contributions

**Data Model: `RiskAssessment`**
- Fields: score, level, factors

---

### 3.10 Scan Modes

**Active Mode (`--mode active`):**
- All modules are available
- Port scanning, banner grabbing, traceroute, LAN scan, speed test, and packet sniffing are enabled
- Default mode

**Passive Mode (`--mode passive`):**
- Non-aggressive intelligence gathering only
- Automatically skipped with warnings:
  - Port scanning
  - Traceroute
  - Speed test
  - LAN scan
  - Packet sniffing
- Allowed modules:
  - DNS analysis
  - WHOIS lookup
  - Threat intelligence
  - Subdomain scanning
  - External IP lookup
  - Security checks

---

### 3.11 LAN Scanner (`lan_scanner.py`)

**Implementation:**
- Accepts CIDR notation (e.g., `192.168.1.0/24`)
- Expands CIDR to individual host addresses using `ipaddress.ip_network()`
- Safety limit: Maximum 1024 hosts per scan
- Active host discovery via async ICMP ping:
  - Windows: `ping -n 1 -w TIMEOUT IP`
  - Linux/macOS: `ping -c 1 -W TIMEOUT IP`
- Concurrency via `asyncio.Semaphore` (default: 256 workers)
- MAC address resolution by parsing ARP table (`arp -a` on Windows, `arp -an` on Linux)
- Hostname resolution via `socket.gethostbyaddr()`

**CLI Flags:**
- `--lan-scan CIDR` — Run LAN active host scan

**Data Models:**
- `LanHost`: ip, hostname, mac_address, vendor
- `LanScanResult`: cidr, active_hosts, duration_seconds, warnings

---

### 3.12 Packet Sniffer (`sniffer.py`)

**Implementation:**
- Uses `scapy.all.sniff()` for packet capture
- Configurable capture limit and timeout
- **Anomaly Detection**:
  - **ARP Spoofing**: Tracks ARP reply source IPs to MAC address mappings. If a source IP changes its MAC, an alert is raised
  - **DNS Poisoning**: Tracks DNS answer sets per query name. If a single domain has more than 3 distinct answers, an alert is raised
  - **High Traffic**: Flags source IPs sending more than 25% of total captured packets or 30+ packets
- Requires elevated privileges (root/admin) for raw socket access

**CLI Flags:**
- `--sniff` — Enable packet sniffer
- `--sniff-limit INT` — Packet capture count (default: 200)
- `--sniff-timeout INT` — Capture timeout in seconds (default: 15)

**Data Model: `SnifferResult`**
- Fields: packets_captured, suspicious_events, warnings

---

### 3.13 Reporting

**Rich Terminal Output (`renderer.py`):**
- Full dashboard with 16 sections rendered using `rich` library:
  - Header panel with ASCII box art and scan mode
  - Summary table (hostname, timestamp, mode, local IP count, external IP, warning/error counts)
  - Local IP address table
  - External IP intelligence table (12 fields)
  - DNS analysis table (9 record types + 3 security checks)
  - Subdomain scan table
  - Port scan summary + banner grabbing table
  - Traceroute hop table (IP, latency, ASN, geo)
  - WHOIS details table
  - Speed test metrics table
  - Threat intelligence metrics table
  - Security check details + findings panel
  - Risk score + risk factors panel
  - LAN scan results table
  - Packet sniffer metrics + alerts panel
  - Network interface details panel
  - Warnings and errors panels

**JSON Output (`renderer.py`):**
- Complete `ReconResult` serialized via `dataclasses.asdict()` to JSON
- Pretty-print with 2-space indentation
- Save to file with auto-directory creation
- Auto-generated filename: `reports/netrecon_report_<YYYYMMDD_HHMMSS>.json`

**HTML Dashboard Report (`html_report.py`):**
- Self-contained HTML with inline CSS and Chart.js from CDN
- Responsive grid layout with card-based design
- Components:
  - Summary card with hostname, mode, external IP, risk score/level
  - Doughnut chart for risk score visualization
  - Open ports and banners table
  - Speed test bar chart (download/upload/ping)
  - Threat intelligence summary card
  - Embedded Google Maps geo iframe
  - Raw JSON snapshot in pre-formatted block
- Risk level color coding: Low (green), Medium (yellow), High (orange), Critical (red)

**CLI Flags:**
- `--json` — Print JSON output to stdout
- `--save-json [PATH]` — Save JSON report to file
- `--html-report [PATH]` — Generate HTML dashboard report
- `--no-color` — Disable Rich colorized output

---

## 4. Non-Functional Requirements

| Requirement | Implementation |
|-------------|----------------|
| **Cross-Platform** | Windows/Linux/macOS with platform-specific command detection and fallbacks |
| **Async Performance** | `asyncio` + `aiohttp` for I/O-bound operations (port scanning, API calls, DNS resolution) |
| **Concurrency Control** | `asyncio.Semaphore` limits for port scanning (300), subdomain scanning (200), LAN scanning (256) |
| **Error Handling** | Every module returns warnings/errors instead of crashing; top-level exception handler in CLI |
| **Timeout Management** | Per-operation timeouts: connect (0.5s), HTTP requests (8.0s), traceroute per-hop (2000ms), LAN ping (800ms), sniffer (15s) |
| **Config-Driven** | `config.json` with `AppConfig` dataclass and `ConfigLoader` with safe defaults for every field |
| **Rate Limiting** | 0.25s sleep between threat intelligence API calls |
| **Graceful Degradation** | Modules check for optional dependencies (`scapy`, `dnspython`, `speedtest-cli`, `python-whois`) and skip with warnings |
| **Testability** | One-to-one test file per module; orchestrator accepts dependency-injected service instances |
| **Logging** | Structured logging with configurable level (DEBUG/INFO/WARNING/ERROR) to console + file |
| **Windows Compatibility** | Custom asyncio exception filter suppresses benign `ConnectionResetError` in Windows Proactor event loop |

---

## 5. Data Architecture

### Central Result Object: `ReconResult`

All module outputs aggregate into a single `ReconResult` dataclass containing:

| Field | Type | Source Module |
|-------|------|---------------|
| `timestamp` | str (ISO 8601) | Orchestrator |
| `hostname` | str | System |
| `mode` | str | CLI/Config |
| `local_ips` | list[str] | IPScanner |
| `external_info` | ExternalIPInfo | IPScanner |
| `reverse_dns` | str | IPScanner |
| `geo_map_url` | str | IPScanner |
| `interface_details` | str | IPScanner |
| `port_scan` | PortScanResult | PortScanner |
| `whois` | WhoisResult | WhoisLookup |
| `speed_test` | SpeedTestResult | SpeedTester |
| `dns` | DNSAnalysisResult | DNSAnalyzer |
| `traceroute` | TracerouteResult | TracerouteScanner |
| `subdomains` | SubdomainScanResult | SubdomainScanner |
| `threat_intel` | ThreatIntelResult | ThreatIntelChecker |
| `security` | SecurityCheckResult | SecurityChecker |
| `risk_assessment` | RiskAssessment | RiskScoringEngine |
| `lan_scan` | LanScanResult | LANScanner |
| `sniffer` | SnifferResult | PacketSniffer |
| `warnings` | list[str] | All modules |
| `errors` | list[str] | All modules |

---

## 6. Success Metrics

| Metric | Criteria |
|--------|----------|
| **Port Scan Performance** | 1000+ ports scanned concurrently with 300-worker semaphore in under 10 seconds for responsive targets |
| **External IP Resolution** | First valid provider response returned within single HTTP roundtrip; remaining tasks cancelled |
| **Passive Mode Isolation** | Port scan, traceroute, speed test, LAN scan, sniffer all produce warning-only output in passive mode |
| **Threat Scoring Accuracy** | Deterministic scoring with documented factor weights; reproducible results for same inputs |
| **Report Generation** | HTML dashboard exports successfully with Chart.js charts, geo map embed, and complete data |
| **JSON Completeness** | JSON output includes all module results serialized via `dataclasses.asdict()` |
| **Test Coverage** | 21 test files covering all modules; tests pass on Windows/Linux/macOS logic paths |
| **Graceful Degradation** | Missing optional packages produce informative warnings, not crashes |
| **Config Flexibility** | All scan parameters overridable via CLI flags, config.json, or programmatic API |
