# System Design Document

## 1. Overview

NetRecon CLI is a modular, async-first network reconnaissance and security analysis toolkit built in Python 3.10+. The system employs a layered architecture with a central orchestrator pattern, where 13 independent scanning modules are coordinated through a single `NetReconOrchestrator` class. All module outputs aggregate into a unified `ReconResult` dataclass, which feeds into three output renderers (Rich terminal, JSON, HTML dashboard).

---

## 2. System Component Diagram

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        ENTRY POINTS                                 │
│  main.py ──► netrecon.cli.main()                                   │
│  python -m netrecon ──► netrecon.__main__ ──► netrecon.cli.main()  │
│  ip_finder.py ──► IPScanner (legacy wrapper)                       │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    CONFIGURATION & SETUP                            │
│                                                                     │
│  ┌──────────────────┐    ┌──────────────────┐   ┌───────────────┐  │
│  │ build_parser()   │    │ ConfigLoader     │   │ setup_logging  │  │
│  │ 30+ CLI flags    │    │ config.json →    │   │ console +     │  │
│  │ argparse.        │    │ AppConfig        │   │ file handlers │  │
│  │ ArgumentParser   │    │ (25+ fields)     │   │               │  │
│  └──────────────────┘    └──────────────────┘   └───────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ resolve_scan_options(args, config) → ScanOptions             │   │
│  │ - CLI flags override config defaults                         │   │
│  │ - Validates port ranges (START-END within 1-65535)           │   │
│  │ - Validates CIDR notation for LAN scan                       │   │
│  │ - Validates positive integers for sniff limit/timeout        │   │
│  │ - Determines mode (active/passive)                           │   │
│  └──────────────────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│              ORCHESTRATOR (orchestrator.py)                          │
│              NetReconOrchestrator                                    │
│                                                                     │
│  Constructor: Accepts 13 optional service instances                 │
│  (dependency injection for testing)                                 │
│                                                                     │
│  run() → run_async() → ReconResult                                 │
│                                                                     │
│  Execution order:                                                   │
│  1. collect_local_ips()          [always]                           │
│  2. lookup_external_ip_async()   [if external_lookup]              │
│  3. reverse_dns + geo_map_url    [if external IP found]            │
│  4. collect_network_interfaces() [if include_interfaces]           │
│  5. scan_ports_async()           [if ports requested, active only] │
│  6. trace_async()                [if traceroute_target, active]    │
│  7. scan_async() subdomains      [if subdomain_target]            │
│  8. whois_lookup.lookup()        [if run_whois]                    │
│  9. dns_analyzer.analyze()       [if dns_host]                     │
│  10. speed_tester.run()          [if run_speedtest, active only]   │
│  11. lan_scanner.scan_async()    [if lan_scan_cidr, active only]   │
│  12. sniffer.capture()           [if sniff, active only]           │
│  13. threat_checker.check_ip()   [if run_threat_check]             │
│  14. security_checker.evaluate() [if security_check]               │
│  15. risk_engine.score()         [always]                          │
│  16. export_geo_map_html()       [if geo_html_path]                │
│  17. html_report.generate()      [if html_report_path]             │
│                                                                     │
│  Target Resolution Priority:                                        │
│  CLI --target → external_info.ip → local_ips[0] → None            │
└────────────────────────────┬────────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────────┐
│ Rich Terminal │   │  JSON Output  │   │  HTML Dashboard  │
│ renderer.py   │   │  renderer.py  │   │  html_report.py  │
│ 16 sections   │   │  to_json()    │   │  Chart.js charts │
│ Tables+Panels │   │  save_json()  │   │  Geo map iframe  │
└──────────────┘   └──────────────┘   └──────────────────┘
```

---

## 3. Detailed Module Design

### 3.1 IP Scanner (`ip_scanner.py`) — Class: `IPScanner`

**Purpose:** Collect local and external IP intelligence with geo-location data.

**Constructor Parameters:**
- `request_timeout_seconds: float = 8.0` — HTTP request timeout
- `external_workers: int = 3` — Maximum concurrent provider lookups

**External IP Provider Pipeline:**

```text
┌──────────────────────────────────────────────────────────┐
│           lookup_external_ip_async()                      │
│                                                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │
│  │  ipinfo.io   │  │  ipapi.co   │  │  ipwho.is   │      │
│  │  /json       │  │  /json/     │  │  /           │      │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘      │
│         │                │                │               │
│         └────────┬───────┘────────────────┘               │
│                  │                                         │
│         asyncio.as_completed()                            │
│                  │                                         │
│         First valid ExternalIPInfo wins                    │
│                  │                                         │
│         Cancel remaining tasks                            │
└──────────────────────────────────────────────────────────┘
```

**Provider-Specific Parsing:**

| Provider | IP Field | Coordinates | Organization | VPN/Proxy |
|----------|----------|-------------|--------------|-----------|
| ipinfo.io | `data.ip` | `data.loc` (split on `,`) | `data.org` | Not available |
| ipapi.co | `data.ip` | `data.latitude`, `data.longitude` | `data.org` | Not available |
| ipwho.is | `data.ip` | `data.latitude`, `data.longitude` | `data.connection.org` | `data.security.proxy`, `data.security.vpn` |

**Fallback Strategy:**
1. Async via `aiohttp` (primary)
2. Sync via `requests` (when `aiohttp` not installed)

**Platform-Specific Interface Commands:**

| Platform | Command |
|----------|---------|
| Windows | `ipconfig /all` |
| Linux | `ip addr show` → fallback `ifconfig -a` |
| macOS | `ifconfig` |

---

### 3.2 Port Scanner (`port_scanner.py`) — Class: `PortScanner`

**Purpose:** Async TCP port scanning with state classification and banner grabbing.

**Constructor Parameters:**
- `common_ports: list[int]` — Predefined ports (default: 14 ports)
- `risky_ports: list[int]` — Security-flagged ports (default: `[21, 23, 25, 445, 3389, 5900]`)
- `timeout: float = 0.5` — Per-port connection timeout
- `max_workers: int = 300` — Maximum concurrent connections

**Scan Algorithm:**

```text
For each port in sorted(ports):
  1. Create asyncio.Task with Semaphore(max_workers)
  2. asyncio.open_connection(target, port, timeout=timeout)
     ├── Success → "open"
     ├── ConnectionRefusedError → "closed"
     └── TimeoutError / OSError → "filtered"
  3. Collect results via asyncio.as_completed()

If grab_banners=True and open_ports exist:
  4. BannerGrabber.grab_banner_async() for each open port
  5. Sort banners by port number
```

**Port Range Parser (`parse_port_range`):**
- Input format: `"START-END"` (e.g., `"1-1000"`)
- Validation: Both values must be integers, START ≥ 1, END ≤ 65535, START ≤ END
- Output: `list[int]` of concrete port numbers

---

### 3.3 Banner Grabber (`banner.py`) — Class: `BannerGrabber`

**Purpose:** Protocol-aware service identification on open TCP ports.

**Detection Strategy:**

| Port Category | Ports | Method |
|---------------|-------|--------|
| HTTP | 80, 81, 443, 8000, 8080, 8443 | Send `HEAD / HTTP/1.1` request, extract `Server` header or first response line |
| SMTP/POP3/IMAP | 25, 110, 143, 587 | Send `EHLO netrecon.local`, read banner |
| FTP | 21 | Send `USER anonymous`, read response |
| Other | All other ports | Read first 512 bytes, infer service from content |

**Service Inference Logic:**
1. Check banner text for keywords: `ssh`, `mysql`, `smtp`, `http`, `postgres`/`postgresql`
2. Fall back to port-number-based lookup (14 known services: ftp, ssh, telnet, smtp, dns, http, pop3, imap, https, mysql, rdp, postgresql, redis, http-alt)

**Return Status Values:**
- `open` — Banner successfully captured
- `open-no-banner` — Connection successful but no banner data received
- `failed:<error>` — Connection attempt failed

---

### 3.4 DNS Analyzer (`dns_analyzer.py`) — Class: `DNSAnalyzer`

**Purpose:** Comprehensive DNS record analysis with email security verification.

**Resolution Pipeline:**

```text
For each record type (A, AAAA, MX, TXT, NS, CNAME):
  1. dns.resolver.Resolver.resolve(hostname, type)
  2. Handle exceptions:
     ├── NoAnswer → empty list
     ├── NXDOMAIN → add warning, empty list
     ├── Timeout/NoNameservers → add warning, empty list
     └── Any other → add warning, empty list
  3. Deduplicate and sort results
  4. For MX: extract hostname from priority-host format

Security Checks:
  5. SPF: Search TXT records for "v=spf1" substring
  6. DMARC: Resolve _dmarc.{hostname} TXT, search for "v=dmarc1"
  7. DNSSEC: Resolve DNSKEY record type, return True if any records exist
```

---

### 3.5 WHOIS Lookup (`whois_lookup.py`) — Class: `WhoisLookup`

**Purpose:** Domain/IP ownership intelligence with dual-method fallback.

**Lookup Pipeline:**

```text
1. Primary: python-whois library
   ├── whois.whois(query) → structured data
   ├── Extract ASN from fields: asn, originas, origin, asnumber
   │   └── Fallback: regex AS\d+ in raw text
   ├── Extract organization from: org, organization, name, orgname
   ├── Extract ISP from: isp, owner, registrar, netname
   └── Extract abuse contact: prioritize emails with "abuse" keyword

2. Fallback: Raw TCP WHOIS (if python-whois fails or not installed)
   ├── Connect to whois.iana.org:43
   ├── Send query, read response
   ├── Find referral server from "refer:" or "whois:" header
   ├── Query referral server if found
   └── Parse key-value fields from raw output
```

**Key Regex Patterns:**
- Email: `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`
- ASN: `\bAS\d+\b` (case-insensitive)
- Referral: `^(?:refer|whois):\s*(\S+)` (multiline)

---

### 3.6 Traceroute Scanner (`traceroute.py`) — Class: `TracerouteScanner`

**Purpose:** Network path tracing with optional geolocation enrichment.

**Execution Pipeline:**

```text
1. Try system traceroute command:
   ├── Windows: tracert -d TARGET
   └── Linux/macOS: traceroute -n TARGET

2. Parse output:
   ├── Match lines: ^\s*(\d+)\s+(.*)$
   ├── Extract IP from tokens (validate with ipaddress.ip_address)
   ├── Extract latency from pattern: (\d+(?:\.\d+)?)\s*ms
   └── "Request timed out" / "*" → hop with no IP

3. If system command fails → TTL ping fallback:
   ├── For TTL = 1 to max_hops:
   │   ├── Windows: ping -n 1 -w TIMEOUT -i TTL TARGET
   │   └── Linux: ping -c 1 -W TIMEOUT -t TTL TARGET
   │   ├── Extract responding IP and latency
   │   └── Stop when responding IP equals target IP
   └── Return hops list

4. If --traceroute-advanced:
   └── For each hop with valid IP:
       └── enrich_ip_async(ip) → (ASN, geo) from ipwho.is API
```

---

### 3.7 Subdomain Scanner (`subdomain_scanner.py`) — Class: `SubdomainScanner`

**Purpose:** Async subdomain enumeration via DNS resolution.

**Algorithm:**

```text
Input: domain, wordlist
Output: SubdomainScanResult

For each word in wordlist (concurrency via Semaphore):
  1. Construct FQDN: {word}.{domain}
  2. loop.getaddrinfo(fqdn, None) → IP addresses
  3. Validate first IP with ipaddress.ip_address()
  4. Measure response time in milliseconds
  5. If resolves → add SubdomainRecord(host, ip, response_ms)

Sort results by host, calculate total duration
```

---

### 3.8 Threat Intelligence (`threat_intel.py`) — Class: `ThreatIntelChecker`

**Purpose:** IP reputation checking via external threat intelligence APIs.

**API Integration Details:**

| Source | Endpoint | Auth Header | Rate Limit | Extracted Data |
|--------|----------|-------------|------------|----------------|
| AbuseIPDB | `GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90` | `Key: {api_key}` | 0.25s sleep | `abuseConfidenceScore` (0-100), `totalReports` |
| VirusTotal | `GET /api/v3/ip_addresses/{ip}` | `x-apikey: {api_key}` | 0.25s sleep | `last_analysis_stats.malicious`, `.suspicious` |
| Shodan | `GET /shodan/host/{ip}?key={key}` | URL parameter | 0.25s sleep | `vulns` dictionary (CVE IDs) |

**Aggregation Logic:**

```text
malicious_score = max(
  AbuseIPDB.abuseConfidenceScore,
  min(100, (VT.malicious + VT.suspicious) * 10)
)

blacklist_count = (VT.malicious + VT.suspicious) + len(Shodan.vulns)

spam_reports = AbuseIPDB.totalReports

known_vulnerabilities = sorted(Shodan.vulns.keys())

If blacklist_count > 0 and malicious_score < 20:
  malicious_score = min(100, blacklist_count * 5)
```

---

### 3.9 Security Checker (`security_checks.py`) — Class: `SecurityChecker`

**Purpose:** Network security posture evaluation with heuristic analysis.

**Evaluation Pipeline:**

```text
1. IP Classification:
   ├── ipaddress.ip_address(ip)
   ├── .is_private → "Private"
   ├── .is_global → "Public"
   └── else → "Special/Reserved"

2. VPN/Proxy Detection:
   ├── Direct flags: external_info.vpn_detected, external_info.proxy_detected
   └── Keyword scan in: reverse_dns, organization, isp, whois.organization, whois.isp
       ├── VPN keywords: vpn, wireguard, openvpn, nord, expressvpn, mullvad, tunnel
       ├── Proxy keywords: proxy, socks, tor, relay, anonymizer
       └── Hosting keywords: datacenter, hosting, vps, colo, cloud, digitalocean, linode, ovh, aws, azure, gcp

3. Firewall Detection:
   ├── filtered_ratio = len(filtered_ports) / len(scanned_ports)
   │   └── ≥ 0.5 → likely_firewall, reason="High filtered-port ratio"
   ├── open=0 AND filtered>0 → likely_firewall
   └── Traceroute unknown_hops / total_hops ≥ 0.4 → icmp_blocked, likely_firewall

4. Risk Level Calculation:
   ├── Public: +1
   ├── VPN: +2
   ├── Proxy: +2
   ├── Risky ports: min(3, count)
   ├── Firewall: +1
   ├── Private: -1
   └── Levels: ≤1=Low, ≤3=Medium, ≤5=High, >5=Critical
```

---

### 3.10 Risk Scoring Engine (`risk_engine.py`) — Class: `RiskScoringEngine`

**Purpose:** Consolidated weighted risk assessment from all available intelligence.

**Scoring Factors Table:**

| Factor | Weight | Max Points | Source |
|--------|--------|------------|--------|
| Risky open ports | +8 per port | 30 | PortScanResult.risky_open_ports |
| Significant filtered ports | +5 (if ≥20 ports scanned) | 5 | PortScanResult.filtered_count |
| Proxy indicator | +15 (flat) | 15 | ExternalIPInfo.proxy_detected |
| VPN indicator | +10 (flat) | 10 | ExternalIPInfo.vpn_detected |
| Suspicious ASN/org | +10 (flat) | 10 | WhoisResult.organization/isp keywords |
| Blacklist presence | +3 per entry | 25 | ThreatIntelResult.blacklist_count |
| Threat malicious score | +0.3 × score | 30 | ThreatIntelResult.malicious_score |
| Spam reports | +1 per 10 reports | 10 | ThreatIntelResult.spam_reports |
| Known vulnerabilities | +3 per CVE | 15 | ThreatIntelResult.known_vulnerabilities |
| SPF missing | +8 (flat) | 8 | DNSAnalysisResult.spf_present |
| DMARC missing | +8 (flat) | 8 | DNSAnalysisResult.dmarc_present |
| DNSSEC not detected | +5 (flat) | 5 | DNSAnalysisResult.dnssec_enabled |
| Firewall anomalies | +4 (flat) | 4 | FirewallDetectionResult.likely_firewall |
| **Maximum possible** | | **175 (clamped to 100)** | |

**Severity Levels:**
- **Low**: Score 0-24
- **Medium**: Score 25-49
- **High**: Score 50-74
- **Critical**: Score 75-100

---

### 3.11 Speed Tester (`speed_test.py`) — Class: `SpeedTester`

**Purpose:** Internet bandwidth and latency measurement.

**Execution Logic:**

```text
1. Try secure mode: speedtest.Speedtest(secure=True)
2. If 403 error → retry insecure: speedtest.Speedtest(secure=False)
3. If TypeError on secure param → fallback: speedtest.Speedtest()
4. get_best_server() → select optimal test server
5. download() / 1,000,000 → download_mbps
6. upload() / 1,000,000 → upload_mbps
7. best_server.latency or results.ping → ping_ms
```

---

### 3.12 LAN Scanner (`lan_scanner.py`) — Class: `LANScanner`

**Purpose:** Local network active host discovery.

**Algorithm:**

```text
1. Parse CIDR → list of host IPs (max 1024)
2. For each host (concurrency via Semaphore(256)):
   ├── Async ping (platform-specific command)
   └── returncode == 0 → alive
3. Read ARP table:
   ├── Windows: arp -a
   └── Linux: arp -an
   └── Parse IP → MAC mappings
4. For each alive host:
   ├── socket.gethostbyaddr(ip) → hostname
   └── ARP table lookup → MAC address
5. Return LanScanResult with sorted active hosts
```

---

### 3.13 Packet Sniffer (`sniffer.py`) — Class: `PacketSniffer`

**Purpose:** Network traffic analysis with anomaly detection.

**Capture and Analysis Pipeline:**

```text
1. scapy.sniff(count=limit, timeout=timeout, store=True)
   └── Requires admin/root privileges

2. For each captured packet:
   ├── IP layer → count source IP occurrences
   ├── ARP (op=2 reply) → track IP-to-MAC mappings
   │   └── Same IP, different MAC → "Possible ARP spoofing"
   └── DNS + DNSRR → track answer sets per query name
       └── >3 distinct answers → "Potential DNS poisoning"

3. Post-capture analysis:
   └── Source IPs with count > max(30, limit * 0.25)
       → "High traffic anomaly detected"
```

---

## 4. Async Scanning Architecture

### 4.1 Event Loop Management

```text
run_async(coroutine):
  ├── Try asyncio.get_running_loop()
  │   ├── Loop exists and running:
  │   │   └── Spawn daemon thread → asyncio.run() in thread
  │   │       └── Thread.join() → return result
  │   └── No running loop:
  │       └── asyncio.run(coroutine)
  └── Install Windows exception filter (if win32):
      └── Suppress ConnectionResetError in _call_connection_lost
```

### 4.2 Concurrency Limits

| Module | Mechanism | Default Workers | Purpose |
|--------|-----------|-----------------|---------|
| Port Scanner | `asyncio.Semaphore` | 300 | Prevent file descriptor exhaustion |
| Subdomain Scanner | `asyncio.Semaphore` | 200 | DNS resolution throttling |
| LAN Scanner | `asyncio.Semaphore` | 256 | Ping subprocess control |
| External IP | `aiohttp.TCPConnector(limit=N)` | 3 | Provider API throttling |
| Threat Intel | Sequential with sleep | 0.25s delay | API rate limit compliance |

### 4.3 First-Success Cancellation Pattern (External IP)

```text
providers = [ipinfo, ipapi, ipwhois]
tasks = [create_task(fetch(p)) for p in providers]

for task in as_completed(tasks):
  result = await task
  if result is valid:
    for other_task in tasks:
      if not done: other_task.cancel()
    await gather(*tasks, return_exceptions=True)
    return result

return None  # all failed
```

---

## 5. Mode Logic

### Active Mode (Default)

All 13 scanning modules are available. The orchestrator executes each requested module in sequence.

### Passive Mode

The orchestrator checks `options.mode == "passive"` before executing aggressive modules:

| Module | Passive Mode Behavior |
|--------|----------------------|
| Port Scanner | Skipped → warning: "Port scan skipped in passive mode" |
| Traceroute | Skipped → warning: "Traceroute skipped in passive mode" |
| Speed Test | Skipped → warning: "Speed test skipped in passive mode" |
| LAN Scanner | Skipped → warning: "LAN scan skipped in passive mode" |
| Packet Sniffer | Skipped → warning: "Packet sniffing skipped in passive mode" |
| DNS Analyzer | Allowed |
| WHOIS | Allowed |
| Threat Intelligence | Allowed |
| Subdomain Scanner | Allowed |
| External IP Lookup | Allowed |
| Security Checker | Allowed |
| Risk Engine | Always runs |

---

## 6. Reporting Layer Design

### 6.1 Rich Terminal Output (`renderer.py`)

**16 rendering functions** executed in sequence:

| Function | Section | Content |
|----------|---------|---------|
| `_render_header` | Header Panel | "NetRecon CLI" title with mode indicator |
| `_render_summary` | Summary Table | hostname, timestamp, mode, IP counts, warnings/errors |
| `_render_local_ips` | Local IPs Table | Numbered list of local IP addresses |
| `_render_external` | External IP Table | 12 fields: ip, city, region, country, coordinates, org, isp, timezone, source, reverse_dns, map_url, map_html |
| `_render_dns` | DNS Table | 6 record types + SPF/DMARC/DNSSEC status |
| `_render_subdomains` | Subdomain Table | host, ip, response_ms per active subdomain |
| `_render_ports` | Port Scan Table | scanned/open/closed/filtered counts + banner table |
| `_render_traceroute` | Traceroute Table | hop, ip, latency, ASN, geo per hop |
| `_render_whois` | WHOIS Table | ASN, ISP, organization, abuse contact, source |
| `_render_speed` | Speed Table | download/upload Mbps, ping ms, server info |
| `_render_threat` | Threat Table | malicious score, blacklist count, spam, vulnerabilities |
| `_render_security` | Security Table + Panel | classification, VPN/proxy, risk level, firewall + findings |
| `_render_risk` | Risk Table + Panel | score/100, level, factor breakdown |
| `_render_lan` | LAN Table | IP, hostname, MAC per active host |
| `_render_sniffer` | Sniffer Table + Panel | packets captured, suspicious events with alerts |
| `_render_interfaces` | Interface Panel | Raw ipconfig/ifconfig output |
| `_render_warnings` | Warning/Error Panels | All warnings and errors from all modules |

### 6.2 HTML Dashboard (`html_report.py`)

**Self-contained HTML structure:**

```text
HTML Report
├── <head>
│   ├── Chart.js CDN script
│   └── Inline CSS (Segoe UI font, grid layout, card design)
├── <body>
│   ├── <h1> Report title + timestamp
│   ├── Grid Layout (responsive, min 320px per card)
│   │   ├── Summary Card
│   │   │   ├── Hostname, mode, external IP
│   │   │   ├── Risk score/level with color coding
│   │   │   └── Doughnut chart (risk score visualization)
│   │   ├── Open Ports Card
│   │   │   └── Table: port, service, banner
│   │   ├── Speed Test Card
│   │   │   └── Bar chart + download/upload/ping values
│   │   └── Threat Intel Card
│   │       └── Malicious score, blacklist count, spam, vulnerabilities
│   ├── Geo Map Card
│   │   ├── Google Maps link
│   │   └── Embedded iframe (if coordinates available)
│   └── Raw JSON Snapshot
│       └── <pre> formatted complete ReconResult JSON
└── <script>
    ├── Risk doughnut chart (Chart.js)
    └── Speed bar chart (Chart.js)
```

### 6.3 JSON Output

- **Serialization**: `dataclasses.asdict(result)` → `json.dumps(indent=2)`
- **Stdout**: `--json` flag prints to stdout with UTF-8 encoding fallback
- **File**: `--save-json` saves to specified path or auto-generated `reports/netrecon_report_<YYYYMMDD_HHMMSS>.json`
- **Directory**: Auto-created via `Path.parent.mkdir(parents=True, exist_ok=True)`

---

## 7. Error Handling Strategy

### Module-Level Error Handling

Every scanning module follows this pattern:
1. Check for required dependencies → return warning if missing
2. Perform operation within try/except → append warning/error on failure
3. Return result object (never raise to orchestrator)

### Orchestrator-Level Error Handling

- Missing target for module → warning appended, module skipped
- Passive mode restriction → warning appended, module skipped
- Individual module failures → logged, result collects warnings/errors

### CLI-Level Error Handling

```text
try:
  result = orchestrator.run(options)
except Exception:
  LOGGER.exception("Fatal scan error")
  if --json: print JSON error
  else: print Rich error
  return 1
```

### Validation Errors

- Invalid port range → `ValueError` caught by `parser.error()`
- Invalid CIDR → `ValueError` caught by `parser.error()`
- Invalid sniff parameters → `ValueError` caught by `parser.error()`

---

## 8. Configuration Validation Pipeline

The `ConfigLoader` validates each field using type-specific static methods:

| Method | Validates | Behavior on Invalid |
|--------|-----------|---------------------|
| `_mode(value, default)` | string ∈ {active, passive} | Returns default |
| `_bool(value, default)` | isinstance(value, bool) | Returns default |
| `_str(value, default)` | Non-empty string after strip | Returns default |
| `_positive_float(value, default)` | float(value) > 0 | Returns default |
| `_positive_int(value, default)` | int(value) > 0 | Returns default |
| `_ports_list(value, default)` | list of ints within 1-65535 | Returns default (deduped, sorted) |
| `_wordlist(value, default)` | list of non-empty strings | Returns default (lowered, deduped, sorted) |
| `_api_keys(value, default)` | dict of string→string (non-empty values only) | Returns default |

---

## 9. Logging Architecture

**Setup (`logging_utils.py`):**

```text
Root Logger
├── Level: configurable (DEBUG/INFO/WARNING/ERROR)
├── Format: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
├── Console Handler (StreamHandler)
└── File Handler (FileHandler → logs/netrecon.log, UTF-8)
```

**Log Points:**
- Config loading (INFO/WARNING)
- External IP provider resolution (INFO)
- Scan start/completion (INFO)
- Banner grab failures (DEBUG)
- Module exceptions (WARNING)
- Fatal errors (EXCEPTION)
- Windows exception filter suppression (DEBUG)

---

## 10. Testing Architecture

**Test Organization:** One test file per module (21 test files total)

```text
tests/
├── test_async_utils.py      → run_async, gather_limited, fetch_json
├── test_banner.py            → BannerGrabber protocol handling
├── test_cli.py               → build_parser, resolve_scan_options, main
├── test_config.py            → AppConfig, ConfigLoader validation
├── test_dns_analyzer.py      → DNSAnalyzer record resolution
├── test_html_report.py       → HTMLReportBuilder generation
├── test_ip_scanner.py        → IPScanner provider parsing
├── test_lan_scanner.py       → LANScanner CIDR handling
├── test_logging_utils.py     → setup_logging handler setup
├── test_models.py            → Dataclass instantiation and serialization
├── test_orchestrator.py      → NetReconOrchestrator module coordination
├── test_port_scanner.py      → PortScanner range parsing, async scanning
├── test_renderer.py          → Rich rendering, JSON serialization
├── test_risk_engine.py       → RiskScoringEngine factor calculation
├── test_security_checks.py   → SecurityChecker heuristics
├── test_sniffer.py           → PacketSniffer capture handling
├── test_speed_test.py        → SpeedTester execution
├── test_subdomain_scanner.py → SubdomainScanner resolution
├── test_threat_intel.py      → ThreatIntelChecker API integration
├── test_traceroute.py        → TracerouteScanner parsing
└── test_whois_lookup.py      → WhoisLookup field extraction
```

**Testability Features:**
- Orchestrator accepts dependency-injected service instances
- All modules use pure function patterns where possible
- Network-dependent operations are isolated in methods that can be mocked
- Dataclass models provide `to_dict()` for assertion comparisons
