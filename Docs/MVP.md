# MVP — NetRecon CLI Advanced Network Reconnaissance Toolkit

## Goal

Deliver a production-ready, modular, async-first network reconnaissance and security analysis toolkit with comprehensive scanning capabilities, threat intelligence integration, risk scoring, and multi-format reporting.

---

## Phase 1 — Core Reconnaissance Modules

### Must Have

- [x] **Async External IP Lookup** — Multi-provider concurrent lookup (ipinfo.io, ipapi.co, ipwho.is) with first-success cancellation pattern. Synchronous `requests` fallback when `aiohttp` is unavailable. Implemented in `ip_scanner.py` → `IPScanner.lookup_external_ip_async()`.

- [x] **Local IP Detection** — Collects all local IPv4/IPv6 addresses via `socket.getaddrinfo()` with `gethostbyname_ex()` fallback. Returns sorted, deduplicated list. Implemented in `ip_scanner.py` → `IPScanner.collect_local_ips()`.

- [x] **Reverse DNS Lookup** — Resolves hostname for any IP using `socket.gethostbyaddr()`. Implemented in `ip_scanner.py` → `IPScanner.reverse_dns_lookup()`.

- [x] **Async Port Scanner** — TCP port scanning using `asyncio.open_connection()` with `Semaphore(300)` concurrency. Classifies ports as open/closed/filtered. Supports common ports (14 predefined) and custom range (START-END format, 1-65535). Implemented in `port_scanner.py` → `PortScanner.scan_ports_async()`.

- [x] **Banner Grabbing** — Protocol-aware service identification on open ports. HTTP ports: sends `HEAD / HTTP/1.1`, extracts `Server` header. SMTP/FTP/SSH: protocol-specific prompts. Infers service from banner content or port number (14 known services). Implemented in `banner.py` → `BannerGrabber.grab_banner_async()`.

- [x] **DNS Analyzer** — Resolves 6 record types (A, AAAA, MX, TXT, NS, CNAME) using `dnspython`. SPF detection via TXT record substring search. DMARC detection via `_dmarc.{hostname}` TXT lookup. DNSSEC detection via DNSKEY record resolution. Implemented in `dns_analyzer.py` → `DNSAnalyzer.analyze()`.

- [x] **Traceroute Support** — Cross-platform: `tracert -d` (Windows), `traceroute -n` (Linux/macOS). TTL-based ping fallback when system command fails. Advanced mode enriches each hop with ASN and geolocation via ipwho.is API. Configurable max hops (30) and per-hop timeout (2000ms). Implemented in `traceroute.py` → `TracerouteScanner.trace_async()`.

- [x] **Subdomain Scanner** — Async DNS resolution of configurable wordlist (15 default subdomains). Uses `loop.getaddrinfo()` with `Semaphore(200)` concurrency. Measures per-resolution response time in milliseconds. Implemented in `subdomain_scanner.py` → `SubdomainScanner.scan_async()`.

- [x] **Passive vs Active Mode** — Active mode (default): All modules available. Passive mode: Port scanning, traceroute, speed test, LAN scan, and packet sniffing automatically skipped with warning messages. DNS, WHOIS, threat checks, subdomain scanning, and external lookups allowed in both modes.

---

## Phase 2 — Security and Threat Intelligence

- [x] **Threat Intelligence API Integration** — Concurrent async checks via `aiohttp` for AbuseIPDB (abuse confidence score, total reports), VirusTotal (malicious/suspicious detection stats), and Shodan (known CVE vulnerabilities). Rate-limit sleep (0.25s) between calls. API keys configured in `config.json`. Graceful skip when keys are missing. Implemented in `threat_intel.py` → `ThreatIntelChecker.check_ip_async()`.

- [x] **Security Checks** — IP classification (Private/Public/Special) via `ipaddress` module. VPN detection via provider flags + keyword scanning (vpn, wireguard, nord, etc.). Proxy detection via provider flags + keyword scanning (proxy, socks, tor, etc.). Hosting indicator detection (datacenter, aws, azure, etc.). Risk level: Low/Medium/High/Critical. Implemented in `security_checks.py` → `SecurityChecker.evaluate()`.

- [x] **Firewall Detection Heuristics** — Filtered-port ratio analysis (≥50% filtered → likely firewall). Zero open ports with filtered responses → likely firewall. Traceroute unknown hop ratio (≥40%) → ICMP blocked. Implemented in `security_checks.py` → `SecurityChecker.detect_firewall()`.

- [x] **Risk Scoring Engine** — Weighted scoring (0-100) with 13 factor categories. Risky ports (+8 each, max 30), proxy (+15), VPN (+10), blacklists (+3 each, max 25), malicious score (+0.3×, max 30), SPF/DMARC/DNSSEC missing (+8/+8/+5), and more. Four severity levels: Low (<25), Medium (<50), High (<75), Critical (≥75). Human-readable factor breakdown included. Implemented in `risk_engine.py` → `RiskScoringEngine.score()`.

- [x] **WHOIS Lookup with Fallback** — Primary: `python-whois` library with structured field extraction (ASN, ISP, organization, abuse contact). Fallback: Raw TCP WHOIS via port 43 with IANA referral server following. ASN extraction via field keys and regex `\bAS\d+\b`. Abuse contact prioritized by "abuse" keyword. Implemented in `whois_lookup.py` → `WhoisLookup.lookup()`.

---

## Phase 3 — Operational Features

- [x] **LAN Scanner** — CIDR-based active host discovery using async ICMP ping with `Semaphore(256)` concurrency. Safety limit: 1024 hosts maximum. ARP table parsing for MAC address resolution. Hostname lookup via `socket.gethostbyaddr()`. Cross-platform ping commands. Implemented in `lan_scanner.py` → `LANScanner.scan_async()`.

- [x] **Packet Sniffer** — Packet capture via `scapy.sniff()` with configurable limit and timeout. ARP spoofing detection (IP-to-MAC mapping changes). DNS poisoning detection (>3 distinct answers per query). High traffic anomaly detection (>25% of captured packets from single source). Requires admin/root privileges. Implemented in `sniffer.py` → `PacketSniffer.capture()`.

- [x] **HTML Dashboard Report** — Self-contained HTML with Chart.js from CDN. Responsive grid layout with card design. Doughnut chart for risk score. Bar chart for speed test. Open ports + banners table. Threat intelligence summary. Embedded Google Maps geo iframe. Raw JSON snapshot. Risk level color coding (Low=green, Medium=yellow, High=orange, Critical=red). Implemented in `html_report.py` → `HTMLReportBuilder.generate()`.

- [x] **Config-Driven Defaults + API Keys** — `config.json` with 25+ configurable fields. `AppConfig` dataclass with safe defaults. `ConfigLoader` validates every field with type-specific methods. Supports custom config file path via `--config`. API keys for AbuseIPDB, VirusTotal, Shodan. Implemented in `config.py` → `ConfigLoader.load()`.

- [x] **Structured Logging** — Root logger with console + file handlers. Configurable level (DEBUG/INFO/WARNING/ERROR). Configurable file path (default: `logs/netrecon.log`). Format: `%(asctime)s [%(levelname)s] %(name)s: %(message)s`. Implemented in `logging_utils.py` → `setup_logging()`.

- [x] **JSON Export** — Complete `ReconResult` serialization via `dataclasses.asdict()`. Pretty-printed JSON to stdout (`--json`). File export with auto-directory creation (`--save-json`). Auto-generated filename: `reports/netrecon_report_<timestamp>.json`. Implemented in `renderer.py` → `to_json()`, `save_json_report()`.

- [x] **Rich Terminal Dashboard** — 16-section rendering using `rich` library. Tables for each module output. Panels for findings, risk factors, sniffer alerts, warnings, errors. ASCII box styling with color-coded borders. `--no-color` flag for plain output. Implemented in `renderer.py` → `render_rich()`.

- [x] **Unit Tests** — 21 test files covering all modules (one test file per source module). Tests cover dataclass instantiation, serialization, range parsing, provider parsing, heuristic evaluation, and orchestrator coordination. Run via `python -m unittest discover -s tests -v`.

---

## Phase 4 — Infrastructure and Cross-Platform Support

- [x] **Async Utilities** — `run_async()`: Runs coroutine in fresh event loop with thread fallback when loop is already running (Jupyter/test environments). `gather_limited()`: Semaphore-based concurrency limiter for coroutine factories. `fetch_json()`: Generic async JSON HTTP GET via `aiohttp`. Windows Proactor event loop exception filter for benign `ConnectionResetError` suppression. Implemented in `async_utils.py`.

- [x] **Cross-Platform Support** — Windows: `tracert`, `ping -n`, `ipconfig /all`, `arp -a`. Linux: `traceroute`, `ping -c`, `ip addr show` / `ifconfig -a`, `arp -an`. macOS: `traceroute`, `ping -c`, `ifconfig`, `arp -an`. Platform detection via `platform.system()`. Automatic command fallbacks.

- [x] **Graceful Degradation** — Optional package detection: `scapy`, `dnspython`, `speedtest-cli`, `python-whois`, `aiohttp`. Missing packages produce informative warnings, not crashes. Modules return partial results with warnings appended.

- [x] **Dependency Injection** — `NetReconOrchestrator` constructor accepts 13 optional service instances. Default instances created from `AppConfig` when not provided. Enables isolated unit testing with mock services.

- [x] **Legacy Compatibility** — `ip_finder.py` provides backward-compatible entrypoint using `IPScanner` class. Prints basic local and external IP information.

---

## MVP Completion Criteria

| Criterion | Status | Verification |
|-----------|--------|-------------|
| Active mode performs end-to-end recon with async scanning | ✅ Complete | Orchestrator coordinates all 13 modules sequentially with async execution |
| Passive mode avoids aggressive probing modules | ✅ Complete | Port scan, traceroute, speed test, LAN scan, sniffer all skip with warnings |
| Threat and risk scoring produce deterministic output | ✅ Complete | Weighted scoring with documented factors; reproducible for same inputs |
| HTML dashboard exports successfully | ✅ Complete | Self-contained HTML with Chart.js, geo map, tables, and JSON snapshot |
| JSON output includes all module results | ✅ Complete | `ReconResult.to_dict()` serializes 20+ fields via `dataclasses.asdict()` |
| Tests pass on Windows/Linux/macOS-compatible logic paths | ✅ Complete | 21 test files covering all modules |
| Config-driven behavior with safe defaults | ✅ Complete | 25+ configurable fields with typed validation |
| Graceful degradation for missing dependencies | ✅ Complete | Optional packages checked at module level with warning fallback |
| Multiple output formats (terminal, JSON, HTML) | ✅ Complete | Rich terminal (16 sections), JSON (stdout + file), HTML (dashboard) |
| Cross-platform execution | ✅ Complete | Windows/Linux/macOS command detection and fallbacks |
