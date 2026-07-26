from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ReconResult


def _h(value: object) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _join_escaped(items: list[str], sep: str = ", ") -> str:
    return sep.join(_h(item) for item in items) if items else "None"


class HTMLReportBuilder:

    def generate(self, result: ReconResult, path: str | Path) -> Path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = result.to_dict()
        risk_score = result.risk_assessment.score if result.risk_assessment else 0
        risk_level = result.risk_assessment.level if result.risk_assessment else "Unknown"
        speed = result.speed_test
        speed_dl = speed.download_mbps if speed else 0
        speed_ul = speed.upload_mbps if speed else 0
        speed_ping = speed.ping_ms if speed else 0

        sections = [
            self._build_summary(result, risk_score, risk_level),
            self._build_external(result),
            self._build_port_scan(result),
            self._build_dns(result),
            self._build_traceroute(result),
            self._build_whois(result),
            self._build_subdomains(result),
            self._build_lan(result),
            self._build_sniffer(result),
            self._build_speed(result),
            self._build_security(result),
            self._build_threat(result),
            self._build_risk(result, risk_score, risk_level),
            self._build_geo(result),
            self._build_warnings(result),
        ]
        all_sections = "\n".join(s for s in sections if s)

        html_content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetRecon HTML Report</title>
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
  <style>
    *, *::before, *::after {{ box-sizing:border-box; }}
    body {{ font-family:'Segoe UI',Tahoma,sans-serif; background:#f5f7fb; margin:0; padding:20px; color:#1b1f2a; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:16px; }}
    .card {{ background:#fff; border-radius:12px; box-shadow:0 6px 20px rgba(0,0,0,0.06); padding:16px; overflow-x:auto; }}
    .card h2 {{ font-size:1.1rem; margin:0 0 12px; color:#1a237e; border-bottom:2px solid #e8ecf4; padding-bottom:8px; }}
    .card.wide {{ grid-column:1/-1; }}
    table {{ width:100%; border-collapse:collapse; font-size:14px; }}
    th, td {{ border-bottom:1px solid #e8ecf4; text-align:left; padding:8px; }}
    th {{ background:#f0f2f8; font-weight:600; }}
    tr:hover td {{ background:#f8f9ff; }}
    .critical {{ color:#b10020; font-weight:700; }}
    .high {{ color:#d35400; font-weight:700; }}
    .medium {{ color:#b58900; font-weight:700; }}
    .low {{ color:#2e7d32; font-weight:700; }}
    .warn {{ color:#b58900; }};
    .error {{ color:#b10020; }};
    pre {{ background:#f4f5f7; padding:12px; border-radius:8px; font-size:12px; overflow-x:auto; }}
    a {{ color:#1565c0; }}
    .flex-row {{ display:flex; flex-wrap:wrap; gap:12px; }}
    .stat {{ flex:1; min-width:120px; }}
    .stat-label {{ font-size:12px; color:#666; }}
    .stat-value {{ font-size:1.5rem; font-weight:700; }}
  </style>
</head>
<body>
  <h1>NetRecon Report</h1>
  <p>Generated at: {_h(result.timestamp)} | Hostname: {_h(result.hostname)} | Mode: {_h(result.mode)}</p>
  <div class="grid">
    {all_sections}
  </div>
  <div class="card" style="margin-top:16px;">
    <h2>Raw JSON Snapshot</h2>
    <pre>{_h(json.dumps(data, indent=2, ensure_ascii=False))}</pre>
  </div>
  <script>
    (function() {{
      function drawDoughnut(canvas, value) {{
        var ctx = canvas.getContext('2d');
        var w = canvas.width, h = canvas.height;
        var cx = w/2, cy = h/2, r = Math.min(cx,cy)-10, lw = 20;
        ctx.clearRect(0,0,w,h);
        ctx.beginPath(); ctx.arc(cx,cy,r,0,2*Math.PI); ctx.strokeStyle='#cfd8dc'; ctx.lineWidth=lw; ctx.stroke();
        var end = -Math.PI/2 + (value/100)*2*Math.PI;
        ctx.beginPath(); ctx.arc(cx,cy,r,-Math.PI/2,end); ctx.strokeStyle='#e53935'; ctx.lineWidth=lw; ctx.stroke();
        ctx.fillStyle='#1b1f2a'; ctx.font='bold 24px sans-serif'; ctx.textAlign='center'; ctx.textBaseline='middle';
        ctx.fillText(value+'%',cx,cy);
      }}
      function drawBar(canvas, labels, data, colors) {{
        var ctx = canvas.getContext('2d');
        var w = canvas.width, h = canvas.height;
        var pad = {{t:20,b:30,l:40,r:20}};
        var cw = w-pad.l-pad.r, ch = h-pad.t-pad.b;
        ctx.clearRect(0,0,w,h);
        var max = Math.max(...data,1);
        var bw = cw / data.length * 0.6;
        var gap = cw / data.length * 0.4;
        data.forEach(function(v,i) {{
          var barH = (v/max)*ch;
          var x = pad.l + i*(bw+gap) + gap/2;
          var y = pad.t + ch - barH;
          ctx.fillStyle=colors[i]; ctx.fillRect(x,y,bw,barH);
          ctx.fillStyle='#1b1f2a'; ctx.font='12px sans-serif'; ctx.textAlign='center';
          ctx.fillText(v.toFixed(1),x+bw/2,y-4);
          ctx.fillText(labels[i],x+bw/2,pad.t+ch+16);
        }});
      }}
      document.addEventListener('DOMContentLoaded', function() {{
        var rc = document.getElementById('riskChart');
        if (rc) drawDoughnut(rc, {risk_score});
        var sc = document.getElementById('speedChart');
        if (sc) drawBar(sc, ['Download Mbps','Upload Mbps','Ping ms'], [{speed_dl},{speed_ul},{speed_ping}], ['#1e88e5','#43a047','#fb8c00']);
      }});
    }})();
  </script>
</body>
</html>"""

        output_path.write_text(html_content, encoding="utf-8")
        return output_path

    def _build_summary(self, result: ReconResult, risk_score: int, risk_level: str) -> str:
        return f"""<div class="card">
  <h2>Summary</h2>
  <div class="flex-row">
    <div class="stat"><div class="stat-label">External IP</div><div class="stat-value">{_h(result.external_info.ip if result.external_info else 'N/A')}</div></div>
    <div class="stat"><div class="stat-label">Local IPs</div><div class="stat-value">{len(result.local_ips)}</div></div>
    <div class="stat"><div class="stat-label">Risk Score</div><div class="stat-value">{risk_score}/100</div></div>
    <div class="stat"><div class="stat-label">Risk Level</div><div class="stat-value"><span class="{_h(risk_level.lower())}">{_h(risk_level)}</span></div></div>
  </div>
  <canvas id="riskChart" height="150"></canvas>
</div>"""

    def _build_external(self, result: ReconResult) -> str:
        info = result.external_info
        if info is None:
            return ""
        return f"""<div class="card">
  <h2>External IP Intelligence</h2>
  <table><tbody>
    <tr><td>IP</td><td>{_h(info.ip)}</td></tr>
    <tr><td>City</td><td>{_h(info.city) or 'Unknown'}</td></tr>
    <tr><td>Region</td><td>{_h(info.region) or 'Unknown'}</td></tr>
    <tr><td>Country</td><td>{_h(info.country) or 'Unknown'}</td></tr>
    <tr><td>Coordinates</td><td>{_h(info.coordinates) or 'Unknown'}</td></tr>
    <tr><td>Organization</td><td>{_h(info.organization) or 'Unknown'}</td></tr>
    <tr><td>ISP</td><td>{_h(info.isp) or 'Unknown'}</td></tr>
    <tr><td>Timezone</td><td>{_h(info.timezone) or 'Unknown'}</td></tr>
    <tr><td>Source</td><td>{_h(info.source) or 'Unknown'}</td></tr>
    <tr><td>Reverse DNS</td><td>{_h(result.reverse_dns) or 'Unavailable'}</td></tr>
  </tbody></table>
</div>"""

    def _build_port_scan(self, result: ReconResult) -> str:
        ps = result.port_scan
        if ps is None:
            return ""

        banner_rows = ""
        if ps.banners:
            rows = []
            for b in ps.banners:
                rows.append(
                    f"<tr><td>{b.port}</td><td>{_h(b.service)}</td>"
                    f"<td>{_h(b.version) or '-'}</td>"
                    f"<td>{_h(b.banner) or '-'}</td><td>{_h(b.status)}</td></tr>"
                )
            banner_rows = "<h3>Banners</h3><table><thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Banner</th><th>Status</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"

        return f"""<div class="card wide">
  <h2>Port Scan ({_h(ps.target)})</h2>
  <div class="flex-row">
    <div class="stat"><div class="stat-label">Scanned</div><div class="stat-value">{len(ps.scanned_ports)}</div></div>
    <div class="stat"><div class="stat-label">Open</div><div class="stat-value">{', '.join(str(p) for p in ps.open_ports) or 'None'}</div></div>
    <div class="stat"><div class="stat-label">Filtered</div><div class="stat-value">{ps.filtered_count}</div></div>
    <div class="stat"><div class="stat-label">Duration</div><div class="stat-value">{ps.duration_seconds}s</div></div>
  </div>
  {banner_rows}
</div>"""

    def _build_dns(self, result: ReconResult) -> str:
        dns = result.dns
        if dns is None:
            return ""
        return f"""<div class="card">
  <h2>DNS Analysis ({_h(dns.hostname)})</h2>
  <table><tbody>
    <tr><td>A</td><td>{_join_escaped(dns.a_records)}</td></tr>
    <tr><td>AAAA</td><td>{_join_escaped(dns.aaaa_records)}</td></tr>
    <tr><td>MX</td><td>{_join_escaped(dns.mx_records)}</td></tr>
    <tr><td>TXT</td><td>{_join_escaped(dns.txt_records)}</td></tr>
    <tr><td>NS</td><td>{_join_escaped(dns.ns_records)}</td></tr>
    <tr><td>CNAME</td><td>{_join_escaped(dns.cname_records)}</td></tr>
    <tr><td>SOA</td><td>{_h(dns.soa_record) or 'None'}</td></tr>
    <tr><td>SRV</td><td>{_join_escaped(dns.srv_records)}</td></tr>
    <tr><td>CAA</td><td>{_join_escaped(dns.caa_records)}</td></tr>
    <tr><td>TLSA</td><td>{_join_escaped(dns.tlsa_records)}</td></tr>
    <tr><td>SPF</td><td>{dns.spf_present}{f' ({_esc(dns.spf_source)})' if dns.spf_source else ''}</td></tr>
    <tr><td>DMARC</td><td>{dns.dmarc_present}{f' ({_esc(dns.dmarc_source)})' if dns.dmarc_source else ''}</td></tr>
    <tr><td>DNSSEC</td><td>{dns.dnssec_enabled}{f' ({_esc(dns.dnssec_source)})' if dns.dnssec_source else ''}</td></tr>
  </tbody></table>
</div>"""

    def _build_traceroute(self, result: ReconResult) -> str:
        tr = result.traceroute
        if tr is None:
            return ""

        hop_rows = ""
        if tr.hops:
            rows = []
            for hop in tr.hops:
                rows.append(
                    f"<tr><td>{hop.hop}</td><td>{_h(hop.ip) or '*'}</td>"
                    f"<td>{_h(str(hop.latency_ms)) if hop.latency_ms is not None else '*'}</td>"
                    f"<td>{_h(hop.asn) or '-'}</td><td>{_h(hop.geo) or '-'}</td></tr>"
                )
            hop_rows = "<table><thead><tr><th>Hop</th><th>IP</th><th>Latency (ms)</th><th>ASN</th><th>Geo</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"

        return f"""<div class="card">
  <h2>Traceroute ({_h(tr.target)})</h2>
  <p>Method: {_h(tr.method)}</p>
  {hop_rows}
</div>"""

    def _build_whois(self, result: ReconResult) -> str:
        w = result.whois
        if w is None:
            return ""
        return f"""<div class="card">
  <h2>WHOIS ({_h(w.query)})</h2>
  <table><tbody>
    <tr><td>ASN</td><td>{_h(w.asn) or 'Unknown'}</td></tr>
    <tr><td>ISP</td><td>{_h(w.isp) or 'Unknown'}</td></tr>
    <tr><td>Organization</td><td>{_h(w.organization) or 'Unknown'}</td></tr>
    <tr><td>Abuse Contact</td><td>{_h(w.abuse_contact) or 'Unknown'}</td></tr>
    <tr><td>Source</td><td>{_h(w.source) or 'Unknown'}</td></tr>
  </tbody></table>
</div>"""

    def _build_subdomains(self, result: ReconResult) -> str:
        sd = result.subdomains
        if sd is None:
            return ""

        rows = ""
        if sd.active_hosts:
            rows_list = []
            for r in sd.active_hosts:
                http_str = f"port {r.http_status}" if r.http_status else "-"
                rows_list.append(
                    f"<tr><td>{_h(r.host)}</td><td>{_h(r.ip)}</td>"
                    f"<td>{r.response_ms}</td><td>{http_str}</td></tr>"
                )
            rows = "<table><thead><tr><th>Subdomain</th><th>IP</th><th>Response (ms)</th><th>HTTP</th></tr></thead><tbody>" + "\n".join(rows_list) + "</tbody></table>"

        crt_label = f" | crt.sh: {sd.crt_sh_count}" if sd.crt_sh_count else ""
        return f"""<div class="card">
  <h2>Subdomains ({_h(sd.domain)})</h2>
  <p>Scanned: {sd.scanned_count} | Found: {len(sd.active_hosts)} | Duration: {sd.duration_seconds}s{crt_label}</p>
  {rows or '<p>No active subdomains found.</p>'}
</div>"""

    def _build_lan(self, result: ReconResult) -> str:
        lan = result.lan_scan
        if lan is None:
            return ""

        rows = ""
        if lan.active_hosts:
            rows_list = []
            for h in lan.active_hosts:
                rows_list.append(f"<tr><td>{_h(h.ip)}</td><td>{_h(h.hostname) or '-'}</td><td>{_h(h.mac_address) or '-'}</td></tr>")
            rows = "<table><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th></tr></thead><tbody>" + "\n".join(rows_list) + "</tbody></table>"
        else:
            rows = "<p>No active hosts found.</p>"

        return f"""<div class="card">
  <h2>LAN Scan ({_h(lan.cidr)})</h2>
  <p>Hosts: {len(lan.active_hosts)} | Duration: {lan.duration_seconds}s</p>
  {rows}
</div>"""

    def _build_sniffer(self, result: ReconResult) -> str:
        sn = result.sniffer
        if sn is None:
            return ""

        events = ""
        if sn.suspicious_events:
            events = "<h3>Suspicious Events</h3><ul>" + "".join(f"<li>{_h(e)}</li>" for e in sn.suspicious_events) + "</ul>"

        return f"""<div class="card">
  <h2>Packet Sniffer</h2>
  <p>Packets Captured: {sn.packets_captured} | Suspicious Events: {len(sn.suspicious_events)}</p>
  {events}
</div>"""

    def _build_speed(self, result: ReconResult) -> str:
        sp = result.speed_test
        if sp is None:
            return ""

        return f"""<div class="card">
  <h2>Speed Test</h2>
  <canvas id="speedChart" height="150"></canvas>
  <p>Download: {sp.download_mbps} Mbps | Upload: {sp.upload_mbps} Mbps | Ping: {sp.ping_ms} ms</p>
  <p>Server: {_h(sp.server_name) or 'Unknown'} ({_h(sp.server_country) or 'Unknown'})</p>
</div>"""

    def _build_security(self, result: ReconResult) -> str:
        sec = result.security
        if sec is None:
            return ""

        findings = ""
        if sec.findings:
            findings = "<h3>Findings</h3><ul>" + "".join(f"<li>{_h(f)}</li>" for f in sec.findings) + "</ul>"

        firewall = ""
        if sec.firewall:
            firewall = f"<p>Firewall: {sec.firewall.likely_firewall} | ICMP Blocked: {sec.firewall.icmp_blocked}</p>"

        return f"""<div class="card">
  <h2>Security Check</h2>
  <table><tbody>
    <tr><td>Classification</td><td>{_h(sec.classification)}</td></tr>
    <tr><td>Private</td><td>{sec.is_private}</td></tr>
    <tr><td>Public</td><td>{sec.is_public}</td></tr>
    <tr><td>Suspected VPN</td><td>{sec.suspected_vpn}</td></tr>
    <tr><td>Suspected Proxy</td><td>{sec.suspected_proxy}</td></tr>
    <tr><td>Risk Level</td><td class="{_h(sec.risk_level.lower())}">{_h(sec.risk_level)}</td></tr>
    <tr><td>Risky Ports</td><td>{_join_escaped([str(p) for p in sec.risky_open_ports])}</td></tr>
  </tbody></table>
  {firewall}
  {findings}
</div>"""

    def _build_threat(self, result: ReconResult) -> str:
        ti = result.threat_intel
        if ti is None:
            return ""
        return f"""<div class="card">
  <h2>Threat Intelligence ({_h(ti.ip)})</h2>
  <table><tbody>
    <tr><td>Malicious Score</td><td>{ti.malicious_score}</td></tr>
    <tr><td>Blacklist Count</td><td>{ti.blacklist_count}</td></tr>
    <tr><td>Spam Reports</td><td>{ti.spam_reports}</td></tr>
    <tr><td>Known Vulns</td><td>{_join_escaped(ti.known_vulnerabilities)}</td></tr>
  </tbody></table>
</div>"""

    def _build_risk(self, result: ReconResult, risk_score: int, risk_level: str) -> str:
        ra = result.risk_assessment
        if ra is None:
            return ""

        factors = ""
        if ra.factors:
            factors = "<h3>Risk Factors</h3><ul>" + "".join(f"<li>{_h(f)}</li>" for f in ra.factors) + "</ul>"

        return f"""<div class="card">
  <h2>Risk Assessment</h2>
  <p>Score: {ra.score}/100 | Level: <span class="{_h(ra.level.lower())}">{_h(ra.level)}</span></p>
  {factors}
</div>"""

    def _build_geo(self, result: ReconResult) -> str:
        geo_url = result.geo_map_url or ""
        if not geo_url:
            return ""
        safe_geo_url = _h(geo_url)
        return f"""<div class="card wide">
  <h2>Geo Map</h2>
  <p><a href="{safe_geo_url}" target="_blank" rel="noopener noreferrer">{safe_geo_url}</a></p>
  <iframe src="{safe_geo_url}&output=embed" width="100%" height="450" loading="lazy"></iframe>
</div>"""

    def _build_warnings(self, result: ReconResult) -> str:
        parts = []
        if result.warnings:
            items = "".join(f"<li>{_h(w)}</li>" for w in result.warnings)
            parts.append(f'<div class="card wide"><h2 class="warn">Warnings</h2><ul>{items}</ul></div>')
        if result.errors:
            items = "".join(f"<li>{_h(e)}</li>" for e in result.errors)
            parts.append(f'<div class="card wide"><h2 class="error">Errors</h2><ul>{items}</ul></div>')
        if result.html_report_path:
            parts.append(f'<div class="card"><p>HTML report: {_h(result.html_report_path)}</p></div>')
        return "\n".join(parts)
