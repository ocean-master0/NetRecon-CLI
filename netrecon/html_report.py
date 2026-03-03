from __future__ import annotations

import json
from pathlib import Path

from .models import ReconResult


class HTMLReportBuilder:
    """Build a dashboard-style HTML report for NetRecon results."""

    def generate(self, result: ReconResult, path: str | Path) -> Path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = result.to_dict()
        risk_score = result.risk_assessment.score if result.risk_assessment else 0
        risk_level = result.risk_assessment.level if result.risk_assessment else "Unknown"
        open_ports = result.port_scan.open_ports if result.port_scan else []
        banners = result.port_scan.banners if result.port_scan else []
        speed = result.speed_test
        threat = result.threat_intel
        geo_url = result.geo_map_url or ""

        rows = []
        for port in open_ports:
            banner_text = next((item.banner for item in banners if item.port == port), None)
            service_text = next((item.service for item in banners if item.port == port), "unknown")
            rows.append(
                "<tr>"
                f"<td>{port}</td>"
                f"<td>{service_text}</td>"
                f"<td>{(banner_text or '').replace('<', '&lt;').replace('>', '&gt;')}</td>"
                "</tr>"
            )
        port_rows = "\n".join(rows) or "<tr><td colspan='3'>No open ports detected</td></tr>"

        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetRecon HTML Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background:#f5f7fb; margin:0; padding:20px; color:#1b1f2a; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(320px,1fr)); gap:16px; }}
    .card {{ background:#fff; border-radius:12px; box-shadow:0 6px 20px rgba(0,0,0,0.06); padding:16px; }}
    h1 {{ margin-top:0; }}
    table {{ width:100%; border-collapse:collapse; }}
    th, td {{ border-bottom:1px solid #e8ecf4; text-align:left; padding:8px; font-size:14px; }}
    .critical {{ color:#b10020; font-weight:700; }}
    .high {{ color:#d35400; font-weight:700; }}
    .medium {{ color:#b58900; font-weight:700; }}
    .low {{ color:#2e7d32; font-weight:700; }}
  </style>
</head>
<body>
  <h1>NetRecon Report</h1>
  <p>Generated at: {result.timestamp}</p>
  <div class="grid">
    <div class="card">
      <h2>Summary</h2>
      <p><strong>Hostname:</strong> {result.hostname}</p>
      <p><strong>Mode:</strong> {result.mode}</p>
      <p><strong>External IP:</strong> {result.external_info.ip if result.external_info else 'N/A'}</p>
      <p><strong>Risk Score:</strong> {risk_score}/100</p>
      <p><strong>Risk Level:</strong> <span class="{risk_level.lower()}">{risk_level}</span></p>
      <canvas id="riskChart"></canvas>
    </div>
    <div class="card">
      <h2>Open Ports and Banners</h2>
      <table>
        <thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
        <tbody>
          {port_rows}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Speed Test</h2>
      <canvas id="speedChart"></canvas>
      <p>Download: {speed.download_mbps if speed else 0} Mbps</p>
      <p>Upload: {speed.upload_mbps if speed else 0} Mbps</p>
      <p>Ping: {speed.ping_ms if speed else 0} ms</p>
    </div>
    <div class="card">
      <h2>Threat Intelligence</h2>
      <p><strong>Malicious Score:</strong> {threat.malicious_score if threat else 0}</p>
      <p><strong>Blacklist Count:</strong> {threat.blacklist_count if threat else 0}</p>
      <p><strong>Spam Reports:</strong> {threat.spam_reports if threat else 0}</p>
      <p><strong>Known Vulns:</strong> {', '.join(threat.known_vulnerabilities) if threat and threat.known_vulnerabilities else 'None'}</p>
    </div>
  </div>
  <div class="card" style="margin-top:16px;">
    <h2>Geo Map</h2>
    <p><a href="{geo_url}" target="_blank" rel="noopener noreferrer">{geo_url or 'Unavailable'}</a></p>
    {"<iframe src='" + geo_url + "&output=embed' width='100%' height='450' loading='lazy'></iframe>" if geo_url else "<p>No map coordinates available.</p>"}
  </div>
  <div class="card" style="margin-top:16px;">
    <h2>Raw JSON Snapshot</h2>
    <pre style="white-space:pre-wrap;">{json.dumps(data, indent=2, ensure_ascii=False).replace('<', '&lt;').replace('>', '&gt;')}</pre>
  </div>
  <script>
    const riskScore = {risk_score};
    const riskCtx = document.getElementById('riskChart').getContext('2d');
    new Chart(riskCtx, {{
      type: 'doughnut',
      data: {{
        labels: ['Risk', 'Remaining'],
        datasets: [{{ data: [riskScore, 100 - riskScore], backgroundColor: ['#e53935','#cfd8dc'] }}]
      }},
      options: {{ responsive: true }}
    }});

    const speedCtx = document.getElementById('speedChart').getContext('2d');
    new Chart(speedCtx, {{
      type: 'bar',
      data: {{
        labels: ['Download Mbps', 'Upload Mbps', 'Ping ms'],
        datasets: [{{
          label: 'Network Metrics',
          data: [{speed.download_mbps if speed else 0}, {speed.upload_mbps if speed else 0}, {speed.ping_ms if speed else 0}],
          backgroundColor: ['#1e88e5', '#43a047', '#fb8c00']
        }}]
      }},
      options: {{ responsive: true }}
    }});
  </script>
</body>
</html>"""

        output_path.write_text(html, encoding="utf-8")
        return output_path
