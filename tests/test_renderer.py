import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from rich.console import Console

from netrecon.models import (
    DNSAnalysisResult,
    LanHost,
    LanScanResult,
    PortScanResult,
    ReconResult,
    SubdomainRecord,
    SubdomainScanResult,
)
from netrecon.renderer import render_rich, save_csv_report, save_json_report, to_json


class RendererTests(unittest.TestCase):
    def test_json_and_save(self):
        result = ReconResult(timestamp="2026-02-22T00:00:00+00:00", hostname="demo")
        text = to_json(result)
        self.assertIn('"hostname": "demo"', text)
        with TemporaryDirectory() as temp_dir:
            path = save_json_report(result, Path(temp_dir) / "out.json")
            self.assertTrue(path.exists())

    def test_render_rich(self):
        result = ReconResult(timestamp="2026-02-22T00:00:00+00:00", hostname="demo")
        buffer = io.StringIO()
        console = Console(file=buffer, force_terminal=False, no_color=True, width=120)
        render_rich(console, result)
        self.assertTrue(buffer.getvalue())

    def test_save_csv_with_subdomains(self):
        result = ReconResult(timestamp="2026-02-22T00:00:00+00:00", hostname="demo")
        result.subdomains = SubdomainScanResult(
            domain="example.com",
            scanned_count=2,
            active_hosts=[
                SubdomainRecord(host="www.example.com", ip="1.1.1.1", response_ms=10.0),
                SubdomainRecord(host="mail.example.com", ip="2.2.2.2", response_ms=15.0),
            ],
        )
        with TemporaryDirectory() as temp_dir:
            path = save_csv_report(result, Path(temp_dir) / "out.csv")
            content = path.read_text(encoding="utf-8")
        self.assertIn("www.example.com", content)
        self.assertIn("mail.example.com", content)
        self.assertIn("1.1.1.1", content)

    def test_save_csv_with_lan_hosts(self):
        result = ReconResult(timestamp="2026-02-22T00:00:00+00:00", hostname="demo")
        result.lan_scan = LanScanResult(
            cidr="192.168.1.0/24",
            active_hosts=[
                LanHost(ip="192.168.1.1", hostname="router", mac_address="aa:bb:cc:dd:ee:ff", vendor="VendorX"),
            ],
        )
        with TemporaryDirectory() as temp_dir:
            path = save_csv_report(result, Path(temp_dir) / "out.csv")
            content = path.read_text(encoding="utf-8")
        self.assertIn("192.168.1.1", content)
        self.assertIn("VendorX", content)

    def test_save_csv_empty_result(self):
        result = ReconResult(timestamp="2026-02-22T00:00:00+00:00", hostname="demo")
        with TemporaryDirectory() as temp_dir:
            path = save_csv_report(result, Path(temp_dir) / "empty.csv")
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
