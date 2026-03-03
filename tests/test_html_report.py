from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from netrecon.html_report import HTMLReportBuilder
from netrecon.models import ReconResult, RiskAssessment


class HTMLReportTests(unittest.TestCase):
    def test_generate_html(self):
        result = ReconResult(
            timestamp="2026-02-22T00:00:00+00:00",
            hostname="demo",
            risk_assessment=RiskAssessment(score=50, level="High"),
        )
        with TemporaryDirectory() as temp_dir:
            output = HTMLReportBuilder().generate(result, Path(temp_dir) / "report.html")
            self.assertTrue(output.exists())
            content = output.read_text(encoding="utf-8")
            self.assertIn("NetRecon Report", content)


if __name__ == "__main__":
    unittest.main()
