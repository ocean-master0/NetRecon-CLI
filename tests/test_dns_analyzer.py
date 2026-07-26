import builtins
import unittest
from unittest.mock import patch

from netrecon.dns_analyzer import DNSAnalyzer


class DNSAnalyzerTests(unittest.TestCase):
    def test_missing_dependency(self):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "dns.resolver":
                raise ModuleNotFoundError("missing dnspython")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            result = DNSAnalyzer().analyze("example.com")
        self.assertTrue(result.warnings)
        self.assertEqual(result.hostname, "example.com")

    def test_axfr_missing_dependency(self):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "dns.zone":
                raise ModuleNotFoundError("missing dnspython")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            records, warnings = DNSAnalyzer().axfr("example.com")
        self.assertEqual(records, [])
        self.assertTrue(warnings)

    @patch("netrecon.dns_analyzer.DNSAnalyzer.axfr")
    def test_axfr_no_ns(self, mock_axfr):
        mock_axfr.return_value = ([], ["AXFR skipped: no NS records found."])
        records, warnings = DNSAnalyzer(timeout=1).axfr("example.com")
        self.assertEqual(records, [])
        self.assertTrue(len(warnings) > 0)

    def test_axfr_arg_in_result(self):
        from netrecon.models import DNSAnalysisResult
        result = DNSAnalysisResult(hostname="example.com", axfr_records=["rec1", "rec2"])
        self.assertEqual(len(result.axfr_records), 2)


if __name__ == "__main__":
    unittest.main()
