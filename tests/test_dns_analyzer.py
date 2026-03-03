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


if __name__ == "__main__":
    unittest.main()
