import unittest
from unittest.mock import patch

from netrecon.models import WhoisResult
from netrecon.whois_lookup import WhoisLookup


class WhoisLookupTests(unittest.TestCase):
    @patch.object(WhoisLookup, "_lookup_with_python_whois")
    def test_lookup_primary(self, mock_primary):
        mock_primary.return_value = WhoisResult(query="8.8.8.8", asn="AS15169")
        result, warnings = WhoisLookup().lookup("8.8.8.8")
        self.assertEqual(result.asn, "AS15169")
        self.assertFalse(warnings)

    @patch.object(WhoisLookup, "_lookup_raw_whois")
    @patch.object(WhoisLookup, "_lookup_with_python_whois", return_value=None)
    def test_lookup_fallback(self, _mock_primary, mock_raw):
        mock_raw.return_value = WhoisResult(query="1.1.1.1", organization="Cloudflare")
        result, warnings = WhoisLookup().lookup("1.1.1.1")
        self.assertEqual(result.organization, "Cloudflare")
        self.assertFalse(warnings)


if __name__ == "__main__":
    unittest.main()
