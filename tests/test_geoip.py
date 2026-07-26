import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from netrecon.geoip import GeoIpLookup
from netrecon.models import GeoIpResult


class GeoIpModelTests(unittest.TestCase):
    def test_defaults(self):
        g = GeoIpResult(ip="8.8.8.8")
        self.assertEqual(g.ip, "8.8.8.8")
        self.assertEqual(g.source, "unknown")

    def test_to_dict(self):
        g = GeoIpResult(ip="1.1.1.1", country="US", source="test")
        d = g.to_dict()
        self.assertEqual(d["country"], "US")


class GeoIpLookupTests(unittest.TestCase):
    def test_no_db_fallback(self):
        lookup = GeoIpLookup(db_path="/nonexistent/nope.mmdb")
        result = lookup.lookup("8.8.8.8")
        self.assertEqual(result.ip, "8.8.8.8")
        self.assertEqual(result.source, "unavailable")

    def test_no_geoip2_module(self):
        lookup = GeoIpLookup(db_path=None)
        result = lookup.lookup("8.8.8.8")
        self.assertEqual(result.source, "unavailable")


if __name__ == "__main__":
    unittest.main()
