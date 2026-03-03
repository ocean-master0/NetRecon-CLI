import unittest
from unittest.mock import patch

from netrecon.ip_scanner import IPScanner
from netrecon.models import ExternalIPInfo


class IPScannerTests(unittest.TestCase):
    @patch("netrecon.ip_scanner.socket.gethostbyname_ex")
    @patch("netrecon.ip_scanner.socket.getaddrinfo")
    def test_collect_local_ips(self, mock_getaddrinfo, mock_gethostbyname_ex):
        mock_getaddrinfo.return_value = [
            (0, 0, 0, "", ("192.168.1.20", 0)),
            (0, 0, 0, "", ("192.168.1.20", 0)),
            (0, 0, 0, "", ("::1", 0, 0, 0)),
            (0, 0, 0, "", ("bad-ip", 0)),
        ]
        mock_gethostbyname_ex.return_value = ("host", [], [])
        scanner = IPScanner()
        self.assertEqual(scanner.collect_local_ips(), ["192.168.1.20", "::1"])

    def test_geo_url_generation(self):
        info = ExternalIPInfo(ip="1.1.1.1", latitude=10.5, longitude=20.6)
        url = IPScanner.build_geo_map_url(info)
        self.assertEqual(url, "https://www.google.com/maps?q=10.5,20.6")


if __name__ == "__main__":
    unittest.main()
