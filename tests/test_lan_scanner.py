import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from netrecon.lan_scanner import LANScanner, _oui_lookup


class OuiLookupTests(unittest.TestCase):
    def test_lookup_known_oui(self):
        self.assertEqual(_oui_lookup("b8:27:eb:12:34:56"), "Raspberry Pi")

    def test_lookup_known_oui_dashes(self):
        self.assertEqual(_oui_lookup("B8-27-EB-12-34-56"), "Raspberry Pi")

    def test_lookup_unknown_oui(self):
        self.assertIsNone(_oui_lookup("11:22:33:44:55:66"))

    def test_lookup_none(self):
        self.assertIsNone(_oui_lookup(None))

    def test_lookup_empty(self):
        self.assertIsNone(_oui_lookup(""))


class LANScannerTests(unittest.TestCase):
    @patch.object(LANScanner, "_reverse_lookup", return_value="host1")
    @patch.object(LANScanner, "_read_arp_table", return_value={"192.168.1.1": "aa:bb:cc:dd:ee:ff"})
    @patch.object(LANScanner, "_ping_host", new_callable=AsyncMock)
    def test_scan_async(self, mock_ping, _mock_arp, _mock_reverse):
        mock_ping.side_effect = [True, False]
        scanner = LANScanner(max_workers=5)
        result = asyncio.run(scanner.scan_async("192.168.1.0/30"))
        self.assertEqual(len(result.active_hosts), 1)
        self.assertEqual(result.active_hosts[0].ip, "192.168.1.1")

    @patch.object(LANScanner, "_reverse_lookup", return_value="host1")
    @patch.object(LANScanner, "_read_arp_table", return_value={"192.168.1.1": "b8:27:eb:dd:ee:ff"})
    @patch.object(LANScanner, "_ping_host", new_callable=AsyncMock)
    def test_scan_async_with_vendor(self, mock_ping, _mock_arp, _mock_reverse):
        mock_ping.side_effect = [True, False]
        scanner = LANScanner(max_workers=5)
        result = asyncio.run(scanner.scan_async("192.168.1.0/30"))
        self.assertEqual(result.active_hosts[0].vendor, "Raspberry Pi")


if __name__ == "__main__":
    unittest.main()
