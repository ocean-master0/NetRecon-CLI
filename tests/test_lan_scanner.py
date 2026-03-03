import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from netrecon.lan_scanner import LANScanner


class LANScannerTests(unittest.TestCase):
    @patch.object(LANScanner, "_reverse_lookup", return_value="host1")
    @patch.object(LANScanner, "_read_arp_table", return_value={"192.168.1.1": "aa:bb:cc:dd:ee:ff"})
    @patch.object(LANScanner, "_ping_host", new_callable=AsyncMock)
    def test_scan_async(self, mock_ping, _mock_arp, _mock_reverse):
        # 192.168.1.0/30 => hosts .1 and .2
        mock_ping.side_effect = [True, False]
        scanner = LANScanner(max_workers=5)
        result = asyncio.run(scanner.scan_async("192.168.1.0/30"))
        self.assertEqual(len(result.active_hosts), 1)
        self.assertEqual(result.active_hosts[0].ip, "192.168.1.1")


if __name__ == "__main__":
    unittest.main()
