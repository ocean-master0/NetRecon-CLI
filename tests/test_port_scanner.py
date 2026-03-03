import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from netrecon.port_scanner import PortScanner


class PortScannerTests(unittest.TestCase):
    def test_parse_port_range(self):
        self.assertEqual(PortScanner.parse_port_range("1-3"), [1, 2, 3])
        with self.assertRaises(ValueError):
            PortScanner.parse_port_range("10-2")

    @patch.object(PortScanner, "_scan_single_port", new_callable=AsyncMock)
    def test_async_scan_ports(self, mock_scan):
        mock_scan.side_effect = [(22, "open"), (80, "closed"), (445, "filtered")]
        scanner = PortScanner(risky_ports=[445], max_workers=5)
        result = asyncio.run(scanner.scan_ports_async("127.0.0.1", [22, 80, 445], grab_banners=False))

        self.assertEqual(result.open_ports, [22])
        self.assertEqual(result.closed_ports, [80])
        self.assertEqual(result.filtered_ports, [445])


if __name__ == "__main__":
    unittest.main()
