import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from netrecon.subdomain_scanner import SubdomainScanner
from netrecon.models import SubdomainRecord


class SubdomainScannerTests(unittest.TestCase):
    @patch.object(SubdomainScanner, "_resolve_subdomain", new_callable=AsyncMock)
    def test_scan_async(self, mock_resolve):
        mock_resolve.side_effect = [
            SubdomainRecord(host="www.example.com", ip="1.1.1.1", response_ms=10.0),
            None,
        ]
        scanner = SubdomainScanner(wordlist=["www", "api"], max_workers=5)
        result = asyncio.run(scanner.scan_async("example.com"))
        self.assertEqual(result.scanned_count, 2)
        self.assertEqual(len(result.active_hosts), 1)
        self.assertEqual(result.active_hosts[0].host, "www.example.com")


if __name__ == "__main__":
    unittest.main()
