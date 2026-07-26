import asyncio
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, patch

from netrecon.subdomain_scanner import SubdomainScanner
from netrecon.models import SubdomainRecord


class SubdomainScannerTests(unittest.TestCase):
    def _make_scanner(self, wordlist=None, **kw):
        wl = wordlist or ["www"]
        return SubdomainScanner(wordlist=wl, max_workers=5)

    @patch.object(SubdomainScanner, "_crt_sh_subdomains", new_callable=AsyncMock)
    @patch.object(SubdomainScanner, "_detect_wildcard", new_callable=AsyncMock)
    @patch.object(SubdomainScanner, "_resolve_subdomain", new_callable=AsyncMock)
    def test_scan_async(self, mock_resolve, mock_wc, mock_crt):
        mock_crt.return_value = set()
        mock_wc.return_value = (False, None)
        mock_resolve.side_effect = [
            SubdomainRecord(host="www.example.com", ip="1.1.1.1", response_ms=10.0),
            None,
        ]
        scanner = self._make_scanner(wordlist=["www", "api"])
        result = asyncio.run(scanner.scan_async("example.com"))
        self.assertEqual(result.scanned_count, 2)
        self.assertEqual(len(result.active_hosts), 1)
        self.assertEqual(result.active_hosts[0].host, "www.example.com")

    @patch.object(SubdomainScanner, "_crt_sh_subdomains", new_callable=AsyncMock)
    @patch.object(SubdomainScanner, "_detect_wildcard", new_callable=AsyncMock)
    @patch.object(SubdomainScanner, "_resolve_subdomain", new_callable=AsyncMock)
    def test_wordlist_empty_file_falls_back(self, mock_resolve, mock_wc, mock_crt):
        mock_crt.return_value = set()
        mock_wc.return_value = (False, None)
        mock_resolve.return_value = None
        scanner = self._make_scanner(wordlist=["www"])
        result = asyncio.run(scanner.scan_async("example.com"))
        self.assertEqual(result.scanned_count, 1)

    @patch.object(SubdomainScanner, "_resolve_subdomain", new_callable=AsyncMock)
    def test_wordlist_deduplicates_and_sorts(self, mock_resolve):
        mock_resolve.return_value = None
        scanner = self._make_scanner(wordlist=["WWW", "www", " API ", "api"])
        self.assertEqual(scanner.wordlist, ["api", "www"])

    @patch.object(SubdomainScanner, "_crt_sh_subdomains", new_callable=AsyncMock)
    @patch.object(SubdomainScanner, "_resolve_subdomain", new_callable=AsyncMock)
    def test_wildcard_detected(self, mock_resolve, mock_crt):
        mock_crt.return_value = set()
        async def side_effect(fqdn):
            if "zxqj" in fqdn or "abc123" in fqdn or secrets.token_hex in str(fqdn):
                return SubdomainRecord(host=fqdn, ip="1.2.3.4", response_ms=5.0)
            return None

        with patch.object(SubdomainScanner, "_detect_wildcard", new_callable=AsyncMock) as mock_wc:
            mock_wc.return_value = (True, "1.2.3.4")
            scanner = self._make_scanner(wordlist=["www"])
            result = asyncio.run(scanner.scan_async("example.com"))
            self.assertTrue(result.wildcard_detected)
            self.assertEqual(result.wildcard_ip, "1.2.3.4")
            self.assertTrue(any("Wildcard" in w for w in result.warnings))

    @patch.object(SubdomainScanner, "_crt_sh_subdomains", new_callable=AsyncMock)
    @patch.object(SubdomainScanner, "_resolve_subdomain", new_callable=AsyncMock)
    def test_no_wildcard(self, mock_resolve, mock_crt):
        mock_crt.return_value = set()
        with patch.object(SubdomainScanner, "_detect_wildcard", new_callable=AsyncMock) as mock_wc:
            mock_wc.return_value = (False, None)
            scanner = self._make_scanner(wordlist=["www"])
            result = asyncio.run(scanner.scan_async("example.com"))
            self.assertFalse(result.wildcard_detected)
            self.assertIsNone(result.wildcard_ip)


if __name__ == "__main__":
    unittest.main()
