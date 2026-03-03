import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from netrecon.threat_intel import ThreatIntelChecker


class ThreatIntelTests(unittest.TestCase):
    @patch.object(ThreatIntelChecker, "_check_abuseipdb", new_callable=AsyncMock)
    @patch.object(ThreatIntelChecker, "_check_virustotal", new_callable=AsyncMock)
    @patch.object(ThreatIntelChecker, "_check_shodan", new_callable=AsyncMock)
    def test_check_ip_async(self, mock_shodan, mock_vt, mock_abuse):
        checker = ThreatIntelChecker(api_keys={"abuseipdb": "a", "virustotal": "b", "shodan": "c"})
        mock_abuse.return_value = (
            "abuseipdb",
            {"data": {"abuseConfidenceScore": 75, "totalReports": 25}},
            None,
        )
        mock_vt.return_value = (
            "virustotal",
            {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1}}}},
            None,
        )
        mock_shodan.return_value = ("shodan", {"vulns": {"CVE-2024-0001": {}}}, None)

        result = asyncio.run(checker.check_ip_async("8.8.8.8"))
        self.assertGreaterEqual(result.malicious_score, 30)
        self.assertGreaterEqual(result.blacklist_count, 1)
        self.assertIn("CVE-2024-0001", result.known_vulnerabilities)

    def test_no_api_keys_is_clean_skip(self):
        checker = ThreatIntelChecker(api_keys={})
        result = asyncio.run(checker.check_ip_async("8.8.8.8"))
        self.assertFalse(result.warnings)
        self.assertIn("status", result.source_details)
        self.assertEqual(result.source_details["status"].get("state"), "skipped")


if __name__ == "__main__":
    unittest.main()
