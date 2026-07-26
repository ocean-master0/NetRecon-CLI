import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from netrecon.cve_lookup import (
    CveCache,
    CveLookup,
    _parse_nvd_response,
    _version_in_description,
)
from netrecon.models import CveLookupResult, CveRecord


class VersionFilterTests(unittest.TestCase):
    def test_version_found_in_text(self):
        self.assertTrue(_version_in_description("2.4.49", "Apache HTTPD 2.4.49 path traversal"))

    def test_version_not_found(self):
        self.assertFalse(_version_in_description("2.4.49", "Apache HTTPD 2.4.50 fixed the issue"))

    def test_partial_version_no_match(self):
        self.assertFalse(_version_in_description("1.1", "OpenSSL 1.1.1 vulnerability"))

    def test_version_at_start(self):
        self.assertTrue(_version_in_description("9.0", "OpenSSH 9.0 vulnerability in scp"))


class NvdParseTests(unittest.TestCase):
    def test_parse_valid_response(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTPD"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }
        result = _parse_nvd_response(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "CVE-2021-41773")
        self.assertEqual(result[0]["base_score"], 7.5)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_parse_empty(self):
        self.assertEqual(_parse_nvd_response({}), [])

    def test_parse_sorts_by_score(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2022-0002",
                        "descriptions": [{"lang": "en", "value": "Low severity"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"}}
                            ]
                        },
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2022-0001",
                        "descriptions": [{"lang": "en", "value": "High severity"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
                            ]
                        },
                    }
                },
            ]
        }
        result = _parse_nvd_response(data)
        self.assertEqual(result[0]["id"], "CVE-2022-0001")


class CveCacheTests(unittest.TestCase):
    def test_set_and_get(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Path(temp_dir) / "cve.db"
            cache = CveCache(db)
            cves = [{"id": "CVE-2021-41773", "base_score": 7.5, "severity": "HIGH", "description": "test", "cvss_vector": "vector"}]
            cache.set("apache httpd|2.4.49", cves)
            result = cache.get("apache httpd|2.4.49")
            self.assertIsNotNone(result)
            self.assertEqual(result[0]["id"], "CVE-2021-41773")

    def test_get_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Path(temp_dir) / "cve.db"
            cache = CveCache(db)
            self.assertIsNone(cache.get("nonexistent"))


class CveLookupTests(unittest.TestCase):
    def test_model_defaults(self):
        result = CveLookupResult(software="test")
        self.assertEqual(result.software, "test")
        self.assertEqual(result.total_found, 0)

    def test_cve_record_defaults(self):
        record = CveRecord(cve_id="CVE-2021-41773")
        self.assertEqual(record.cve_id, "CVE-2021-41773")
        self.assertIsNone(record.base_score)

    @patch.object(CveLookup, "lookup", new_callable=AsyncMock)
    def test_lookup_no_api(self, mock_lookup):
        mock_lookup.return_value = CveLookupResult(
            software="apache httpd",
            version="2.4.49",
            cves=[CveRecord(cve_id="CVE-2021-41773", base_score=7.5, severity="HIGH")],
            total_found=1,
        )
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "cve.db"
            lookup = CveLookup(api_key=None, db_path=db)
            result = lookup.lookup_without_api("apache httpd", "2.4.49")
            self.assertFalse(result.cves)
            self.assertTrue(result.warnings)


if __name__ == "__main__":
    unittest.main()
