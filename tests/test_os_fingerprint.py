import unittest

from netrecon.os_fingerprint import _guess_os_from_ttl, _guess_os_from_window, _parse_ping_ttl
from netrecon.models import OsFingerprintResult


class OsFingerprintTtlTests(unittest.TestCase):
    def test_ttl_64_linux(self):
        os_name, confidence = _guess_os_from_ttl(64)
        self.assertEqual(os_name, "Linux")
        self.assertGreater(confidence, 0.9)

    def test_ttl_128_windows(self):
        os_name, confidence = _guess_os_from_ttl(128)
        self.assertEqual(os_name, "Windows")
        self.assertGreater(confidence, 0.9)

    def test_ttl_255_cisco(self):
        os_name, confidence = _guess_os_from_ttl(255)
        self.assertEqual(os_name, "Cisco IOS")

    def test_ttl_63_linux_after_hop(self):
        os_name, confidence = _guess_os_from_ttl(63)
        self.assertEqual(os_name, "Linux")

    def test_ttl_56_linux_far(self):
        os_name, confidence = _guess_os_from_ttl(56)
        self.assertEqual(os_name, "Linux")
        self.assertLess(confidence, 0.9)

    def test_ttl_unknown(self):
        os_name, confidence = _guess_os_from_ttl(1)
        self.assertIsNone(os_name)
        self.assertEqual(confidence, 0.0)

    def test_window_65535(self):
        os_name = _guess_os_from_window(65535)
        self.assertIn(os_name, ["FreeBSD", "macOS", "Windows XP"])

    def test_window_64240(self):
        os_name = _guess_os_from_window(64240)
        self.assertIn(os_name, ["Windows 10/11", "Linux (modern)"])

    def test_window_unknown(self):
        os_name = _guess_os_from_window(12345)
        self.assertIsNone(os_name)

    def test_parse_ping_ttl_windows(self):
        output = "Reply from 8.8.8.8: bytes=32 time=10ms TTL=117"
        self.assertEqual(_parse_ping_ttl(output), 117)

    def test_parse_ping_ttl_unix(self):
        output = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=54 time=10.0 ms"
        self.assertEqual(_parse_ping_ttl(output), 54)

    def test_parse_ping_ttl_none(self):
        self.assertIsNone(_parse_ping_ttl(""))


class OsFingerprintModelTests(unittest.TestCase):
    def test_model_defaults(self):
        result = OsFingerprintResult(host="8.8.8.8")
        self.assertEqual(result.host, "8.8.8.8")
        self.assertIsNone(result.guessed_os)
        self.assertEqual(result.confidence, 0.0)

    def test_model_with_data(self):
        result = OsFingerprintResult(
            host="8.8.8.8",
            guessed_os="Linux",
            confidence=0.95,
            ttl_observed=64,
            details=["TTL=64 suggests Linux"],
        )
        self.assertEqual(result.guessed_os, "Linux")
        self.assertEqual(result.ttl_observed, 64)

    def test_model_to_dict(self):
        result = OsFingerprintResult(host="8.8.8.8", guessed_os="Linux")
        data = result.to_dict()
        self.assertEqual(data["host"], "8.8.8.8")
        self.assertEqual(data["guessed_os"], "Linux")


if __name__ == "__main__":
    unittest.main()
