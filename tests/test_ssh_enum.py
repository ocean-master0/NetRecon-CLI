import struct
import unittest
from unittest.mock import MagicMock, patch

from netrecon.models import SshEnumResult
from netrecon.ssh_enum import SshEnumerator


class SshModelTests(unittest.TestCase):
    def test_defaults(self):
        s = SshEnumResult(target="example.com")
        self.assertEqual(s.target, "example.com")
        self.assertEqual(s.port, 22)

    def test_to_dict(self):
        s = SshEnumResult(target="test", banner="SSH-2.0-OpenSSH_8.9")
        d = s.to_dict()
        self.assertEqual(d["banner"], "SSH-2.0-OpenSSH_8.9")


class SshEnumeratorTests(unittest.TestCase):
    def test_connection_refused(self):
        enum = SshEnumerator(timeout=1)
        result = enum.enumerate("127.0.0.1", 1)
        self.assertTrue(result.warnings)

    def test_invalid_host(self):
        enum = SshEnumerator(timeout=1)
        result = enum.enumerate("nonexistent.invalid", 22)
        self.assertTrue(result.warnings)

    @staticmethod
    def _build_kex_init(kex: str, hostkey: str, enc: str, mac: str, comp: str) -> bytes:
        cookie = b"\x00" * 16
        def nl(s: str) -> bytes:
            raw = s.encode()
            return struct.pack(">I", len(raw)) + raw
        msg = b"\x14" + cookie
        msg += nl(kex) + nl(hostkey) + nl(enc) + nl(enc) + nl(mac) + nl(mac) + nl(comp) + nl(comp)
        msg += nl("") + nl("")
        msg += b"\x00\x00\x00\x00"
        return msg

    def test_parse_kex_simple(self):
        import struct
        data = self._build_kex_init(
            kex="curve25519-sha256,diffie-hellman-group14-sha256",
            hostkey="ssh-rsa,ssh-ed25519",
            enc="aes256-ctr,aes128-ctr",
            mac="hmac-sha2-256,hmac-sha1",
            comp="none,zlib",
        )
        result = SshEnumResult(target="test")
        result = SshEnumerator._parse_kex_init(result, data)
        self.assertIn("curve25519-sha256", result.kex_algorithms)
        self.assertIn("ssh-rsa", result.host_key_algorithms)
        self.assertIn("aes256-ctr", result.encryption_algorithms)
        self.assertIn("hmac-sha2-256", result.mac_algorithms)
        self.assertIn("none", result.compression_algorithms)

    def test_parse_kex_empty(self):
        result = SshEnumResult(target="test")
        result = SshEnumerator._parse_kex_init(result, b"")
        self.assertEqual(result.kex_algorithms, [])

    @patch("netrecon.ssh_enum.SshEnumerator.enumerate")
    def test_mocked_enum(self, mock_enum):
        mock_enum.return_value = SshEnumResult(
            target="example.com",
            banner="SSH-2.0-OpenSSH_9.0",
            software_version="OpenSSH_9.0",
            kex_algorithms=["curve25519-sha256"],
        )
        enum = SshEnumerator()
        result = enum.enumerate("example.com", 22)
        self.assertEqual(result.software_version, "OpenSSH_9.0")
        self.assertIn("curve25519-sha256", result.kex_algorithms)


if __name__ == "__main__":
    unittest.main()
