import builtins
import unittest
from unittest.mock import patch

from netrecon.sniffer import PacketSniffer


class SnifferTests(unittest.TestCase):
    def test_missing_scapy_dependency(self):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "scapy.all":
                raise ModuleNotFoundError("missing scapy")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            result = PacketSniffer().capture(limit=10, timeout=1)
        self.assertEqual(result.packets_captured, 0)
        self.assertTrue(any("scapy" in warning.lower() for warning in result.warnings))


if __name__ == "__main__":
    unittest.main()
