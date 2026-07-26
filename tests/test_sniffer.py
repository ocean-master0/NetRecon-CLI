import builtins
import unittest
from unittest.mock import MagicMock, patch

from netrecon.sniffer import PacketSniffer

FAKE_SCAPY_CODE = '''
class ARP:
    pass
class DNS:
    pass
class DNSRR:
    pass
class IP:
    pass
def sniff(**kw):
    return []
'''


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

    def test_sniffer_result_pcap_field(self):
        from netrecon.models import SnifferResult
        r = SnifferResult(packets_captured=10, pcap_path="/tmp/test.pcap")
        self.assertEqual(r.pcap_path, "/tmp/test.pcap")
        d = r.to_dict()
        self.assertEqual(d["pcap_path"], "/tmp/test.pcap")


class SnifferWithMockTests(unittest.TestCase):
    @patch("netrecon.sniffer.PacketSniffer.capture")
    def test_mocked_capture(self, mock_capture):
        from netrecon.models import SnifferResult
        mock_capture.return_value = SnifferResult(
            packets_captured=5,
            pcap_path="out.pcap",
        )
        result = PacketSniffer().capture(limit=10, timeout=1, filter_bpf="tcp", pcap_path="out.pcap")
        self.assertEqual(result.packets_captured, 5)
        self.assertEqual(result.pcap_path, "out.pcap")


if __name__ == "__main__":
    unittest.main()
