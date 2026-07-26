import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from netrecon.models import (
    CveLookupResult,
    ExternalIPInfo,
    LanHost,
    LanScanResult,
    PortScanResult,
    ReconResult,
    ScanOptions,
)
from netrecon.monitor import (
    ContinuousMonitor,
    compute_deltas,
    format_deltas,
    has_changes,
)


class DeltaComputeTests(unittest.TestCase):
    def test_no_changes_when_none(self):
        old = ReconResult(timestamp="a", hostname="h")
        new = ReconResult(timestamp="b", hostname="h")
        self.assertEqual(compute_deltas(old, new), {})

    def test_new_ports_detected(self):
        old = ReconResult(timestamp="a", hostname="h")
        old.port_scan = PortScanResult(target="x", open_ports=[80, 443])
        new = ReconResult(timestamp="b", hostname="h")
        new.port_scan = PortScanResult(target="x", open_ports=[80, 443, 8080])
        deltas = compute_deltas(old, new)
        self.assertIn("ports_opened", deltas)
        self.assertEqual(deltas["ports_opened"], [8080])

    def test_ports_closed(self):
        old = ReconResult(timestamp="a", hostname="h")
        old.port_scan = PortScanResult(target="x", open_ports=[80, 443, 8080])
        new = ReconResult(timestamp="b", hostname="h")
        new.port_scan = PortScanResult(target="x", open_ports=[80, 443])
        deltas = compute_deltas(old, new)
        self.assertIn("ports_closed", deltas)
        self.assertEqual(deltas["ports_closed"], [8080])

    def test_new_lan_hosts(self):
        old = ReconResult(timestamp="a", hostname="h")
        old.lan_scan = LanScanResult(cidr="192.168.1.0/24")
        new = ReconResult(timestamp="b", hostname="h")
        new.lan_scan = LanScanResult(
            cidr="192.168.1.0/24",
            active_hosts=[LanHost(ip="192.168.1.10")],
        )
        deltas = compute_deltas(old, new)
        self.assertIn("lan_hosts_added", deltas)
        self.assertEqual(deltas["lan_hosts_added"], ["192.168.1.10"])

    def test_lan_hosts_removed(self):
        old = ReconResult(timestamp="a", hostname="h")
        old.lan_scan = LanScanResult(
            cidr="192.168.1.0/24",
            active_hosts=[LanHost(ip="192.168.1.10"), LanHost(ip="192.168.1.11")],
        )
        new = ReconResult(timestamp="b", hostname="h")
        new.lan_scan = LanScanResult(
            cidr="192.168.1.0/24",
            active_hosts=[LanHost(ip="192.168.1.10")],
        )
        deltas = compute_deltas(old, new)
        self.assertIn("lan_hosts_removed", deltas)
        self.assertEqual(deltas["lan_hosts_removed"], ["192.168.1.11"])

    def test_external_ip_change(self):
        old = ReconResult(timestamp="a", hostname="h")
        old.external_info = ExternalIPInfo(ip="1.2.3.4")
        new = ReconResult(timestamp="b", hostname="h")
        new.external_info = ExternalIPInfo(ip="5.6.7.8")
        deltas = compute_deltas(old, new)
        self.assertIn("external_ip_changed", deltas)
        self.assertEqual(deltas["external_ip_changed"], {"from": "1.2.3.4", "to": "5.6.7.8"})


class HasChangesTests(unittest.TestCase):
    def test_empty(self):
        self.assertFalse(has_changes({}))

    def test_with_changes(self):
        self.assertTrue(has_changes({"ports_opened": [8080]}))


class FormatDeltasTests(unittest.TestCase):
    def test_format_ports_opened(self):
        text = format_deltas({"ports_opened": [8080, 8443]})
        self.assertIn("8080", text)
        self.assertIn("8443", text)


class ContinuousMonitorTests(unittest.TestCase):
    @patch("netrecon.monitor.ContinuousMonitor.run_async", new_callable=AsyncMock)
    def test_run_calls_run_async(self, mock_run):
        monitor = ContinuousMonitor(orchestrator=None, options=None)
        mock_run.return_value = None
        monitor.run()
        mock_run.assert_called_once()

    def test_initial_last_result_is_none(self):
        monitor = ContinuousMonitor(orchestrator=None, options=None)
        self.assertIsNone(monitor._last_result)

    def test_custom_interval(self):
        monitor = ContinuousMonitor(orchestrator=None, options=None, interval_seconds=120)
        self.assertEqual(monitor.interval, 120)


if __name__ == "__main__":
    unittest.main()
