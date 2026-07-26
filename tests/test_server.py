import json
import unittest
from unittest.mock import MagicMock, patch

from netrecon.models import ReconResult, ScanOptions
from netrecon.server import ApiServer


class ApiServerInitTests(unittest.TestCase):
    def test_default_values(self):
        server = ApiServer()
        self.assertEqual(server.host, "127.0.0.1")
        self.assertEqual(server.port, 8088)
        self.assertIsNone(server._last_result)

    def test_custom_host_port(self):
        server = ApiServer(host="0.0.0.0", port=9090)
        self.assertEqual(server.host, "0.0.0.0")
        self.assertEqual(server.port, 9090)

    def test_initial_state(self):
        server = ApiServer()
        self.assertFalse(server._scan_in_progress)
        self.assertEqual(server._cycle_count, 0)


class ApiServerScanTests(unittest.TestCase):
    def test_run_scan_calls_orchestrator(self):
        mock_orch = MagicMock()
        mock_orch.run.return_value = ReconResult(timestamp="t", hostname="h")
        server = ApiServer(options=ScanOptions(target="test"), orchestrator=mock_orch)
        server._run_scan()
        mock_orch.run.assert_called_once()
        self.assertIsNotNone(server._last_result)
        self.assertIsNotNone(server._last_scan_time)
        self.assertEqual(server._cycle_count, 1)

    def test_run_scan_handles_error(self):
        mock_orch = MagicMock()
        mock_orch.run.side_effect = RuntimeError("boom")
        server = ApiServer(options=ScanOptions(target="test"), orchestrator=mock_orch)
        server._run_scan()
        self.assertFalse(server._scan_in_progress)

    def test_run_scan_rejects_concurrent(self):
        mock_orch = MagicMock()
        mock_orch.run.return_value = ReconResult(timestamp="t", hostname="h")
        server = ApiServer(options=ScanOptions(target="test"), orchestrator=mock_orch)
        server._scan_in_progress = True
        server._run_scan()
        self.assertTrue(server._scan_in_progress)


class ApiServerResultsTests(unittest.TestCase):
    def test_results_none_initially(self):
        server = ApiServer()
        self.assertIsNone(server._last_result)

    def test_results_after_scan(self):
        mock_orch = MagicMock()
        mock_orch.run.return_value = ReconResult(timestamp="t", hostname="h")
        server = ApiServer(options=ScanOptions(target="test"), orchestrator=mock_orch)
        server._run_scan()
        self.assertEqual(server._last_result.hostname, "h")


class ApiServerShutdownTests(unittest.TestCase):
    def test_shutdown_sets_flag(self):
        server = ApiServer()
        server._httpd = MagicMock()
        server.shutdown()
        server._httpd.shutdown.assert_called_once()


if __name__ == "__main__":
    unittest.main()
