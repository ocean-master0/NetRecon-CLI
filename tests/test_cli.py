import io
import json
import unittest
from unittest.mock import MagicMock, patch

from netrecon.cli import build_parser, main, resolve_scan_options
from netrecon.config import AppConfig
from netrecon.models import ReconResult


class CLITests(unittest.TestCase):
    def test_resolve_mode_and_range(self):
        parser = build_parser()
        args = parser.parse_args(["--mode", "passive", "--scan-ports", "10-20"])
        options = resolve_scan_options(args, AppConfig())
        self.assertEqual(options.mode, "passive")
        self.assertEqual(options.scan_port_range, "10-20")

    def test_invalid_lan_cidr(self):
        parser = build_parser()
        args = parser.parse_args(["--lan-scan", "invalid"])
        with self.assertRaises(ValueError):
            resolve_scan_options(args, AppConfig())

    @patch("netrecon.cli.NetReconOrchestrator")
    @patch("netrecon.cli.ConfigLoader")
    def test_main_json_output(self, mock_loader_class, mock_orchestrator_class):
        mock_loader_class.return_value.load.return_value = AppConfig()
        fake_result = ReconResult(timestamp="2026-02-22T00:00:00+00:00", hostname="demo-host")
        mock_orchestrator = MagicMock()
        mock_orchestrator.run.return_value = fake_result
        mock_orchestrator_class.return_value = mock_orchestrator

        out = io.StringIO()
        with patch("sys.stdout", new=out):
            code = main(["--json", "--no-external"])
        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["hostname"], "demo-host")


if __name__ == "__main__":
    unittest.main()
