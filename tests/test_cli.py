import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
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

    def test_subdomain_wordlist_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--subdomain", "example.com", "--subdomain-wordlist", "my_words.txt"])
        self.assertEqual(args.subdomain, "example.com")
        self.assertEqual(args.subdomain_wordlist, "my_words.txt")

    def test_save_csv_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--save-csv"])
        self.assertEqual(args.save_csv, "")

    def test_save_csv_arg_with_path(self):
        parser = build_parser()
        args = parser.parse_args(["--save-csv", "out.csv"])
        self.assertEqual(args.save_csv, "out.csv")

    def test_init_config_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--init-config"])
        self.assertTrue(args.init_config)

    def test_dns_axfr_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--dns-axfr", "example.com"])
        self.assertEqual(args.dns_axfr, "example.com")

    def test_os_fingerprint_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--os-fingerprint", "8.8.8.8"])
        self.assertEqual(args.os_fingerprint, "8.8.8.8")

    def test_cve_lookup_args(self):
        parser = build_parser()
        args = parser.parse_args(["--cve-lookup", "apache httpd", "--cve-version", "2.4.49"])
        self.assertEqual(args.cve_lookup, "apache httpd")
        self.assertEqual(args.cve_version, "2.4.49")

    def test_watch_args(self):
        parser = build_parser()
        args = parser.parse_args(["--watch", "--watch-interval", "30"])
        self.assertTrue(args.watch)
        self.assertEqual(args.watch_interval, 30)

    def test_watch_default_interval(self):
        parser = build_parser()
        args = parser.parse_args(["--watch"])
        self.assertTrue(args.watch)
        self.assertEqual(args.watch_interval, 60)

    def test_serve_args(self):
        parser = build_parser()
        args = parser.parse_args(["--serve", "--serve-host", "0.0.0.0", "--serve-port", "9090"])
        self.assertTrue(args.serve)
        self.assertEqual(args.serve_host, "0.0.0.0")
        self.assertEqual(args.serve_port, 9090)

    def test_serve_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["--serve"])
        self.assertTrue(args.serve)
        self.assertEqual(args.serve_host, "127.0.0.1")
        self.assertEqual(args.serve_port, 8088)

    def test_plugin_args(self):
        parser = build_parser()
        args = parser.parse_args(["--plugin-dir", "my_plugins", "--list-plugins"])
        self.assertEqual(args.plugin_dir, "my_plugins")
        self.assertTrue(args.list_plugins)

    def test_ssl_enum_args(self):
        parser = build_parser()
        args = parser.parse_args(["--ssl-enum", "example.com", "--ssl-port", "8443"])
        self.assertEqual(args.ssl_enum, "example.com")
        self.assertEqual(args.ssl_port, 8443)

    def test_ssh_enum_args(self):
        parser = build_parser()
        args = parser.parse_args(["--ssh-enum", "example.com", "--ssh-port", "2222"])
        self.assertEqual(args.ssh_enum, "example.com")
        self.assertEqual(args.ssh_port, 2222)

    def test_geoip_db_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--geoip-db", "data/GeoLite2-City.mmdb"])
        self.assertEqual(args.geoip_db, "data/GeoLite2-City.mmdb")

    def test_sniff_filter_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--sniff", "--sniff-filter", "tcp port 80", "--sniff-pcap", "out.pcap"])
        self.assertTrue(args.sniff)
        self.assertEqual(args.sniff_filter, "tcp port 80")
        self.assertEqual(args.sniff_pcap, "out.pcap")

    def test_tui_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--tui"])
        self.assertTrue(args.tui)

    def test_init_config_generates_file(self):
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            code = main(["--init-config", "--config", str(config_path)])
            self.assertEqual(code, 0)
            self.assertTrue(config_path.exists())
            data = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(data["mode"], "active")

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
