import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from netrecon.config import AppConfig, ConfigLoader


class ConfigLoaderTests(unittest.TestCase):
    def test_missing_config_uses_defaults(self):
        config = ConfigLoader("missing_config.json").load()
        self.assertIsInstance(config, AppConfig)
        self.assertEqual(config.mode, "active")

    def test_load_config_values(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "mode": "passive",
                        "default_port_range": "5-10",
                        "external_workers": 9,
                        "api_keys": {"abuseipdb": "abc"},
                    }
                ),
                encoding="utf-8",
            )
            config = ConfigLoader(path).load()

        self.assertEqual(config.mode, "passive")
        self.assertEqual(config.default_port_range, "5-10")
        self.assertEqual(config.external_workers, 9)
        self.assertEqual(config.api_keys["abuseipdb"], "abc")


if __name__ == "__main__":
    unittest.main()
