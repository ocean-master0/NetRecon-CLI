import builtins
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from netrecon.speed_test import SpeedTester


class _FakeResults:
    ping = 10.0


class _FakeSpeedtest:
    def __init__(self):
        self.results = _FakeResults()

    def get_best_server(self):
        return {"latency": 12.5, "name": "Demo", "country": "IN"}

    def download(self):
        return 100_000_000

    def upload(self):
        return 40_000_000


class SpeedTestModuleTests(unittest.TestCase):
    def test_missing_dependency(self):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "speedtest":
                raise ModuleNotFoundError("missing speedtest")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            result, warnings = SpeedTester().run()
        self.assertIsNone(result)
        self.assertTrue(warnings)

    def test_success(self):
        fake_module = SimpleNamespace(Speedtest=_FakeSpeedtest)
        with patch.dict("sys.modules", {"speedtest": fake_module}):
            result, warnings = SpeedTester().run()
        self.assertFalse(warnings)
        self.assertEqual(result.download_mbps, 100.0)


if __name__ == "__main__":
    unittest.main()
