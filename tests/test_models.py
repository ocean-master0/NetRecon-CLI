import unittest

from netrecon.models import ExternalIPInfo, ReconResult


class ModelTests(unittest.TestCase):
    def test_external_coordinates(self):
        info = ExternalIPInfo(ip="1.1.1.1", latitude=1.2, longitude=3.4)
        self.assertEqual(info.coordinates, "1.2,3.4")

    def test_recon_result_to_dict(self):
        result = ReconResult(timestamp="2026-02-22T00:00:00+00:00", hostname="x")
        data = result.to_dict()
        self.assertEqual(data["hostname"], "x")


if __name__ == "__main__":
    unittest.main()
