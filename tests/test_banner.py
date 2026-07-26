import asyncio
import unittest

from netrecon.banner import BannerGrabber


class BannerGrabberTests(unittest.TestCase):
    def test_guess_service(self):
        grabber = BannerGrabber()
        self.assertEqual(grabber._guess_service(22), "ssh")
        self.assertEqual(grabber._guess_service(9999), "unknown")

    def test_infer_service_from_banner(self):
        grabber = BannerGrabber()
        service, version = grabber._infer_service(3306, "5.7.41-MySQL")
        self.assertEqual(service, "mysql")
        self.assertEqual(version, "5.7.41")

    def test_grab_banner_invalid_target(self):
        grabber = BannerGrabber(timeout=0.2)
        result = asyncio.run(grabber.grab_banner_async("127.0.0.1", 1))
        self.assertEqual(result.port, 1)


if __name__ == "__main__":
    unittest.main()
