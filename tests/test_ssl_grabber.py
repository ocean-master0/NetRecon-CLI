import unittest
from unittest.mock import MagicMock, patch

from netrecon.models import SslCertResult
from netrecon.ssl_grabber import SslGrabber


class SslCertModelTests(unittest.TestCase):
    def test_defaults(self):
        s = SslCertResult(target="example.com")
        self.assertEqual(s.target, "example.com")
        self.assertEqual(s.port, 443)

    def test_to_dict(self):
        s = SslCertResult(target="test", self_signed=True)
        d = s.to_dict()
        self.assertTrue(d["self_signed"])
        self.assertEqual(d["target"], "test")


class SslGrabberTests(unittest.TestCase):
    def test_connection_refused(self):
        grabber = SslGrabber(timeout=1)
        result = grabber.grab("127.0.0.1", 1)
        self.assertTrue(result.warnings)

    def test_grab_invalid_host(self):
        grabber = SslGrabber(timeout=1)
        result = grabber.grab("nonexistent.invalid", 443)
        self.assertTrue(result.warnings)

    @patch("netrecon.ssl_grabber.SslGrabber.grab")
    def test_mocked_grab(self, mock_grab):
        mock_grab.return_value = SslCertResult(
            target="example.com", subject_cn="example.com", cipher="TLS_AES_256_GCM_SHA384", protocol="TLSv1.3"
        )
        grabber = SslGrabber()
        result = grabber.grab("example.com", 443)
        self.assertEqual(result.subject_cn, "example.com")
        self.assertEqual(result.protocol, "TLSv1.3")


if __name__ == "__main__":
    unittest.main()
