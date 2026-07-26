import unittest
from unittest.mock import MagicMock, patch

from netrecon.tui_app import NetReconTuiApp, _AVAILABLE


class TuiTests(unittest.TestCase):
    def test_no_textual_fallback(self):
        app = NetReconTuiApp(orchestrator=MagicMock(), options=MagicMock())
        with patch("netrecon.tui_app._AVAILABLE", False):
            with patch("builtins.print") as mock_print:
                app.run()
                mock_print.assert_called_once()

    def test_import_available(self):
        self.assertIsInstance(_AVAILABLE, bool)


if __name__ == "__main__":
    unittest.main()
