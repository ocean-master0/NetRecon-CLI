import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from rich.console import Console

from netrecon.models import ReconResult
from netrecon.renderer import render_rich, save_json_report, to_json


class RendererTests(unittest.TestCase):
    def test_json_and_save(self):
        result = ReconResult(timestamp="2026-02-22T00:00:00+00:00", hostname="demo")
        text = to_json(result)
        self.assertIn('"hostname": "demo"', text)
        with TemporaryDirectory() as temp_dir:
            path = save_json_report(result, Path(temp_dir) / "out.json")
            self.assertTrue(path.exists())

    def test_render_rich(self):
        result = ReconResult(timestamp="2026-02-22T00:00:00+00:00", hostname="demo")
        buffer = io.StringIO()
        console = Console(file=buffer, force_terminal=False, no_color=True, width=120)
        render_rich(console, result)
        self.assertTrue(buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
