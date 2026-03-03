import logging
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from netrecon.logging_utils import setup_logging


class LoggingTests(unittest.TestCase):
    def test_setup_logging_file(self):
        with TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "logs" / "netrecon.log"
            setup_logging(level="INFO", log_file=str(log_file))
            logging.getLogger("netrecon.test").info("hello")
            self.assertTrue(log_file.exists())
            root_logger = logging.getLogger()
            for handler in list(root_logger.handlers):
                root_logger.removeHandler(handler)
                handler.close()
            logging.shutdown()


if __name__ == "__main__":
    unittest.main()
