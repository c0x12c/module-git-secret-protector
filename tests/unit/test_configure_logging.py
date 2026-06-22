import logging
import logging.handlers
import sys
import unittest
from unittest.mock import patch, MagicMock

from git_secret_protector.utils.configure_logging import configure_logging


class TestConfigureLogging(unittest.TestCase):
    @patch("git_secret_protector.utils.configure_logging.get_settings")
    def _run(self, verbose, mock_get_settings, tmp_log="/tmp/gsp-test.log"):
        s = MagicMock()
        s.log_file = tmp_log
        s.log_level = "WARN"
        s.log_max_size = 1048576
        s.log_backup_count = 1
        mock_get_settings.return_value = s
        root = logging.getLogger()
        root.handlers = []
        configure_logging(verbose=verbose)
        return root.handlers

    def test_verbose_adds_stderr_stream_handler(self):
        handlers = self._run(True)
        stream = [
            h
            for h in handlers
            if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.handlers.RotatingFileHandler)
        ]
        self.assertTrue(stream)
        self.assertIs(stream[0].stream, sys.stderr)

    def test_non_verbose_has_no_extra_stream_handler(self):
        handlers = self._run(False)
        stream = [h for h in handlers if type(h) is logging.StreamHandler]
        self.assertEqual(stream, [])
