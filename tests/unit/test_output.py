# tests/unit/test_output.py
import contextlib
import io
import json
import unittest

from git_secret_protector.core.output import Output


class TestOutput(unittest.TestCase):
    def _capture(self, fn):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            fn()
        return out.getvalue(), err.getvalue()

    def test_normal_info_to_stdout(self):
        out, err = self._capture(lambda: Output().info("hi"))
        self.assertEqual(out, "hi\n")
        self.assertEqual(err, "")

    def test_error_to_stderr_always(self):
        out, err = self._capture(lambda: Output(quiet=True).error("boom"))
        self.assertEqual(out, "")
        self.assertEqual(err, "boom\n")

    def test_quiet_suppresses_info_and_progress(self):
        out, err = self._capture(
            lambda: (Output(quiet=True).info("x"), Output(quiet=True).progress("p"))
        )
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_progress_to_stderr_in_normal(self):
        out, err = self._capture(lambda: Output().progress("[1/2] a"))
        self.assertEqual(out, "")
        self.assertEqual(err, "[1/2] a\n")

    def test_json_result_to_stdout(self):
        out, err = self._capture(lambda: Output(json=True).result({"ok": True}))
        self.assertEqual(json.loads(out), {"ok": True})
        self.assertEqual(err, "")

    def test_json_suppresses_info_and_progress(self):
        out, err = self._capture(
            lambda: (Output(json=True).info("x"), Output(json=True).progress("p"))
        )
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_result_noop_in_human_mode(self):
        out, err = self._capture(lambda: Output().result({"ok": True}))
        self.assertEqual(out, "")
