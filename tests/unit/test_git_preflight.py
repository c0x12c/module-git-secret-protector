import os
import subprocess
import unittest
from unittest.mock import patch

from git_secret_protector.core.git_preflight import check_repo_preflight


def _cp(stdout="", returncode=0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=""
    )


class TestCheckRepoPreflight(unittest.TestCase):
    """check_repo_preflight is pure git-command plumbing, so subprocess.run is
    mocked call-by-call rather than exercised against a real repo - each test
    asserts one gate in isolation, matching the shell script this ports."""

    def _run_git_side_effects(self, responses):
        """responses: list of (args_substring, CompletedProcess) matched in order
        of the first git subcommand token, e.g. "symbolic-ref"."""

        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            # cmd[0] is "git"; cmd[1] is the subcommand.
            for key, result in responses:
                if key in cmd:
                    return result
            # The cleanliness probe runs on EVERY preflight, so answering it clean by
            # default keeps each test about the one gate it names. A test that cares
            # about cleanliness lists its own response above and wins by precedence.
            if cmd[1] in ("update-index", "diff"):
                return _cp()
            raise AssertionError(f"unexpected git call: {cmd}")

        return fake_run

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_detached_head_is_refused(self, mock_run):
        mock_run.side_effect = self._run_git_side_effects(
            [
                ("symbolic-ref", _cp(returncode=1)),
                ("rev-parse", _cp(stdout="abc1234\n")),
                ("ls-files", _cp(returncode=0)),
            ]
        )

        refusals = check_repo_preflight(["a.txt"], cwd="/repo")

        self.assertEqual(len(refusals), 1)
        self.assertIn("detached", refusals[0])
        self.assertIn("abc1234", refusals[0])

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_behind_upstream_is_refused(self, mock_run):
        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            if "symbolic-ref" in cmd:
                return _cp(stdout="master\n")
            if cmd[1:4] == ["config", "--get", "branch.master.remote"]:
                return _cp(stdout="origin\n")
            if cmd[1:4] == ["config", "--get", "branch.master.merge"]:
                return _cp(stdout="refs/heads/master\n")
            if "fetch" in cmd:
                return _cp()
            if "rev-list" in cmd:
                return _cp(stdout="7\n")
            if "ls-files" in cmd:
                return _cp(returncode=0)
            if cmd[1] in ("update-index", "diff"):
                return _cp()
            raise AssertionError(f"unexpected git call: {cmd}")

        mock_run.side_effect = fake_run

        refusals = check_repo_preflight(["a.txt"], cwd="/repo")

        self.assertEqual(len(refusals), 1)
        self.assertIn("7 commit(s) behind", refusals[0])
        self.assertIn("origin/master", refusals[0])

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_unmeasurable_behind_count_fails_closed(self, mock_run):
        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            if "symbolic-ref" in cmd:
                return _cp(stdout="master\n")
            if cmd[1:4] == ["config", "--get", "branch.master.remote"]:
                return _cp(stdout="origin\n")
            if cmd[1:4] == ["config", "--get", "branch.master.merge"]:
                return _cp(stdout="refs/heads/master\n")
            if "fetch" in cmd:
                return _cp()
            if "rev-list" in cmd:
                # Measurement failure - a missing ref, an unreadable object.
                return _cp(returncode=1, stdout="")
            if "ls-files" in cmd:
                return _cp(returncode=0)
            if cmd[1] in ("update-index", "diff"):
                return _cp()
            raise AssertionError(f"unexpected git call: {cmd}")

        mock_run.side_effect = fake_run

        refusals = check_repo_preflight(["a.txt"], cwd="/repo")

        self.assertEqual(len(refusals), 1)
        self.assertIn("cannot measure", refusals[0])

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_no_upstream_warns_but_allows(self, mock_run):
        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            if "symbolic-ref" in cmd:
                return _cp(stdout="master\n")
            if cmd[1:4] == ["config", "--get", "branch.master.remote"]:
                return _cp(returncode=1)  # not configured
            if cmd[1:4] == ["config", "--get", "branch.master.merge"]:
                return _cp(returncode=1)
            if "ls-files" in cmd:
                return _cp(returncode=0)
            if cmd[1] in ("update-index", "diff"):
                return _cp()
            raise AssertionError(f"unexpected git call: {cmd}")

        mock_run.side_effect = fake_run

        refusals = check_repo_preflight(["a.txt"], cwd="/repo")

        self.assertEqual(refusals, [])

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_untracked_matched_file_is_refused(self, mock_run):
        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            if "symbolic-ref" in cmd:
                return _cp(stdout="master\n")
            if cmd[1:4] == ["config", "--get", "branch.master.remote"]:
                return _cp(returncode=1)
            if cmd[1:4] == ["config", "--get", "branch.master.merge"]:
                return _cp(returncode=1)
            if "ls-files" in cmd:
                # Untracked -> git ls-files --error-unmatch exits non-zero.
                return _cp(returncode=1)
            if cmd[1] in ("update-index", "diff"):
                return _cp()
            raise AssertionError(f"unexpected git call: {cmd}")

        mock_run.side_effect = fake_run

        refusals = check_repo_preflight(["secret.txt"], cwd="/repo")

        self.assertEqual(len(refusals), 1)
        self.assertIn("not tracked", refusals[0])
        self.assertIn("secret.txt", refusals[0])

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_clean_repo_returns_no_refusals(self, mock_run):
        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            if "symbolic-ref" in cmd:
                return _cp(stdout="master\n")
            if cmd[1:4] == ["config", "--get", "branch.master.remote"]:
                return _cp(stdout="origin\n")
            if cmd[1:4] == ["config", "--get", "branch.master.merge"]:
                return _cp(stdout="refs/heads/master\n")
            if "fetch" in cmd:
                return _cp()
            if "rev-list" in cmd:
                return _cp(stdout="0\n")
            if "ls-files" in cmd:
                return _cp(returncode=0)
            if cmd[1] in ("update-index", "diff"):
                return _cp()
            raise AssertionError(f"unexpected git call: {cmd}")

        mock_run.side_effect = fake_run

        refusals = check_repo_preflight(["a.txt", "b.txt"], cwd="/repo")

        self.assertEqual(refusals, [])

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_subprocess_error_on_detached_check_fails_closed(self, mock_run):
        # A git invocation that raises (not installed, bad cwd) must read as a
        # measurement failure, never as "clear".
        mock_run.side_effect = FileNotFoundError("git not found")

        refusals = check_repo_preflight(["a.txt"], cwd="/repo")

        self.assertTrue(refusals)
        self.assertIn("detached", refusals[0])

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_garbled_max_behind_override_refuses_without_raising(self, mock_run):
        # A bad override must produce a readable refusal, not a traceback out of a
        # safety gate. A traceback reads as a bug in the tool, which is how someone
        # talks themselves into working around the gate instead of fixing the value.
        mock_run.return_value = _cp("main\n")

        for bad in ("abc", "1.5", "-3"):
            with self.subTest(value=bad):
                with patch.dict(
                    os.environ, {"UPGRADE_SCHEME_MAX_BEHIND": bad}, clear=False
                ):
                    refusals = check_repo_preflight([], cwd="/repo")
                self.assertTrue(
                    any("UPGRADE_SCHEME_MAX_BEHIND" in r for r in refusals),
                    f"{bad!r} should be refused, got {refusals}",
                )

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_valid_max_behind_override_is_honoured(self, mock_run):
        mock_run.side_effect = self._run_git_side_effects(
            [
                ("symbolic-ref", _cp("main\n")),
                ("branch.main.remote", _cp("origin\n")),
                ("branch.main.merge", _cp("refs/heads/main\n")),
                ("fetch", _cp()),
                ("rev-list", _cp("2\n")),
            ]
        )

        # 2 behind is tolerated at a bar of 5 and refused at a bar of 1.
        with patch.dict(os.environ, {"UPGRADE_SCHEME_MAX_BEHIND": "5"}, clear=False):
            self.assertEqual(check_repo_preflight([], cwd="/repo"), [])
        with patch.dict(os.environ, {"UPGRADE_SCHEME_MAX_BEHIND": "1"}, clear=False):
            self.assertTrue(check_repo_preflight([], cwd="/repo"))

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_uncommitted_matched_file_is_refused(self, mock_run):
        # The abort path restores with `git checkout`, which DISCARDS local edits.
        # Measured before this gate existed: an uncommitted line added to a secret
        # file was gone after an aborted run, with nothing reported. The shell
        # harness this module was ported from carries the same gate; the port took
        # the destructive restore without its precondition.
        def fake_run(args, **kwargs):
            argv = args[1:]
            if argv[:1] == ["symbolic-ref"]:
                return _cp("main\n")
            if argv[:1] == ["config"]:
                return _cp("", returncode=1)
            if argv[:2] == ["diff", "--quiet"]:
                return _cp("", returncode=1)
            return _cp()

        mock_run.side_effect = fake_run

        refusals = check_repo_preflight(["a.secret"], cwd="/repo")

        self.assertTrue(any("uncommitted" in r for r in refusals), refusals)
        self.assertTrue(any("discard" in r for r in refusals), refusals)

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_unreadable_index_fails_closed_on_cleanliness(self, mock_run):
        def fake_run(args, **kwargs):
            argv = args[1:]
            if argv[:1] == ["symbolic-ref"]:
                return _cp("main\n")
            if argv[:1] == ["config"]:
                return _cp("", returncode=1)
            if argv[:1] == ["diff"]:
                return _cp("", returncode=128)
            return _cp()

        mock_run.side_effect = fake_run

        refusals = check_repo_preflight(["a.secret"], cwd="/repo")

        self.assertTrue(any("cannot determine" in r for r in refusals), refusals)


if __name__ == "__main__":
    unittest.main()
