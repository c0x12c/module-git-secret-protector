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

    def _content_aware_side_effect(
        self, dirty_unstaged, head_blob, index_blob, worktree_bytes
    ):
        """Common plumbing for the content-aware tests below: a clean
        detached/behind/untracked gate, a dirty UNSTAGED diff over the whole
        batch and over each listed file, and fixed git-show bytes for the
        staged/unstaged bases."""

        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            argv = cmd[1:]
            if argv[:1] == ["symbolic-ref"]:
                return _cp("main\n")
            if argv[:1] == ["config"]:
                return _cp("", returncode=1)  # no upstream configured
            if argv[:1] == ["ls-files"]:
                return _cp(returncode=0)  # tracked
            if argv[:1] == ["update-index"]:
                return _cp()
            if argv[:2] == ["diff", "--cached"]:
                return _cp()  # nothing staged in these tests
            if argv[:2] == ["diff", "--raw"]:
                # Unchanged mode by default - these tests are about content,
                # not mode; the dedicated chmod tests below supply their own.
                path = argv[-1]
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout=f":100644 100644 38904f8 0000000 M\t{path}\n",
                    stderr="",
                )
            if argv[:1] == ["diff"]:
                path = argv[-1]
                return _cp(returncode=1 if path in dirty_unstaged else 0)
            if argv[:2] == ["show", f":{self._path}"]:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=index_blob, stderr=b""
                )
            raise AssertionError(f"unexpected git call: {cmd}")

        return fake_run

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    @patch("git_secret_protector.core.git_preflight.open")
    def test_equal_plaintext_is_not_refused_and_notes_why(self, mock_open, mock_run):
        self._path = "a.secret"
        committed = b"ciphertext-v2"
        worktree = b"ciphertext-v1"
        plaintext = b"same plaintext either way"

        mock_run.side_effect = self._content_aware_side_effect(
            dirty_unstaged={"a.secret"},
            head_blob=None,
            index_blob=committed,
            worktree_bytes=worktree,
        )
        mock_open.return_value.__enter__.return_value.read.return_value = worktree

        def plaintext_of(path, data):
            return plaintext  # both sides decrypt identically regardless

        notes = []
        refusals = check_repo_preflight(
            ["a.secret"], cwd="/repo", plaintext_of=plaintext_of, notes=notes
        )

        self.assertEqual(refusals, [])
        self.assertTrue(notes, "expected a note explaining the dirty-but-safe tree")
        self.assertIn("a.secret", notes[0])

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    @patch("git_secret_protector.core.git_preflight.open")
    def test_differing_plaintext_is_refused(self, mock_open, mock_run):
        self._path = "a.secret"
        committed = b"ciphertext-old"
        worktree = b"ciphertext-new"

        mock_run.side_effect = self._content_aware_side_effect(
            dirty_unstaged={"a.secret"},
            head_blob=None,
            index_blob=committed,
            worktree_bytes=worktree,
        )
        mock_open.return_value.__enter__.return_value.read.return_value = worktree

        def plaintext_of(path, data):
            return data  # no transform - committed vs worktree bytes differ

        refusals = check_repo_preflight(
            ["a.secret"], cwd="/repo", plaintext_of=plaintext_of, notes=[]
        )

        self.assertTrue(any("content changes" in r for r in refusals), refusals)
        self.assertTrue(any("a.secret" in r for r in refusals), refusals)

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_plaintext_of_none_keeps_legacy_refusal(self, mock_run):
        mock_run.side_effect = self._content_aware_side_effect(
            dirty_unstaged={"a.secret"},
            head_blob=None,
            index_blob=b"x",
            worktree_bytes=b"y",
        )

        refusals = check_repo_preflight(["a.secret"], cwd="/repo")

        self.assertTrue(any("uncommitted" in r for r in refusals), refusals)
        self.assertTrue(any("discard" in r for r in refusals), refusals)

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    @patch("git_secret_protector.core.git_preflight.open")
    def test_plaintext_of_raising_is_cannot_compare_refusal(self, mock_open, mock_run):
        self._path = "a.secret"
        mock_run.side_effect = self._content_aware_side_effect(
            dirty_unstaged={"a.secret"},
            head_blob=None,
            index_blob=b"ciphertext",
            worktree_bytes=b"ciphertext2",
        )
        mock_open.return_value.__enter__.return_value.read.return_value = b"ciphertext2"

        def plaintext_of(path, data):
            raise RuntimeError("key not cached")

        refusals = check_repo_preflight(
            ["a.secret"], cwd="/repo", plaintext_of=plaintext_of, notes=[]
        )

        self.assertTrue(any("cannot compare" in r for r in refusals), refusals)
        self.assertFalse(
            any("content changes" in r for r in refusals),
            "cannot-compare must use a distinct message from content-differs",
        )

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    def test_staged_only_divergence_is_refused_without_reading_worktree(self, mock_run):
        # Staged scope compares HEAD:<path> against :<path> (the index) and
        # must never consult the worktree - a staged change is judged by
        # what is staged, not what is currently on disk.
        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            argv = cmd[1:]
            if argv[:1] == ["symbolic-ref"]:
                return _cp("main\n")
            if argv[:1] == ["config"]:
                return _cp("", returncode=1)
            if argv[:1] == ["ls-files"]:
                return _cp(returncode=0)
            if argv[:1] == ["update-index"]:
                return _cp()
            if argv[:2] == ["diff", "--cached"]:
                path = argv[-1]
                return _cp(returncode=1 if path == "a.secret" else 0)
            if argv[:1] == ["diff"]:
                return _cp()  # nothing unstaged
            if argv[:2] == ["show", "HEAD:a.secret"]:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=b"head-bytes", stderr=b""
                )
            if argv[:2] == ["show", ":a.secret"]:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=b"index-bytes", stderr=b""
                )
            raise AssertionError(f"unexpected git call: {cmd}")

        mock_run.side_effect = fake_run

        def plaintext_of(path, data):
            return data  # head-bytes != index-bytes -> real content change

        refusals = check_repo_preflight(
            ["a.secret"], cwd="/repo", plaintext_of=plaintext_of, notes=[]
        )

        self.assertTrue(any("staged" in r and "a.secret" in r for r in refusals))

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    @patch("git_secret_protector.core.git_preflight.open")
    def test_chmod_only_change_is_refused_not_admitted(self, mock_open, mock_run):
        # Identical plaintext on both sides (a scheme-mismatch artifact) but
        # the mode also changed (chmod +x). `git diff --quiet` cannot tell a
        # mode-only change from a content change, and plaintext equality
        # alone is not proof there was no real edit here - the mode IS the
        # edit. Admitting this would let the abort path's `git checkout -- `
        # silently reset the mode later, discarding it.
        worktree_bytes = b"ciphertext-same-plaintext"

        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            argv = cmd[1:]
            if argv[:1] == ["symbolic-ref"]:
                return _cp("main\n")
            if argv[:1] == ["config"]:
                return _cp("", returncode=1)  # no upstream configured
            if argv[:1] == ["ls-files"]:
                return _cp(returncode=0)  # tracked
            if argv[:1] == ["update-index"]:
                return _cp()
            if argv[:2] == ["diff", "--cached"]:
                return _cp()  # nothing staged
            if argv[:2] == ["diff", "--raw"]:
                # :<oldmode> <newmode> <oldsha> <newsha> <status>\t<path>
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout=":100644 100755 38904f8 0000000 M\ta.secret\n",
                    stderr="",
                )
            if argv[:1] == ["diff"]:
                return _cp(returncode=1)  # dirty, both batch and per-file probes
            if argv[:2] == ["show", ":a.secret"]:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=worktree_bytes, stderr=b""
                )
            raise AssertionError(f"unexpected git call: {cmd}")

        mock_run.side_effect = fake_run
        mock_open.return_value.__enter__.return_value.read.return_value = worktree_bytes

        def plaintext_of(path, data):
            return b"same plaintext either way"

        notes = []
        refusals = check_repo_preflight(
            ["a.secret"], cwd="/repo", plaintext_of=plaintext_of, notes=notes
        )

        self.assertTrue(
            any(("mode" in r or "type" in r) and "a.secret" in r for r in refusals),
            refusals,
        )
        self.assertFalse(
            any("content changes" in r for r in refusals),
            "mode/type change must use its own wording, not content-changed",
        )
        self.assertFalse(
            any("cannot compare" in r for r in refusals),
            "mode/type change must use its own wording, not cannot-compare",
        )
        self.assertFalse(
            notes, "a chmod-only change must not be noted as a safe no-op admit"
        )

    @patch("git_secret_protector.core.git_preflight.subprocess.run")
    @patch("git_secret_protector.core.git_preflight.open")
    def test_mode_equal_plaintext_equal_still_admits(self, mock_open, mock_run):
        # Regression guard for the fix above: a scheme-mismatch artifact with
        # UNCHANGED mode must still be admitted - the whole point of the
        # content-aware gate.
        worktree_bytes = b"ciphertext-same-plaintext"

        def fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None):
            argv = cmd[1:]
            if argv[:1] == ["symbolic-ref"]:
                return _cp("main\n")
            if argv[:1] == ["config"]:
                return _cp("", returncode=1)
            if argv[:1] == ["ls-files"]:
                return _cp(returncode=0)
            if argv[:1] == ["update-index"]:
                return _cp()
            if argv[:2] == ["diff", "--cached"]:
                return _cp()
            if argv[:2] == ["diff", "--raw"]:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout=":100644 100644 38904f8 0000000 M\ta.secret\n",
                    stderr="",
                )
            if argv[:1] == ["diff"]:
                return _cp(returncode=1)
            if argv[:2] == ["show", ":a.secret"]:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=worktree_bytes, stderr=b""
                )
            raise AssertionError(f"unexpected git call: {cmd}")

        mock_run.side_effect = fake_run
        mock_open.return_value.__enter__.return_value.read.return_value = worktree_bytes

        def plaintext_of(path, data):
            return b"same plaintext either way"

        notes = []
        refusals = check_repo_preflight(
            ["a.secret"], cwd="/repo", plaintext_of=plaintext_of, notes=notes
        )

        self.assertEqual(refusals, [])
        self.assertTrue(notes)


if __name__ == "__main__":
    unittest.main()
