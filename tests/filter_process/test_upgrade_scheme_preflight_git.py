"""Real git driving check_repo_preflight with the ABSOLUTE paths
get_files_for_filter actually returns.

A scheme-mismatch artifact (a file committed under one encryption scheme
while its key blob declares the other) must be ADMITTED by the preflight
gate - that is the whole point of the content-aware gate. The real caller
(upgrade_scheme / upgrade_scheme_all in encryption_manager.py) passes
check_repo_preflight the paths get_files_for_filter returns, and that parser
globs with the repo root joined in, so every path is ABSOLUTE.

check_repo_preflight builds `git show ":<path>"` to read the indexed blob.
An absolute path there is parsed by git as `:/text`, its commit-message
SEARCH syntax, not a pathspec - so with absolute paths the blob read fails
and every dirty matched file is wrongly refused as cannot-compare, even
though the content is identical. A test that hand-writes a relative path
cannot see this - that is exactly the gap that let the defect merge.

No cloud backend: the key is cached locally before git ever runs, same
precedent as test_filter_process_git.py and test_verify_upgrade_scheme_script.py.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.core.git_preflight import check_repo_preflight

GIT_AVAILABLE = shutil.which("git") is not None

FILTER_NAME = "preflight-abs-filter"


def _run(cmd, cwd, check=True, env=None):
    return subprocess.run(
        cmd, cwd=cwd, check=check, capture_output=True, text=True, env=env
    )


def _subprocess_env():
    env = os.environ.copy()
    src_root = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src",
    )
    env["PYTHONPATH"] = src_root + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _write_gsp_wrapper(path, src_root):
    with open(path, "w") as fh:
        fh.write(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f'export PYTHONPATH="{src_root}:${{PYTHONPATH:-}}"\n'
            f'exec "{sys.executable}" -m git_secret_protector.main "$@"\n'
        )
    os.chmod(path, 0o755)


def _write_key_blob(workdir, version):
    # Same key material across the flip - this is a scheme-mismatch artifact
    # (one key, two declared schemes), not a rotation. Regenerating the key
    # here would make decryption fail on authentication, a different bug.
    path = os.path.join(
        workdir, ".git_secret_protector", "cache", f"{FILTER_NAME}_key_iv.json"
    )
    if os.path.exists(path):
        with open(path) as fh:
            data = json.load(fh)
        data.pop("version", None)
    else:
        data = {
            "aes_key": base64.b64encode(os.urandom(32)).decode("ascii"),
            "iv": base64.b64encode(os.urandom(16)).decode("ascii"),
        }
    if version is not None:
        data["version"] = version
    with open(path, "w") as fh:
        fh.write(json.dumps(data))


def _init_repo(workdir, env):
    _run(["git", "init", "-q"], cwd=workdir)
    _run(["git", "config", "user.email", "gate@example.com"], cwd=workdir)
    _run(["git", "config", "user.name", "gate"], cwd=workdir)
    with open(os.path.join(workdir, ".gitattributes"), "w") as fh:
        fh.write(f"*.secret filter={FILTER_NAME}\n")

    module_dir = os.path.join(workdir, ".git_secret_protector")
    os.makedirs(os.path.join(module_dir, "cache"), exist_ok=True)
    os.makedirs(os.path.join(module_dir, "logs"), exist_ok=True)
    with open(os.path.join(module_dir, "config.ini"), "w") as fh:
        fh.write(
            "[DEFAULT]\n"
            "module_name = git-secret-protector\n"
            "storage_type = AWS_SSM\n"
            "encryption_scheme = v2\n"
            "log_level = WARN\n"
        )

    src_root = env["PYTHONPATH"].split(os.pathsep)[0]
    gsp = os.path.join(workdir, "gsp-wrapper.sh")
    _write_gsp_wrapper(gsp, src_root)
    _run(
        ["git", "config", f"filter.{FILTER_NAME}.clean", f"{gsp} encrypt %f"],
        cwd=workdir,
    )
    _run(
        ["git", "config", f"filter.{FILTER_NAME}.smudge", f"{gsp} decrypt %f"],
        cwd=workdir,
    )
    _run(["git", "config", f"filter.{FILTER_NAME}.required", "true"], cwd=workdir)
    return gsp


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_scheme_mismatch_with_absolute_paths_is_admitted():
    workdir = tempfile.mkdtemp()
    try:
        env = _subprocess_env()
        _init_repo(workdir, env)
        _write_key_blob(workdir, version=2)

        secret_path = os.path.join(workdir, "a.secret")
        with open(secret_path, "wb") as fh:
            fh.write(b"identical-plaintext-content\n")
        _run(["git", "add", "-A"], cwd=workdir, env=env)
        _run(["git", "commit", "-q", "-m", "add secret"], cwd=workdir, env=env)

        committed = _run(["git", "show", "HEAD:a.secret"], cwd=workdir, env=env).stdout
        assert committed.startswith("ENCRYPTED"), "fixture did not commit ciphertext"

        # Flip the blob to version-less (v1-era) AFTER commit: same bytes
        # committed, different scheme now declared. No edit happened.
        _write_key_blob(workdir, version=None)

        # LOAD-BEARING: git's stat cache can skip re-running the clean filter
        # unless the file's mtime changes, in which case the tree reads clean
        # and the test proves nothing.
        os.utime(secret_path, None)
        dirty_probe = _run(
            ["git", "diff", "--quiet", "--", "a.secret"], cwd=workdir, check=False
        )
        assert (
            dirty_probe.returncode == 1
        ), "fixture did not reproduce mismatch-as-dirty"

        # Resolve the matched files the way the real caller does: through the
        # parser, not hand-written relative strings. This is the crux of the
        # regression - these paths are ABSOLUTE.
        # Built without __init__ (which reads the process-wide Settings
        # singleton - unreliable across test order) but with every attribute
        # get_files_for_filter actually touches.
        parser = GitAttributesParser.__new__(GitAttributesParser)
        parser.base_dir = workdir
        parser.git_attributes_file = os.path.join(workdir, ".gitattributes")
        parser._patterns = None
        matched_files = parser.get_files_for_filter(FILTER_NAME)

        assert matched_files, "parser matched no files"
        for f in matched_files:
            assert os.path.isabs(f), f"expected an absolute path, got {f!r}"

        def plaintext_of(path, data):
            # decrypt via the real CLI through subprocess, same as the
            # production resolver (__plaintext_of_resolver), but data is
            # already the raw git-show bytes here.
            gsp = os.path.join(workdir, "gsp-wrapper.sh")
            result = subprocess.run(
                [gsp, "decrypt", path],
                input=data,
                cwd=workdir,
                capture_output=True,
                env=env,
            )
            assert result.returncode == 0, result.stderr
            return result.stdout

        notes = []
        refusals = check_repo_preflight(
            matched_files, cwd=workdir, plaintext_of=plaintext_of, notes=notes
        )

        assert refusals == [], refusals
        assert notes, "expected a note explaining the dirty-but-safe tree"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
