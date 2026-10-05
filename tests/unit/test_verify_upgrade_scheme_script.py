"""Real git exercising verify-upgrade-scheme.sh's clean-tree gate.

tkt 5126: the gate at lines 199-205 refused a tree whose only "dirt" was a
scheme-mismatch artifact (a file committed under one encryption scheme while
its key blob declares the other) - exactly the state `upgrade-scheme` exists
to repair. This pins the content-aware replacement: a scheme-mismatch artifact
must pass, a real plaintext edit must still be refused, and a decrypt that
yields nothing must refuse rather than read as "identical" (the empty-
output trap).

No cloud backend: the key is cached locally before git ever runs, same
precedent as tests/filter_process/test_filter_process_git.py.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

GIT_AVAILABLE = shutil.which("git") is not None

FILTER_NAME = "shell-gate-filter"

_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SCRIPT = os.path.join(_REPO_ROOT, "scripts", "migration", "verify-upgrade-scheme.sh")
SRC_ROOT = os.path.join(_REPO_ROOT, "src")


def _run(cmd, cwd, check=False, env=None):
    return subprocess.run(
        cmd, cwd=cwd, check=check, capture_output=True, text=True, env=env
    )


def _write_gsp_wrapper(path):
    # GSP must be an executable FILE - the script checks `command -v "$GSP"`,
    # which a multi-word command fails.
    with open(path, "w") as fh:
        fh.write(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f'export PYTHONPATH="{SRC_ROOT}:${{PYTHONPATH:-}}"\n'
            f'exec "{sys.executable}" -m git_secret_protector.main "$@"\n'
        )
    os.chmod(path, 0o755)


def _write_gsp_stub_empty_decrypt(path, real_gsp_path):
    # The empty-decrypt trap: decrypt exits 0 printing nothing. Every other subcommand
    # (status --json in particular, so the script gets past its own startup)
    # forwards to the real wrapper.
    with open(path, "w") as fh:
        fh.write(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            'if [ "${1:-}" = decrypt ]; then\n'
            "  cat >/dev/null\n"
            "  exit 0\n"
            "fi\n"
            f'exec "{real_gsp_path}" "$@"\n'
        )
    os.chmod(path, 0o755)


def _init_repo(workdir, magic_header=None):
    _run(["git", "init", "-q"], cwd=workdir, check=True)
    _run(["git", "config", "user.email", "gate@example.com"], cwd=workdir, check=True)
    _run(["git", "config", "user.name", "gate"], cwd=workdir, check=True)
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
        if magic_header is not None:
            fh.write(f"magic_header = {magic_header}\n")


def _write_key_blob(workdir, version):
    # Flipping version must reuse the SAME key material - this is the
    # scheme-mismatch artifact (one key, two declared schemes), not a key
    # rotation. Regenerating aes_key/iv here would make decrypt fail on
    # authentication, which is a different bug than the one under test.
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


def _configure_clean_smudge(workdir, gsp_path):
    _run(
        ["git", "config", f"filter.{FILTER_NAME}.clean", f"{gsp_path} encrypt %f"],
        cwd=workdir,
        check=True,
    )
    _run(
        ["git", "config", f"filter.{FILTER_NAME}.smudge", f"{gsp_path} decrypt %f"],
        cwd=workdir,
        check=True,
    )
    _run(
        ["git", "config", f"filter.{FILTER_NAME}.required", "true"],
        cwd=workdir,
        check=True,
    )


def _run_script(workdir, gsp_path):
    env = os.environ.copy()
    env["GSP"] = gsp_path
    return _run(["bash", SCRIPT, workdir, FILTER_NAME], cwd=workdir, env=env)


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_scheme_mismatch_with_identical_plaintext_passes():
    """Case A: a scheme-mismatch artifact (no real edit) must not refuse."""
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir)
        gsp = os.path.join(workdir, "gsp-wrapper.sh")
        _write_gsp_wrapper(gsp)
        _configure_clean_smudge(workdir, gsp)

        _write_key_blob(workdir, version=2)
        secret_path = os.path.join(workdir, "a.secret")
        with open(secret_path, "wb") as fh:
            fh.write(b"identical-plaintext-content\n")
        _run(["git", "add", "-A"], cwd=workdir, check=True)
        _run(["git", "commit", "-q", "-m", "add secret"], cwd=workdir, check=True)

        committed = _run(
            ["git", "show", "HEAD:a.secret"], cwd=workdir, check=True
        ).stdout
        assert committed.startswith("ENCRYPTED"), "fixture did not commit ciphertext"

        # Flip the blob to version-less (v1-era) AFTER commit: same bytes
        # committed, different scheme now declared. No edit happened.
        _write_key_blob(workdir, version=None)

        # LOAD-BEARING (measured today): git diff can trust its stat cache and
        # skip re-running the clean filter unless the file's mtime changes, in
        # which case the tree would read clean and the test would prove
        # nothing. Invalidate it unconditionally rather than assert on the
        # pre-touch state, which depends on racy-git timing this run cannot
        # control.
        os.utime(secret_path, None)
        dirty_probe = _run(["git", "diff", "--quiet", "--", "a.secret"], cwd=workdir)
        assert (
            dirty_probe.returncode == 1
        ), "fixture did not reproduce mismatch-as-dirty"

        result = _run_script(workdir, gsp)
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        assert "no content change" in combined
        assert "a.secret" in combined
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_scheme_mismatch_with_custom_magic_header_passes():
    """Case A2: same construction as case A, but a repo-configured custom
    magic_header. The gate must not hardcode the default header - it must
    delegate the ciphertext/plaintext judgment to `$GSP decrypt` itself,
    which already uses the configured header."""
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir, magic_header="SEALED")
        gsp = os.path.join(workdir, "gsp-wrapper.sh")
        _write_gsp_wrapper(gsp)
        _configure_clean_smudge(workdir, gsp)

        _write_key_blob(workdir, version=2)
        secret_path = os.path.join(workdir, "d.secret")
        with open(secret_path, "wb") as fh:
            fh.write(b"identical-plaintext-content\n")
        _run(["git", "add", "-A"], cwd=workdir, check=True)
        _run(["git", "commit", "-q", "-m", "add secret"], cwd=workdir, check=True)

        committed = _run(
            ["git", "show", "HEAD:d.secret"], cwd=workdir, check=True
        ).stdout
        assert committed.startswith("SEALED"), "fixture did not commit ciphertext"

        # Flip the blob to version-less (v1-era) AFTER commit: same bytes
        # committed, different scheme now declared. No edit happened.
        _write_key_blob(workdir, version=None)

        os.utime(secret_path, None)
        dirty_probe = _run(["git", "diff", "--quiet", "--", "d.secret"], cwd=workdir)
        assert (
            dirty_probe.returncode == 1
        ), "fixture did not reproduce mismatch-as-dirty"

        result = _run_script(workdir, gsp)
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        assert "no content change" in combined
        assert "d.secret" in combined
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_chmod_only_change_is_refused_not_admitted():
    """Defect 2: identical plaintext (scheme-mismatch artifact) PLUS a mode
    change (chmod +x) must refuse, naming the mode/type change - never admit
    as no-content-change. Admitting it would let the failure-path `git
    checkout -- ` later reset the mode and silently discard it."""
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir)
        gsp = os.path.join(workdir, "gsp-wrapper.sh")
        _write_gsp_wrapper(gsp)
        _configure_clean_smudge(workdir, gsp)

        _write_key_blob(workdir, version=2)
        secret_path = os.path.join(workdir, "e.secret")
        with open(secret_path, "wb") as fh:
            fh.write(b"identical-plaintext-content\n")
        _run(["git", "add", "-A"], cwd=workdir, check=True)
        _run(["git", "commit", "-q", "-m", "add secret"], cwd=workdir, check=True)

        committed = _run(
            ["git", "show", "HEAD:e.secret"], cwd=workdir, check=True
        ).stdout
        assert committed.startswith("ENCRYPTED"), "fixture did not commit ciphertext"

        # Same scheme-mismatch construction as case A - no real content edit.
        _write_key_blob(workdir, version=None)
        os.chmod(secret_path, 0o755)
        os.utime(secret_path, None)
        dirty_probe = _run(["git", "diff", "--quiet", "--", "e.secret"], cwd=workdir)
        assert dirty_probe.returncode == 1, "fixture did not reproduce dirty tree"

        result = _run_script(workdir, gsp)
        combined = result.stdout + result.stderr
        assert result.returncode != 0, combined
        assert "mode" in combined or "type" in combined
        assert "e.secret" in combined
        # Must be its own refusal, distinct from both other outcomes.
        assert "no content change" not in combined
        assert "have content changes" not in combined
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_real_uncommitted_edit_is_still_refused():
    """Case B: a genuine plaintext edit must still refuse, naming the path."""
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir)
        gsp = os.path.join(workdir, "gsp-wrapper.sh")
        _write_gsp_wrapper(gsp)
        _configure_clean_smudge(workdir, gsp)
        _write_key_blob(workdir, version=2)

        secret_path = os.path.join(workdir, "b.secret")
        with open(secret_path, "wb") as fh:
            fh.write(b"original-content\n")
        _run(["git", "add", "-A"], cwd=workdir, check=True)
        _run(["git", "commit", "-q", "-m", "add secret"], cwd=workdir, check=True)

        with open(secret_path, "ab") as fh:
            fh.write(b"appended-by-the-operator\n")

        dirty_probe = _run(["git", "diff", "--quiet", "--", "b.secret"], cwd=workdir)
        assert dirty_probe.returncode == 1, "fixture did not produce a real edit"

        result = _run_script(workdir, gsp)
        combined = result.stdout + result.stderr
        assert result.returncode != 0
        assert "have content changes" in combined
        assert "b.secret" in combined
        # Must be the CONTENT-CHANGED path, never the no-content-change note.
        assert "no content change" not in combined
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_empty_decrypt_output_refuses_as_cannot_compare():
    """Case C: an empty decrypt must never be read as 'identical'."""
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir)
        real_gsp = os.path.join(workdir, "gsp-real.sh")
        _write_gsp_wrapper(real_gsp)
        _configure_clean_smudge(workdir, real_gsp)
        _write_key_blob(workdir, version=2)

        secret_path = os.path.join(workdir, "c.secret")
        with open(secret_path, "wb") as fh:
            fh.write(b"content-for-cannot-compare-case\n")
        _run(["git", "add", "-A"], cwd=workdir, check=True)
        _run(["git", "commit", "-q", "-m", "add secret"], cwd=workdir, check=True)

        # Same scheme-mismatch construction as case A, so the batch gate finds
        # the tree dirty and the per-file comparison path runs.
        _write_key_blob(workdir, version=None)
        os.utime(secret_path, None)
        dirty_probe = _run(["git", "diff", "--quiet", "--", "c.secret"], cwd=workdir)
        assert (
            dirty_probe.returncode == 1
        ), "fixture did not reproduce mismatch-as-dirty"

        stub_gsp = os.path.join(workdir, "gsp-stub.sh")
        _write_gsp_stub_empty_decrypt(stub_gsp, real_gsp)

        result = _run_script(workdir, stub_gsp)
        combined = result.stdout + result.stderr
        assert result.returncode != 0
        assert "cannot compare" in combined
        assert "c.secret" in combined
        # Must be the CANNOT-COMPARE path, distinct from both other outcomes.
        assert "have content changes" not in combined
        assert "no content change" not in combined
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
