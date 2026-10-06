"""Real process: status with no local key cache and no usable AWS credentials.

Mocked tests can prove the scheme-read failure is handled; they cannot prove the
process-level EXIT CODE (sys.exit happens inside the CLI, not inside a mocked
call) or that scripts/migration/verify-upgrade-scheme.sh actually refuses on it.
Both only show up by running the real `git_secret_protector.main` entry point and
the real shell script against a repo whose key cache is absent and whose AWS
credentials cannot resolve an account id, same no-network precedent as
test_filter_process_git.py and test_verify_upgrade_scheme_script.py.
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

FILTER_NAME = "unknown-scheme-filter"

_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SCRIPT = os.path.join(_REPO_ROOT, "scripts", "migration", "verify-upgrade-scheme.sh")
SRC_ROOT = os.path.join(_REPO_ROOT, "src")


def _run(cmd, cwd, check=False, env=None):
    return subprocess.run(
        cmd, cwd=cwd, check=check, capture_output=True, text=True, env=env
    )


def _init_repo(workdir):
    _run(["git", "init", "-q"], cwd=workdir, check=True)
    _run(["git", "config", "user.email", "u@example.com"], cwd=workdir, check=True)
    _run(["git", "config", "user.name", "u"], cwd=workdir, check=True)

    with open(os.path.join(workdir, ".gitattributes"), "w") as fh:
        fh.write(f"*.secret filter={FILTER_NAME}\n")
    with open(os.path.join(workdir, "a.secret"), "wb") as fh:
        fh.write(b"plaintext\n")

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
    # Deliberately NO key cache file here: get_scheme_info must fall through to
    # the backend, where it will fail - the scenario this ticket is about.


def _key_cache_path(workdir):
    return os.path.join(
        workdir, ".git_secret_protector", "cache", f"{FILTER_NAME}_key_iv.json"
    )


def _write_key_cache(workdir):
    with open(_key_cache_path(workdir), "w") as fh:
        fh.write(
            json.dumps(
                {
                    "aes_key": base64.b64encode(os.urandom(32)).decode("ascii"),
                    "iv": base64.b64encode(os.urandom(16)).decode("ascii"),
                    "version": 2,
                }
            )
        )


def _write_gsp_wrapper(path, src_root):
    with open(path, "w") as fh:
        fh.write(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            f'export PYTHONPATH="{src_root}:${{PYTHONPATH:-}}"\n'
            f'exec "{sys.executable}" -m git_secret_protector.main "$@"\n'
        )
    os.chmod(path, 0o755)


def _subprocess_env():
    # Plain environment (inherits real AWS credentials if any, but none are
    # needed here since the key cache is present) - used only for the git
    # operations that round-trip through the clean filter.
    env = os.environ.copy()
    env["PYTHONPATH"] = SRC_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _no_credentials_env(workdir):
    # Pointing AWS_PROFILE at a profile name that does not exist, inside
    # otherwise-empty config/credentials files, makes botocore raise
    # ProfileNotFound while constructing the client itself - before any
    # socket opens. The previous approach (bogus static AWS_ACCESS_KEY_ID /
    # AWS_SECRET_ACCESS_KEY) does NOT achieve this: boto3 treats env-var
    # credentials as real and goes ahead with an actual STS network call
    # using them, which is exactly the CI-network-call bug this fixes.
    env = os.environ.copy()
    env.pop("SECRET_PROTECTOR_BASE_DIR", None)
    env["PYTHONPATH"] = SRC_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    for var in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    ):
        env.pop(var, None)
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    empty_aws_file = os.path.join(workdir, "no-such-aws-credentials")
    open(empty_aws_file, "w").close()
    env["AWS_SHARED_CREDENTIALS_FILE"] = empty_aws_file
    env["AWS_CONFIG_FILE"] = empty_aws_file
    env["AWS_PROFILE"] = "no-such-scheme-test-profile"
    return env


def _run_status_json(workdir, env):
    return _run(
        [sys.executable, "-m", "git_secret_protector.main", "status", "--json"],
        cwd=workdir,
        env=env,
    )


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_status_json_reports_unknown_scheme_and_exits_nonzero():
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir)
        env = _no_credentials_env(workdir)

        result = _run_status_json(workdir, env)

        assert result.returncode != 0, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        entry = payload["filters"][0]
        assert entry["scheme"] == "unknown"
        assert entry["scheme_error"]
        # Proof the failure was a LOCAL profile-resolution error, not a
        # network/endpoint error: botocore's ProfileNotFound message names
        # the profile and never mentions a connection, a timeout, or a host.
        lowered = entry["scheme_error"].lower()
        assert "profile" in lowered
        for leak in ("connect", "timed out", "timeout", "endpoint", "resolve"):
            assert leak not in lowered, entry["scheme_error"]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_verify_upgrade_scheme_refuses_on_unreadable_scheme():
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir)
        gsp = os.path.join(workdir, "gsp-wrapper.sh")
        _write_gsp_wrapper(gsp, SRC_ROOT)

        # a.secret must be TRACKED, so that once the scheme gate is removed
        # the later untracked-matched-file gate cannot produce a non-zero
        # exit of its own and mask the scheme gate's absence. Committing it
        # needs a working clean filter, which needs a real key - so the key
        # cache is written and the filters configured FIRST, and the file is
        # committed while the scheme is still readable.
        _write_key_cache(workdir)
        _run(
            ["git", "config", f"filter.{FILTER_NAME}.clean", f"{gsp} encrypt %f"],
            cwd=workdir,
            check=True,
        )
        _run(
            ["git", "config", f"filter.{FILTER_NAME}.smudge", f"{gsp} decrypt %f"],
            cwd=workdir,
            check=True,
        )
        _run(
            ["git", "config", f"filter.{FILTER_NAME}.required", "true"],
            cwd=workdir,
            check=True,
        )

        commit_env = _subprocess_env()
        _run(["git", "add", "-A"], cwd=workdir, check=True, env=commit_env)
        _run(
            ["git", "commit", "-q", "-m", "add secret"],
            cwd=workdir,
            check=True,
            env=commit_env,
        )

        committed = _run(
            ["git", "show", "HEAD:a.secret"], cwd=workdir, env=commit_env
        ).stdout
        assert committed.startswith(
            "ENCRYPTED"
        ), "fixture did not commit ciphertext; a.secret stayed untracked plaintext"

        # NOW delete the key cache: the scheme becomes unreadable, which is
        # the scenario under test, and a.secret is already a tracked,
        # committed file - so the gate this test exists for is the only one
        # standing between the run and success.
        os.remove(_key_cache_path(workdir))

        env = _no_credentials_env(workdir)
        script_env = dict(env)
        script_env["GSP"] = gsp

        result = _run(
            ["bash", SCRIPT, workdir, FILTER_NAME], cwd=workdir, env=script_env
        )

        combined = result.stdout + result.stderr
        assert result.returncode != 0, combined
        assert "status --json failed" not in combined
        # Specific refusal, not just "contains the word scheme" (every
        # refusal here is prefixed "verify-upgrade-scheme:", which on its
        # own would make a looser substring check pass for the wrong reason).
        assert "scheme could not be read" in combined, combined
        assert FILTER_NAME in combined, combined
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
