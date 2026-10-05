"""Real process: status with no local key cache and no usable AWS credentials.

Mocked tests can prove the scheme-read failure is handled; they cannot prove the
process-level EXIT CODE (sys.exit happens inside the CLI, not inside a mocked
call) or that scripts/migration/verify-upgrade-scheme.sh actually refuses on it.
Both only show up by running the real `git_secret_protector.main` entry point and
the real shell script against a repo whose key cache is absent and whose AWS
credentials cannot resolve an account id, same no-network precedent as
test_filter_process_git.py and test_verify_upgrade_scheme_script.py.
"""

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
    # Deliberately NO key cache file: get_scheme_info must fall through to the
    # backend, where it will fail - the scenario this ticket is about.


def _no_credentials_env(workdir):
    # Bogus creds take precedence over any real profile/instance role on the
    # host running this suite, so the STS call fails deterministically
    # regardless of where it runs. IMDS is disabled so a sandboxed host
    # without network does not stall waiting on the metadata endpoint.
    env = os.environ.copy()
    env.pop("SECRET_PROTECTOR_BASE_DIR", None)
    env["PYTHONPATH"] = SRC_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["AWS_ACCESS_KEY_ID"] = "AKIAUNKNOWNSCHEMETEST"
    env["AWS_SECRET_ACCESS_KEY"] = "unknown-scheme-test-secret"
    env.pop("AWS_SESSION_TOKEN", None)
    env["AWS_DEFAULT_REGION"] = "us-east-1"
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    bogus_creds_file = os.path.join(workdir, "no-such-aws-credentials")
    env["AWS_SHARED_CREDENTIALS_FILE"] = bogus_creds_file
    env["AWS_CONFIG_FILE"] = bogus_creds_file
    env.pop("AWS_PROFILE", None)
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
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_verify_upgrade_scheme_refuses_on_unreadable_scheme():
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir)
        env = _no_credentials_env(workdir)
        gsp = os.path.join(workdir, "gsp-wrapper.sh")
        with open(gsp, "w") as fh:
            fh.write(
                "#!/usr/bin/env bash\n"
                "set -u\n"
                f'export PYTHONPATH="{SRC_ROOT}:${{PYTHONPATH:-}}"\n'
                f'exec "{sys.executable}" -m git_secret_protector.main "$@"\n'
            )
        os.chmod(gsp, 0o755)

        script_env = dict(env)
        script_env["GSP"] = gsp

        result = _run(
            ["bash", SCRIPT, workdir, FILTER_NAME], cwd=workdir, env=script_env
        )

        combined = result.stdout + result.stderr
        assert result.returncode != 0, combined
        assert "status --json failed" not in combined
        assert "scheme" in combined.lower()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
