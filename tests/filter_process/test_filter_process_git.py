"""Real git driving filter.<name>.process end-to-end. No cloud backend: the key is
cached locally before git ever runs, same as scripts/bench-filter-modes.sh models it.
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

FILTER_NAME = "e2e-filter"


def _run(cmd, cwd, check=True, env=None):
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
        env=env,
    )


def _init_repo(workdir, with_key_cache=True):
    _run(["git", "init", "-q"], cwd=workdir)
    _run(["git", "config", "user.email", "e2e@example.com"], cwd=workdir)
    _run(["git", "config", "user.name", "e2e"], cwd=workdir)

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

    if with_key_cache:
        data = {
            "aes_key": base64.b64encode(os.urandom(32)).decode("ascii"),
            "iv": base64.b64encode(os.urandom(16)).decode("ascii"),
            "version": 2,
        }
        cache_path = os.path.join(module_dir, "cache", f"{FILTER_NAME}_key_iv.json")
        with open(cache_path, "w") as fh:
            fh.write(json.dumps(data))

    process_cmd = (
        f"{sys.executable} -m git_secret_protector.main filter-process {FILTER_NAME}"
    )
    _run(["git", "config", f"filter.{FILTER_NAME}.process", process_cmd], cwd=workdir)
    _run(["git", "config", f"filter.{FILTER_NAME}.required", "true"], cwd=workdir)


def _subprocess_env():
    # The filter subprocess must see the same interpreter/module on its path as
    # this test process (the editable install), not whatever `python` resolves to
    # on a bare PATH.
    env = os.environ.copy()
    src_root = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "src",
    )
    env["PYTHONPATH"] = src_root + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_process_filter_round_trips_files_and_commits_ciphertext():
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir)
        env = _subprocess_env()

        contents = {}
        for i in range(5):
            name = f"file{i}.secret"
            body = f"plaintext-content-{i}\n".encode()
            contents[name] = body
            with open(os.path.join(workdir, name), "wb") as fh:
                fh.write(body)

        _run(["git", "add", "-A"], cwd=workdir, env=env)
        _run(["git", "commit", "-q", "-m", "add secrets"], cwd=workdir, env=env)

        for name in contents:
            committed = _run(
                ["git", "show", f"HEAD:{name}"], cwd=workdir, env=env
            ).stdout.encode()
            assert (
                committed != contents[name]
            ), f"{name} committed as plaintext, filter did not encrypt"

        for name in contents:
            os.remove(os.path.join(workdir, name))

        _run(["git", "checkout", "--", "."], cwd=workdir, env=env)

        for name, body in contents.items():
            with open(os.path.join(workdir, name), "rb") as fh:
                restored = fh.read()
            assert restored == body, f"{name} did not round-trip byte-identical"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not available")
def test_process_filter_with_unusable_key_fails_add_and_stages_nothing():
    workdir = tempfile.mkdtemp()
    try:
        _init_repo(workdir, with_key_cache=False)
        env = _subprocess_env()

        with open(os.path.join(workdir, "file0.secret"), "wb") as fh:
            fh.write(b"plaintext-content\n")

        result = _run(["git", "add", "-A"], cwd=workdir, env=env, check=False)
        assert result.returncode != 0

        staged = _run(
            ["git", "diff", "--cached", "--name-only"], cwd=workdir, env=env
        ).stdout.strip()
        assert staged == ""
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
