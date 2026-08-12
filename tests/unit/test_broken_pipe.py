import base64
import json
import os
import secrets
import subprocess
import sys

from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler


def _repo_env():
    env = os.environ.copy()
    src_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "src"
    )
    env["PYTHONPATH"] = (
        src_path
        if not env.get("PYTHONPATH")
        else os.pathsep.join([src_path, env["PYTHONPATH"]])
    )
    return env


def _write_repo_fixture(repo_dir):
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    os.makedirs(repo_dir / ".git_secret_protector" / "cache", exist_ok=True)
    (repo_dir / ".gitattributes").write_text("*.secret filter=secret\n")
    (repo_dir / ".git_secret_protector" / "config.ini").write_text(
        "[DEFAULT]\nmodule_name = git-secret-protector\n"
    )

    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    (repo_dir / ".git_secret_protector" / "cache" / "secret_key_iv.json").write_text(
        json.dumps(
            {
                "aes_key": base64.b64encode(aes_key).decode("utf-8"),
                "iv": base64.b64encode(iv).decode("utf-8"),
                "version": 2,
            }
        )
    )
    return aes_key, iv


def _run_with_closed_stdout(repo_dir, args, stdin_data=b"", extra_env=None):
    env = _repo_env()
    if extra_env:
        env.update(extra_env)
    process = subprocess.Popen(
        [sys.executable, "-m", "git_secret_protector.main", *args],
        cwd=repo_dir,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdin is not None:
        process.stdin.write(stdin_data)
        process.stdin.close()
    if process.stdout is not None:
        process.stdout.close()
    stderr = b""
    if process.stderr is not None:
        stderr = process.stderr.read()
    return process.wait(), stderr.decode("utf-8", errors="replace")


def _assert_exits_quietly(returncode, stderr):
    # 141 = 128 + SIGPIPE. Both strings are the exact user-visible symptom: the first
    # comes from our own handlers, the second only from the interpreter's shutdown
    # flush, so asserting on both is what distinguishes the two halves of the bug.
    assert returncode == 141
    assert "Broken pipe" not in stderr
    assert "Exception ignored" not in stderr


def test_status_suppresses_broken_pipe_noise(tmp_path):
    _write_repo_fixture(tmp_path)

    returncode, stderr = _run_with_closed_stdout(tmp_path, ["status"])

    _assert_exits_quietly(returncode, stderr)


def test_doctor_suppresses_broken_pipe_noise(tmp_path):
    # doctor leaves _run via sys.exit(), so it only stays quiet if the flush is in a
    # `finally` - a trailing flush statement would be skipped and surface at shutdown.
    _write_repo_fixture(tmp_path)

    returncode, stderr = _run_with_closed_stdout(tmp_path, ["doctor"])

    _assert_exits_quietly(returncode, stderr)


def test_encrypt_suppresses_broken_pipe_noise(tmp_path):
    _write_repo_fixture(tmp_path)

    returncode, stderr = _run_with_closed_stdout(
        tmp_path, ["encrypt", "secret.secret"], stdin_data=b"plain-secret"
    )

    _assert_exits_quietly(returncode, stderr)


def test_decrypt_suppresses_broken_pipe_noise(tmp_path):
    aes_key, iv = _write_repo_fixture(tmp_path)
    handler = AesEncryptionHandler(aes_key=aes_key, iv=iv, magic_header=b"ENCRYPTED")
    encrypted_data = handler.encrypt_data(b"plain-secret")

    returncode, stderr = _run_with_closed_stdout(
        tmp_path, ["decrypt", "secret.secret"], stdin_data=encrypted_data
    )

    _assert_exits_quietly(returncode, stderr)


def test_encrypt_files_suppresses_broken_pipe_noise(tmp_path):
    _write_repo_fixture(tmp_path)
    (tmp_path / "secret.secret").write_text("plain-secret")

    returncode, stderr = _run_with_closed_stdout(
        tmp_path,
        ["encrypt-files", "secret"],
        extra_env={"PYTHONUNBUFFERED": "1"},
    )

    _assert_exits_quietly(returncode, stderr)
