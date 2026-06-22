import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run_main(args, tmp_path):
    env = os.environ.copy()
    env.pop("SECRET_PROTECTOR_BASE_DIR", None)

    pythonpath = str(ROOT / "src")
    env["PYTHONPATH"] = (
        f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
        if env.get("PYTHONPATH")
        else pythonpath
    )

    return subprocess.run(
        [sys.executable, "-m", "git_secret_protector.main", *args],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
    )


def _init_git_repo(tmp_path):
    subprocess.run(
        ["git", "init"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
        text=True,
    )


def test_status_outside_git_repo_exits_cleanly(tmp_path):
    result = _run_main(["status"], tmp_path)

    assert result.returncode == 1
    assert "git repository" in result.stderr
    assert "Traceback" not in result.stderr


def test_help_outside_git_repo_still_works(tmp_path):
    result = _run_main(["--help"], tmp_path)

    assert result.returncode == 0
    assert "usage" in result.stdout


def test_version_flag_outside_git_repo_works(tmp_path):
    result = _run_main(["--version"], tmp_path)

    assert result.returncode == 0
    assert "git-secret-protector" in result.stdout


def test_short_version_flag_outside_git_repo_works(tmp_path):
    result = _run_main(["-V"], tmp_path)

    assert result.returncode == 0
    assert "git-secret-protector" in result.stdout


def test_repo_root_before_subcommand_uses_override(tmp_path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _init_git_repo(repo_root)
    (repo_root / ".gitattributes").write_text("*.secret filter=secret\n")
    (repo_root / "example.secret").write_text("plain\n")

    result = _run_main(["--repo-root", str(repo_root), "status"], tmp_path)

    assert result.returncode == 0
    assert "git repository" not in result.stderr
    assert "Filter: secret" in result.stdout


def test_repo_root_before_subcommand_missing_directory_errors(tmp_path):
    missing = tmp_path / "missing"

    result = _run_main(["--repo-root", str(missing), "status"], tmp_path)

    assert result.returncode == 1
    assert "missing directory" in result.stderr


def test_repo_root_before_doctor_scans_target_repo(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    _init_git_repo(target)
    (target / ".gitattributes").write_text("secret.env filter=app\n")
    (target / "secret.env").write_text("PLAINTEXT\n")

    result = _run_main(["--repo-root", str(target), "doctor"], tmp_path)

    assert result.returncode == 1
    assert "[FAIL]" in result.stdout
    assert "PLAINTEXT" in result.stdout


def test_help_includes_typical_workflow_epilog(tmp_path):
    result = _run_main(["--help"], tmp_path)

    assert result.returncode == 0
    assert "Typical workflow" in result.stdout


def test_quiet_and_verbose_conflict_exits_2(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".gitattributes").write_text("*.secret filter=secret\n")
    result = _run_main(
        ["--repo-root", str(repo), "--quiet", "--verbose", "status"], tmp_path
    )
    assert result.returncode == 2
    assert "quiet" in result.stderr.lower()


def test_json_flag_after_subcommand_parses(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".gitattributes").write_text("*.secret filter=secret\n")
    result = _run_main(["--repo-root", str(repo), "status", "--json"], tmp_path)
    assert result.returncode == 0
    import json

    json.loads(result.stdout)  # stdout is a valid JSON document


def test_repo_root_after_subcommand_is_accepted(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".gitattributes").write_text("*.secret filter=secret\n")
    (repo / "example.secret").write_text("plain\n")

    result = _run_main(["status", "--repo-root", str(repo)], tmp_path)

    assert result.returncode == 0
    assert "Filter: secret" in result.stdout


def test_quiet_after_subcommand_is_accepted(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".gitattributes").write_text("*.secret filter=secret\n")

    # --repo-root before subcommand, --quiet after - both must parse
    result = _run_main(["--repo-root", str(repo), "status", "--quiet"], tmp_path)

    # quiet suppresses info output but command must succeed
    assert result.returncode == 0
    # no "Filter:" line in quiet mode - success is returncode 0 with no error
    assert "git repository" not in result.stderr


# ---------------------------------------------------------------------------
# stdout-purity guard: encrypt/decrypt must never mix log/status bytes into
# the payload stream regardless of output flags.
# ---------------------------------------------------------------------------

import base64
import json
import os as _os


def _seed_key_cache(repo, filter_name: str) -> None:
    """Write a local AES key cache so the CLI never touches a storage backend."""
    cache_dir = repo / ".git_secret_protector" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    key_data = {
        "aes_key": base64.b64encode(_os.urandom(32)).decode(),
        "iv": base64.b64encode(_os.urandom(16)).decode(),
        "version": 2,
    }
    cache_file = cache_dir / f"{filter_name}_key_iv.json"
    cache_file.write_text(json.dumps(key_data))
    cache_file.chmod(0o600)


def _run_filter(args, cwd, stdin_bytes):
    """Run the CLI in binary mode; used for encrypt/decrypt filter commands."""
    env = _os.environ.copy()
    env.pop("SECRET_PROTECTOR_BASE_DIR", None)
    pythonpath = str(ROOT / "src")
    env["PYTHONPATH"] = (
        f"{pythonpath}{_os.pathsep}{env['PYTHONPATH']}"
        if env.get("PYTHONPATH")
        else pythonpath
    )
    return subprocess.run(
        [sys.executable, "-m", "git_secret_protector.main", *args],
        cwd=str(cwd),
        env=env,
        input=stdin_bytes,
        capture_output=True,
        # No text=True - we need raw bytes on stdout
    )


def test_init_creates_config_in_fresh_git_repo(tmp_path):
    """init --yes in a bare git repo (no .git_secret_protector) must create config.ini."""
    import configparser

    _init_git_repo(tmp_path)
    result = _run_main(
        ["init", "--yes", "--backend", "GCP_SECRET", "--module-name", "demo"],
        tmp_path,
    )
    assert result.returncode == 0, f"init failed: {result.stderr}"
    config_file = tmp_path / ".git_secret_protector" / "config.ini"
    assert config_file.exists(), "config.ini was not created"
    cfg = configparser.ConfigParser()
    cfg.read(str(config_file))
    assert cfg["DEFAULT"]["storage_type"] == "GCP_SECRET"
    assert cfg["DEFAULT"]["module_name"] == "demo"


def test_setup_aes_key_scheme_v1_parses(tmp_path):
    """setup-aes-key --scheme v1 must be accepted by argparse."""
    import argparse
    import sys as _sys

    # Import main module to get its parser
    ROOT_SRC = ROOT / "src"
    _sys.path.insert(0, str(ROOT_SRC))
    from git_secret_protector import main as _main

    # Rebuild the parser by running main() up to parse_args - instead, replicate
    # the argparse setup just enough to test the --scheme flag.
    result = _run_main(["setup-aes-key", "--help"], tmp_path)
    assert "--scheme" in result.stdout
    assert "v1" in result.stdout
    assert "v2" in result.stdout


def test_setup_aes_key_scheme_v1_reaches_manager(tmp_path):
    """Subprocess: setup-aes-key myfilter --scheme v1 must not crash on argparse."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".gitattributes").write_text("*.secret filter=myfilter\n")
    _seed_key_cache(repo, "myfilter")

    from unittest.mock import patch, MagicMock

    # Just verify argparse passes without error (backend call will fail w/o creds,
    # that's fine - we only need returncode != 2, which would mean argparse error)
    result = _run_main(
        ["--repo-root", str(repo), "setup-aes-key", "myfilter", "--scheme", "v1"],
        tmp_path,
    )
    # returncode 2 = argparse error; anything else means argparse accepted it
    assert result.returncode != 2, f"argparse rejected --scheme v1: {result.stderr}"


def test_encrypt_decrypt_stdout_is_pure_bytes_under_all_flags(tmp_path):
    """encrypt/decrypt stdout must equal exact payload bytes for every flag combo."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".gitattributes").write_text("*.secret filter=secret\n")

    # Seed the local key cache so the CLI never contacts AWS/GCP.
    # Must happen before the first CLI run (init_module_folder creates the dirs,
    # but _seed_key_cache creates them too via parents=True so order doesn't matter).
    _seed_key_cache(repo, "secret")

    plaintext = b"hello-secret-payload"

    flag_sets = [
        [],
        ["--json"],
        ["--quiet"],
        ["--verbose"],
    ]

    for flags in flag_sets:
        enc = _run_filter(
            [*flags, "encrypt", "x.secret"], cwd=repo, stdin_bytes=plaintext
        )
        assert enc.returncode == 0, f"encrypt failed (flags={flags}): {enc.stderr!r}"
        ciphertext = enc.stdout
        assert ciphertext != plaintext, f"encrypt produced plaintext (flags={flags})"

        dec = _run_filter(
            [*flags, "decrypt", "x.secret"], cwd=repo, stdin_bytes=ciphertext
        )
        assert dec.returncode == 0, f"decrypt failed (flags={flags}): {dec.stderr!r}"
        assert dec.stdout == plaintext, (
            f"stdout purity violated with flags={flags}: "
            f"got {dec.stdout[:60]!r}, expected {plaintext!r}"
        )
