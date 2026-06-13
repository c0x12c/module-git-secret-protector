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


def test_help_includes_typical_workflow_epilog(tmp_path):
    result = _run_main(["--help"], tmp_path)

    assert result.returncode == 0
    assert "Typical workflow" in result.stdout
