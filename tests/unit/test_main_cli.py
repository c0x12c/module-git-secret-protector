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


def test_status_outside_git_repo_exits_cleanly(tmp_path):
    result = _run_main(["status"], tmp_path)

    assert result.returncode == 1
    assert "git repository" in result.stderr
    assert "Traceback" not in result.stderr


def test_help_outside_git_repo_still_works(tmp_path):
    result = _run_main(["--help"], tmp_path)

    assert result.returncode == 0
    assert "usage" in result.stdout
