import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run_import_check(code: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    pythonpath = str(ROOT / "src")
    env["PYTHONPATH"] = (
        f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
        if env.get("PYTHONPATH")
        else pythonpath
    )
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def test_importing_factory_does_not_import_cloud_sdks():
    result = _run_import_check(
        "import git_secret_protector.storage.storage_manager_factory as f; "
        "import sys; "
        "assert 'boto3' not in sys.modules; "
        "assert not any(m == 'google.cloud' or m.startswith('google.cloud.') for m in sys.modules)"
    )

    assert result.returncode == 0, result.stderr


def test_importing_aws_manager_module_does_not_import_boto3():
    result = _run_import_check(
        "import git_secret_protector.storage.aws_ssm_storage_manager; "
        "import sys; "
        "assert 'boto3' not in sys.modules"
    )

    assert result.returncode == 0, result.stderr


def test_importing_gcp_manager_module_does_not_import_google_sdk():
    result = _run_import_check(
        "import git_secret_protector.storage.gcp_secret_storage_manager; "
        "import sys; "
        "assert not any(m == 'google.cloud' or m.startswith('google.cloud.') for m in sys.modules)"
    )

    assert result.returncode == 0, result.stderr
