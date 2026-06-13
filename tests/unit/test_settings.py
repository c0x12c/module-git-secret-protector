import os

import pytest

from git_secret_protector.core.settings import Settings


def test_find_base_dir_prefers_outer_marker_for_nested_repo(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_PROTECTOR_BASE_DIR", raising=False)
    outer_dir = tmp_path / "outer"
    inner_dir = outer_dir / "inner"
    (outer_dir / ".git_secret_protector").mkdir(parents=True)
    (outer_dir / ".git").mkdir()
    (inner_dir / ".git").mkdir(parents=True)

    monkeypatch.chdir(inner_dir)

    assert os.path.realpath(Settings._find_base_dir()) == os.path.realpath(
        str(outer_dir)
    )


def test_find_base_dir_prefers_nearest_marker_when_both_initialized(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("SECRET_PROTECTOR_BASE_DIR", raising=False)
    outer_dir = tmp_path / "outer"
    inner_dir = outer_dir / "inner"
    (outer_dir / ".git_secret_protector").mkdir(parents=True)
    (outer_dir / ".git").mkdir()
    (inner_dir / ".git_secret_protector").mkdir(parents=True)
    (inner_dir / ".git").mkdir()

    monkeypatch.chdir(inner_dir)

    assert os.path.realpath(Settings._find_base_dir()) == os.path.realpath(
        str(inner_dir)
    )


def test_find_base_dir_env_override_takes_precedence(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_PROTECTOR_BASE_DIR", raising=False)
    override_dir = tmp_path / "override"
    repo_dir = tmp_path / "repo"
    nested_dir = repo_dir / "nested"
    override_dir.mkdir()
    (repo_dir / ".git_secret_protector").mkdir(parents=True)
    (repo_dir / ".git").mkdir()
    nested_dir.mkdir()
    monkeypatch.setenv("SECRET_PROTECTOR_BASE_DIR", str(override_dir))
    monkeypatch.chdir(nested_dir)

    assert os.path.realpath(Settings._find_base_dir()) == os.path.realpath(
        str(override_dir)
    )


def test_find_base_dir_rejects_invalid_env_override(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_PROTECTOR_BASE_DIR", raising=False)
    missing_dir = tmp_path / "missing"
    monkeypatch.setenv("SECRET_PROTECTOR_BASE_DIR", str(missing_dir))

    with pytest.raises(FileNotFoundError) as exc_info:
        Settings._find_base_dir()

    assert "SECRET_PROTECTOR_BASE_DIR" in str(exc_info.value)
    assert str(missing_dir) in str(exc_info.value)


def test_find_base_dir_bootstraps_from_git_dir_without_marker(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_PROTECTOR_BASE_DIR", raising=False)
    repo_dir = tmp_path / "repo"
    nested_dir = repo_dir / "nested"
    (repo_dir / ".git").mkdir(parents=True)
    nested_dir.mkdir()

    monkeypatch.chdir(nested_dir)

    assert os.path.realpath(Settings._find_base_dir()) == os.path.realpath(
        str(repo_dir)
    )


def test_find_base_dir_supports_git_file_for_worktrees(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_PROTECTOR_BASE_DIR", raising=False)
    repo_dir = tmp_path / "repo"
    nested_dir = repo_dir / "nested"
    repo_dir.mkdir()
    (repo_dir / ".git").write_text("gitdir: /tmp/worktree\n")
    nested_dir.mkdir()

    monkeypatch.chdir(nested_dir)

    assert os.path.realpath(Settings._find_base_dir()) == os.path.realpath(
        str(repo_dir)
    )


def test_find_base_dir_raises_when_not_in_repo(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_PROTECTOR_BASE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(FileNotFoundError, match="git repository"):
        Settings._find_base_dir()
