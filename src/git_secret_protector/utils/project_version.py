from importlib.metadata import version


def get_project_version_from_metadata():
    return version("git-secret-protector")
