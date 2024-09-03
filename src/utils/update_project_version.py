"""
This Python script updates the version specified in a pyproject.toml file.
By default, it bumps the patch version (e.g., from 1.0.0 to 1.0.1).
It also allows for an optional version override through a command-line argument.
The script reads the pyproject.toml file, updates the version, and writes the changes back to the file.

Usage:

- Without version override: python script.py
- With version override: python script.py 1.2.3
"""

import sys
from tomlkit import parse, dumps


def bump_patch_version(version):
    major, minor, patch = map(int, version.split("."))
    patch += 1
    return f"{major}.{minor}.{patch}"


def update_project_version(project_config_file, version_override=None):
    with open(project_config_file, "r") as file:
        content = parse(file.read())

    if version_override:
        bumped_version = version_override
    else:
        current_version = content["tool"]["poetry"]["version"]
        bumped_version = bump_patch_version(current_version)

    content["tool"]["poetry"]["version"] = bumped_version

    with open(project_config_file, "w") as file:
        file.write(dumps(content))

    return bumped_version


if __name__ == "__main__":
    version_override = sys.argv[1] if len(sys.argv) > 1 else None
    new_version = update_project_version("pyproject.toml", version_override)
    print(new_version)
