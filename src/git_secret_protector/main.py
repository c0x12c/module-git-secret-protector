import argparse
import configparser
import os
import sys
from pathlib import Path

from git_secret_protector.context.module import GitSecretProtectorModule
from git_secret_protector.core.output import Output
from git_secret_protector.core.settings import Settings, get_settings
from git_secret_protector.services.encryption_manager import EncryptionManager
from git_secret_protector.utils.configure_logging import configure_logging
from git_secret_protector.utils.project_version import get_project_version_from_metadata

MODULE_FOLDER = ".git_secret_protector"

manager = None


def _safe_version():
    try:
        return get_project_version_from_metadata()
    except Exception:
        return "unknown"


def init_module_folder():
    settings = get_settings()
    module_path = Path(settings.module_dir)

    if not module_path.exists():
        module_path.mkdir(parents=True, exist_ok=True)
        (module_path / "cache").mkdir(exist_ok=True)
        (module_path / "logs").mkdir(exist_ok=True)
    else:
        (module_path / "cache").mkdir(exist_ok=True)
        (module_path / "logs").mkdir(exist_ok=True)

    gitignore_path = Path(settings.base_dir) / ".gitignore"
    gitignore_entry = f"{MODULE_FOLDER}/"
    existing_lines = []

    if gitignore_path.exists():
        existing_lines = gitignore_path.read_text().splitlines()

    if gitignore_entry not in existing_lines:
        with open(gitignore_path, "a") as gitignore_file:
            if gitignore_path.exists() and gitignore_path.stat().st_size > 0:
                gitignore_file.write("\n")
            gitignore_file.write(f"{gitignore_entry}\n")

    # Check if config.ini exists, if not, create it with default settings
    config_file = module_path / "config.ini"
    if not config_file.exists():
        config = configparser.ConfigParser()
        config["DEFAULT"] = {
            "module_name": "git-secret-protector",
            "log_level": "WARN",
            "log_max_size": "1048576",  # 10MB
        }

        with open(config_file, "w") as configfile:
            config.write(configfile)


def setup_aes_key(args):
    filter_name = args.filter_name
    manager.setup_aes_key(filter_name=filter_name, scheme=args.scheme)


def setup_filters(_):
    manager.setup_filters()


def pull_aes_key(args):
    filter_name = args.filter_name
    manager.pull_aes_key(filter_name=filter_name)


def rotate_key(args):
    filter_name = args.filter_name
    manager.rotate_keys(filter_name=filter_name, assume_yes=getattr(args, "yes", False))


def upgrade_scheme(args):
    manager.upgrade_scheme(
        filter_name=args.filter_name, assume_yes=getattr(args, "yes", False)
    )


def decrypt_stdin(args):
    file_name = args.file_name
    manager.decrypt_stdin(file_name=file_name)


def encrypt_stdin(args):
    file_name = args.file_name
    manager.encrypt_stdin(file_name=file_name)


def decrypt_files_by_filter(args):
    filter_name = args.filter_name
    manager.decrypt_files(filter_name=filter_name)


def encrypt_files_by_filter(args):
    filter_name = args.filter_name
    manager.encrypt_files(filter_name=filter_name)


def clean_filter(args):
    filter_name = args.filter_name
    manager.clean_filter(filter_name=filter_name)


def status_command(_):
    manager.status()


def doctor_command(_):
    sys.exit(manager.doctor())


def show_project_version(args, output=None):
    EncryptionManager.show_project_version(args, output)


def init_command(args):
    sys.exit(
        EncryptionManager.init_config(
            backend=getattr(args, "backend", None),
            module_name=getattr(args, "module_name", None),
            assume_yes=getattr(args, "yes", False),
            force=getattr(args, "force", False),
        )
    )


def main():
    # Shared parent inherited by both the top-level parser and every subparser.
    # SUPPRESS means an absent flag sets NO attribute, so a subparser parse
    # cannot clobber a value already captured by the top-level parse.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--repo-root",
        type=str,
        default=argparse.SUPPRESS,
        help=(
            "Repo root to operate on (overrides auto-detection; same as the "
            "SECRET_PROTECTOR_BASE_DIR env var)."
        ),
    )
    common.add_argument(
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Suppress success/info output (errors still shown).",
    )
    common.add_argument(
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show internal logs on stderr.",
    )
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Emit machine-readable JSON (status/doctor/version and "
            "action results; ignored for encrypt/decrypt)."
        ),
    )

    parser = argparse.ArgumentParser(
        description=(
            "Encrypt selected repository files transparently with Git filters and "
            "per-filter AES keys."
        ),
        epilog=(
            "Typical workflow (repo owner):\n"
            "  1. create .gitattributes mapping globs to filters\n"
            "  2. git-secret-protector setup-filters\n"
            "  3. git-secret-protector setup-aes-key <filter>\n"
            "  4. edit/commit - files are encrypted transparently\n"
            "Team member:\n"
            "  git-secret-protector pull-aes-key <filter> && "
            "git-secret-protector setup-filters"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"git-secret-protector {_safe_version()}",
    )
    subparsers = parser.add_subparsers(help="Available commands")

    # setup-aes-key has its own subparser (--scheme flag)
    parser_setup_aes_key = subparsers.add_parser(
        "setup-aes-key", help="Set up AES key for a filter", parents=[common]
    )
    parser_setup_aes_key.add_argument(
        "filter_name", type=str, nargs="?", help="The filter name"
    )
    parser_setup_aes_key.add_argument(
        "--scheme",
        choices=["v1", "v2"],
        default="v2",
        help="Encryption scheme (default: v2; v1 is legacy AES-CBC)",
    )
    parser_setup_aes_key.set_defaults(func=setup_aes_key)

    # Add filter commands to the parser
    filter_commands = [
        ("pull-aes-key", pull_aes_key, "Pull AES key for a filter"),
        (
            "decrypt-files",
            decrypt_files_by_filter,
            "Decrypt files for a specific filter",
        ),
        (
            "encrypt-files",
            encrypt_files_by_filter,
            "Encrypt all files for a specified filter",
        ),
        ("clean-filter", clean_filter, "Clean staged data for a specified filter"),
    ]

    # Command to set up Git filters
    parser_setup_filters_stdin = subparsers.add_parser(
        "setup-filters",
        help="Set up Git filters in Git config",
        parents=[common],
    )
    parser_setup_filters_stdin.set_defaults(func=setup_filters)

    # Command to decrypt data from stdin
    parser_decrypt_stdin = subparsers.add_parser(
        "decrypt", help="Decrypt data from stdin", parents=[common]
    )
    parser_decrypt_stdin.add_argument(
        "file_name", type=str, help="Filename for decryption"
    )
    parser_decrypt_stdin.set_defaults(func=decrypt_stdin)

    # Command to encrypt data from stdin
    parser_encrypt_stdin = subparsers.add_parser(
        "encrypt", help="Encrypt data from stdin", parents=[common]
    )
    parser_encrypt_stdin.add_argument(
        "file_name", type=str, help="Filename for encryption"
    )
    parser_encrypt_stdin.set_defaults(func=encrypt_stdin)

    for cmd_name, func, help_text in filter_commands:
        parser_cmd = subparsers.add_parser(cmd_name, help=help_text, parents=[common])
        parser_cmd.add_argument(
            "filter_name", type=str, nargs="?", help="The filter name"
        )
        parser_cmd.set_defaults(func=func)

    parser_rotate_key = subparsers.add_parser(
        "rotate-key",
        help="Rotate AES key and re-encrypt secrets",
        parents=[common],
    )
    parser_rotate_key.add_argument(
        "filter_name", type=str, nargs="?", help="The filter name"
    )
    parser_rotate_key.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip the rotate confirmation prompt",
    )
    parser_rotate_key.set_defaults(func=rotate_key)

    parser_upgrade_scheme = subparsers.add_parser(
        "upgrade-scheme",
        help="One-way upgrade of a filter from v1 (legacy AES-CBC) to v2 (AES-256-CTR+HMAC)",
        parents=[common],
    )
    parser_upgrade_scheme.add_argument(
        "filter_name", type=str, nargs="?", help="The filter name"
    )
    parser_upgrade_scheme.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip the upgrade confirmation prompt",
    )
    parser_upgrade_scheme.set_defaults(func=upgrade_scheme)

    # Status command
    parser_status = subparsers.add_parser(
        "status", help="List all filters and file statuses", parents=[common]
    )
    parser_status.set_defaults(func=status_command)

    parser_doctor = subparsers.add_parser(
        "doctor", help="Diagnose the git-secret-protector setup", parents=[common]
    )
    parser_doctor.set_defaults(func=doctor_command)

    # Version command
    parser_version = subparsers.add_parser(
        "version", help="Show version", parents=[common]
    )
    parser_version.set_defaults(func=show_project_version)

    # Init command - writes config.ini interactively
    parser_init = subparsers.add_parser(
        "init",
        help="Initialize git-secret-protector config (writes config.ini)",
        parents=[common],
    )
    parser_init.add_argument(
        "--backend",
        choices=["AWS_SSM", "GCP_SECRET"],
        default=None,
        help="Storage backend (default: prompt or AWS_SSM with --yes)",
    )
    parser_init.add_argument(
        "--module-name",
        dest="module_name",
        default=None,
        help="Module name written into config.ini (default: prompt or git-secret-protector with --yes)",
    )
    parser_init.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Non-interactive: accept all defaults, skip prompts",
    )
    parser_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing config.ini without prompting",
    )
    parser_init.set_defaults(func=init_command)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return

    if getattr(args, "quiet", False) and getattr(args, "verbose", False):
        print("Error: --quiet and --verbose are mutually exclusive.", file=sys.stderr)
        sys.exit(2)

    output = Output(
        quiet=getattr(args, "quiet", False),
        verbose=getattr(args, "verbose", False),
        json=getattr(args, "json", False),
    )

    try:
        if args.func not in (show_project_version, init_command):
            if getattr(args, "repo_root", None):
                repo_root = Path(args.repo_root).resolve()
                if not repo_root.is_dir():
                    print(
                        f"Error: --repo-root points to a missing directory: {getattr(args, 'repo_root', '')}",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                os.environ[Settings.BASE_DIR_ENV_VAR] = str(repo_root)
                os.chdir(repo_root)
            init_module_folder()
            configure_logging(verbose=output.verbose)
            GitSecretProtectorModule.set_output(output)
            global manager
            manager = GitSecretProtectorModule.get_injector().get(EncryptionManager)
            args.func(args)
        elif args.func is show_project_version:
            show_project_version(args, output)
        else:
            args.func(args)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
