import argparse
import configparser
import logging
from pathlib import Path

from git_secret_protector.context.module import GitSecretProtectorModule
from git_secret_protector.core.settings import get_settings
from git_secret_protector.services.encryption_manager import EncryptionManager
from git_secret_protector.utils.configure_logging import configure_logging

logger = logging.getLogger(__name__)

MODULE_FOLDER = '.git_secret_protector'

inj = GitSecretProtectorModule.get_injector()
manager = inj.get(EncryptionManager)


def init_module_folder():
    module_path = Path(get_settings().module_dir)

    if not module_path.exists():
        module_path.mkdir(parents=True, exist_ok=True)
        (module_path / 'cache').mkdir(exist_ok=True)
        (module_path / 'logs').mkdir(exist_ok=True)

    # Check if config.ini exists, if not, create it with default settings
    config_file = module_path / 'config.ini'
    if not config_file.exists():
        config = configparser.ConfigParser()
        config['DEFAULT'] = {
            'module_name': 'git-secret-protector',
            'log_level': 'WARN',
            'log_max_size': '10485760'  # 10MB
        }

        with open(config_file, 'w') as configfile:
            config.write(configfile)


def setup_aes_key(args):
    filter_name = args.filter_name
    logger.info("Set up AES key for filter: %s", filter_name)

    init_module_folder()

    manager.setup_aes_key(filter_name=filter_name)
    logger.info(f"Filters for '{filter_name}' have been set up successfully.")


def init_filter(args):
    filter_name = args.filter_name
    logger.info("Initializing filter: %s", filter_name)

    init_module_folder()

    manager.init_filter(filter_name=filter_name)


def pull_aes_key(args):
    filter_name = args.filter_name
    logger.info("Pull AES key for filter: %s", filter_name)

    init_module_folder()

    manager.pull_aes_key(filter_name=filter_name)


def rotate_key(args):
    filter_name = args.filter_name
    manager.rotate_keys(filter_name=filter_name)


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


def status_command(_):
    manager.status()


def main():
    configure_logging()
    parser = argparse.ArgumentParser(description="Git Secret Protector CLI")
    subparsers = parser.add_subparsers(help="Available commands")

    # Add filter commands to the parser
    filter_commands = [
        ('init', init_filter, "Init filter actions in git config"),
        ('setup-aes-key', setup_aes_key, "Set up AES key for a filter"),
        ('pull-aes-key', pull_aes_key, "Pull AES key for a filter"),
        ('rotate-key', rotate_key, "Rotate AES key and re-encrypt secrets"),
        ('decrypt-files', decrypt_files_by_filter, "Decrypt files for a specific filter"),
        ('encrypt-files', encrypt_files_by_filter, "Encrypt all files for a specified filter")
    ]

    # Command to decrypt data from stdin
    parser_decrypt_stdin = subparsers.add_parser('decrypt', help="Decrypt data from stdin")
    parser_decrypt_stdin.add_argument('file_name', type=str, help="Filename for decryption")
    parser_decrypt_stdin.set_defaults(func=decrypt_stdin)

    # Command to encrypt data from stdin
    parser_encrypt_stdin = subparsers.add_parser('encrypt', help="Encrypt data from stdin")
    parser_encrypt_stdin.add_argument('file_name', type=str, help="Filename for encryption")
    parser_encrypt_stdin.set_defaults(func=encrypt_stdin)

    for cmd_name, func, help_text in filter_commands:
        parser_cmd = subparsers.add_parser(cmd_name, help=help_text)
        parser_cmd.add_argument('filter_name', type=str, nargs='?', help="The filter name")
        parser_cmd.set_defaults(func=func)

    # Status command
    parser_status = subparsers.add_parser('status', help="List all filters and file statuses")
    parser_status.set_defaults(func=status_command)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
