import argparse
import configparser
import logging
import subprocess
import sys
from pathlib import Path

from git_secret_protector.aes_key_manager import AesKeyManager
from git_secret_protector.encryption_manager import EncryptionManager
from git_secret_protector.git_attributes_parser import GitAttributesParser
from git_secret_protector.key_rotator import KeyRotator
from git_secret_protector.logging import configure_logging
from git_secret_protector.settings import get_settings

logger = logging.getLogger(__name__)

MODULE_FOLDER = '.git_secret_protector'


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

    key_manager = AesKeyManager()
    key_manager.setup_aes_key_and_iv(args.filter_name)
    logger.info(f"Filters for '{filter_name}' have been set up successfully.")


def init_filter(args):
    filter_name = args.filter_name
    logger.info("Initializing filter: %s", filter_name)

    init_module_folder()

    # Check for existing Git filters
    check_clean = subprocess.getoutput(f'git config --get filter.{filter_name}.clean')
    check_smudge = subprocess.getoutput(f'git config --get filter.{filter_name}.smudge')

    logger.info("Setting up Git filters for '%s'", filter_name)
    if check_clean or check_smudge:
        sys.stdout.buffer.write(f"Git filters for '{filter_name}' already exist. Skipping filter setup.".encode())
        sys.stdout.buffer.flush()
        return

    # Set Git filters
    subprocess.run(['git', 'config', f'filter.{filter_name}.clean', 'git-secret-protector encrypt %f'], check=True)
    subprocess.run(['git', 'config', f'filter.{filter_name}.smudge', 'git-secret-protector decrypt %f'], check=True)
    subprocess.run(['git', 'config', f'filter.{filter_name}.required', 'true'], check=True)
    logger.debug("Git clean & smudge filters for '%s' have been set up successfully.", filter_name)


def pull_aes_key(args):
    key_manager = AesKeyManager()
    key_manager.retrieve_key_and_iv(args.filter_name)
    logger.info("AES key pulled and cached for filter: %s", args.filter_name)


def rotate_key(args):
    key_manager = AesKeyManager()
    git_attributes_parser = GitAttributesParser()
    rotator = KeyRotator(key_manager, git_attributes_parser)
    rotator.rotate_key(args.filter_name)
    logger.info("Key rotation complete for filter: %s", args.filter_name)


def decrypt_stdin(args):
    file_name = args.file_name  # Local variable to reduce duplication
    logger.info("Decrypting data from stdin with file_name: %s", file_name)

    # Read all data from stdin
    encrypted_data = sys.stdin.buffer.read()

    if not encrypted_data:
        logger.error("No data provided on stdin")
        return

    git_attributes_parser = GitAttributesParser()
    filter_name = git_attributes_parser.get_filter_name_for_file(file_name)
    logger.debug("Found filter_name to decrypt: %s", filter_name)

    if filter_name is None:
        logger.error("No filter found for file: %s", args.file_name)
        return

    # Assuming you have a modified version of the EncryptionManager to handle data instead of file names
    encryption_manager = EncryptionManager.from_filter_name(filter_name, git_attributes_parser)
    decrypted_data = encryption_manager.decrypt_data(
        encrypted_data)  # This needs to be implemented in EncryptionManager

    # Print the encrypted data to stdout
    sys.stdout.buffer.write(decrypted_data)
    sys.stdout.buffer.flush()


def encrypt_stdin(args):
    file_name = args.file_name  # Local variable to reduce duplication
    logger.info("Encrypting data from stdin with file_name: %s", file_name)

    # Read all data from stdin
    input_data = sys.stdin.buffer.read()

    if not input_data:
        logger.error("No data provided on stdin")
        return

    git_attributes_parser = GitAttributesParser()
    filter_name = git_attributes_parser.get_filter_name_for_file(file_name)
    logger.debug("Found filter_name to decrypt: %s", filter_name)

    if filter_name is None:
        logger.error("No filter found for file: %s", args.file_name)
        return

    encryption_manager = EncryptionManager.from_filter_name(filter_name, git_attributes_parser)
    encrypted_data = encryption_manager.encrypt_data(input_data)

    sys.stdout.buffer.write(encrypted_data)
    sys.stdout.buffer.flush()


def decrypt_files_by_filter(args):
    filter_name = args.filter_name
    logger.info("Decrypting files for filter: %s", filter_name)

    try:
        git_attributes_parser = GitAttributesParser()
        files = git_attributes_parser.get_files_for_filter(filter_name)

        if not files:
            logger.info("No files to decrypt for filter: %s", filter_name)
            return

        key_manager = AesKeyManager()
        aes_key, iv = key_manager.retrieve_key_and_iv(filter_name)
        encryption_manager = EncryptionManager(aes_key, iv, git_attributes_parser)
        encryption_manager.decrypt(filter_name)

        logger.info("All files decrypted for filter: %s", filter_name)
    except Exception as e:
        logger.error("Failed to decrypt files for filter %s: %s", filter_name, e)
        raise


def encrypt_files_by_filter(args):
    filter_name = args.filter_name
    logger.info("Encrypting files for filter: %s", filter_name)

    try:
        git_attributes_parser = GitAttributesParser()
        files = git_attributes_parser.get_files_for_filter(filter_name)

        if not files:
            logger.info("No files to encrypt for filter: %s", filter_name)
            return

        key_manager = AesKeyManager()
        aes_key, iv = key_manager.retrieve_key_and_iv(filter_name)
        encryption_manager = EncryptionManager(aes_key, iv, git_attributes_parser)
        encryption_manager.encrypt(filter_name)

        logger.info("All files encrypted for filter: %s", filter_name)
    except Exception as e:
        logger.error("Failed to encrypt files for filter %s: %s", filter_name, e)
        raise


def status_command(args):
    logger.info("Gathering status of all filters and their files...")
    git_attributes_parser = GitAttributesParser()
    filter_names = git_attributes_parser.get_filter_names()

    for filter_name in filter_names:
        print(f"Filter: {filter_name}")
        files = git_attributes_parser.get_files_for_filter(filter_name)
        if files:
            for file in files:
                # Assuming an EncryptionManager method to check if the file is encrypted
                encrypted = EncryptionManager.is_encrypted(file)
                status = "Encrypted" if encrypted else "Decrypted"
                print(f"  {file}: {status}")
        else:
            print("  No files found for this filter.")


def main():
    configure_logging()

    parser = argparse.ArgumentParser(description="Git Secret Protector CLI")

    subparsers = parser.add_subparsers(help="Available commands")

    # Command to init filter
    parser_init = subparsers.add_parser('init', help="Init filter actions in git config")
    parser_init.add_argument('filter_name', type=str, help="The filter name")
    parser_init.set_defaults(func=init_filter)

    # Command to set up AES key
    parser_setup_aes_key = subparsers.add_parser('setup-aes-key', help="Set up AES key for a filter")
    parser_setup_aes_key.add_argument('filter_name', type=str, help="The filter name for the AES key")
    parser_setup_aes_key.set_defaults(func=setup_aes_key)

    # Command to pull AES key
    parser_pull_aes_key = subparsers.add_parser('pull-aes-key', help="Pull AES key for a filter")
    parser_pull_aes_key.add_argument('filter_name', type=str, help="The filter name for the AES key")
    parser_pull_aes_key.set_defaults(func=pull_aes_key)

    # Command to rotate AES keys
    parser_rotate_key = subparsers.add_parser('rotate-key', help="Rotate AES key and re-encrypt secrets")
    parser_rotate_key.add_argument('filter_name', type=str, help="The filter name for the AES key")
    parser_rotate_key.set_defaults(func=rotate_key)

    # Command to decrypt data from stdin
    parser_decrypt_stdin = subparsers.add_parser('decrypt', help="Decrypt data from stdin")
    parser_decrypt_stdin.add_argument('file_name', type=str, help="Filename for decryption")
    parser_decrypt_stdin.set_defaults(func=decrypt_stdin)

    # Command to encrypt data from stdin
    parser_encrypt_stdin = subparsers.add_parser('encrypt', help="Encrypt data from stdin")
    parser_encrypt_stdin.add_argument('file_name', type=str, help="Filename for encryption")
    parser_encrypt_stdin.set_defaults(func=encrypt_stdin)

    # Command to decrypt files for a specific filter
    parser_decrypt_files = subparsers.add_parser('decrypt-files', help="Decrypt files for a specific filter")
    parser_decrypt_files.add_argument('filter_name', type=str, help="The filter name whose files to decrypt")
    parser_decrypt_files.set_defaults(func=decrypt_files_by_filter)

    # Add a command to encrypt files by filter
    parser_encrypt_files = subparsers.add_parser('encrypt-files', help="Encrypt all files for a specified filter")
    parser_encrypt_files.add_argument('filter_name', type=str, help="The filter name for which to encrypt files")
    parser_encrypt_files.set_defaults(func=encrypt_files_by_filter)

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
