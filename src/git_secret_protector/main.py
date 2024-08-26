import argparse
import logging

from git_secret_protector.encryption_manager import EncryptionManager
from git_secret_protector.git_hooks_installer import GitHooksInstaller
from git_secret_protector.key_rotator import KeyRotator
from git_secret_protector.kms_key_manager import KMSKeyManager
from git_secret_protector.logging import configure_logging
from git_secret_protector.settings import get_settings

logger = logging.getLogger(__name__)


def setup_logging():
    settings = get_settings()
    log_file = settings.log_file
    logging.basicConfig(
        filename=log_file,
        filemode='a',
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    logger.info("Logging initialized. Logs will be written to: %s", log_file)


def setup_aes_key(args):
    kms_manager = KMSKeyManager()
    kms_manager.setup_aes_key(args.filter_name)
    logger.info("AES key setup complete for filter: %s", args.filter_name)


def pull_kms_key(args):
    kms_manager = KMSKeyManager()
    kms_manager.get_aes_key(args.filter_name, force_refresh=True)
    logger.info("KMS key pulled and cached for filter: %s", args.filter_name)


def rotate_key(args):
    rotator = KeyRotator()
    rotator.rotate_key(args.filter_name)
    logger.info("Key rotation complete for filter: %s", args.filter_name)


def install(args):
    installer = GitHooksInstaller()
    installer.setup_hooks()
    logger.info("Git hooks installed successfully.")


def encrypt_files(args):
    encryption_manager = EncryptionManager.from_filter_name(args.filter_name)
    encryption_manager.encrypt(args.filter_name)
    logger.info("Files encrypted for filter: %s", args.filter_name)


def decrypt_files(args):
    encryption_manager = EncryptionManager.from_filter_name(args.filter_name)
    encryption_manager.decrypt(args.filter_name)
    logger.info("Files decrypted for filter: %s", args.filter_name)


def main():
    configure_logging()

    parser = argparse.ArgumentParser(description="Git Secret Protector CLI")

    subparsers = parser.add_subparsers(help="Available commands")

    # Command to setup AES key in KMS
    parser_setup_aes_key = subparsers.add_parser('setup-aes-key', help="Setup AES key in KMS")
    parser_setup_aes_key.add_argument('filter_name', type=str, help="The filter name for the AES key")
    parser_setup_aes_key.set_defaults(func=setup_aes_key)

    # Command to pull KMS keys
    parser_pull_kms_key = subparsers.add_parser('pull-kms-key', help="Pull KMS key for a filter")
    parser_pull_kms_key.add_argument('filter_name', type=str, help="The filter name for the KMS key")
    parser_pull_kms_key.set_defaults(func=pull_kms_key)

    # Command to rotate KMS keys
    parser_rotate_key = subparsers.add_parser('rotate-key', help="Rotate KMS key and re-encrypt secrets")
    parser_rotate_key.add_argument('filter_name', type=str, help="The filter name for the KMS key")
    parser_rotate_key.set_defaults(func=rotate_key)

    # Command to install Git hooks
    parser_install = subparsers.add_parser('install', help="Install Git hooks and initialize the module")
    parser_install.set_defaults(func=install)

    # Command to encrypt files
    parser_encrypt_files = subparsers.add_parser('encrypt', help="Encrypt files using KMS")
    parser_encrypt_files.add_argument('filter_name', type=str, help="The filter name for the AES key")
    parser_encrypt_files.set_defaults(func=encrypt_files)

    # Command to decrypt files
    parser_decrypt_files = subparsers.add_parser('decrypt', help="Decrypt files using KMS")
    parser_decrypt_files.add_argument('filter_name', type=str, help="The filter name for the AES key")
    parser_decrypt_files.set_defaults(func=decrypt_files)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
