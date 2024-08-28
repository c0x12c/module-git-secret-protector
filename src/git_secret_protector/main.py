import argparse
import logging

from git_secret_protector.encryption_manager import EncryptionManager
from git_secret_protector.git_attributes_parser import GitAttributesParser
from git_secret_protector.git_hooks_installer import GitHooksInstaller
from git_secret_protector.key_rotator import KeyRotator
from git_secret_protector.kms_key_manager import KMSKeyManager
from git_secret_protector.logging import configure_logging

logger = logging.getLogger(__name__)


def setup_aes_key(args):
    kms_manager = KMSKeyManager()
    kms_manager.setup_aes_key(args.filter_name)
    logger.info("AES key setup complete for filter: %s", args.filter_name)


def pull_kms_key(args):
    kms_manager = KMSKeyManager()
    kms_manager.pull_aes_key(args.filter_name)
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
    git_attributes_parser = GitAttributesParser()
    filter_names = git_attributes_parser.get_filter_names()

    for filter_name in filter_names:
        encryption_manager = EncryptionManager.from_filter_name(filter_name)
        encryption_manager.encrypt(filter_name)
        logger.info("Files encrypted for filter: %s", filter_name)


def decrypt_files(args):
    git_attributes_parser = GitAttributesParser()
    filter_names = git_attributes_parser.get_filter_names()

    for filter_name in filter_names:
        encryption_manager = EncryptionManager.from_filter_name(filter_name)
        encryption_manager.decrypt(filter_name)
        logger.info("Files decrypted for filter: %s", filter_name)


def encrypt_file(args):
    logger.info("Executing encrypt_file command: %s", args)
    git_attributes_parser = GitAttributesParser()
    filter_name = git_attributes_parser.get_filter_name_for_file(args.file_name)
    logger.info("Found filter_name to encrypt: %s", filter_name)

    if filter_name is None:
        logger.error("No filter found for file: %s", args.file_name)
        return

    encryption_manager = EncryptionManager.from_filter_name(filter_name)
    encrypted_data = encryption_manager.encrypt_file(args.file_name)
    print(encrypted_data.decode('utf-8'))


def decrypt_file(args):
    logger.info("Executing decrypt_file command: %s", args)
    git_attributes_parser = GitAttributesParser()
    filter_name = git_attributes_parser.get_filter_name_for_file(args.file_name)
    logger.info("Found filter_name to decrypt: %s", filter_name)

    if filter_name is None:
        logger.error("No filter found for file: %s", args.file_name)
        return

    encryption_manager = EncryptionManager.from_filter_name(filter_name)
    decrypted_data = encryption_manager.decrypt_file(args.file_name)
    print(decrypted_data.decode('utf-8'))


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

    # Command to encrypt a specific file
    parser_encrypt_file = subparsers.add_parser('encrypt-file', help="Encrypt a specific file")
    parser_encrypt_file.add_argument('file_name', type=str, help="The file to encrypt")
    parser_encrypt_file.set_defaults(func=encrypt_file)

    # Command to decrypt a specific file
    parser_decrypt_file = subparsers.add_parser('decrypt-file', help="Decrypt a specific file")
    parser_decrypt_file.add_argument('file_name', type=str, help="The file to decrypt")
    parser_decrypt_file.set_defaults(func=decrypt_file)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
