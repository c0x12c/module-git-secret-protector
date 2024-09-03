import argparse
import logging
import os
import sys
import time

from git_secret_protector.encryption_manager import EncryptionManager
from git_secret_protector.git_attributes_parser import GitAttributesParser
from git_secret_protector.git_hooks_installer import GitHooksInstaller
from git_secret_protector.key_rotator import KeyRotator
from git_secret_protector.aes_key_manager import AesKeyManager
from git_secret_protector.logging import configure_logging

logger = logging.getLogger(__name__)


def setup_aes_key(args):
    logger.info("AES key setup complete for args: %s", args)
    key_manager = AesKeyManager()
    key_manager.setup_aes_key_and_iv(args.filter_name)
    logger.info("AES key setup complete for filter: %s", args.filter_name)


def pull_aes_key(args):
    key_manager = AesKeyManager()
    key_manager.retrieve_key_and_iv(args.filter_name)
    logger.info("KMS key pulled and cached for filter: %s", args.filter_name)


def rotate_key(args):
    key_manager = AesKeyManager()
    git_attributes_parser = GitAttributesParser()
    rotator = KeyRotator(key_manager, git_attributes_parser)
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
    encryption_manager = EncryptionManager.from_filter_name(filter_name)
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

    encryption_manager = EncryptionManager.from_filter_name(filter_name)
    encrypted_data = encryption_manager.encrypt_data(input_data)

    sys.stdout.buffer.write(encrypted_data)
    sys.stdout.buffer.flush()


def main():
    configure_logging()

    parser = argparse.ArgumentParser(description="Git Secret Protector CLI")

    subparsers = parser.add_subparsers(help="Available commands")

    # Command to setup AES key in KMS
    parser_setup_aes_key = subparsers.add_parser('setup-aes-key', help="Setup AES key in KMS")
    parser_setup_aes_key.add_argument('filter_name', type=str, help="The filter name for the AES key")
    parser_setup_aes_key.set_defaults(func=setup_aes_key)

    # Command to pull KMS keys
    parser_pull_aes_key = subparsers.add_parser('pull-aes-key', help="Pull KMS key for a filter")
    parser_pull_aes_key.add_argument('filter_name', type=str, help="The filter name for the KMS key")
    parser_pull_aes_key.set_defaults(func=pull_aes_key)

    # Command to rotate KMS keys
    parser_rotate_key = subparsers.add_parser('rotate-key', help="Rotate KMS key and re-encrypt secrets")
    parser_rotate_key.add_argument('filter_name', type=str, help="The filter name for the KMS key")
    parser_rotate_key.set_defaults(func=rotate_key)

    # Command to install Git hooks
    parser_install = subparsers.add_parser('install', help="Install Git hooks and initialize the module")
    parser_install.set_defaults(func=install)

    # Command to decrypt data from stdin
    parser_decrypt_stdin = subparsers.add_parser('decrypt', help="Decrypt data from stdin")
    parser_decrypt_stdin.add_argument('file_name', type=str, help="Filename for logging/reference")
    parser_decrypt_stdin.set_defaults(func=decrypt_stdin)

    # Command to encrypt data from stdin
    parser_encrypt_stdin = subparsers.add_parser('encrypt', help="Encrypt data from stdin")
    parser_encrypt_stdin.add_argument('file_name', type=str, help="Filename for logging/reference")
    parser_encrypt_stdin.set_defaults(func=encrypt_stdin)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
