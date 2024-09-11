import logging
import subprocess
import sys

import injector

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler
from git_secret_protector.crypto.aes_key_manager import AesKeyManager
from git_secret_protector.services.key_rotator import KeyRotator

logger = logging.getLogger(__name__)


class EncryptionManager:
    @injector.inject
    def __init__(self, key_manager: AesKeyManager, git_attributes_parser: GitAttributesParser, key_rotator: KeyRotator):
        self.git_attributes_parser = git_attributes_parser
        self.key_manager = key_manager
        self.key_rotator = key_rotator

    def get_encryption_handler(self, filter_name: str):
        aes_key, iv = self.key_manager.retrieve_key_and_iv(filter_name)
        return AesEncryptionHandler(aes_key, iv)

    def setup_aes_key(self, filter_name: str):
        self.key_manager.setup_aes_key_and_iv(filter_name)

    def init_filter(self, filter_name: str):
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

    def pull_aes_key(self, filter_name: str):
        self.key_manager.retrieve_key_and_iv(filter_name=filter_name)
        logger.info("AES key pulled and cached for filter: %s", filter_name)

    def encrypt_files(self, filter_name: str):
        files_to_encrypt = self.git_attributes_parser.get_files_for_filter(filter_name=filter_name)
        if not files_to_encrypt:
            logging.info(f"No files to encrypt for filter: {filter_name}")
            return

        self.get_encryption_handler(filter_name=filter_name).encrypt_files(files=files_to_encrypt)
        logging.info(f"All files encrypted for filter: {filter_name}")

    def decrypt_files(self, filter_name: str):
        files_to_decrypt = self.git_attributes_parser.get_files_for_filter(filter_name=filter_name)
        if not files_to_decrypt:
            logging.info(f"No files to decrypt for filter: {filter_name}")
            return

        self.get_encryption_handler(filter_name=filter_name).decrypt_files(files=files_to_decrypt)
        logging.info(f"All files decrypted for filter: {filter_name}")

    def encrypt_stdin(self, file_name):
        logging.info(f"Encrypting data from stdin for file: {file_name}")
        input_data = sys.stdin.buffer.read()

        if not input_data:
            logging.error("No data provided on stdin")
            return

        git_attributes_parser = GitAttributesParser()
        filter_name = git_attributes_parser.get_filter_name_for_file(file_name=file_name)
        logger.debug("Found filter_name to decrypt: %s", filter_name)

        if filter_name is None:
            logger.error("No filter found for file: %s", file_name)
            return

        encrypted_data = self.get_encryption_handler(filter_name=filter_name).encrypt_data(input_data)

        sys.stdout.buffer.write(encrypted_data)
        sys.stdout.buffer.flush()

    def decrypt_stdin(self, file_name):
        logging.info(f"Decrypting data from stdin for file: {file_name}")
        encrypted_data = sys.stdin.buffer.read()

        if not encrypted_data:
            logging.error("No data provided on stdin")
            return

        git_attributes_parser = GitAttributesParser()
        filter_name = git_attributes_parser.get_filter_name_for_file(file_name)
        logger.debug("Found filter_name to decrypt: %s", filter_name)

        if filter_name is None:
            logger.error("No filter found for file: %s", file_name)
            return

        decrypted_data = self.get_encryption_handler(filter_name=filter_name).decrypt_data(encrypted_data)

        sys.stdout.buffer.write(decrypted_data)
        sys.stdout.buffer.flush()

    def rotate_keys(self, filter_name: str):
        rotator = KeyRotator(self.key_manager, self.git_attributes_parser)
        rotator.rotate_key(filter_name)
        logger.info("Key rotation complete for filter: %s", filter_name)

    def status(self):
        filter_names = self.git_attributes_parser.get_filter_names()
        for filter_name in filter_names:
            print(f"Filter: {filter_name}")
            files = self.git_attributes_parser.get_files_for_filter(filter_name)
            if files:
                for file in files:
                    encrypted = self.get_encryption_handler(filter_name=filter_name).is_encrypted(file)
                    status = "Encrypted" if encrypted else "Decrypted"
                    print(f"  {file}: {status}")
            else:
                print("  No files found for this filter.")
