import logging

import injector

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler
from git_secret_protector.crypto.aes_key_manager import AesKeyManager

logger = logging.getLogger(__name__)


class KeyRotator:
    @injector.inject
    def __init__(self, key_manager: AesKeyManager, git_attributes_parser: GitAttributesParser):
        self.aes_key_manager = key_manager
        self.git_attributes_parser = git_attributes_parser

    def rotate_key(self, filter_name: str):
        try:
            logger.info("Starting key and IV rotation for filter: %s", filter_name)

            # Step 1: Retrieve the current AES key and IV
            current_aes_key, current_iv = self.aes_key_manager.retrieve_key_and_iv(filter_name=filter_name)

            # Step 2: Decrypt all files using the current AES key and IV

            files_to_re_encrypt = self.git_attributes_parser.get_files_for_filter(filter_name=filter_name)

            decryption_manager = AesEncryptionHandler(aes_key=current_aes_key, iv=current_iv)
            decryption_manager.decrypt_files(files=files_to_re_encrypt)

            # Step 3: Generate and store a new AES key and IV
            self.aes_key_manager.setup_aes_key_and_iv(filter_name=filter_name)

            # Step 4: Retrieve the new AES key and IV
            new_aes_key, new_iv = self.aes_key_manager.retrieve_key_and_iv(filter_name=filter_name)

            # Step 5: Encrypt all files using the new AES key and IV
            encryption_manager = AesEncryptionHandler(aes_key=new_aes_key, iv=new_iv)
            encryption_manager.encrypt_files(files=files_to_re_encrypt)

            logger.info("Key and IV rotation and re-encryption complete for filter: %s", filter_name)
        except Exception as e:
            logger.error("Failed to rotate key and IV for filter %s: %s", filter_name, e)
            raise
