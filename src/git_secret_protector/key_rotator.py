import logging

from git_secret_protector.encryption_manager import EncryptionManager
from git_secret_protector.git_attributes_parser import GitAttributesParser
from git_secret_protector.kms_key_manager import KMSKeyManager

logger = logging.getLogger(__name__)


class KeyRotator:
    def __init__(self):
        self.kms_key_manager = KMSKeyManager()
        self.git_attributes_parser = GitAttributesParser()

    def rotate_key(self, filter_name):
        try:
            logger.info("Rotating key for filter: %s", filter_name)

            # Step 1: Generate a new AES data key in KMS
            self.kms_key_manager.setup_aes_key(filter_name=filter_name)

            # Step 2: Retrieve the new AES key
            new_aes_key = self.kms_key_manager.pull_aes_key(filter_name=filter_name)

            # Step 3: Encrypt all files associated with this filter with the new AES key
            encryption_manager = EncryptionManager(aes_key=new_aes_key)
            encryption_manager.encrypt(filter_name=filter_name)

            logger.info("Key rotation and re-encryption complete for filter: %s", filter_name)
        except Exception as e:
            logger.error("Failed to rotate key for filter %s: %s", filter_name, e)
            raise
