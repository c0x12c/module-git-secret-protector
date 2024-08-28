import logging
import os

import boto3

from git_secret_protector.settings import get_settings

logger = logging.getLogger(__name__)


class KMSKeyManager:
    def __init__(self):
        # self.kms_client = boto3.client('kms')
        self.cache_dir = get_settings().cache_dir
        logger.info("KMSKeyManager initialized with cache directory: %s", self.cache_dir)

    def setup_aes_key(self, filter_name):
        try:
            logger.info("Setting up AES key for filter: %s", filter_name)
            response = boto3.client('kms').create_key(
                Description=f"Data key for {filter_name}",
                KeyUsage='ENCRYPT_DECRYPT',
                Origin='AWS_KMS'
            )
            key_id = response['KeyMetadata']['KeyId']
            logger.info("Created AES key with ID: %s", key_id)
            self.store_key_id(filter_name, key_id)
            logger.info("AES key created and stored with ID: %s", key_id)
        except Exception as e:
            logger.error("Failed to setup AES key for filter %s: %s", filter_name, e)
            raise

    def pull_aes_key(self, filter_name):
        try:
            logger.info("Pulling AES key for filter: %s from KMS", filter_name)
            key_id = self.get_key_id(filter_name)
            response = boto3.client('kms').generate_data_key(KeyId=key_id, KeySpec='AES_256')
            aes_key = response['Plaintext']
            self.cache_aes_key(filter_name, aes_key)
            logger.info("AES key pulled from KMS and cached for filter: %s", filter_name)
        except Exception as e:
            logger.error("Failed to pull AES key for filter %s: %s", filter_name, e)
            raise

    def get_aes_key(self, filter_name):
        logger.info("Retrieving AES key for filter: %s", filter_name)
        cached_key = self.load_cached_key(filter_name)
        if cached_key:
            logger.info("Cached AES key found for filter: %s", filter_name)
            return cached_key
        logger.warning("No cached AES key found for filter: %s", filter_name)
        return None

    def cache_aes_key(self, filter_name, aes_key):
        cache_file = os.path.join(self.cache_dir, f'{filter_name}.key')
        os.makedirs(self.cache_dir, exist_ok=True)
        with open(cache_file, 'wb') as f:
            f.write(aes_key)
        logger.info("AES key cached for filter: %s", filter_name)

    def load_cached_key(self, filter_name):
        cache_file = os.path.join(self.cache_dir, f'{filter_name}.key')
        if os.path.exists(cache_file):
            with open(cache_file, 'rb') as f:
                logger.info("Loaded cached key for filter: %s", filter_name)
                return f.read()
        logger.warning("No cached key found for filter: %s", filter_name)
        return None

    def clear_cached_key(self, filter_name):
        cache_file = os.path.join(self.cache_dir, f'{filter_name}.key')
        if os.path.exists(cache_file):
            os.remove(cache_file)
            logger.info("Cleared cached key for filter: %s", filter_name)
        else:
            logger.warning("No cached key to clear for filter: %s", filter_name)

    def get_key_id(self, filter_name):
        try:
            key_id_file = os.path.join(self.cache_dir, f'{filter_name}.id')
            if os.path.exists(key_id_file):
                with open(key_id_file, 'r') as f:
                    return f.read().strip()
            else:
                key_alias = f"{get_settings().module_name}/{filter_name}"
                response = boto3.client('kms').describe_key(KeyId=key_alias)
                key_id = response['KeyMetadata']['KeyId']
                self.store_key_id(filter_name, key_id)
                return key_id
        except Exception as e:
            logger.error("Failed to retrieve key ID for filter %s: %s", filter_name, e)
            raise

    def store_key_id(self, filter_name, key_id):
        key_id_file = os.path.join(self.cache_dir, f'{filter_name}.id')
        logger.info("Storing key ID for filter: %s at: %s", filter_name, key_id_file)

        with open(key_id_file, 'w') as f:
            f.write(key_id)
        logger.info("Stored key ID for filter: %s", filter_name)
