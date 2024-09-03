import os
import base64
import boto3
import json
from git_secret_protector.settings import get_settings
import logging

logger = logging.getLogger(__name__)


class AesKeyManager:
    def __init__(self):
        self._ssm_client = None
        self.cache_dir = get_settings().cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

    @property
    def ssm_client(self):
        if self._ssm_client is None:
            self._ssm_client = boto3.client('ssm')
        return self._ssm_client

    def setup_aes_key_and_iv(self, filter_name):
        aes_key = os.urandom(32)  # 256 bits for AES-256
        iv = os.urandom(16)  # 128 bits (AES block size)

        # Encode key and IV as base64 to serialize as JSON
        data = {
            'aes_key': base64.b64encode(aes_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
        json_data = json.dumps(data)

        # Store the serialized key and IV in AWS SSM Parameter Store
        self.ssm_client.put_parameter(
            Name=f"/encryption/{filter_name}/key_iv",
            Value=json_data,
            Type='SecureString',
            Overwrite=True
        )

        logger.info(f"AES key and IV setup and stored in SSM for filter: {filter_name}")
        self.cache_key_iv_locally(filter_name, json_data)

    def retrieve_key_and_iv(self, filter_name):
        local_data = self.load_key_iv_from_cache(filter_name)
        if local_data:
            return base64.b64decode(local_data['aes_key']), base64.b64decode(local_data['iv'])

        response = self.ssm_client.get_parameter(
            Name=f"/encryption/{filter_name}/key_iv",
            WithDecryption=True
        )
        data = json.loads(response['Parameter']['Value'])
        self.cache_key_iv_locally(filter_name, response['Parameter']['Value'])
        return base64.b64decode(data['aes_key']), base64.b64decode(data['iv'])

    def cache_key_iv_locally(self, filter_name, json_data):
        cache_path = os.path.join(self.cache_dir, f"{filter_name}_key_iv.json")
        with open(cache_path, 'w') as cache_file:
            cache_file.write(json_data)
        logger.debug("Cached AES key and IV locally for filter: %s", filter_name)

    def load_key_iv_from_cache(self, filter_name):
        cache_path = os.path.join(self.cache_dir, f"{filter_name}_key_iv.json")
        if os.path.exists(cache_path):
            with open(cache_path, 'r') as cache_file:
                json_data = cache_file.read()
                data = json.loads(json_data)
                return data
        logger.debug("No local cache found for filter: %s", filter_name)
        return None

    def destroy_aes_key_and_iv(self, filter_name):
        """Destroy the AES key and IV for a specific filter name in AWS SSM."""
        try:
            parameter_name = f"/encryption/{filter_name}/key_iv"
            self.ssm_client.delete_parameter(Name=parameter_name)
            logging.info(f"Successfully destroyed AES key and IV in SSM for filter: {filter_name}")
        except Exception as e:
            logging.error(f"Failed to destroy AES key and IV for filter {filter_name}: {e}")
            raise
