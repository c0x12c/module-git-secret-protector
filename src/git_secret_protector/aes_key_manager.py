import base64
import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

from git_secret_protector.settings import get_settings

logger = logging.getLogger(__name__)


class AesKeyManager:
    AES_KEY_SIZE = 32  # 256 bits for AES-256
    IV_SIZE = 16  # 128 bits (AES block size)

    def __init__(self):
        self._ssm_client = None
        self.cache_dir = get_settings().cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

        self.module_name = get_settings().module_name

    @property
    def ssm_client(self):
        if self._ssm_client is None:
            self._ssm_client = boto3.client('ssm')
        return self._ssm_client

    def setup_aes_key_and_iv(self, filter_name):
        try:
            logger.info("Set up AES key and IV for filter: %s", filter_name)

            parameter_name = self._ssm_parameter_name(filter_name)

            if self._parameter_exists(parameter_name):
                logger.error(
                    f"Parameter with name {parameter_name} already exists. Use a different filter name or manually delete the existing parameter.")
                raise ValueError(f"Parameter with name {parameter_name} already exists.")

            aes_key = os.urandom(self.AES_KEY_SIZE)  # 256 bits for AES-256
            iv = os.urandom(self.IV_SIZE)  # 128 bits (AES block size)

            # Encode key and IV as base64 to serialize as JSON
            data = {
                'aes_key': base64.b64encode(aes_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8')
            }
            json_data = json.dumps(data)

            # Store the serialized key and IV in AWS SSM Parameter Store
            self.ssm_client.put_parameter(
                Name=self._ssm_parameter_name(filter_name),
                Value=json_data,
                Type='SecureString',
                Overwrite=True
            )

            logger.info(f"AES key and IV setup and stored in SSM for filter: {filter_name}")
            self.cache_key_iv_locally(filter_name, json_data)
        except Exception as e:
            logger.error("Failed to setup AES key and IV for filter %s: %s", filter_name, str(e))
            raise

    def retrieve_key_and_iv(self, filter_name):
        logger.info("Retrieve AES key and IV for filter: %s", filter_name)
        parameter_name = self._ssm_parameter_name(filter_name)

        try:
            local_data = self.load_key_iv_from_cache(filter_name)
            if local_data:
                return base64.b64decode(local_data['aes_key']), base64.b64decode(local_data['iv'])

            response = self.ssm_client.get_parameter(
                Name=parameter_name,
                WithDecryption=True
            )
            data = json.loads(response['Parameter']['Value'])
            self.cache_key_iv_locally(filter_name, response['Parameter']['Value'])
            return base64.b64decode(data['aes_key']), base64.b64decode(data['iv'])
        except Exception as e:
            logger.error("Failed to retrieve AES key and IV with parameter name %s: %s", parameter_name, str(e))
            raise

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
            self.ssm_client.delete_parameter(Name=self._ssm_parameter_name(filter_name))
            logging.info(f"Successfully destroyed AES key and IV in SSM for filter: {filter_name}")
        except Exception as e:
            logging.error(f"Failed to destroy AES key and IV for filter {filter_name}: {e}")
            raise

    def _parameter_exists(self, parameter_name):
        """Check if a parameter exists in the SSM."""
        try:
            self.ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
            return True
        except ClientError:
            return False

    def _ssm_parameter_name(self, filter_name):
        return f"/encryption/{self.module_name}/{filter_name}/key_iv"
