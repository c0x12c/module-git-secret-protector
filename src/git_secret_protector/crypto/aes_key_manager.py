import base64
import json
import logging
import os

from git_secret_protector.core.settings import get_settings
from git_secret_protector.storage.storage_manager_factory import StorageManagerFactory

logger = logging.getLogger(__name__)


class AesKeyManager:
    AES_KEY_SIZE = 32  # 256 bits for AES-256
    IV_SIZE = 16  # 128 bits (AES block size)

    def __init__(self):
        self._storage_manager = None
        self.cache_dir = get_settings().cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

        self.module_name = get_settings().module_name

    @property
    def storage_manager(self):
        if self._storage_manager is None:
            storage_type = get_settings().storage_type.value
            self._storage_manager = StorageManagerFactory.create(storage_type=storage_type)
        return self._storage_manager

    def setup_aes_key_and_iv(self, filter_name: str):
        try:
            logger.info("Set up AES key and IV for filter: %s", filter_name)

            parameter_name = self._parameter_name(filter_name=filter_name)

            if self._parameter_exists(parameter_name=parameter_name):
                logger.error(
                    f"Parameter with name {parameter_name} already exists. Use a different filter name or manually delete the existing parameter.")
                raise ValueError(f"Parameter with name {parameter_name} already exists.")

            aes_key = os.urandom(self.AES_KEY_SIZE)  # 256 bits for AES-256
            iv = os.urandom(self.IV_SIZE)  # 128 bits (AES block size)

            # Encode key and IV as base64 to serialize as JSON
            data = {
                'aes_key': base64.b64encode(s=aes_key).decode(encoding='utf-8'),
                'iv': base64.b64encode(s=iv).decode(encoding='utf-8')
            }
            json_data = json.dumps(obj=data)

            # Store the serialized key and IV using the storage manager
            self.storage_manager.store(parameter_name, json_data)

            logger.info(f"AES key and IV setup and stored in storage for filter: {filter_name}")
            self.cache_key_iv_locally(filter_name, json_data)
        except Exception as e:
            logger.error("Failed to setup AES key and IV for filter %s: %s", filter_name, str(e))
            raise

    def retrieve_key_and_iv(self, filter_name):
        logger.info("Retrieve AES key and IV for filter: %s", filter_name)
        parameter_name = self._parameter_name(filter_name=filter_name)

        try:
            local_data = self.load_key_iv_from_cache(filter_name=filter_name)
            if local_data:
                return base64.b64decode(local_data['aes_key']), base64.b64decode(local_data['iv'])

            # Retrieve the serialized key and IV using the storage manager
            data = json.loads(self.storage_manager.retrieve(parameter_name))
            self.cache_key_iv_locally(filter_name, json.dumps(data))
            return base64.b64decode(data['aes_key']), base64.b64decode(data['iv'])
        except Exception as e:
            logger.error("Failed to retrieve AES key and IV with parameter name %s: %s", parameter_name, str(e))
            raise

    def cache_key_iv_locally(self, filter_name: str, json_data: str):
        cache_path = os.path.join(self.cache_dir, f"{filter_name}_key_iv.json")
        with open(cache_path, 'w') as cache_file:
            cache_file.write(json_data)
        logger.debug("Cached AES key and IV locally for filter: %s", filter_name)

    def load_key_iv_from_cache(self, filter_name: str):
        cache_path = os.path.join(self.cache_dir, f"{filter_name}_key_iv.json")
        if os.path.exists(cache_path):
            with open(cache_path, 'r') as cache_file:
                json_data = cache_file.read()
                data = json.loads(json_data)
                return data
        logger.debug("No local cache found for filter: %s", filter_name)
        return None

    def destroy_aes_key_and_iv(self, filter_name: str):
        """Destroy the AES key and IV for a specific filter name using the storage manager."""
        try:
            parameter_name = self._parameter_name(filter_name=filter_name)
            self.storage_manager.delete(name=parameter_name)
            logger.info(f"Successfully destroyed AES key and IV in storage for filter: {filter_name}")
        except Exception as e:
            logger.error(f"Failed to destroy AES key and IV for filter {filter_name}: {e}")
            raise

    def _parameter_exists(self, parameter_name):
        """Check if a parameter exists in the storage manager."""
        try:
            return self.storage_manager.exists(parameter_name)
        except Exception as e:
            logger.error(f"Error while checking existence of parameter {parameter_name}: {e}")
            return False

    def _parameter_name(self, filter_name) -> str:
        return self.storage_manager.parameter_name(module_name=self.module_name, filter_name=filter_name)
