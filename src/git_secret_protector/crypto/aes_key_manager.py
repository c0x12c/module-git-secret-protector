import base64
import json
import logging
import os

from git_secret_protector.core.settings import get_settings
from git_secret_protector.error.aes_key_error import AesKeyError
from git_secret_protector.storage.storage_manager_factory import StorageManagerFactory

logger = logging.getLogger(__name__)


class AesKeyManager:
    AES_KEY_SIZE = 32  # 256 bits for AES-256
    IV_SIZE = 16  # 128 bits (AES block size)

    def __init__(self):
        self.storage_manager = None
        self.settings = get_settings()
        self.cache_dir = self.settings.cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

        self.module_name = self.settings.module_name

    def _get_storage_manager(self):
        if self.storage_manager is None:
            storage_type = self.settings.storage_type.value
            self.storage_manager = StorageManagerFactory.create(storage_type=storage_type)
        return self.storage_manager

    """
    Sets up an AES key and initialization vector (IV) for encryption, and stores them securely.

    This method generates a new AES key and IV, checks whether a parameter with the corresponding name already 
    exists in the storage, and if not, stores the key and IV both in the storage manager and locally in the cache 
    directory. If a parameter with the same name already exists, an error is raised.

    :param filter_name: The filter name used to generate and store the AES key and IV
    :type filter_name: str
    :raises AesKeyError: If there is any error during the setup process
    """

    def setup_aes_key_and_iv(self, filter_name: str):
        try:
            logger.info("Set up AES key and IV for filter: %s", filter_name)

            parameter_name = self._parameter_name(filter_name=filter_name)

            if self._parameter_exists(parameter_name=parameter_name):
                logger.error(
                    f"Parameter with name {parameter_name} already exists. Use a different filter name or manually delete the existing parameter.")
                raise ValueError(f"Parameter with name {parameter_name} already exists.")

            aes_key = os.urandom(self.AES_KEY_SIZE)
            iv = os.urandom(self.IV_SIZE)

            data = {
                'aes_key': base64.b64encode(s=aes_key).decode(encoding='utf-8'),
                'iv': base64.b64encode(s=iv).decode(encoding='utf-8')
            }
            json_data = json.dumps(obj=data)

            self._get_storage_manager().store(parameter_name, json_data)

            logger.info(f"AES key and IV setup and stored in storage for filter: {filter_name}")
            self.cache_key_iv_locally(filter_name, json_data)
        except Exception as e:
            raise AesKeyError(f"Failed to setup AES key and IV for filter '{filter_name}': {str(e)}")

    """
    Destroys the AES key and initialization vector (IV) associated with the given filter name.

    This method deletes the AES key and IV from the secure storage. It retrieves the parameter name 
    associated with the filter name and invokes the storage manager to delete the corresponding parameter.
    
    If an error occurs during the deletion process, an `AesKeyError` is raised.

    :param filter_name: The filter name whose associated AES key and IV are to be deleted
    :type filter_name: str
    :raises AesKeyError: If there is any error during the deletion process
    """

    def retrieve_key_and_iv(self, filter_name):
        logger.info("Retrieve AES key and IV for filter: %s", filter_name)

        try:
            local_data = self.load_key_iv_from_cache(filter_name=filter_name)
            if local_data:
                logger.debug("Using locally cached AES key and IV for filter: %s", filter_name)
                return base64.b64decode(local_data['aes_key']), base64.b64decode(local_data['iv'])

            parameter_name = self._parameter_name(filter_name=filter_name)
            data = json.loads(self._get_storage_manager().retrieve(name=parameter_name))
            self.cache_key_iv_locally(filter_name, json.dumps(data))

            return base64.b64decode(data['aes_key']), base64.b64decode(data['iv'])
        except Exception as e:
            raise AesKeyError(f"Failed to retrieve AES key and IV for filter '{filter_name}': {str(e)}")

    """
    Clears the locally cached AES key and initialization vector (IV) associated with the given filter name.
    
    This method deletes the cached AES key and IV from the local cache directory. It constructs the path
    to the locally cached file corresponding to the filter name and removes the file from the system.
    If an error occurs during the deletion process, an `AesKeyError` is raised.
    
    :param filter_name: The filter name whose associated AES key and IV are to be deleted from the local cache
    :type filter_name: str
    :raises AesKeyError: If there is any error during the deletion process
    """

    def destroy_aes_key_and_iv(self, filter_name: str):
        try:
            parameter_name = self._parameter_name(filter_name=filter_name)
            self._get_storage_manager().delete(name=parameter_name)
            logger.info(f"Successfully destroyed AES key and IV in storage for filter: {filter_name}")
        except Exception as e:
            raise AesKeyError(f"Failed to destroy AES key and IV for filter '{filter_name}': {str(e)}")

    def cache_key_iv_locally(self, filter_name: str, json_data: str):
        cache_path = self._cache_path(filter_name=filter_name)

        with open(cache_path, 'w') as cache_file:
            cache_file.write(json_data)
        logger.debug("Cached AES key and IV locally for filter: %s", filter_name)

    def load_key_iv_from_cache(self, filter_name: str):
        cache_path = self._cache_path(filter_name=filter_name)

        if os.path.exists(cache_path):
            with open(cache_path, 'r') as cache_file:
                json_data = cache_file.read()
                data = json.loads(json_data)
                return data

        logger.debug("No local cache found for filter: %s", filter_name)
        return None

    def remove_key_iv_from_cache(self, filter_name: str):
        cache_path = self._cache_path(filter_name=filter_name)
        logger.debug("Remove cache file: %s", cache_path)

        if os.path.exists(cache_path):
            os.remove(cache_path)
            logger.debug(f"Successfully removed local cache for filter: {filter_name}")

    def _parameter_exists(self, parameter_name):
        """Check if a parameter exists in the storage manager."""
        try:
            return self._get_storage_manager().exists(parameter_name)
        except Exception as e:
            logger.error(f"Error while checking existence of parameter {parameter_name}: {e}")
            return False

    def _parameter_name(self, filter_name) -> str:
        return self._get_storage_manager().parameter_name(module_name=self.module_name, filter_name=filter_name)

    def _cache_path(self, filter_name: str) -> str:
        return os.path.join(self.cache_dir, f"{filter_name}_key_iv.json")
