import json
import logging

import boto3
from botocore.exceptions import NoCredentialsError, NoRegionError

from git_secret_protector.error.storage_error import StorageError
from git_secret_protector.storage.storage_manager_interface import StorageManagerInterface

logger = logging.getLogger(__name__)


class AwsSsmStorageManager(StorageManagerInterface):
    def __init__(self):
        self._account_id = None
        self._client = None

    @property
    def account_id(self):
        if self._account_id is None:
            try:
                sts_client = boto3.client('sts')
                self._account_id = sts_client.get_caller_identity().get('Account')
            except NoCredentialsError:
                raise StorageError("No AWS region configured. Please ensure your terminal is logged in to AWS.")
        return self._account_id

    @property
    def client(self):
        if self._client is None:
            try:
                self._client = boto3.client('ssm')
            except NoRegionError:
                raise StorageError("No AWS region configured. Please ensure your terminal is logged in to AWS.")
        return self._client

    def store(self, name: str, value: str) -> None:
        try:
            self.client.put_parameter(
                Name=name,
                Value=json.dumps(value),
                Type='SecureString',
                Overwrite=True
            )
        except Exception as e:
            raise StorageError(f"Failed to store parameter with [name={name}]: {str(e)}") from e

    def retrieve(self, name: str) -> str:

        try:
            response = self.client.get_parameter(Name=name, WithDecryption=True)
            return json.loads(response['Parameter']['Value'])
        except Exception as e:
            error_message = str(e)
            if "ParameterNotFound" in error_message:
                if self.account_id in name:
                    return self._handle_legacy_parameter(parameter=name)
                raise StorageError(f"Parameter not found [name={name}]") from e
            raise StorageError(f"Failed to retrieve parameter [name={name}]: {error_message}") from e

    def _handle_legacy_parameter(self, parameter: str) -> str:
        legacy_parameter = parameter.replace(f"/encryption/{self.account_id}/", "/encryption/")
        logger.warning(
            f"Parameter '{parameter}' not found. Attempting to retrieve from legacy parameter '{legacy_parameter}'.")

        result = self.retrieve(name=legacy_parameter)

        logger.info(f"Legacy parameter '{legacy_parameter}' found. Copying to parameter: '{parameter}'")
        self.store(parameter, result)

        return result

    def delete(self, name: str) -> None:
        try:
            self.client.delete_parameter(Name=name)
        except Exception as e:
            raise StorageError(f"Failed to delete parameter with [name={name}]: {str(e)}") from e

    def exists(self, name: str) -> bool:
        try:
            self.client.get_parameter(Name=name, WithDecryption=True)
            return True
        except Exception as e:
            error_message = str(e)
            if "ParameterNotFound" in error_message:
                return False
            raise StorageError(f"Failed to check if parameter exists [name={name}]: {error_message}") from e

    def parameter_name(self, module_name: str, filter_name: str):
        return f"/encryption/{self.account_id}/{module_name}/{filter_name}/key_iv"
