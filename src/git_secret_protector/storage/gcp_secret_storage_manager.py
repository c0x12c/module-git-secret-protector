import json
import logging
import subprocess

from google.api_core.exceptions import NotFound, AlreadyExists, GoogleAPIError
from google.auth import default
from google.cloud import secretmanager
from google.cloud.secretmanager_v1 import Secret, SecretPayload

from git_secret_protector.core.settings import get_settings
from git_secret_protector.error.storage_error import StorageError
from git_secret_protector.storage.storage_manager_interface import StorageManagerInterface

logger = logging.getLogger(__name__)


class GcpSecretStorageManager(StorageManagerInterface):
    def __init__(self):
        self.settings = get_settings()
        self.client = secretmanager.SecretManagerServiceClient()
        self._project_id = None

    @property
    def project_id(self):
        if self._project_id is None:
            self._project_id = self._fetch_project_id()
        return self._project_id

    @staticmethod
    def _fetch_project_id() -> str:
        try:
            logger.debug('Getting project ID from default credentials')
            _, project_id = default()
            return project_id
        except Exception as e:
            raise StorageError(f"Failed to retrieve project ID from the default credentials: {str(e)}") from e

    def store(self, name: str, value: str) -> None:
        secret_id = f"projects/{self.project_id}/secrets/{name}"
        try:
            # Check if the secret already exists, otherwise create it
            self.client.access_secret_version(name=f"{secret_id}/versions/latest")
        except NotFound:
            # Create the secret if it doesn't exist
            try:
                self.client.create_secret(
                    parent=f"projects/{self.project_id}",
                    secret_id=name,
                    secret=Secret(
                        replication={"automatic": {}}
                    )
                )
            except AlreadyExists:
                raise ValueError(f"Secret with name [{name}] already exists.")
        except GoogleAPIError as e:
            raise StorageError(f"Google API error while storing the secret: {str(e)}") from e

        # Add a new version with the updated secret value
        try:
            self.client.add_secret_version(
                parent=secret_id,
                payload=SecretPayload({"data": value.encode("UTF-8")})
            )
        except GoogleAPIError as e:
            raise StorageError(f"Failed to add secret version: {str(e)}") from e

    def retrieve(self, name: str) -> str:
        secret_id = f"projects/{self.project_id}/secrets/{name}/versions/latest"
        try:
            logger.info("Retrieving secret from GCP Secret Manager with ID: %s", secret_id)
            response = self.client.access_secret_version(name=secret_id)
            return response.payload.data.decode("UTF-8")
        except NotFound:
            raise ValueError(f"Secret [name={name}] not found.")
        except GoogleAPIError as e:
            raise StorageError(f"Google API error while retrieving the secret: {str(e)}") from e

    def delete(self, name: str) -> None:
        secret_id = f"projects/{self.project_id}/secrets/{name}"
        try:
            self.client.delete_secret(name=secret_id)
        except NotFound:
            raise ValueError(f"Secret [name={name}] not found.")
        except GoogleAPIError as e:
            raise StorageError(f"Google API error while deleting the secret: {str(e)}") from e

    def exists(self, name: str) -> bool:
        secret_id = f"projects/{self.project_id}/secrets/{name}"
        try:
            self.client.access_secret_version(name=f"{secret_id}/versions/latest")
            return True
        except NotFound:
            return False
        except GoogleAPIError as e:
            raise StorageError(f"Google API error while checking if the secret exists: {str(e)}") from e

    def parameter_name(self, module_name: str, filter_name: str):
        return f"encryption_{module_name}_{filter_name}_key_iv"
