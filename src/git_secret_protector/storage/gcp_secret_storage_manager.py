import json
import subprocess

from google.api_core.exceptions import NotFound, AlreadyExists, GoogleAPIError
from google.cloud import secretmanager
from google.cloud.secretmanager_v1 import Secret, SecretPayload

from git_secret_protector.storage.storage_manager_interface import StorageManagerInterface


class GcpSecretStorageManager(StorageManagerInterface):
    def __init__(self):
        self.client = secretmanager.SecretManagerServiceClient()
        self.project_id = self.get_gcloud_project_id()

    @staticmethod
    def get_gcloud_project_id() -> str:
        try:
            # Run 'gcloud config list --format=json' to get the active project
            result = subprocess.run(
                ["gcloud", "config", "list", "--format=json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            # Parse the JSON response
            config = json.loads(result.stdout)
            project_id = config.get("core", {}).get("project", "")
            if not project_id:
                raise RuntimeError("No project ID found in the current gcloud configuration.")
            return project_id
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to retrieve project ID from gcloud: {e}")

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
            raise RuntimeError(f"Google API error while storing the secret: {e}")

        # Add a new version with the updated secret value
        try:
            self.client.add_secret_version(
                parent=secret_id,
                payload=SecretPayload({"data": value.encode("UTF-8")})
            )
        except GoogleAPIError as e:
            raise RuntimeError(f"Failed to add secret version: {e}")

    def retrieve(self, name: str) -> str:
        secret_id = f"projects/{self.project_id}/secrets/{name}/versions/latest"
        try:
            response = self.client.access_secret_version(name=secret_id)
            return response.payload.data.decode("UTF-8")
        except NotFound:
            raise ValueError(f"Secret [name={name}] not found.")
        except GoogleAPIError as e:
            raise RuntimeError(f"Google API error while retrieving the secret: {e}")

    def delete(self, name: str) -> None:
        secret_id = f"projects/{self.project_id}/secrets/{name}"
        try:
            self.client.delete_secret(name=secret_id)
        except NotFound:
            raise ValueError(f"Secret [name={name}] not found.")
        except GoogleAPIError as e:
            raise RuntimeError(f"Google API error while deleting the secret: {e}")

    def exists(self, name: str) -> bool:
        secret_id = f"projects/{self.project_id}/secrets/{name}"
        try:
            self.client.access_secret_version(name=f"{secret_id}/versions/latest")
            return True
        except NotFound:
            return False
        except GoogleAPIError as e:
            raise RuntimeError(f"Google API error while checking if the secret exists: {e}")

    def parameter_name(self, module_name: str, filter_name: str):
        return f"encryption_{module_name}_{filter_name}_key_iv"
