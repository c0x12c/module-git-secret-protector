from git_secret_protector.core.settings import StorageType
from git_secret_protector.storage.aws_ssm_storage_manager import AwsSsmStorageManager
from git_secret_protector.storage.gcp_secret_storage_manager import GcpSecretStorageManager
from git_secret_protector.storage.storage_manager_interface import StorageManagerInterface


class StorageManagerFactory:

    @staticmethod
    def create(storage_type: str = 'aws_ssm') -> 'StorageManagerInterface':
        if storage_type == StorageType.AWS_SSM.value:
            return AwsSsmStorageManager()
        elif storage_type == StorageType.GCP_SECRET.value:
            return GcpSecretStorageManager()
        else:
            raise ValueError(f"Unknown storage type: {storage_type}")
