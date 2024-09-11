import json

import boto3
from botocore.exceptions import ClientError

from git_secret_protector.storage.storage_manager_interface import StorageManagerInterface


class AwsSsmStorageManager(StorageManagerInterface):
    def __init__(self):
        self.client = boto3.client('ssm')

    def store(self, name: str, value: str) -> None:
        try:
            self.client.put_parameter(
                Name=name,
                Value=json.dumps(value),
                Type='SecureString',
                Overwrite=True
            )
        except ClientError as e:
            raise ValueError(f"Failed to store parameter with [name={name}]") from e

    def retrieve(self, name: str) -> str:
        try:
            response = self.client.get_parameter(Name=name, WithDecryption=True)
            return json.loads(response['Parameter']['Value'])
        except ClientError as e:
            raise ValueError(f"Failed to retrieve parameter [name={name}]") from e

    def delete(self, name: str) -> None:
        try:
            self.client.delete_parameter(Name=name)
        except ClientError as e:
            raise ValueError(f"Failed to delete parameter with [name={name}]") from e

    def exists(self, name: str) -> bool:
        try:
            self.client.get_parameter(Name=name, WithDecryption=True)
            return True
        except ClientError:
            return False

    def parameter_name(self, module_name: str, filter_name: str):
        return f"/encryption/{module_name}/{filter_name}/key_iv"
