import json
import unittest
from unittest.mock import MagicMock

from git_secret_protector.error.storage_error import StorageError
from git_secret_protector.storage.aws_ssm_storage_manager import AwsSsmStorageManager


class TestAwsSsmStorageManager(unittest.TestCase):
    def setUp(self):
        self.manager = AwsSsmStorageManager()
        self.manager._client = MagicMock()

    def test_retrieve_parameter_not_found_raises_without_fallback(self):
        self.manager._client.get_parameter.side_effect = Exception(
            "ParameterNotFound: missing parameter"
        )

        with self.assertRaises(StorageError) as context:
            self.manager.retrieve("/encryption/123456789012/uswe2/module/filter/key_iv")

        self.assertTrue(
            str(context.exception).startswith("Parameter not found"),
            "Expected ParameterNotFound to raise an immediate StorageError",
        )
        self.assertFalse(hasattr(AwsSsmStorageManager, "_handle_legacy_parameter"))
        self.manager._client.get_parameter.assert_called_once_with(
            Name="/encryption/123456789012/uswe2/module/filter/key_iv",
            WithDecryption=True,
        )
        self.assertEqual(self.manager._client.get_parameter.call_count, 1)

    def test_retrieve_other_boto_error_raises_storage_error(self):
        self.manager._client.get_parameter.side_effect = Exception("AccessDenied: nope")

        with self.assertRaises(StorageError) as context:
            self.manager.retrieve("/path/to/secret")

        self.assertIn("Failed to retrieve parameter", str(context.exception))

    def test_retrieve_success_returns_decoded_parameter_value(self):
        value = {"aes_key": "abc", "iv": "def"}
        self.manager._client.get_parameter.return_value = {
            "Parameter": {"Value": json.dumps(value)}
        }

        result = self.manager.retrieve("/path/to/secret")

        self.assertEqual(result, value)


if __name__ == "__main__":
    unittest.main()
