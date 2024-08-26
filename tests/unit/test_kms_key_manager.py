import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from git_secret_protector.kms_key_manager import KMSKeyManager


class TestKMSKeyManager(unittest.TestCase):

    @patch('git_secret_protector.kms_key_manager.get_settings')
    @patch('boto3.client')
    def setUp(self, mock_boto_client, mock_get_settings):
        self.mock_settings = MagicMock()
        self.mock_temp_dir = tempfile.TemporaryDirectory()
        self.mock_settings.cache_dir = self.mock_temp_dir.name
        self.mock_settings.module_name = 'git-secret-protector'
        mock_get_settings.return_value = self.mock_settings

        # Set up the mock for the boto3 client
        self.mock_kms_client = MagicMock()
        self.mock_kms_client.generate_data_key.return_value = {'Plaintext': b'new-aes-key'}
        mock_boto_client.return_value = self.mock_kms_client

        self.kms_manager = KMSKeyManager()

    @patch('git_secret_protector.kms_key_manager.KMSKeyManager.store_key_id')
    def test_setup_aes_key(self, mock_store_key_id):
        self.mock_kms_client.create_key.return_value = {
            'KeyMetadata': {
                'KeyId': 'mock-key-id'
            }
        }

        self.kms_manager.setup_aes_key('mock-filter')

        self.mock_kms_client.create_key.assert_called_once_with(
            Description='Data key for mock-filter',
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS'
        )
        mock_store_key_id.assert_called_once_with('mock-filter', 'mock-key-id')

    @patch('git_secret_protector.kms_key_manager.KMSKeyManager.load_cached_key', return_value=None)
    @patch('git_secret_protector.kms_key_manager.KMSKeyManager.cache_aes_key')
    @patch('git_secret_protector.kms_key_manager.KMSKeyManager.get_key_id')
    def test_get_aes_key_no_cache(self, mock_get_key_id, mock_cache_aes_key, mock_load_cached_key):
        mock_get_key_id.return_value = 'mock-key-id'
        self.mock_kms_client.generate_data_key.return_value = {'Plaintext': b'new-aes-key'}

        aes_key = self.kms_manager.get_aes_key('mock-filter')

        self.assertEqual(aes_key, b'new-aes-key')
        mock_get_key_id.assert_called_once_with('mock-filter')
        self.mock_kms_client.generate_data_key.assert_called_once_with(KeyId='mock-key-id', KeySpec='AES_256')
        mock_cache_aes_key.assert_called_once_with('mock-filter', b'new-aes-key')

    @patch('git_secret_protector.kms_key_manager.KMSKeyManager.load_cached_key', return_value=b'cached-aes-key')
    def test_get_aes_key_with_cache(self, mock_load_cached_key):
        aes_key = self.kms_manager.get_aes_key('mock-filter')

        self.assertEqual(aes_key, b'cached-aes-key')
        mock_load_cached_key.assert_called_once_with('mock-filter')
        self.mock_kms_client.generate_data_key.assert_not_called()

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=MagicMock)
    def test_get_key_id_from_cache(self, mock_open, mock_exists):
        mock_file = mock_open.return_value.__enter__.return_value
        mock_file.read.return_value = 'mock-key-id'

        key_id = self.kms_manager.get_key_id('mock-filter')

        self.assertEqual(key_id, 'mock-key-id')
        mock_open.assert_called_once_with(os.path.join(self.mock_settings.cache_dir, 'mock-filter.id'), 'r')

    @patch('os.path.exists', return_value=False)
    @patch('git_secret_protector.kms_key_manager.KMSKeyManager.store_key_id')
    def test_get_key_id_from_kms(self, mock_store_key_id, mock_exists):
        self.mock_kms_client.describe_key.return_value = {
            'KeyMetadata': {
                'KeyId': 'mock-key-id'
            }
        }

        key_id = self.kms_manager.get_key_id('mock-filter')

        self.assertEqual(key_id, 'mock-key-id')
        self.mock_kms_client.describe_key.assert_called_once_with(KeyId=f"{self.mock_settings.module_name}/mock-filter")
        mock_store_key_id.assert_called_once_with('mock-filter', 'mock-key-id')

    @patch('os.path.exists', return_value=False)
    @patch('builtins.open', new_callable=MagicMock)
    def test_cache_aes_key(self, mock_open, mock_exists):
        aes_key = b'new-aes-key'

        self.kms_manager.cache_aes_key('mock-filter', aes_key)

        mock_open.assert_called_once_with(os.path.join(self.mock_settings.cache_dir, 'mock-filter.key'), 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_once_with(aes_key)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=MagicMock)
    def test_load_cached_key(self, mock_open, mock_exists):
        mock_file = mock_open.return_value.__enter__.return_value
        mock_file.read.return_value = b'cached-aes-key'

        cached_key = self.kms_manager.load_cached_key('mock-filter')

        self.assertEqual(cached_key, b'cached-aes-key')
        mock_open.assert_called_once_with(os.path.join(self.mock_settings.cache_dir, 'mock-filter.key'), 'rb')

    @patch('os.path.exists', return_value=True)
    @patch('os.remove')
    def test_clear_cached_key(self, mock_remove, mock_exists):
        self.kms_manager.clear_cached_key('mock-filter')
        mock_exists.assert_called_once_with(os.path.join(self.mock_settings.cache_dir, 'mock-filter.key'))
        mock_remove.assert_called_once_with(os.path.join(self.mock_settings.cache_dir, 'mock-filter.key'))


if __name__ == '__main__':
    unittest.main()
