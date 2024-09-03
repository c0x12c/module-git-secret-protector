import base64
import json
import os
import secrets
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from git_secret_protector.aes_key_manager import AesKeyManager


class TestAesKeyManager(unittest.TestCase):

    @patch('git_secret_protector.aes_key_manager.get_settings')
    @patch('boto3.client')
    def setUp(self, mock_boto_client, mock_get_settings):
        self.mock_settings = MagicMock()
        self.mock_temp_dir = tempfile.TemporaryDirectory()
        self.mock_settings.cache_dir = self.mock_temp_dir.name
        self.mock_settings.module_name = secrets.token_hex(8)
        mock_get_settings.return_value = self.mock_settings

        self.mock_ssm_client = MagicMock()
        mock_boto_client.return_value = self.mock_ssm_client

        self.aes_key_manager = AesKeyManager()

    @staticmethod
    def random_encoded_data():
        aes_key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        iv = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
        return json.dumps({'aes_key': aes_key, 'iv': iv})

    @patch('boto3.client')
    def test_setup_aes_key_and_iv(self, mock_boto_client):
        filter_name = secrets.token_hex(8)

        self.aes_key_manager.setup_aes_key_and_iv(filter_name)

        expected_parameter_name = f"/encryption/{self.mock_settings.module_name}/{filter_name}/key_iv"

        mock_boto_client.return_value.put_parameter.assert_called_once()
        args, kwargs = mock_boto_client.return_value.put_parameter.call_args
        self.assertEqual(kwargs['Name'], expected_parameter_name)
        self.assertEqual('SecureString', kwargs['Type'])
        data = json.loads(kwargs['Value'])
        self.assertTrue('aes_key' in data and 'iv' in data)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_retrieve_key_and_iv_from_cache_hit(self, mock_open, mock_exists):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        mock_open.return_value.read.return_value = json_data

        aes_key, iv = self.aes_key_manager.retrieve_key_and_iv(filter_name)

        data = json.loads(json_data)
        self.assertEqual(aes_key, base64.b64decode(data['aes_key']))
        self.assertEqual(iv, base64.b64decode(data['iv']))

    @patch('os.path.exists', return_value=False)
    @patch('boto3.client')
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_retrieve_key_and_iv_from_cache_miss(self, mock_open, mock_boto_client, mock_exists):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        mock_boto_client.return_value.get_parameter.return_value = {'Parameter': {'Value': json_data}}

        aes_key, iv = self.aes_key_manager.retrieve_key_and_iv(filter_name)

        mock_boto_client.return_value.get_parameter.assert_called_once()
        data = json.loads(json_data)
        self.assertEqual(aes_key, base64.b64decode(data['aes_key']))
        self.assertEqual(iv, base64.b64decode(data['iv']))

    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_cache_key_iv_locally(self, mock_open):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)

        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        mock_open.assert_called_once_with(os.path.join(self.mock_temp_dir.name, f'{filter_name}_key_iv.json'), 'w')
        handle = mock_open()
        handle.write.assert_called_once_with(json_data)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_load_key_iv_from_cache(self, mock_open, mock_exists):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        mock_open.return_value.read.return_value = json_data

        data = self.aes_key_manager.load_key_iv_from_cache(filter_name)

        mock_exists.assert_called_once_with(os.path.join(self.mock_temp_dir.name, f'{filter_name}_key_iv.json'))
        self.assertEqual(data, json.loads(json_data), "Expected data to match JSON content")

    @patch('os.path.exists', return_value=False)
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_load_key_iv_from_cache_not_found(self, mock_open, mock_exists):
        filter_name = secrets.token_hex(8)

        result = self.aes_key_manager.load_key_iv_from_cache(filter_name)

        mock_exists.assert_called_once_with(os.path.join(self.mock_settings.cache_dir, f'{filter_name}_key_iv.json'))
        mock_open.assert_not_called()  # Ensures open was not called since file does not exist
        self.assertIsNone(result, "Expected result to be None when cache file does not exist")


if __name__ == '__main__':
    unittest.main()
