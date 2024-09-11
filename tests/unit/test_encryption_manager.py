import base64
import secrets
import unittest
from unittest.mock import patch, MagicMock

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.core.settings import get_settings
from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler


class TestEncryptionManager(unittest.TestCase):

    def setUp(self):
        self.aes_key = secrets.token_bytes(16)  # Generate a random AES key
        self.iv = secrets.token_bytes(AES.block_size)  # AES block size for IV should be 16 bytes

        # Create a MagicMock for GitAttributesParser
        self.mock_git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.mock_git_attributes_parser.get_files_for_filter.return_value = ['file1.txt', 'file2.txt']

        # Instantiate EncryptionManager with the mocked GitAttributesParser
        self.manager = AesEncryptionHandler(aes_key=self.aes_key, iv=self.iv)

        # Create a cipher instance for use in tests
        self.cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)

    def test_decrypt_data(self):
        # Generate random test data
        test_data = secrets.token_bytes(128)  # Generating 128 bytes of random data
        padded_data = pad(test_data, AES.block_size)
        encrypted_data = self.cipher.encrypt(padded_data)
        encrypted_data_base64 = base64.b64encode(encrypted_data)

        # Prepare data with MAGIC_HEADER
        data_with_header = get_settings().magic_header.encode() + encrypted_data_base64

        # Test normal decryption
        decrypted_data = self.manager.decrypt_data(data_with_header)
        self.assertEqual(decrypted_data, test_data, "Decrypted data does not match the original")

    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_encrypt_file(self, mock_open):
        test_data = b'This is some test data'
        mock_open.return_value.read.return_value = test_data

        # Generate a random path
        dummy_path = '/tmp/' + secrets.token_hex(10)
        mock_open.return_value.read.return_value = test_data

        self.manager.encrypt_file(dummy_path)

        mock_open().write.assert_called_once_with(self.manager.encrypt_data(test_data))

    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_decrypt_file(self, mock_open):
        # Generate test data and encrypt it
        test_data = b'This is some test data'

        file_data = self.manager.encrypt_data(data=test_data)

        # Setup the path and prepare the mock file
        dummy_path = '/tmp/' + secrets.token_hex(10)
        mock_open.return_value.read.return_value = file_data

        result = self.manager.decrypt_file(dummy_path)


        mock_open().write.assert_called_once_with(test_data)


if __name__ == '__main__':
    unittest.main()
