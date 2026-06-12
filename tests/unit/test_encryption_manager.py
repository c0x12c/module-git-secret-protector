import base64
import io
import secrets
import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler
from git_secret_protector.services.encryption_manager import EncryptionManager
from tests.utils.random_utils import generate_random_string


class TestEncryptionManager(unittest.TestCase):

    @patch("git_secret_protector.crypto.aes_key_manager.get_settings")
    def setUp(self, mock_get_settings):
        self.mock_settings = MagicMock()
        self.magic_header = generate_random_string()
        self.mock_settings.magic_header = self.magic_header
        mock_get_settings.return_value = self.mock_settings

        self.aes_key = secrets.token_bytes(16)
        self.iv = secrets.token_bytes(AES.block_size)

        self.manager = AesEncryptionHandler(
            aes_key=self.aes_key,
            iv=self.iv,
            magic_header=self.mock_settings.magic_header.encode(),
        )
        self.cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)

        self.mock_git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.mock_git_attributes_parser.get_files_for_filter.return_value = [
            "file1.txt",
            "file2.txt",
        ]

    def test_decrypt_data(self):
        test_data = secrets.token_bytes(128)  # Generating 128 bytes of random data
        padded_data = pad(test_data, AES.block_size)
        encrypted_data = self.cipher.encrypt(padded_data)
        encrypted_data_base64 = base64.b64encode(encrypted_data)

        data_with_header = self.magic_header.encode() + encrypted_data_base64

        decrypted_data = self.manager.decrypt_data(data_with_header)
        self.assertEqual(
            decrypted_data, test_data, "Decrypted data does not match the original"
        )

    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_encrypt_file(self, mock_open):
        test_data = b"This is some test data"
        mock_open.return_value.read.return_value = test_data

        # Generate a random path
        dummy_path = "/tmp/" + secrets.token_hex(10)
        mock_open.return_value.read.return_value = test_data

        self.manager.encrypt_file(dummy_path)

        mock_open().write.assert_called_once_with(self.manager.encrypt_data(test_data))

    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_decrypt_file(self, mock_open):
        test_data = b"This is some test data"

        file_data = self.manager.encrypt_data(data=test_data)

        dummy_path = "/tmp/" + secrets.token_hex(10)
        mock_open.return_value.read.return_value = file_data

        self.manager.decrypt_file(dummy_path)

        mock_open().write.assert_called_once_with(test_data)


class TestEncryptionManagerService(unittest.TestCase):

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def setUp(self, mock_get_settings):
        mock_settings = MagicMock()
        mock_settings.magic_header = generate_random_string()
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

    def test_encrypt_stdin_exits_non_zero_and_writes_nothing_when_encryption_raises(
        self,
    ):
        self.git_attributes_parser.get_filter_name_for_file.return_value = "secret"

        with patch.object(
            self.manager,
            "_EncryptionManager__get_encryption_handler",
            side_effect=RuntimeError("boom"),
        ):
            stdout_buffer = io.BytesIO()
            stdin = SimpleNamespace(buffer=io.BytesIO(b"plain-secret"))
            stdout = SimpleNamespace(buffer=stdout_buffer)

            with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
                with self.assertRaises(SystemExit) as context:
                    self.manager.encrypt_stdin("secrets.env")

        self.assertNotEqual(context.exception.code, 0)
        self.assertEqual(stdout_buffer.getvalue(), b"")

    def test_encrypt_stdin_exits_non_zero_when_no_filter_matches(self):
        self.git_attributes_parser.get_filter_name_for_file.return_value = None
        stdout_buffer = io.BytesIO()
        stdin = SimpleNamespace(buffer=io.BytesIO(b"plain-secret"))
        stdout = SimpleNamespace(buffer=stdout_buffer)

        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            with self.assertRaises(SystemExit) as context:
                self.manager.encrypt_stdin("secrets.env")

        self.assertNotEqual(context.exception.code, 0)
        self.assertEqual(stdout_buffer.getvalue(), b"")

    def test_encrypt_stdin_writes_ciphertext_on_success(self):
        self.git_attributes_parser.get_filter_name_for_file.return_value = "secret"
        handler = MagicMock()
        handler.encrypt_data.return_value = b"ciphertext"
        stdout_buffer = io.BytesIO()
        stdin = SimpleNamespace(buffer=io.BytesIO(b"plain-secret"))
        stdout = SimpleNamespace(buffer=stdout_buffer)

        with patch.object(
            self.manager,
            "_EncryptionManager__get_encryption_handler",
            return_value=handler,
        ):
            with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
                self.manager.encrypt_stdin("secrets.env")

        self.assertEqual(stdout_buffer.getvalue(), b"ciphertext")

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    @patch("git_secret_protector.services.encryption_manager.subprocess.getoutput")
    def test_setup_filters_sets_required_for_existing_filter(
        self, mock_getoutput, mock_run
    ):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        mock_getoutput.side_effect = [
            "git-secret-protector encrypt %f",
            "git-secret-protector decrypt %f",
        ]

        self.manager.setup_filters()

        mock_run.assert_called_once_with(
            ["git", "config", "filter.secret.required", "true"],
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
