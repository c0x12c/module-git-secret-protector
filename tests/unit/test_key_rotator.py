import unittest
from unittest.mock import MagicMock, patch, call

from git_secret_protector.services.key_rotator import KeyRotator


class TestKeyRotator(unittest.TestCase):
    @patch("git_secret_protector.services.key_rotator.get_settings")
    def setUp(self, mock_get_settings):
        mock_settings = MagicMock()
        mock_settings.magic_header = "ENCRYPTED"
        mock_get_settings.return_value = mock_settings

        self.aes_key_manager = MagicMock()
        self.git_attributes_parser = MagicMock()
        self.rotator = KeyRotator(
            key_manager=self.aes_key_manager,
            git_attributes_parser=self.git_attributes_parser,
        )

    @patch("git_secret_protector.services.key_rotator.AesEncryptionHandler")
    def test_rotate_key_preserves_v1_scheme(self, mock_handler_cls):
        """Rotating a v1 filter must NOT silently upgrade it to v2."""
        current_key = b"current-key-bytes"
        current_iv = b"current-iv-bytes"
        new_key = b"new-key-bytes"
        new_iv = b"new-iv-bytes"
        files = ["secret.txt", "config.env"]

        self.aes_key_manager.get_scheme.return_value = "v1"
        self.aes_key_manager.retrieve_key_and_iv.side_effect = [
            (current_key, current_iv),
            (new_key, new_iv),
        ]
        self.git_attributes_parser.get_files_for_filter.return_value = files

        self.rotator.rotate_key("my-filter")

        # scheme read at the start
        self.aes_key_manager.get_scheme.assert_called_once_with("my-filter")

        # new key generated with preserved v1 scheme
        self.aes_key_manager.setup_aes_key_and_iv.assert_called_once_with(
            filter_name="my-filter", scheme="v1"
        )

        # two AesEncryptionHandler instantiations: decrypt then encrypt
        self.assertEqual(mock_handler_cls.call_count, 2)
        decrypt_call, encrypt_call = mock_handler_cls.call_args_list

        # decrypt handler: no scheme override required (wire-byte-authoritative)
        self.assertEqual(decrypt_call.kwargs.get("aes_key"), current_key)
        self.assertEqual(decrypt_call.kwargs.get("iv"), current_iv)

        # encrypt handler: must carry the preserved v1 scheme
        self.assertEqual(encrypt_call.kwargs.get("aes_key"), new_key)
        self.assertEqual(encrypt_call.kwargs.get("iv"), new_iv)
        self.assertEqual(encrypt_call.kwargs.get("scheme"), "v1")

    @patch("git_secret_protector.services.key_rotator.AesEncryptionHandler")
    def test_rotate_key_preserves_v2_scheme(self, mock_handler_cls):
        """Rotating a v2 filter threads v2 through to the new key setup and encrypt handler."""
        current_key = b"current-key"
        current_iv = b"current-iv"
        new_key = b"new-key"
        new_iv = b"new-iv"

        self.aes_key_manager.get_scheme.return_value = "v2"
        self.aes_key_manager.retrieve_key_and_iv.side_effect = [
            (current_key, current_iv),
            (new_key, new_iv),
        ]
        self.git_attributes_parser.get_files_for_filter.return_value = ["file.txt"]

        self.rotator.rotate_key("v2-filter")

        self.aes_key_manager.setup_aes_key_and_iv.assert_called_once_with(
            filter_name="v2-filter", scheme="v2"
        )

        _, encrypt_call = mock_handler_cls.call_args_list
        self.assertEqual(encrypt_call.kwargs.get("scheme"), "v2")
