import base64
import json
import secrets
import tempfile
import unittest
from unittest.mock import MagicMock, patch, call

from git_secret_protector.core.settings import StorageType
from git_secret_protector.crypto.aes_key_manager import AesKeyManager
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

    @patch("git_secret_protector.services.key_rotator.AesEncryptionHandler")
    @patch("git_secret_protector.crypto.aes_key_manager.get_settings")
    @patch("git_secret_protector.crypto.aes_key_manager.StorageManagerFactory.create")
    def test_rotate_key_reads_backend_key_not_stale_cache(
        self, mock_create, mock_get_settings_aes, mock_handler_cls
    ):
        """When cache is stale, rotate_key must use the backend key, not the cached one."""
        mock_temp_dir = tempfile.TemporaryDirectory()
        mock_settings = MagicMock()
        mock_settings.cache_dir = mock_temp_dir.name
        mock_settings.module_name = secrets.token_hex(8)
        mock_settings.storage_type = StorageType.AWS_SSM
        mock_get_settings_aes.return_value = mock_settings

        mock_storage_manager = MagicMock()
        mock_create.return_value = mock_storage_manager

        aes_key_manager = AesKeyManager()

        cached_key = secrets.token_bytes(32)
        cached_iv = secrets.token_bytes(16)
        cached_blob = {
            "aes_key": base64.b64encode(cached_key).decode("utf-8"),
            "iv": base64.b64encode(cached_iv).decode("utf-8"),
            "version": 1,
        }

        backend_key = secrets.token_bytes(32)
        backend_iv = secrets.token_bytes(16)
        backend_blob = {
            "aes_key": base64.b64encode(backend_key).decode("utf-8"),
            "iv": base64.b64encode(backend_iv).decode("utf-8"),
            "version": 1,
        }

        filter_name = "test-filter"
        aes_key_manager.cache_key_iv_locally(filter_name, json.dumps(cached_blob))

        mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        mock_storage_manager.exists.return_value = False
        mock_storage_manager.retrieve.return_value = json.dumps(backend_blob)

        git_attributes_parser = MagicMock()
        git_attributes_parser.get_files_for_filter.return_value = ["secret.txt"]

        with patch(
            "git_secret_protector.services.key_rotator.get_settings"
        ) as mock_get_settings_rotator:
            mock_settings_rotator = MagicMock()
            mock_settings_rotator.magic_header = "ENCRYPTED"
            mock_get_settings_rotator.return_value = mock_settings_rotator

            rotator = KeyRotator(
                key_manager=aes_key_manager,
                git_attributes_parser=git_attributes_parser,
            )

            rotator.rotate_key(filter_name)

        decrypt_call = mock_handler_cls.call_args_list[0]
        self.assertEqual(decrypt_call.kwargs.get("aes_key"), backend_key)
        self.assertEqual(decrypt_call.kwargs.get("iv"), backend_iv)

        mock_temp_dir.cleanup()

    @patch("git_secret_protector.services.key_rotator.AesEncryptionHandler")
    @patch("git_secret_protector.crypto.aes_key_manager.get_settings")
    @patch("git_secret_protector.crypto.aes_key_manager.StorageManagerFactory.create")
    def test_rotate_key_preserves_scheme_from_backend_blob(
        self, mock_create, mock_get_settings_aes, mock_handler_cls
    ):
        """When cache is version-less and backend has v2, rotate_key must use v2."""
        mock_temp_dir = tempfile.TemporaryDirectory()
        mock_settings = MagicMock()
        mock_settings.cache_dir = mock_temp_dir.name
        mock_settings.module_name = secrets.token_hex(8)
        mock_settings.storage_type = StorageType.AWS_SSM
        mock_get_settings_aes.return_value = mock_settings

        mock_storage_manager = MagicMock()
        mock_create.return_value = mock_storage_manager

        aes_key_manager = AesKeyManager()

        cached_key = secrets.token_bytes(32)
        cached_iv = secrets.token_bytes(16)
        cached_blob = {
            "aes_key": base64.b64encode(cached_key).decode("utf-8"),
            "iv": base64.b64encode(cached_iv).decode("utf-8"),
        }

        backend_key = secrets.token_bytes(32)
        backend_iv = secrets.token_bytes(16)
        backend_blob = {
            "aes_key": base64.b64encode(backend_key).decode("utf-8"),
            "iv": base64.b64encode(backend_iv).decode("utf-8"),
            "version": 2,
        }

        filter_name = "test-filter"
        aes_key_manager.cache_key_iv_locally(filter_name, json.dumps(cached_blob))

        mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        mock_storage_manager.exists.return_value = False
        mock_storage_manager.retrieve.return_value = json.dumps(backend_blob)

        git_attributes_parser = MagicMock()
        git_attributes_parser.get_files_for_filter.return_value = ["secret.txt"]

        with patch.object(
            aes_key_manager,
            "setup_aes_key_and_iv",
            wraps=aes_key_manager.setup_aes_key_and_iv,
        ):
            with patch(
                "git_secret_protector.services.key_rotator.get_settings"
            ) as mock_get_settings_rotator:
                mock_settings_rotator = MagicMock()
                mock_settings_rotator.magic_header = "ENCRYPTED"
                mock_get_settings_rotator.return_value = mock_settings_rotator

                rotator = KeyRotator(
                    key_manager=aes_key_manager,
                    git_attributes_parser=git_attributes_parser,
                )

                rotator.rotate_key(filter_name)

            self.assertEqual(
                aes_key_manager.setup_aes_key_and_iv.call_args.kwargs.get("scheme"),
                "v2",
            )

        mock_temp_dir.cleanup()
