import base64
import json
import os
import secrets
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from git_secret_protector.core.settings import StorageType
from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler
from git_secret_protector.crypto.aes_key_manager import AesKeyManager
from git_secret_protector.services.key_rotator import KeyRotator

MAGIC_HEADER = b"ENCRYPTED"


class TestKeyRotator(unittest.TestCase):
    """Every test here uses a REAL AesKeyManager with only the storage backend
    mocked, and exists=True (the realistic state once a filter has a key).
    Mocking aes_key_manager wholesale, as the four tests this file replaces
    did, proves nothing about the rotation flow itself.
    """

    @patch("git_secret_protector.services.key_rotator.get_settings")
    @patch("git_secret_protector.crypto.aes_key_manager.get_settings")
    @patch("git_secret_protector.crypto.aes_key_manager.StorageManagerFactory.create")
    def setUp(self, mock_create, mock_aes_get_settings, mock_rotator_get_settings):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)

        mock_settings = MagicMock()
        mock_settings.cache_dir = self.tmp_dir.name
        mock_settings.module_name = secrets.token_hex(8)
        mock_settings.storage_type = StorageType.AWS_SSM
        mock_settings.magic_header = MAGIC_HEADER.decode()
        mock_settings.base_dir = self.tmp_dir.name

        mock_aes_get_settings.return_value = mock_settings
        mock_rotator_get_settings.return_value = mock_settings

        self.storage = MagicMock()
        self.storage.parameter_name.return_value = "/enc/my-filter"
        self.storage.exists.return_value = True
        mock_create.return_value = self.storage

        self.aes_key_manager = AesKeyManager()
        # Pre-wire the storage manager directly: the @patch decorators on setUp
        # only patch for the duration of setUp itself, not for the test methods
        # that run afterward, so _get_storage_manager()'s lazy-create path must
        # be bypassed the same way TestAesKeyManagerScheme does.
        self.aes_key_manager.storage_manager = self.storage
        self.git_attributes_parser = MagicMock()
        self.rotator = KeyRotator(
            key_manager=self.aes_key_manager,
            git_attributes_parser=self.git_attributes_parser,
        )

    def _seed_backend_key(self, aes_key, iv, version=2):
        data = {
            "aes_key": base64.b64encode(aes_key).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "version": version,
        }
        self.storage.retrieve.return_value = json.dumps(data)

    def _write_encrypted_file(self, path, plaintext, aes_key, iv, scheme="v2"):
        handler = AesEncryptionHandler(
            aes_key=aes_key, iv=iv, magic_header=MAGIC_HEADER, scheme=scheme
        )
        with open(path, "wb") as f:
            f.write(handler.encrypt_data(plaintext))

    def test_rotation_completes_and_backend_holds_matching_key(self):
        """The whole ticket in one test: rotation completes against a backend
        whose parameter already exists, and the backend ends up holding the
        key the files were ACTUALLY encrypted with."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file_path = os.path.join(self.tmp_dir.name, "secret.txt")
        plaintext = b"super secret value"
        self._write_encrypted_file(file_path, plaintext, old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file_path]

        self.rotator.rotate_key("my-filter")

        self.storage.store.assert_called_once()
        stored_name, stored_json = self.storage.store.call_args[0]
        stored_data = json.loads(stored_json)
        new_key = base64.b64decode(stored_data["aes_key"])
        new_iv = base64.b64decode(stored_data["iv"])

        with open(file_path, "rb") as f:
            on_disk = f.read()
        verify_handler = AesEncryptionHandler(
            aes_key=new_key, iv=new_iv, magic_header=MAGIC_HEADER, scheme="v2"
        )
        self.assertEqual(verify_handler.decrypt_data(on_disk), plaintext)

    def test_reads_current_key_from_backend_not_stale_cache(self):
        """force=True is load-bearing: retrieve_key_and_iv must be called with
        force=True so a stale local cache is never the source of the key used
        to decrypt the existing files. The pre-write F1 check adds a second call."""
        backend_key = secrets.token_bytes(32)
        backend_iv = secrets.token_bytes(16)
        self._seed_backend_key(backend_key, backend_iv, version=2)

        stale_key = secrets.token_bytes(32)
        stale_iv = secrets.token_bytes(16)
        self.aes_key_manager.cache_key_iv_locally(
            "my-filter",
            json.dumps(
                {
                    "aes_key": base64.b64encode(stale_key).decode("utf-8"),
                    "iv": base64.b64encode(stale_iv).decode("utf-8"),
                    "version": 2,
                }
            ),
        )

        file_path = os.path.join(self.tmp_dir.name, "secret.txt")
        self._write_encrypted_file(file_path, b"value", backend_key, backend_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file_path]

        with patch.object(
            self.aes_key_manager,
            "retrieve_key_and_iv",
            wraps=self.aes_key_manager.retrieve_key_and_iv,
        ) as spy:
            self.rotator.rotate_key("my-filter")
            self.assertEqual(spy.call_count, 2)
            for call in spy.call_args_list:
                self.assertEqual(
                    call, unittest.mock.call(filter_name="my-filter", force=True)
                )

        self.storage.store.assert_called_once()

    def test_scheme_preserved_from_refreshed_blob(self):
        """A version-less local cache (legacy v1-shaped) must not decide the
        scheme when the backend's blob - refreshed by step 1's force read -
        says v2."""
        backend_key = secrets.token_bytes(32)
        backend_iv = secrets.token_bytes(16)
        self._seed_backend_key(backend_key, backend_iv, version=2)

        self.aes_key_manager.cache_key_iv_locally(
            "my-filter",
            json.dumps(
                {
                    "aes_key": base64.b64encode(backend_key).decode("utf-8"),
                    "iv": base64.b64encode(backend_iv).decode("utf-8"),
                    # no "version" key - legacy, version-less cache entry
                }
            ),
        )

        file_path = os.path.join(self.tmp_dir.name, "secret.txt")
        self._write_encrypted_file(
            file_path, b"value", backend_key, backend_iv, scheme="v2"
        )
        self.git_attributes_parser.get_files_for_filter.return_value = [file_path]

        self.rotator.rotate_key("my-filter")

        stored_json = self.storage.store.call_args[0][1]
        self.assertEqual(json.loads(stored_json)["version"], 2)

    def test_transform_failure_leaves_backend_unchanged_and_restores(self):
        """A failure during the per-file transform loop must never reach the
        backend write, and must trigger the abort restore path."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file1 = os.path.join(self.tmp_dir.name, "a.txt")
        file2 = os.path.join(self.tmp_dir.name, "b.txt")
        self._write_encrypted_file(file1, b"one", old_key, old_iv)
        self._write_encrypted_file(file2, b"two", old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file1, file2]

        original_encrypt_data = AesEncryptionHandler.encrypt_data
        calls = {"n": 0}

        def flaky_encrypt_data(self_handler, data):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("simulated transform failure")
            return original_encrypt_data(self_handler, data)

        with patch.object(
            AesEncryptionHandler, "encrypt_data", flaky_encrypt_data
        ), patch(
            "git_secret_protector.services.key_rotator.tree_state.restore_on_abort"
        ) as mock_restore:
            mock_restore.return_value = []
            with self.assertRaises(Exception):
                self.rotator.rotate_key("my-filter")
            mock_restore.assert_called_once()

        self.storage.store.assert_not_called()

    def test_verify_mismatch_aborts_before_backend_write(self):
        """A content-verify mismatch after the transform loop must abort
        before the backend write, same as a transform failure."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file_path = os.path.join(self.tmp_dir.name, "secret.txt")
        self._write_encrypted_file(file_path, b"value", old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file_path]

        with patch(
            "git_secret_protector.services.key_rotator.tree_state.plaintext_checksums",
            side_effect=[{file_path: "before-hash"}, {file_path: "after-hash"}],
        ), patch(
            "git_secret_protector.services.key_rotator.tree_state.restore_on_abort"
        ) as mock_restore:
            mock_restore.return_value = []
            with self.assertRaises(Exception):
                self.rotator.rotate_key("my-filter")
            mock_restore.assert_called_once()

        self.storage.store.assert_not_called()

    def test_failed_checkout_restores_converted_files_under_the_old_key(self):
        """When checkout fails on the abort path, converted files must be restored
        to their original state using the old key, and files never converted must
        remain untouched. This test pins DEFECT 1."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file1 = os.path.join(self.tmp_dir.name, "a.txt")
        file2 = os.path.join(self.tmp_dir.name, "b.txt")
        plaintext1 = b"content one"
        plaintext2 = b"content two"
        self._write_encrypted_file(file1, plaintext1, old_key, old_iv)
        self._write_encrypted_file(file2, plaintext2, old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file1, file2]

        original_encrypt_data = AesEncryptionHandler.encrypt_data
        calls = {"n": 0}

        def flaky_encrypt_data(self_handler, data):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("simulated transform failure on file 2")
            return original_encrypt_data(self_handler, data)

        with patch.object(
            AesEncryptionHandler, "encrypt_data", flaky_encrypt_data
        ), patch(
            "git_secret_protector.services.key_rotator.tree_state.git_checkout_files"
        ) as mock_checkout:
            mock_checkout.return_value = False
            with self.assertRaises(Exception):
                self.rotator.rotate_key("my-filter")

        self.storage.store.assert_not_called()

        old_handler = AesEncryptionHandler(
            aes_key=old_key, iv=old_iv, magic_header=MAGIC_HEADER
        )
        with open(file1, "rb") as f:
            decrypted1 = old_handler.decrypt_data(f.read())
        self.assertEqual(decrypted1, plaintext1)

        with open(file2, "rb") as f:
            decrypted2 = old_handler.decrypt_data(f.read())
        self.assertEqual(decrypted2, plaintext2)

    def test_blob_write_failure_with_live_blob_reports_rotation_succeeded(self):
        """When replace_key_and_iv fails but a forced retrieve shows the blob IS
        live with the new key, rotation_succeeded must be True."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file_path = os.path.join(self.tmp_dir.name, "secret.txt")
        plaintext = b"test data"
        self._write_encrypted_file(file_path, plaintext, old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file_path]

        captured_keys = {"new_key": None, "new_iv": None}
        retrieve_call_count = {"n": 0}

        def retrieve_with_state(*args, **kwargs):
            retrieve_call_count["n"] += 1
            if retrieve_call_count["n"] <= 2:
                return old_key, old_iv
            return captured_keys["new_key"], captured_keys["new_iv"]

        def failing_replace(*args, **kwargs):
            captured_keys["new_key"] = kwargs.get("aes_key")
            captured_keys["new_iv"] = kwargs.get("iv")
            raise RuntimeError("simulated blob write failure")

        with patch.object(
            self.aes_key_manager, "replace_key_and_iv", side_effect=failing_replace
        ), patch.object(
            self.aes_key_manager, "retrieve_key_and_iv", side_effect=retrieve_with_state
        ), patch(
            "git_secret_protector.services.key_rotator.tree_state.restore_to_found_state"
        ) as mock_restore:
            mock_restore.return_value = []
            with self.assertRaises(Exception) as ctx:
                self.rotator.rotate_key("my-filter")
            self.assertTrue(ctx.exception.fields.get("rotation_succeeded"))

    def test_blob_write_failure_with_old_blob_runs_the_pre_write_restore(self):
        """When replace_key_and_iv fails and the forced retrieve shows the blob
        is still the OLD key, the pre-write restore must run and rotation_succeeded
        must be False."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file1 = os.path.join(self.tmp_dir.name, "a.txt")
        file2 = os.path.join(self.tmp_dir.name, "b.txt")
        plaintext1 = b"one"
        plaintext2 = b"two"
        self._write_encrypted_file(file1, plaintext1, old_key, old_iv)
        self._write_encrypted_file(file2, plaintext2, old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file1, file2]

        retrieve_call_count = {"n": 0}

        def retrieve_returns_old_key(*args, **kwargs):
            retrieve_call_count["n"] += 1
            return old_key, old_iv

        def failing_replace(*args, **kwargs):
            raise RuntimeError("simulated blob write failure")

        with patch.object(
            self.aes_key_manager, "replace_key_and_iv", side_effect=failing_replace
        ), patch.object(
            self.aes_key_manager,
            "retrieve_key_and_iv",
            side_effect=retrieve_returns_old_key,
        ), patch(
            "git_secret_protector.services.key_rotator.tree_state.git_checkout_files",
            return_value=False,
        ):
            with self.assertRaises(Exception) as ctx:
                self.rotator.rotate_key("my-filter")
            self.assertFalse(ctx.exception.fields.get("rotation_succeeded", True))

        old_handler = AesEncryptionHandler(
            aes_key=old_key, iv=old_iv, magic_header=MAGIC_HEADER
        )
        with open(file1, "rb") as f:
            decrypted1 = old_handler.decrypt_data(f.read())
        self.assertEqual(decrypted1, plaintext1)

    def test_blob_write_failure_with_unreadable_backend_leaves_the_tree_alone(self):
        """When replace_key_and_iv fails and the forced retrieve also fails,
        the tree must NOT be restored (left as-is from the rotation loop) and
        the error must name both recovery commands."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file_path = os.path.join(self.tmp_dir.name, "secret.txt")
        plaintext = b"secret"
        self._write_encrypted_file(file_path, plaintext, old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file_path]

        original_data = open(file_path, "rb").read()

        retrieve_call_count = {"n": 0}

        captured_keys = {"new_key": None, "new_iv": None}

        def retrieve_first_succeeds_then_fails(*args, **kwargs):
            retrieve_call_count["n"] += 1
            if retrieve_call_count["n"] <= 2:
                return old_key, old_iv
            raise RuntimeError("backend unreachable")

        def failing_replace(*args, **kwargs):
            captured_keys["new_key"] = kwargs.get("aes_key")
            captured_keys["new_iv"] = kwargs.get("iv")
            raise RuntimeError("blob write error")

        with patch.object(
            self.aes_key_manager, "replace_key_and_iv", side_effect=failing_replace
        ), patch.object(
            self.aes_key_manager,
            "retrieve_key_and_iv",
            side_effect=retrieve_first_succeeds_then_fails,
        ):
            with self.assertRaises(Exception) as ctx:
                self.rotator.rotate_key("my-filter")
            error_msg = str(ctx.exception)
            self.assertIn("could not verify", error_msg)
            self.assertIn("pull-aes-key", error_msg)
            self.assertIn("git checkout", error_msg)
            self.assertIsNone(ctx.exception.fields.get("rotation_succeeded"))

        current_data = open(file_path, "rb").read()
        new_handler = AesEncryptionHandler(
            aes_key=captured_keys["new_key"],
            iv=captured_keys["new_iv"],
            magic_header=MAGIC_HEADER,
            scheme="v2",
        )
        decrypted = new_handler.decrypt_data(current_data)
        self.assertEqual(decrypted, plaintext)

    def test_file_truncated_mid_write_is_reported_not_silently_skipped(self):
        """A file truncated mid-write during rotation must be reported as a
        restore failure, not silently skipped by the restore path. This tests
        the fix for the defect where open(..., "wb") truncates before the write,
        and if fh.write fails, the file is left corrupt but converted.append
        never runs - so restore_converted_files skips it silently."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file1 = os.path.join(self.tmp_dir.name, "a.txt")
        file2 = os.path.join(self.tmp_dir.name, "b.txt")
        file3 = os.path.join(self.tmp_dir.name, "c.txt")
        plaintext1 = b"content one"
        plaintext2 = b"content two"
        plaintext3 = b"content three"
        self._write_encrypted_file(file1, plaintext1, old_key, old_iv)
        self._write_encrypted_file(file2, plaintext2, old_key, old_iv)
        self._write_encrypted_file(file3, plaintext3, old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [
            file1,
            file2,
            file3,
        ]

        original_open = open

        def failing_open_on_second_write(path, mode="r", *args, **kwargs):
            # file2's write-mode call will fail mid-write after truncation.
            # The file is opened and truncated, but the write fails.
            if path == file2 and mode == "wb":
                fh = original_open(path, mode)
                # At this point, file2 is truncated on disk. Close it and raise.
                fh.close()
                raise IOError("simulated mid-write disk failure")
            return original_open(path, mode, *args, **kwargs)

        # Verify file2 starts with content
        with open(file2, "rb") as f:
            before_truncation = f.read()
        self.assertTrue(len(before_truncation) > 0)

        with patch("builtins.open", side_effect=failing_open_on_second_write), patch(
            "git_secret_protector.services.key_rotator.tree_state.git_checkout_files"
        ) as mock_checkout:
            mock_checkout.return_value = False
            with self.assertRaises(Exception) as ctx:
                self.rotator.rotate_key("my-filter")

        # Assert: backend store was never called
        self.storage.store.assert_not_called()

        # Assert: the exception's restore_failed_files contains file2
        restore_failed = ctx.exception.fields.get("restore_failed_files", [])
        self.assertIn(file2, restore_failed)

        # Assert: file1 was restored to its original plaintext (decrypts under old key)
        old_handler = AesEncryptionHandler(
            aes_key=old_key, iv=old_iv, magic_header=MAGIC_HEADER
        )
        with open(file1, "rb") as f:
            decrypted1 = old_handler.decrypt_data(f.read())
        self.assertEqual(decrypted1, plaintext1)

        # Assert: file3 is untouched (never reached in the loop)
        with open(file3, "rb") as f:
            decrypted3 = old_handler.decrypt_data(f.read())
        self.assertEqual(decrypted3, plaintext3)

    def test_failed_checkout_fallback_restores_v1_files_in_v1(self):
        """A v1 filter whose abort restore path re-encrypts must emit v1 bytes,
        not v2. Without the fix (old_handler built without scheme=scheme), the
        fallback would write v2 bytes while the blob declares v1, leaving the
        file permanently dirty."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=1)

        file1 = os.path.join(self.tmp_dir.name, "a.txt")
        file2 = os.path.join(self.tmp_dir.name, "b.txt")
        plaintext1 = b"content one"
        plaintext2 = b"content two"
        self._write_encrypted_file(file1, plaintext1, old_key, old_iv, scheme="v1")
        self._write_encrypted_file(file2, plaintext2, old_key, old_iv, scheme="v1")
        self.git_attributes_parser.get_files_for_filter.return_value = [file1, file2]

        original_encrypt_data = AesEncryptionHandler.encrypt_data
        calls = {"n": 0}

        def flaky_encrypt_data(self_handler, data):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("simulated transform failure on file 2")
            return original_encrypt_data(self_handler, data)

        with patch.object(
            AesEncryptionHandler, "encrypt_data", flaky_encrypt_data
        ), patch(
            "git_secret_protector.services.key_rotator.tree_state.git_checkout_files"
        ) as mock_checkout:
            mock_checkout.return_value = False
            with self.assertRaises(Exception):
                self.rotator.rotate_key("my-filter")

        self.storage.store.assert_not_called()

        with open(file1, "rb") as f:
            restored_bytes = f.read()

        old_handler = AesEncryptionHandler(
            aes_key=old_key, iv=old_iv, magic_header=MAGIC_HEADER, scheme="v1"
        )

        byte_after_magic = restored_bytes[len(MAGIC_HEADER) : len(MAGIC_HEADER) + 1]
        self.assertIn(
            byte_after_magic[0],
            AesEncryptionHandler._B64_FIRST_BYTES,
            f"Restored file must be v1 (base64 alphabet first byte), not v2 "
            f"(0x02 version byte). Got byte: {byte_after_magic.hex()}",
        )

        decrypted1 = old_handler.decrypt_data(restored_bytes)
        self.assertEqual(decrypted1, plaintext1)

    def test_rotation_aborts_when_the_stored_key_changed_underneath(self):
        """F1: A concurrent rotation that lands while this one is running must
        abort before the blob write, with a message naming the race and pointing
        to recovery. The pre-write re-read catches this."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file_path = os.path.join(self.tmp_dir.name, "secret.txt")
        plaintext = b"test data"
        self._write_encrypted_file(file_path, plaintext, old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file_path]

        retrieve_call_count = {"n": 0}
        different_key = secrets.token_bytes(32)

        def retrieve_different_on_prewrite_check(*args, **kwargs):
            retrieve_call_count["n"] += 1
            if retrieve_call_count["n"] == 1:
                return old_key, old_iv
            return different_key, old_iv

        with patch.object(
            self.aes_key_manager,
            "replace_key_and_iv",
        ) as mock_replace, patch.object(
            self.aes_key_manager,
            "retrieve_key_and_iv",
            side_effect=retrieve_different_on_prewrite_check,
        ):
            with self.assertRaises(Exception) as ctx:
                self.rotator.rotate_key("my-filter")

        # Assert: replace_key_and_iv was never called
        mock_replace.assert_not_called()

        # Assert: error message mentions the race condition
        error_msg = str(ctx.exception)
        self.assertIn("key changed under us", error_msg)
        self.assertIn("pull-aes-key", error_msg)

        # Assert: rotation_succeeded is False (blob was not touched, state is known)
        self.assertIs(ctx.exception.fields.get("rotation_succeeded"), False)

        # Assert: plaintext can still be decrypted with old key (restore worked)
        old_handler = AesEncryptionHandler(
            aes_key=old_key, iv=old_iv, magic_header=MAGIC_HEADER
        )
        with open(file_path, "rb") as f:
            decrypted = old_handler.decrypt_data(f.read())
        self.assertEqual(decrypted, plaintext)

    def test_empty_file_list_blob_write_failure_is_discriminated(self):
        """F2: When a filter has no matched files, the blob write must still go
        through the guarded path so that a write failure is discriminated. If the
        backend succeeds but the cache write fails, rotation_succeeded must be True."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        self.git_attributes_parser.get_files_for_filter.return_value = []

        captured_keys = {"new_key": None, "new_iv": None}
        retrieve_call_count = {"n": 0}

        def retrieve_returns_captured_key_on_post_write_check(*args, **kwargs):
            retrieve_call_count["n"] += 1
            if retrieve_call_count["n"] <= 2:
                return old_key, old_iv
            return captured_keys["new_key"], captured_keys["new_iv"]

        def failing_replace(*args, **kwargs):
            captured_keys["new_key"] = kwargs.get("aes_key")
            captured_keys["new_iv"] = kwargs.get("iv")
            raise RuntimeError("simulated cache write failure")

        with patch.object(
            self.aes_key_manager, "replace_key_and_iv", side_effect=failing_replace
        ), patch.object(
            self.aes_key_manager,
            "retrieve_key_and_iv",
            side_effect=retrieve_returns_captured_key_on_post_write_check,
        ), patch(
            "git_secret_protector.services.key_rotator.tree_state.restore_to_found_state"
        ) as mock_restore:
            mock_restore.return_value = []
            with self.assertRaises(Exception) as ctx:
                self.rotator.rotate_key("my-filter")

        # Assert: rotation_succeeded is True (backend DID change even though cache write failed)
        self.assertTrue(ctx.exception.fields.get("rotation_succeeded"))

    def test_abort_fallback_message_names_rotate_key(self):
        """F3: When the abort restore path falls back to crypto re-encrypt because
        git checkout failed, the operator-facing message must name the command that
        failed (rotate-key, not upgrade-scheme)."""
        old_key = secrets.token_bytes(32)
        old_iv = secrets.token_bytes(16)
        self._seed_backend_key(old_key, old_iv, version=2)

        file_path = os.path.join(self.tmp_dir.name, "secret.txt")
        plaintext = b"test data"
        self._write_encrypted_file(file_path, plaintext, old_key, old_iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [file_path]

        # Cause the rotation to fail during the transform, triggering the abort path
        def failing_encrypt_data(self_handler, data):
            raise RuntimeError("simulated transform failure")

        with patch.object(
            AesEncryptionHandler, "encrypt_data", failing_encrypt_data
        ), patch(
            "git_secret_protector.services.key_rotator.tree_state.git_checkout_files",
            return_value=False,
        ), patch.object(
            self.rotator.output, "error"
        ) as mock_error:
            with self.assertRaises(Exception) as ctx:
                self.rotator.rotate_key("my-filter")

            # Assert: on_error was called with a message naming rotate-key
            mock_error.assert_called_once()
            error_output = mock_error.call_args[0][0]
            self.assertIn("rotate-key", error_output)
            self.assertNotIn("upgrade-scheme", error_output)
