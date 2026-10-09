import base64
import errno
import json
import os
import secrets
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from botocore.exceptions import ClientError

from git_secret_protector.core.settings import StorageType
from git_secret_protector.crypto.aes_key_manager import AesKeyManager
from git_secret_protector.error.aes_key_error import AesKeyError
from git_secret_protector.error.unsupported_format_error import UnsupportedFormatError


class TestAesKeyManager(unittest.TestCase):

    @patch("git_secret_protector.crypto.aes_key_manager.get_settings")
    @patch("git_secret_protector.crypto.aes_key_manager.StorageManagerFactory.create")
    def setUp(self, mock_create, mock_get_settings):
        self.mock_settings = MagicMock()
        self.mock_temp_dir = tempfile.TemporaryDirectory()
        self.mock_settings.cache_dir = self.mock_temp_dir.name
        self.mock_settings.module_name = secrets.token_hex(8)
        self.mock_settings.storage_type = StorageType.AWS_SSM

        mock_get_settings.return_value = self.mock_settings

        self.mock_storage_manager = MagicMock()
        mock_create.return_value = self.mock_storage_manager

        self.aes_key_manager = AesKeyManager()

    @staticmethod
    def random_encoded_data():
        aes_key = base64.b64encode(secrets.token_bytes(32)).decode("utf-8")
        iv = base64.b64encode(secrets.token_bytes(16)).decode("utf-8")
        return json.dumps({"aes_key": aes_key, "iv": iv})

    @patch("boto3.client")
    @patch("boto3.session.Session")
    def test_setup_aes_key_and_iv(self, mock_session, mock_boto_client):
        filter_name = secrets.token_hex(8)
        account_id = secrets.token_hex(8)

        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": account_id
        }
        mock_session.return_value.region_name = "us-west-2"

        # Configure the mock to raise a ClientError for get_parameter
        mock_boto_client.return_value.get_parameter.side_effect = ClientError(
            {"Error": {"Code": "ParameterNotFound", "Message": "Parameter not found"}},
            "GetParameter",
        )

        self.aes_key_manager.setup_aes_key_and_iv(filter_name)

        expected_parameter_name = f"/encryption/{account_id}/uswe2/{self.mock_settings.module_name}/{filter_name}/key_iv"

        mock_boto_client.return_value.put_parameter.assert_called_once()
        args, kwargs = mock_boto_client.return_value.put_parameter.call_args
        self.assertEqual(kwargs["Name"], expected_parameter_name)
        self.assertEqual("SecureString", kwargs["Type"])
        data = json.loads(kwargs["Value"])
        self.assertTrue("aes_key" in data and "iv" in data)

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_retrieve_key_and_iv_from_cache_hit(self, mock_open, _):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        mock_open.return_value.read.return_value = json_data

        aes_key, iv = self.aes_key_manager.retrieve_key_and_iv(filter_name)

        data = json.loads(json_data)
        self.assertEqual(aes_key, base64.b64decode(data["aes_key"]))
        self.assertEqual(iv, base64.b64decode(data["iv"]))

    @patch("os.path.exists", return_value=False)
    @patch("git_secret_protector.crypto.aes_key_manager.StorageManagerFactory.create")
    def test_retrieve_key_and_iv_from_cache_miss(self, mock_create, _):
        mock_create.return_value = self.mock_storage_manager
        self.mock_storage_manager.parameter_name.return_value = secrets.token_hex(8)

        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        self.mock_storage_manager.retrieve.return_value = json_data

        aes_key, iv = self.aes_key_manager.retrieve_key_and_iv(filter_name)

        self.mock_storage_manager.retrieve.assert_called_once()
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        with open(cache_path, "r") as cache_file:
            self.assertEqual(cache_file.read(), json_data)
        self.assertEqual(oct(os.stat(cache_path).st_mode & 0o777), "0o600")

        data = json.loads(json_data)
        self.assertEqual(aes_key, base64.b64decode(data["aes_key"]))
        self.assertEqual(iv, base64.b64decode(data["iv"]))

    @patch("os.path.exists", return_value=False)
    def test_retrieve_key_and_iv_cache_only_miss_raises_with_pull_hint(self, _):
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.storage_manager = self.mock_storage_manager

        with self.assertRaises(AesKeyError) as context:
            self.aes_key_manager.retrieve_key_and_iv(filter_name, cache_only=True)

        self.mock_storage_manager.retrieve.assert_not_called()
        self.assertIn("pull-aes-key", str(context.exception))

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_retrieve_key_and_iv_cache_only_hit_uses_cache(self, mock_open, _):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.storage_manager = self.mock_storage_manager
        mock_open.return_value.read.return_value = json_data

        aes_key, iv = self.aes_key_manager.retrieve_key_and_iv(
            filter_name, cache_only=True
        )

        data = json.loads(json_data)
        self.mock_storage_manager.retrieve.assert_not_called()
        self.assertEqual(aes_key, base64.b64decode(data["aes_key"]))
        self.assertEqual(iv, base64.b64decode(data["iv"]))

    def test_retrieve_key_and_iv_force_refreshes_stale_cache(self):
        # Catches the reported bug: a stale cache made pull-aes-key a no-op
        # because the backend was never contacted when a cache file existed.
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.storage_manager = self.mock_storage_manager
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"

        stale_json = self.random_encoded_data()
        self.aes_key_manager.cache_key_iv_locally(filter_name, stale_json)

        fresh_json = self.random_encoded_data()
        self.mock_storage_manager.retrieve.return_value = fresh_json

        self.aes_key_manager.retrieve_key_and_iv(filter_name, force=True)

        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        with open(cache_path, "r") as cache_file:
            cached_content = cache_file.read()
        self.assertNotEqual(cached_content, stale_json)
        self.assertEqual(cached_content, fresh_json)

    def test_retrieve_key_and_iv_without_force_never_contacts_backend_when_cached(self):
        # Regression guard for the git clean/smudge hot path: a cache hit must
        # never touch the storage manager unless force is explicitly requested.
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.storage_manager = self.mock_storage_manager
        json_data = self.random_encoded_data()
        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        self.aes_key_manager.retrieve_key_and_iv(filter_name)

        self.assertEqual(self.mock_storage_manager.mock_calls, [])

    @patch("os.path.exists", return_value=False)
    def test_retrieve_key_and_iv_cache_only_still_skips_backend_on_miss(self, _):
        # cache_only must keep its existing guarantee unchanged by the force addition.
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.storage_manager = self.mock_storage_manager

        with self.assertRaises(AesKeyError):
            self.aes_key_manager.retrieve_key_and_iv(filter_name, cache_only=True)

        self.mock_storage_manager.retrieve.assert_not_called()

    def test_retrieve_key_and_iv_force_and_cache_only_raises_value_error(self):
        # force + cache_only is a contradictory request from a programming error,
        # not a case any caller should silently resolve one way or the other.
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.storage_manager = self.mock_storage_manager

        with self.assertRaises(ValueError):
            self.aes_key_manager.retrieve_key_and_iv(
                filter_name, cache_only=True, force=True
            )

        self.mock_storage_manager.retrieve.assert_not_called()

    @patch.object(AesKeyManager, "cache_key_iv_locally")
    def test_peek_stored_key_and_iv_does_not_write_cache(self, mock_cache):
        # The whole point of peek: it reads the backend but must never trigger
        # the cache-write side effect retrieve_key_and_iv(force=True) has.
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.storage_manager = self.mock_storage_manager
        json_data = self.random_encoded_data()
        self.mock_storage_manager.retrieve.return_value = json_data

        aes_key, iv = self.aes_key_manager.peek_stored_key_and_iv(filter_name)

        data = json.loads(json_data)
        self.assertEqual(aes_key, base64.b64decode(data["aes_key"]))
        self.assertEqual(iv, base64.b64decode(data["iv"]))
        mock_cache.assert_not_called()

    def test_peek_stored_key_and_iv_leaves_no_cache_file_where_none_existed(self):
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.storage_manager = self.mock_storage_manager
        json_data = self.random_encoded_data()
        self.mock_storage_manager.retrieve.return_value = json_data

        self.aes_key_manager.peek_stored_key_and_iv(filter_name)

        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        self.assertFalse(os.path.exists(cache_path))

    def test_cache_key_iv_locally(self):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)

        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        with open(cache_path, "r") as cache_file:
            self.assertEqual(cache_file.read(), json_data)
        self.assertEqual(oct(os.stat(cache_path).st_mode & 0o777), "0o600")

    def test_cache_key_iv_locally_tightens_existing_file_permissions(self):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)

        existing_fd = os.open(cache_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(existing_fd, "w") as cache_file:
            cache_file.write("stale-data")
        os.chmod(cache_path, 0o644)

        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        with open(cache_path, "r") as cache_file:
            self.assertEqual(cache_file.read(), json_data)
        self.assertEqual(oct(os.stat(cache_path).st_mode & 0o777), "0o600")

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_load_key_iv_from_cache(self, mock_open, mock_exists):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        mock_open.return_value.read.return_value = json_data

        data = self.aes_key_manager.load_key_iv_from_cache(filter_name)

        mock_exists.assert_called_once_with(
            os.path.join(self.mock_temp_dir.name, f"{filter_name}_key_iv.json")
        )
        self.assertEqual(
            data, json.loads(json_data), "Expected data to match JSON content"
        )

    @patch("os.path.exists", return_value=False)
    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_load_key_iv_from_cache_not_found(self, mock_open, mock_exists):
        filter_name = secrets.token_hex(8)

        result = self.aes_key_manager.load_key_iv_from_cache(filter_name)

        mock_exists.assert_called_once_with(
            os.path.join(self.mock_settings.cache_dir, f"{filter_name}_key_iv.json")
        )
        mock_open.assert_not_called()  # Ensures open was not called since file does not exist
        self.assertIsNone(
            result, "Expected result to be None when cache file does not exist"
        )

    def test_failed_replace_leaves_previous_cache_intact(self):
        # Seed a valid cache, then fail the atomic replace.
        # The original content must still be there and still parseable.
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        # Verify the cache was written
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        with open(cache_path, "r") as f:
            original_content = f.read()
        self.assertEqual(original_content, json_data)

        # Fail during os.replace (after the temp file is successfully written).
        # This simulates an interruption after the write completes but before atomicity.
        new_json = self.random_encoded_data()
        with patch("os.replace", side_effect=OSError("Simulated failure")):
            with self.assertRaises(OSError):
                self.aes_key_manager.cache_key_iv_locally(filter_name, new_json)

        # The original content should still be there and parseable
        with open(cache_path, "r") as f:
            recovered_content = f.read()
        self.assertEqual(recovered_content, json_data)
        json.loads(recovered_content)  # Verify it parses

    def test_failed_write_leaves_previous_cache_intact(self):
        # Seed a valid cache, then fail the write/fdopen itself (earlier failure point).
        # The original content must still be there and parseable, and no temp file remains.
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        # Verify the cache was written
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        with open(cache_path, "r") as f:
            original_content = f.read()
        self.assertEqual(original_content, json_data)

        # Fail during fdopen (before write happens).
        new_json = self.random_encoded_data()
        with patch("os.fdopen", side_effect=OSError("Simulated write failure")):
            with self.assertRaises(OSError):
                self.aes_key_manager.cache_key_iv_locally(filter_name, new_json)

        # The original content should still be there and parseable
        with open(cache_path, "r") as f:
            recovered_content = f.read()
        self.assertEqual(recovered_content, json_data)
        json.loads(recovered_content)  # Verify it parses

        # No temp file should remain after cleanup
        cache_dir = self.aes_key_manager.cache_dir
        tmp_files = [f for f in os.listdir(cache_dir) if f.endswith(".tmp")]
        self.assertEqual(
            len(tmp_files),
            0,
            f"Found unexpected .tmp files after write failure: {tmp_files}",
        )

    def test_failed_write_inside_the_file_object_leaves_previous_cache_intact(self):
        # Fail the write itself (fdopen succeeds, the write call raises ENOSPC).
        # This pins the bug where a double os.close masked the real error as EBADF.
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        with open(cache_path, "r") as f:
            original_content = f.read()
        self.assertEqual(original_content, json_data)

        real_fdopen = os.fdopen

        def fdopen_with_failing_write(fd, *args, **kwargs):
            cache_file = real_fdopen(fd, *args, **kwargs)
            cache_file.write = MagicMock(
                side_effect=OSError(errno.ENOSPC, "No space left on device")
            )
            return cache_file

        new_json = self.random_encoded_data()
        with patch("os.fdopen", side_effect=fdopen_with_failing_write):
            with self.assertRaises(OSError) as ctx:
                self.aes_key_manager.cache_key_iv_locally(filter_name, new_json)

        self.assertEqual(ctx.exception.errno, errno.ENOSPC)

        with open(cache_path, "r") as f:
            recovered_content = f.read()
        self.assertEqual(recovered_content, json_data)
        json.loads(recovered_content)  # Verify it parses

        cache_dir = self.aes_key_manager.cache_dir
        tmp_files = [f for f in os.listdir(cache_dir) if f.endswith(".tmp")]
        self.assertEqual(
            len(tmp_files),
            0,
            f"Found unexpected .tmp files after write failure: {tmp_files}",
        )

    def test_no_tmp_file_remains_after_successful_write(self):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)

        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        cache_dir = self.aes_key_manager.cache_dir
        tmp_files = [f for f in os.listdir(cache_dir) if f.endswith(".tmp")]
        self.assertEqual(len(tmp_files), 0, f"Found unexpected .tmp files: {tmp_files}")

    def test_no_tmp_file_remains_after_failed_write(self):
        filter_name = secrets.token_hex(8)
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        json_data = self.random_encoded_data()

        # Pre-populate the cache
        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        # Fail the write by patching os.replace
        with patch("os.replace", side_effect=OSError("Simulated failure")):
            with self.assertRaises(OSError):
                self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        # No .tmp file should remain
        cache_dir = self.aes_key_manager.cache_dir
        tmp_files = [f for f in os.listdir(cache_dir) if f.endswith(".tmp")]
        self.assertEqual(
            len(tmp_files), 0, f"Found unexpected .tmp files after failure: {tmp_files}"
        )

    def test_cache_mode_0600_after_rewrite_over_0644_file(self):
        json_data = self.random_encoded_data()
        filter_name = secrets.token_hex(8)
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)

        # Create a pre-existing file with looser permissions
        existing_fd = os.open(cache_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(existing_fd, "w") as cache_file:
            cache_file.write("stale-data")
        os.chmod(cache_path, 0o644)
        self.assertEqual(oct(os.stat(cache_path).st_mode & 0o777), "0o644")

        # Rewrite the cache
        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        # The file should now have mode 0o600
        self.assertEqual(oct(os.stat(cache_path).st_mode & 0o777), "0o600")

    def test_corrupt_cache_cache_only_raises_with_path_and_recovery(self):
        # Test that a corrupt cache file raises AesKeyError naming the path and recovery command.
        filter_name = secrets.token_hex(8)
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)

        # Write a corrupt cache file (not valid JSON)
        with open(cache_path, "w") as f:
            f.write("not valid json{")
        os.chmod(cache_path, 0o600)

        # Call retrieve_key_and_iv(cache_only=True) to test the error message.
        # The better message lives in retrieve_key_and_iv's cache read path, not
        # in load_key_iv_from_cache, because load_key_iv_from_cache's contract
        # (raising on corruption) is what lets pull-aes-key treat a corrupt cache as absent.
        with self.assertRaises(AesKeyError) as context:
            self.aes_key_manager.retrieve_key_and_iv(filter_name, cache_only=True)

        error_msg = str(context.exception)
        self.assertIn(cache_path, error_msg)
        self.assertIn("pull-aes-key", error_msg)
        self.assertIn(filter_name, error_msg)

    def test_absent_cache_still_returns_none(self):
        # Regression guard: load_key_iv_from_cache must keep returning None
        # when no cache file exists, which is load-bearing for every cache-first caller.
        filter_name = secrets.token_hex(8)
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)

        # Ensure no cache file exists
        self.assertFalse(os.path.exists(cache_path))

        result = self.aes_key_manager.load_key_iv_from_cache(filter_name)

        self.assertIsNone(result)

    def test_concurrent_writers_do_not_destroy_each_others_temp_file(self):
        # Concurrent writers with unique temp names cannot destroy each other.
        # Simulate by patching os.replace to run a nested cache write before proceeding.
        filter_name = secrets.token_hex(8)
        json_data_1 = self.random_encoded_data()
        json_data_2 = self.random_encoded_data()

        call_count = [0]

        original_replace = os.replace

        def patched_replace(src, dst):
            call_count[0] += 1
            # On the first call to os.replace, simulate a second writer
            # by running a complete nested cache_key_iv_locally with different data.
            if call_count[0] == 1:
                self.aes_key_manager.cache_key_iv_locally(filter_name, json_data_2)
            # Then proceed with the original replace
            return original_replace(src, dst)

        with patch("os.replace", side_effect=patched_replace):
            # First write is in progress; during its os.replace, the second write happens.
            self.aes_key_manager.cache_key_iv_locally(filter_name, json_data_1)

        # Both writes completed without raising.
        # The final cache content is either data_1 or data_2 (last-writer-wins is acceptable).
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        with open(cache_path, "r") as f:
            final_content = f.read()
        final_data = json.loads(final_content)
        # Verify it's one of the two expected payloads
        payload_1 = json.loads(json_data_1)
        payload_2 = json.loads(json_data_2)
        self.assertTrue(
            final_data == payload_1 or final_data == payload_2,
            "Final cache content is neither expected payload",
        )

        # No .tmp file should remain
        cache_dir = self.aes_key_manager.cache_dir
        tmp_files = [f for f in os.listdir(cache_dir) if f.endswith(".tmp")]
        self.assertEqual(len(tmp_files), 0, f"Found unexpected .tmp files: {tmp_files}")

    def test_stale_tmp_file_does_not_block_a_write(self):
        # A stale .tmp file left by a crashed process doesn't prevent a new write.
        filter_name = secrets.token_hex(8)
        json_data = self.random_encoded_data()
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        cache_dir = os.path.dirname(cache_path)

        # Drop a stale .tmp file by hand
        stale_tmp_path = os.path.join(cache_dir, "stale_leftover.tmp")
        with open(stale_tmp_path, "w") as f:
            f.write("stale data from a crash")

        # Verify the stale file exists
        self.assertTrue(os.path.exists(stale_tmp_path))

        # Now write fresh data - this should succeed despite the stale .tmp
        self.aes_key_manager.cache_key_iv_locally(filter_name, json_data)

        # Verify the write succeeded
        cache_path = self.aes_key_manager._cache_path(filter_name=filter_name)
        with open(cache_path, "r") as f:
            cached_content = f.read()
        cached_data = json.loads(cached_content)
        expected_data = json.loads(json_data)
        self.assertEqual(cached_data, expected_data)

        # The stale .tmp is not this call's responsibility, but it exists and
        # doesn't interfere. Just verify it's still there (no cleanup expected).
        self.assertTrue(os.path.exists(stale_tmp_path))


class TestAesKeyManagerScheme(unittest.TestCase):
    """Tests for scheme-aware key blob methods: setup(scheme), get_scheme, set_scheme."""

    @patch("git_secret_protector.crypto.aes_key_manager.get_settings")
    @patch("git_secret_protector.crypto.aes_key_manager.StorageManagerFactory.create")
    def setUp(self, mock_create, mock_get_settings):
        self.mock_settings = MagicMock()
        self.mock_temp_dir = tempfile.TemporaryDirectory()
        self.mock_settings.cache_dir = self.mock_temp_dir.name
        self.mock_settings.module_name = secrets.token_hex(8)
        self.mock_settings.storage_type = StorageType.AWS_SSM

        mock_get_settings.return_value = self.mock_settings

        self.mock_storage_manager = MagicMock()
        mock_create.return_value = self.mock_storage_manager

        self.aes_key_manager = AesKeyManager()
        # Give the manager a pre-wired storage manager so _get_storage_manager() returns it
        self.aes_key_manager.storage_manager = self.mock_storage_manager

    def _make_blob(self, version=2):
        aes_key = base64.b64encode(secrets.token_bytes(32)).decode("utf-8")
        iv = base64.b64encode(secrets.token_bytes(16)).decode("utf-8")
        data = {"aes_key": aes_key, "iv": iv}
        if version is not None:
            data["version"] = version
        return data

    # ------------------------------------------------------------------
    # setup_aes_key_and_iv scheme tests
    # ------------------------------------------------------------------

    def test_setup_default_scheme_writes_version_2(self):
        filter_name = secrets.token_hex(8)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.exists.return_value = False

        self.aes_key_manager.setup_aes_key_and_iv(filter_name)

        self.mock_storage_manager.store.assert_called_once()
        stored_json = self.mock_storage_manager.store.call_args[0][1]
        data = json.loads(stored_json)
        self.assertEqual(data["version"], 2)

    def test_setup_v1_scheme_writes_version_1(self):
        filter_name = secrets.token_hex(8)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.exists.return_value = False

        self.aes_key_manager.setup_aes_key_and_iv(filter_name, scheme="v1")

        stored_json = self.mock_storage_manager.store.call_args[0][1]
        data = json.loads(stored_json)
        self.assertEqual(data["version"], 1)

    def test_setup_v2_scheme_writes_version_2(self):
        filter_name = secrets.token_hex(8)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.exists.return_value = False

        self.aes_key_manager.setup_aes_key_and_iv(filter_name, scheme="v2")

        stored_json = self.mock_storage_manager.store.call_args[0][1]
        data = json.loads(stored_json)
        self.assertEqual(data["version"], 2)

    # ------------------------------------------------------------------
    # get_scheme tests
    # ------------------------------------------------------------------

    def test_get_scheme_version_1_returns_v1(self):
        filter_name = secrets.token_hex(8)
        blob = self._make_blob(version=1)
        # Write to cache so load_key_iv_from_cache finds it
        self.aes_key_manager.cache_key_iv_locally(filter_name, json.dumps(blob))

        result = self.aes_key_manager.get_scheme(filter_name)

        self.assertEqual(result, "v1")

    def test_get_scheme_version_2_returns_v2(self):
        filter_name = secrets.token_hex(8)
        blob = self._make_blob(version=2)
        self.aes_key_manager.cache_key_iv_locally(filter_name, json.dumps(blob))

        result = self.aes_key_manager.get_scheme(filter_name)

        self.assertEqual(result, "v2")

    def test_get_scheme_version_absent_defaults_v1(self):
        filter_name = secrets.token_hex(8)
        blob = self._make_blob(version=None)  # no "version" key
        self.aes_key_manager.cache_key_iv_locally(filter_name, json.dumps(blob))

        result = self.aes_key_manager.get_scheme(filter_name)

        self.assertEqual(result, "v1")

    def test_get_scheme_info_reports_version_present(self):
        filter_name = secrets.token_hex(8)
        blob = self._make_blob(version=2)
        self.aes_key_manager.cache_key_iv_locally(filter_name, json.dumps(blob))

        result = self.aes_key_manager.get_scheme_info(filter_name)

        self.assertEqual(result, ("v2", True))

    def test_get_scheme_info_reports_version_absent(self):
        filter_name = secrets.token_hex(8)
        blob = self._make_blob(version=None)
        self.aes_key_manager.cache_key_iv_locally(filter_name, json.dumps(blob))

        result = self.aes_key_manager.get_scheme_info(filter_name)

        self.assertEqual(result, ("v1", False))

    def test_get_scheme_newer_version_fails_closed(self):
        filter_name = secrets.token_hex(8)
        blob = self._make_blob(version=4)  # newer than this client supports
        self.aes_key_manager.cache_key_iv_locally(filter_name, json.dumps(blob))

        with self.assertRaisesRegex(
            UnsupportedFormatError, "newer than this client supports"
        ):
            self.aes_key_manager.get_scheme(filter_name)

    def test_get_scheme_cache_miss_falls_back_to_backend(self):
        filter_name = secrets.token_hex(8)
        blob = self._make_blob(version=1)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.retrieve.return_value = json.dumps(blob)

        result = self.aes_key_manager.get_scheme(filter_name)

        self.mock_storage_manager.retrieve.assert_called_once()
        self.assertEqual(result, "v1")

    # ------------------------------------------------------------------
    # set_scheme tests
    # ------------------------------------------------------------------

    def test_set_scheme_v2_rewrites_version_preserving_key_iv(self):
        filter_name = secrets.token_hex(8)
        original_blob = self._make_blob(version=1)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.retrieve.return_value = json.dumps(original_blob)

        self.aes_key_manager.set_scheme(filter_name, "v2")

        # Backend store called with version 2
        self.mock_storage_manager.store.assert_called_once()
        stored_json = self.mock_storage_manager.store.call_args[0][1]
        stored = json.loads(stored_json)
        self.assertEqual(stored["version"], 2)
        self.assertEqual(stored["aes_key"], original_blob["aes_key"])
        self.assertEqual(stored["iv"], original_blob["iv"])

    def test_set_scheme_v1_rewrites_version(self):
        filter_name = secrets.token_hex(8)
        original_blob = self._make_blob(version=2)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.retrieve.return_value = json.dumps(original_blob)

        self.aes_key_manager.set_scheme(filter_name, "v1")

        stored_json = self.mock_storage_manager.store.call_args[0][1]
        self.assertEqual(json.loads(stored_json)["version"], 1)

    def test_set_scheme_v1_writes_version_1(self):
        """set_scheme('v1') stores version 1 in backend (locks the mapping)."""
        filter_name = secrets.token_hex(8)
        original_blob = self._make_blob(version=2)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.retrieve.return_value = json.dumps(original_blob)

        self.aes_key_manager.set_scheme(filter_name, "v1")

        stored_json = self.mock_storage_manager.store.call_args[0][1]
        self.assertEqual(json.loads(stored_json)["version"], 1)

    def test_set_scheme_v2_writes_version_2(self):
        """set_scheme('v2') stores version 2 in backend (locks the mapping)."""
        filter_name = secrets.token_hex(8)
        original_blob = self._make_blob(version=1)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.retrieve.return_value = json.dumps(original_blob)

        self.aes_key_manager.set_scheme(filter_name, "v2")

        stored_json = self.mock_storage_manager.store.call_args[0][1]
        self.assertEqual(json.loads(stored_json)["version"], 2)

    def test_set_scheme_unknown_defaults_to_v2(self):
        """set_scheme with an unrecognised string defaults to version 2 (safe default)."""
        filter_name = secrets.token_hex(8)
        original_blob = self._make_blob(version=1)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.retrieve.return_value = json.dumps(original_blob)

        self.aes_key_manager.set_scheme(filter_name, "unknown")

        stored_json = self.mock_storage_manager.store.call_args[0][1]
        self.assertEqual(json.loads(stored_json)["version"], 2)

    def test_set_scheme_updates_local_cache(self):
        filter_name = secrets.token_hex(8)
        original_blob = self._make_blob(version=1)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.retrieve.return_value = json.dumps(original_blob)

        self.aes_key_manager.set_scheme(filter_name, "v2")

        # Cache should now reflect version 2
        cached = self.aes_key_manager.load_key_iv_from_cache(filter_name)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["version"], 2)

    # ------------------------------------------------------------------
    # replace_key_and_iv tests (key rotation path)
    # ------------------------------------------------------------------

    def test_replace_key_and_iv_overwrites_an_existing_parameter(self):
        filter_name = secrets.token_hex(8)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.exists.return_value = True

        self.aes_key_manager.replace_key_and_iv(filter_name)

        # Should not raise; should store exactly once
        self.mock_storage_manager.store.assert_called_once()

        # Cache should have the new key with version 2
        cached = self.aes_key_manager.load_key_iv_from_cache(filter_name)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["version"], 2)

    def test_replace_key_and_iv_never_consults_parameter_exists(self):
        filter_name = secrets.token_hex(8)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.exists.return_value = True

        self.aes_key_manager.replace_key_and_iv(filter_name)

        # Should never call exists
        self.mock_storage_manager.exists.assert_not_called()

    def test_setup_aes_key_and_iv_still_refuses_an_existing_parameter(self):
        filter_name = secrets.token_hex(8)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.exists.return_value = True

        with self.assertRaises(AesKeyError):
            self.aes_key_manager.setup_aes_key_and_iv(filter_name)

        # Should not have called store
        self.mock_storage_manager.store.assert_not_called()

    def test_replace_key_and_iv_stores_the_given_key_material(self):
        """Rotation re-encrypts files under this exact material before calling
        here - the backend must be given the SAME bytes, never a fresh pair it
        never used."""
        filter_name = secrets.token_hex(8)
        self.mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"
        self.mock_storage_manager.exists.return_value = True

        given_key = secrets.token_bytes(32)
        given_iv = secrets.token_bytes(16)

        self.aes_key_manager.replace_key_and_iv(
            filter_name, aes_key=given_key, iv=given_iv
        )

        stored_name, stored_json = self.mock_storage_manager.store.call_args[0]
        stored_data = json.loads(stored_json)
        self.assertEqual(base64.b64decode(stored_data["aes_key"]), given_key)
        self.assertEqual(base64.b64decode(stored_data["iv"]), given_iv)


if __name__ == "__main__":
    unittest.main()
