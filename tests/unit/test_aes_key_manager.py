import base64
import json
import os
import secrets
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from botocore.exceptions import ClientError

from git_secret_protector.core.settings import StorageType
from git_secret_protector.crypto.aes_key_manager import AesKeyManager


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

    def test_get_scheme_version_absent_defaults_v2(self):
        filter_name = secrets.token_hex(8)
        blob = self._make_blob(version=None)  # no "version" key
        self.aes_key_manager.cache_key_iv_locally(filter_name, json.dumps(blob))

        result = self.aes_key_manager.get_scheme(filter_name)

        self.assertEqual(result, "v2")

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


if __name__ == "__main__":
    unittest.main()
