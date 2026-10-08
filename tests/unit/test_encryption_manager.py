import base64
import configparser
import contextlib
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler
from git_secret_protector.crypto.aes_key_manager import AesKeyManager
from git_secret_protector.main import show_project_version
from git_secret_protector.error.aes_key_error import AesKeyError
from git_secret_protector.error.unsupported_format_error import UnsupportedFormatError
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
        mock_settings.storage_type.value = "AWS_SSM"
        mock_settings.module_name = "git-secret-protector"
        mock_settings.base_dir = "/repo/root"
        mock_settings.encryption_scheme = "v2"
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def test_setup_aes_key_uses_config_default_when_no_flag(self, mock_gs):
        mock_gs.return_value.encryption_scheme = "v1"

        self.manager.setup_aes_key("myfilter")  # no --scheme flag

        _, kwargs = self.key_manager.setup_aes_key_and_iv.call_args
        self.assertEqual(kwargs.get("scheme"), "v1")

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def test_setup_aes_key_flag_overrides_config_default(self, mock_gs):
        mock_gs.return_value.encryption_scheme = "v2"

        self.manager.setup_aes_key("myfilter", scheme="v1")

        _, kwargs = self.key_manager.setup_aes_key_and_iv.call_args
        self.assertEqual(kwargs.get("scheme"), "v1")

    def test_guarded_methods_require_filter_and_list_available_filters(self):
        self.git_attributes_parser.get_filter_names.return_value = ["a", "b"]
        methods = [
            ("setup_aes_key", lambda: self.manager.setup_aes_key("")),
            ("pull_aes_key", lambda: self.manager.pull_aes_key(None)),
            ("encrypt_files", lambda: self.manager.encrypt_files("")),
            ("decrypt_files", lambda: self.manager.decrypt_files(None)),
            ("rotate_keys", lambda: self.manager.rotate_keys("", assume_yes=True)),
            ("clean_filter", lambda: self.manager.clean_filter(None)),
        ]

        for name, invoke in methods:
            with self.subTest(method=name):
                stdout = io.StringIO()
                stderr = io.StringIO()

                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                    stderr
                ):
                    with self.assertRaises(SystemExit) as context:
                        invoke()

                self.assertEqual(context.exception.code, 1)
                self.assertIn("Available filters: a, b", stderr.getvalue())
                self.assertEqual(stdout.getvalue(), "")

        self.key_manager.setup_aes_key_and_iv.assert_not_called()
        self.key_manager.retrieve_key_and_iv.assert_not_called()
        self.key_manager.remove_key_iv_from_cache.assert_not_called()
        self.key_rotator.rotate_key.assert_not_called()

    def test_require_filter_handles_missing_gitattributes_without_traceback(self):
        self.git_attributes_parser.get_filter_names.side_effect = FileNotFoundError(
            "missing"
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as context:
                self.manager.pull_aes_key(None)

        self.assertEqual(context.exception.code, 1)
        self.assertIn("No filters defined", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")
        self.key_manager.retrieve_key_and_iv.assert_not_called()

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
        ) as mock_get_handler:
            with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
                self.manager.encrypt_stdin("secrets.env")

        self.assertEqual(stdout_buffer.getvalue(), b"ciphertext")
        mock_get_handler.assert_called_once_with(filter_name="secret", cache_only=True)

    def test_pull_aes_key_exits_non_zero_when_retrieve_raises(self):
        self.key_manager.retrieve_key_and_iv.side_effect = RuntimeError("boom")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as context:
                self.manager.pull_aes_key("secret")

        self.assertEqual(context.exception.code, 1)
        self.assertNotIn("Pull AES key command failed", stdout.getvalue())
        self.assertIn("Pull AES key command failed: boom", stderr.getvalue())

    @patch("git_secret_protector.crypto.aes_key_manager.get_settings")
    @patch("git_secret_protector.crypto.aes_key_manager.StorageManagerFactory.create")
    def test_pull_aes_key_on_stale_cache_updates_cache_and_reports_scheme(
        self, mock_create, mock_get_settings
    ):
        # Command-level case a user actually hits: a stale local cache must end
        # up carrying the backend's version field, and the JSON envelope must
        # report the scheme the pulled blob declares.
        from git_secret_protector.core.output import Output

        filter_name = "secret"
        key_settings = MagicMock()
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        key_settings.cache_dir = temp_dir.name
        key_settings.module_name = "git-secret-protector"
        key_settings.storage_type = MagicMock(value="AWS_SSM")
        mock_get_settings.return_value = key_settings

        mock_storage_manager = MagicMock()
        mock_create.return_value = mock_storage_manager
        mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"

        real_key_manager = AesKeyManager()
        stale_blob = {
            "aes_key": base64.b64encode(secrets.token_bytes(32)).decode("utf-8"),
            "iv": base64.b64encode(secrets.token_bytes(16)).decode("utf-8"),
            "version": 1,
        }
        real_key_manager.cache_key_iv_locally(filter_name, json.dumps(stale_blob))

        backend_blob = {
            "aes_key": base64.b64encode(secrets.token_bytes(32)).decode("utf-8"),
            "iv": base64.b64encode(secrets.token_bytes(16)).decode("utf-8"),
            "version": 2,
        }
        mock_storage_manager.retrieve.return_value = json.dumps(backend_blob)

        self.manager.key_manager = real_key_manager
        self.manager.output = Output(json=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.manager.pull_aes_key(filter_name)

        cached = real_key_manager.load_key_iv_from_cache(filter_name)
        self.assertEqual(cached["version"], 2)

        payload = json.loads(out.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scheme"], "v2")
        self.assertTrue(payload["changed"])

    def test_encrypt_files_failure_prints_to_stderr_only(self):
        self.git_attributes_parser.get_files_for_filter.side_effect = RuntimeError(
            "boom"
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as context:
                self.manager.encrypt_files("secret")

        self.assertEqual(context.exception.code, 1)
        self.assertNotIn("Encrypt files command failed", stdout.getvalue())
        self.assertIn("Encrypt files command failed: boom", stderr.getvalue())

    def test_status_failure_prints_to_stderr_only(self):
        self.git_attributes_parser.get_filter_names.side_effect = RuntimeError("boom")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as context:
                self.manager.status()

        self.assertEqual(context.exception.code, 1)
        self.assertNotIn("Status command failed", stdout.getvalue())
        self.assertIn("Status command failed: boom", stderr.getvalue())

    @patch("git_secret_protector.services.encryption_manager.KeyRotator")
    @patch("builtins.input", return_value="n")
    def test_rotate_keys_returns_on_negative_confirmation(
        self, mock_input, mock_key_rotator
    ):
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            self.manager.rotate_keys("secret")

        mock_input.assert_called_once()
        mock_key_rotator.assert_not_called()
        self.assertIn("Aborted", stderr.getvalue())

    @patch("git_secret_protector.services.encryption_manager.KeyRotator")
    @patch("builtins.input", side_effect=EOFError)
    def test_rotate_keys_aborts_cleanly_on_eof(self, mock_input, mock_key_rotator):
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            # No SystemExit: EOF (piped/CI stdin) is a decline, not a crash.
            self.manager.rotate_keys("secret")

        mock_input.assert_called_once()
        mock_key_rotator.assert_not_called()
        self.assertIn("Aborted", stderr.getvalue())
        self.assertNotIn("Rotate keys command failed", stderr.getvalue())

    @patch("git_secret_protector.services.encryption_manager.KeyRotator")
    @patch("builtins.input", return_value="y")
    def test_rotate_keys_proceeds_on_positive_confirmation(
        self, mock_input, mock_key_rotator
    ):
        rotator = mock_key_rotator.return_value

        self.manager.rotate_keys("secret")

        mock_input.assert_called_once()
        rotator.rotate_key.assert_called_once_with("secret")

    @patch("git_secret_protector.services.encryption_manager.KeyRotator")
    @patch("builtins.input", side_effect=AssertionError("input should not be called"))
    def test_rotate_keys_assume_yes_skips_confirmation(
        self, mock_input, mock_key_rotator
    ):
        rotator = mock_key_rotator.return_value

        self.manager.rotate_keys("secret", assume_yes=True)

        mock_input.assert_not_called()
        rotator.rotate_key.assert_called_once_with("secret")

    def test_status_json_schema(self):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = [
            "enc.txt",
            "plain.txt",
        ]
        self.key_manager.get_scheme.return_value = "v2"
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch.object(
            self.manager, "_EncryptionManager__is_encrypted", side_effect=[True, False]
        ):
            with contextlib.redirect_stdout(out):
                self.manager.status()
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["backend"], "AWS_SSM")
        self.assertEqual(payload["filters"][0]["name"], "secret")
        self.assertEqual(
            payload["filters"][0]["files"],
            [
                {"path": "enc.txt", "encrypted": True},
                {"path": "plain.txt", "encrypted": False},
            ],
        )

    def test_status_human_text_unchanged(self):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = [
            "enc.txt",
            "plain.txt",
        ]
        out = io.StringIO()
        with patch.object(
            self.manager, "_EncryptionManager__is_encrypted", side_effect=[True, False]
        ):
            with contextlib.redirect_stdout(out):
                self.manager.status()
        self.assertIn("  enc.txt: Encrypted", out.getvalue())
        self.assertIn("  plain.txt: ⚠ PLAINTEXT", out.getvalue())

    def test_status_marks_plaintext_files(self):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = [
            "enc.txt",
            "plain.txt",
        ]
        stdout = io.StringIO()

        with patch.object(
            self.manager,
            "_EncryptionManager__is_encrypted",
            side_effect=[True, False],
        ):
            with contextlib.redirect_stdout(stdout):
                self.manager.status()

        output = stdout.getvalue()
        self.assertIn("  enc.txt: Encrypted", output)
        self.assertIn("  plain.txt: ⚠ PLAINTEXT", output)

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_returns_zero_when_all_checks_are_green(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        stdout = io.StringIO()

        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            MagicMock(stdout="git-secret-protector decrypt %f\n"),
        ]

        with patch("os.path.exists", return_value=True):
            with patch.object(
                self.manager,
                "_EncryptionManager__is_encrypted",
                return_value=True,
            ):
                with contextlib.redirect_stdout(stdout):
                    result = self.manager.doctor()

        self.assertEqual(result, 0)
        self.assertIn("[ OK ]", stdout.getvalue())

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_returns_one_when_plaintext_secret_file_detected(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        stdout = io.StringIO()

        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            # git show HEAD:<path> succeeds and returns plaintext - the file
            # was committed unencrypted, a real leak.
            MagicMock(returncode=0, stdout=b"plaintext-committed-content"),
        ]

        with patch("os.path.exists", return_value=True):
            with patch.object(
                self.manager,
                "_EncryptionManager__is_encrypted",
                return_value=False,
            ):
                with contextlib.redirect_stdout(stdout):
                    result = self.manager.doctor()

        self.assertEqual(result, 1)
        self.assertIn("[FAIL]", stdout.getvalue())
        self.assertIn("PLAINTEXT", stdout.getvalue())

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_ok_when_disk_plaintext_but_head_ciphertext(self, mock_run):
        # The normal smudged state: plaintext on disk, ciphertext committed.
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        stdout = io.StringIO()

        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            MagicMock(
                returncode=0, stdout=self.manager.magic_header + b"ciphertext-body"
            ),
        ]

        with patch("os.path.exists", return_value=True):
            with patch.object(
                self.manager,
                "_EncryptionManager__is_encrypted",
                return_value=False,
            ):
                with contextlib.redirect_stdout(stdout):
                    result = self.manager.doctor()

        self.assertEqual(result, 0)
        self.assertNotIn("[FAIL]", stdout.getvalue())

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_warns_when_plaintext_file_not_yet_committed(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        stdout = io.StringIO()

        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            # git show fails: path is not in HEAD yet.
            MagicMock(returncode=128, stdout=b""),
        ]

        with patch("os.path.exists", return_value=True):
            with patch.object(
                self.manager,
                "_EncryptionManager__is_encrypted",
                return_value=False,
            ):
                with contextlib.redirect_stdout(stdout):
                    result = self.manager.doctor()

        self.assertEqual(result, 0)
        self.assertIn("[WARN]", stdout.getvalue())
        self.assertNotIn("[FAIL]", stdout.getvalue())

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_survives_missing_head_without_crashing(self, mock_run):
        # A repo with no commits at all: git show raises rather than
        # returning a non-zero exit on some platforms - either way, no crash.
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        stdout = io.StringIO()

        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            OSError("no such repository"),
        ]

        with patch("os.path.exists", return_value=True):
            with patch.object(
                self.manager,
                "_EncryptionManager__is_encrypted",
                return_value=False,
            ):
                with contextlib.redirect_stdout(stdout):
                    result = self.manager.doctor()

        self.assertEqual(result, 0)
        self.assertIn("[WARN]", stdout.getvalue())

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_plaintext_scan_never_prints_file_content(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        stdout = io.StringIO()

        leaked_marker = b"super-secret-committed-value-should-never-print"
        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            MagicMock(returncode=0, stdout=leaked_marker),
        ]

        with patch("os.path.exists", return_value=True):
            with patch.object(
                self.manager,
                "_EncryptionManager__is_encrypted",
                return_value=False,
            ):
                with contextlib.redirect_stdout(stdout):
                    self.manager.doctor()

        self.assertNotIn(leaked_marker.decode(), stdout.getvalue())

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_warns_on_offline_backend_without_failing(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.side_effect = RuntimeError("offline")
        stdout = io.StringIO()

        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            MagicMock(stdout="git-secret-protector decrypt %f\n"),
        ]

        with patch("os.path.exists", return_value=True):
            with patch.object(
                self.manager,
                "_EncryptionManager__is_encrypted",
                return_value=True,
            ):
                with contextlib.redirect_stdout(stdout):
                    result = self.manager.doctor()

        self.assertEqual(result, 0)
        self.assertIn("[WARN] backend", stdout.getvalue())

    def test_doctor_warns_when_gitattributes_missing_and_skips_per_filter_checks(self):
        self.git_attributes_parser.get_filter_names.side_effect = FileNotFoundError(
            "missing"
        )
        stdout = io.StringIO()

        with patch("os.path.exists", return_value=True):
            with contextlib.redirect_stdout(stdout):
                result = self.manager.doctor()

        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("[WARN] no filters defined in .gitattributes", output)
        self.assertNotIn(".git/config", output)
        self.key_manager.is_cached.assert_not_called()
        self.key_manager.resolve_parameter_name.assert_not_called()

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def test_status_prints_local_namespace_header_without_resolving_storage_path(
        self, mock_get_settings
    ):
        mock_settings = MagicMock()
        mock_settings.storage_type.value = "AWS_SSM"
        mock_settings.module_name = "git-secret-protector"
        mock_settings.base_dir = "/repo/root"
        mock_get_settings.return_value = mock_settings
        self.git_attributes_parser.get_filter_names.return_value = []
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.manager.status()

        self.key_manager.resolve_parameter_name.assert_not_called()
        output = stderr.getvalue()
        self.assertIn("Backend:   AWS_SSM", output)
        self.assertIn("Module:    git-secret-protector", output)
        self.assertIn("Repo root: /repo/root", output)

    def test_decrypt_stdin_exits_and_writes_nothing_on_generic_error(self):
        self.git_attributes_parser.get_filter_name_for_file.return_value = "secret"
        encrypted_data = b"ciphertext"
        stdout_buffer = io.BytesIO()
        stdin = SimpleNamespace(buffer=io.BytesIO(encrypted_data))
        stdout = SimpleNamespace(buffer=stdout_buffer)

        with patch.object(
            self.manager,
            "_EncryptionManager__get_encryption_handler",
            side_effect=RuntimeError("boom"),
        ):
            with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
                with self.assertRaises(SystemExit) as ctx:
                    self.manager.decrypt_stdin("secrets.env")

        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(stdout_buffer.getvalue(), b"")

    def test_decrypt_stdin_exits_and_prints_hint_on_cache_miss(self):
        # AesKeyError carries the actionable 'run pull-aes-key' recovery hint - it
        # must still reach stderr verbatim on the fail-closed path.
        self.git_attributes_parser.get_filter_name_for_file.return_value = "secret"
        encrypted_data = b"ciphertext"
        stdout_buffer = io.BytesIO()
        stdin = SimpleNamespace(buffer=io.BytesIO(encrypted_data))
        stdout = SimpleNamespace(buffer=stdout_buffer)
        stderr = io.StringIO()
        hint = "no cached key. Run: git-secret-protector pull-aes-key secret"

        with patch.object(
            self.manager,
            "_EncryptionManager__get_encryption_handler",
            side_effect=AesKeyError(hint),
        ):
            with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as ctx:
                        self.manager.decrypt_stdin("secrets.env")

        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(stdout_buffer.getvalue(), b"")
        self.assertIn(hint, stderr.getvalue())

    def test_decrypt_stdin_exits_and_writes_nothing_on_unsupported_format(self):
        # An unknown/newer wire or key format must fail closed: exit non-zero and NOT
        # pass the ciphertext through as if it were the file's content.
        self.git_attributes_parser.get_filter_name_for_file.return_value = "secret"
        encrypted_data = b"\x03unknown-format"
        stdout_buffer = io.BytesIO()
        stdin = SimpleNamespace(buffer=io.BytesIO(encrypted_data))
        stdout = SimpleNamespace(buffer=stdout_buffer)

        with patch.object(
            self.manager,
            "_EncryptionManager__get_encryption_handler",
            side_effect=UnsupportedFormatError("encrypted by a newer client"),
        ):
            with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
                with self.assertRaises(SystemExit) as ctx:
                    self.manager.decrypt_stdin("secrets.env")

        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(stdout_buffer.getvalue(), b"")  # no ciphertext-through

    def test_encrypt_stdin_cache_miss_uses_cache_only_lookup(self):
        self.git_attributes_parser.get_filter_name_for_file.return_value = "secret"
        stdout_buffer = io.BytesIO()
        stdin = SimpleNamespace(buffer=io.BytesIO(b"plain-secret"))
        stdout = SimpleNamespace(buffer=stdout_buffer)
        self.key_manager.retrieve_key_and_iv.side_effect = RuntimeError("cache miss")

        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            with self.assertRaises(SystemExit):
                self.manager.encrypt_stdin("secrets.env")

        self.key_manager.retrieve_key_and_iv.assert_called_once_with(
            "secret", cache_only=True
        )
        self.key_manager.get_scheme.assert_not_called()
        self.assertEqual(stdout_buffer.getvalue(), b"")

    def test_decrypt_stdin_cache_miss_uses_cache_only_lookup(self):
        self.git_attributes_parser.get_filter_name_for_file.return_value = "secret"
        encrypted_data = b"ciphertext"
        stdout_buffer = io.BytesIO()
        stdin = SimpleNamespace(buffer=io.BytesIO(encrypted_data))
        stdout = SimpleNamespace(buffer=stdout_buffer)
        self.key_manager.retrieve_key_and_iv.side_effect = RuntimeError("cache miss")

        with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
            with self.assertRaises(SystemExit) as ctx:
                self.manager.decrypt_stdin("secrets.env")

        self.assertEqual(ctx.exception.code, 1)
        self.key_manager.retrieve_key_and_iv.assert_called_once_with(
            "secret", cache_only=True
        )
        self.key_manager.get_scheme.assert_not_called()
        self.assertEqual(stdout_buffer.getvalue(), b"")

    def test_encrypt_stdin_cache_miss_prints_hint_to_stderr(self):
        self.git_attributes_parser.get_filter_name_for_file.return_value = "secret"
        stdin = SimpleNamespace(buffer=io.BytesIO(b"plain-secret"))
        stdout = SimpleNamespace(buffer=io.BytesIO())
        stderr = io.StringIO()
        self.key_manager.retrieve_key_and_iv.side_effect = RuntimeError(
            "AES key for filter 'secret' is not cached locally. "
            "Run: git-secret-protector pull-aes-key secret"
        )

        with patch("sys.stdin", stdin), patch("sys.stdout", stdout), patch(
            "sys.stderr", stderr
        ):
            with self.assertRaises(SystemExit):
                self.manager.encrypt_stdin("secrets.env")

        self.assertIn("pull-aes-key", stderr.getvalue())

    def test_decrypt_stdin_cache_miss_prints_hint_to_stderr(self):
        self.git_attributes_parser.get_filter_name_for_file.return_value = "secret"
        stdin = SimpleNamespace(buffer=io.BytesIO(b"ciphertext"))
        stdout = SimpleNamespace(buffer=io.BytesIO())
        stderr = io.StringIO()
        self.key_manager.retrieve_key_and_iv.side_effect = RuntimeError(
            "AES key for filter 'secret' is not cached locally. "
            "Run: git-secret-protector pull-aes-key secret"
        )

        with patch("sys.stdin", stdin), patch("sys.stdout", stdout), patch(
            "sys.stderr", stderr
        ):
            with self.assertRaises(SystemExit):
                self.manager.decrypt_stdin("secrets.env")

        self.assertIn("pull-aes-key", stderr.getvalue())

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_setup_filters_sets_required_for_existing_filter(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            MagicMock(stdout="git-secret-protector decrypt %f\n"),
            MagicMock(returncode=1),
            MagicMock(),
        ]

        self.manager.setup_filters()

        self.assertEqual(
            mock_run.call_args_list[0].args[0],
            ["git", "config", "--get", "filter.secret.clean"],
        )
        self.assertEqual(
            mock_run.call_args_list[1].args[0],
            ["git", "config", "--get", "filter.secret.smudge"],
        )
        # Default (no --process): an already-configured filter gets a best-effort
        # `process` unset attempt (declarative config), never a `process` write.
        self.assertEqual(
            mock_run.call_args_list[2].args[0],
            ["git", "config", "--unset", "filter.secret.process"],
        )
        mock_run.assert_called_with(
            ["git", "config", "filter.secret.required", "true"],
            check=True,
        )

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_setup_filters_with_process_flag_writes_process_for_existing_filter(
        self, mock_run
    ):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            MagicMock(stdout="git-secret-protector decrypt %f\n"),
            MagicMock(),
            MagicMock(),
        ]

        self.manager.setup_filters(use_process=True)

        self.assertEqual(
            mock_run.call_args_list[2].args[0],
            [
                "git",
                "config",
                "filter.secret.process",
                "git-secret-protector filter-process secret",
            ],
        )
        mock_run.assert_called_with(
            ["git", "config", "filter.secret.required", "true"],
            check=True,
        )

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_setup_filters_default_unsets_preexisting_process(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            MagicMock(stdout="git-secret-protector decrypt %f\n"),
            MagicMock(returncode=0),
            MagicMock(),
        ]

        self.manager.setup_filters()

        self.assertEqual(
            mock_run.call_args_list[2].args[0],
            ["git", "config", "--unset", "filter.secret.process"],
        )
        # clean/smudge are never unset, only read.
        for call in mock_run.call_args_list:
            self.assertNotIn("--unset", call.args[0][:2])

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_setup_filters_default_writes_no_process_for_fresh_filter(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        mock_run.side_effect = [
            MagicMock(stdout=""),
            MagicMock(stdout=""),
            MagicMock(),
            MagicMock(),
            MagicMock(),
        ]

        self.manager.setup_filters()

        written_targets = [call.args[0][2] for call in mock_run.call_args_list[2:]]
        self.assertNotIn("filter.secret.process", written_targets)
        self.assertEqual(
            mock_run.call_args_list[-1].args[0],
            ["git", "config", "filter.secret.required", "true"],
        )

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_setup_filters_with_process_flag_writes_process_for_fresh_filter(
        self, mock_run
    ):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        mock_run.side_effect = [
            MagicMock(stdout=""),
            MagicMock(stdout=""),
            MagicMock(),
            MagicMock(),
            MagicMock(),
            MagicMock(),
        ]

        self.manager.setup_filters(use_process=True)

        self.assertEqual(
            mock_run.call_args_list[4].args[0],
            [
                "git",
                "config",
                "filter.secret.process",
                "git-secret-protector filter-process secret",
            ],
        )

    def test_cache_key_iv_locally_writes_owner_only_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "git_secret_protector.crypto.aes_key_manager.get_settings"
            ) as mock_get_settings:
                mock_settings = MagicMock()
                mock_settings.cache_dir = temp_dir
                mock_settings.module_name = "git-secret-protector"
                mock_get_settings.return_value = mock_settings

                manager = AesKeyManager()
                data = json.dumps({"aes_key": "a", "iv": "b"})

                manager.cache_key_iv_locally("secret", data)

                cache_path = os.path.join(temp_dir, "secret_key_iv.json")
                self.assertEqual(oct(os.stat(cache_path).st_mode & 0o777), "0o600")

    def test_setup_aes_key_json_envelope(self):
        from git_secret_protector.core.output import Output

        out = io.StringIO()
        self.manager.output = Output(json=True)
        with contextlib.redirect_stdout(out):
            self.manager.setup_aes_key("secret")
        payload = json.loads(out.getvalue())
        self.assertEqual(
            payload,
            {
                "ok": True,
                "command": "setup-aes-key",
                "filter": "secret",
                "scheme": "v2",  # built-in default when no --scheme/config
                "message": "Successfully set up AES key for filter: secret",
            },
        )

    def test_setup_aes_key_scheme_passed_to_key_manager(self):
        self.manager.setup_aes_key("secret", scheme="v1")
        self.key_manager.setup_aes_key_and_iv.assert_called_once_with(
            "secret", scheme="v1"
        )

    def test_setup_aes_key_v1_emits_warning_to_stderr(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.manager.setup_aes_key("secret", scheme="v1")
        err = stderr.getvalue()
        self.assertIn("WARNING", err)
        self.assertIn("v1", err)

    def test_setup_aes_key_v2_does_not_emit_warning(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.manager.setup_aes_key("secret", scheme="v2")
        self.assertNotIn("WARNING", stderr.getvalue())

    def test_setup_aes_key_v1_json_envelope_includes_scheme(self):
        from git_secret_protector.core.output import Output

        out = io.StringIO()
        self.manager.output = Output(json=True)
        with contextlib.redirect_stdout(out):
            self.manager.setup_aes_key("secret", scheme="v1")
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scheme"], "v1")

    def test_get_encryption_handler_uses_filter_scheme(self):
        self.key_manager.retrieve_key_and_iv.return_value = (b"\x00" * 32, b"\x00" * 16)
        self.key_manager.get_scheme.return_value = "v1"
        handler = self.manager._EncryptionManager__get_encryption_handler("secret")
        self.assertEqual(handler.scheme, "v1")

    def test_setup_aes_key_json_error_envelope_and_exit(self):
        from git_secret_protector.core.output import Output

        self.key_manager.setup_aes_key_and_iv.side_effect = RuntimeError("boom")
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                self.manager.setup_aes_key("secret")
        self.assertEqual(ctx.exception.code, 1)
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["command"], "setup-aes-key")
        self.assertIn("boom", payload["error"])

    def test_setup_aes_key_human_text_unchanged(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.manager.setup_aes_key("secret")
        self.assertIn("Successfully set up AES key for filter: secret", out.getvalue())

    def test_setup_filters_json_error_envelope_and_exit_when_parser_raises(self):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.side_effect = RuntimeError(
            "no attrs"
        )
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                self.manager.setup_filters()
        self.assertEqual(ctx.exception.code, 1)
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["command"], "setup-filters")
        self.assertIn("no attrs", payload["error"])

    def test_encrypt_files_progress_and_counts_json(self):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_files_for_filter.return_value = [
            "a.secret",
            "b.secret",
        ]
        out, err = io.StringIO(), io.StringIO()
        self.manager.output = Output(json=True)
        with patch.object(
            self.manager, "_EncryptionManager__get_encryption_handler"
        ) as h, patch.object(
            self.manager,
            "_EncryptionManager__is_encrypted",
            side_effect=[False, True],
        ):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.manager.encrypt_files("secret")
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["counts"], {"encrypted": 1, "skipped": 1, "total": 2})
        self.assertEqual(err.getvalue(), "")  # progress suppressed under json

    def test_encrypt_files_progress_to_stderr_in_normal(self):
        self.git_attributes_parser.get_files_for_filter.return_value = [
            "a.secret",
            "b.secret",
        ]
        err = io.StringIO()
        with patch.object(
            self.manager, "_EncryptionManager__get_encryption_handler"
        ), patch.object(
            self.manager,
            "_EncryptionManager__is_encrypted",
            return_value=False,
        ):
            with contextlib.redirect_stderr(err):
                self.manager.encrypt_files("secret")
        self.assertIn("[1/2] a.secret", err.getvalue())
        self.assertIn("[2/2] b.secret", err.getvalue())

    def test_clean_filter_no_nested_envelope(self):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_files_for_filter.return_value = ["a.secret"]
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch.object(
            self.manager, "_EncryptionManager__get_encryption_handler"
        ), patch.object(
            self.manager,
            "_EncryptionManager__is_encrypted",
            return_value=False,
        ):
            with contextlib.redirect_stdout(out):
                self.manager.clean_filter("secret")
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["command"], "clean-filter")  # not encrypt-files

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_json_schema_and_exit(self, mock_run):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        mock_run.side_effect = [
            MagicMock(stdout="x\n"),
            # git show HEAD:<path> returns plaintext - committed unencrypted.
            MagicMock(returncode=0, stdout=b"y\n"),
        ]
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch("os.path.exists", return_value=True), patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=False
        ):
            with contextlib.redirect_stdout(out):
                rc = self.manager.doctor()
        self.assertEqual(rc, 1)
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["exit_code"], 1)
        self.assertTrue(any(c["status"] == "fail" for c in payload["checks"]))
        supported = next(
            c for c in payload["checks"] if c["check"] == "supported_schemes"
        )
        self.assertIn("v1, v2", supported["detail"])

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_json_per_filter_checks_distinguishable_with_two_filters(
        self, mock_run
    ):
        # Two filters must each appear as `filter` key on every per-filter check so
        # a machine consumer can distinguish which filter each check belongs to.
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["alpha", "beta"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        # subprocess.run called twice per filter (clean + smudge) = 4 calls total
        mock_run.side_effect = [
            MagicMock(stdout="x\n"),
            MagicMock(stdout="y\n"),
            MagicMock(stdout="x\n"),
            MagicMock(stdout="y\n"),
        ]
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch("os.path.exists", return_value=True), patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                rc = self.manager.doctor()
        self.assertEqual(rc, 0)
        payload = json.loads(out.getvalue())
        per_filter_checks = [
            c
            for c in payload["checks"]
            if c.get("check") in ("git_config", "key_cache", "plaintext_scan")
        ]
        # Every per-filter check must carry a `filter` key
        for c in per_filter_checks:
            self.assertIn("filter", c, f"missing 'filter' key on check: {c}")
        # Both filter names must appear
        filter_values = {c["filter"] for c in per_filter_checks}
        self.assertIn("alpha", filter_values)
        self.assertIn("beta", filter_values)

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_human_text_unchanged(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
        out = io.StringIO()
        with patch("os.path.exists", return_value=True), patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                self.manager.doctor()
        text = out.getvalue()
        self.assertIn("[ OK ] filters declared: secret", text)
        self.assertIn("[ OK ] no unencrypted commits found for 'secret'", text)

    # ----- Task-6 tests: scheme surfaced in status and doctor -----

    def test_status_json_includes_scheme_field(self):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["enc.txt"]
        self.key_manager.get_scheme.return_value = "v1"
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                self.manager.status()
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["filters"][0]["scheme"], "v1")

    def test_status_human_includes_scheme_line_and_existing_lines_unchanged(self):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["enc.txt"]
        self.key_manager.get_scheme.return_value = "v1"
        out = io.StringIO()
        with patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                self.manager.status()
        text = out.getvalue()
        # additive: scheme line present
        self.assertIn("  scheme: v1", text)
        # existing lines byte-identical
        self.assertIn("Filter: secret", text)
        self.assertIn("  enc.txt: Encrypted", text)

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_json_scheme_check_v1_is_warn_with_filter_key(self, mock_run):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        self.key_manager.get_scheme_info.return_value = ("v1", True)
        mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch("os.path.exists", return_value=True), patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                rc = self.manager.doctor()
        self.assertEqual(rc, 0)  # warn does NOT change exit code
        payload = json.loads(out.getvalue())
        scheme_checks = [c for c in payload["checks"] if c.get("check") == "scheme"]
        self.assertEqual(len(scheme_checks), 1)
        sc = scheme_checks[0]
        self.assertEqual(sc["status"], "warn")
        self.assertIn("filter", sc)
        self.assertEqual(sc["filter"], "secret")
        self.assertIn("v1", sc["detail"])

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_json_scheme_check_unversioned_blob_is_warn(self, mock_run):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        # version_present=False: a legacy blob with no version field, silently v1.
        self.key_manager.get_scheme_info.return_value = ("v1", False)
        mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch("os.path.exists", return_value=True), patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                rc = self.manager.doctor()
        self.assertEqual(rc, 0)
        payload = json.loads(out.getvalue())
        scheme_checks = [c for c in payload["checks"] if c.get("check") == "scheme"]
        self.assertEqual(len(scheme_checks), 1)
        sc = scheme_checks[0]
        self.assertEqual(sc["status"], "warn")
        self.assertEqual(sc["filter"], "secret")
        self.assertIn("no version field", sc["detail"])

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_json_scheme_check_v2_is_ok(self, mock_run):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        self.key_manager.get_scheme_info.return_value = ("v2", True)
        mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch("os.path.exists", return_value=True), patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                rc = self.manager.doctor()
        self.assertEqual(rc, 0)
        payload = json.loads(out.getvalue())
        scheme_checks = [c for c in payload["checks"] if c.get("check") == "scheme"]
        self.assertEqual(len(scheme_checks), 1)
        self.assertEqual(scheme_checks[0]["status"], "ok")

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_json_scheme_check_undeterminable_is_warn(self, mock_run):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        self.key_manager.get_scheme_info.side_effect = UnsupportedFormatError("newer")
        mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch("os.path.exists", return_value=True), patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                rc = self.manager.doctor()
        self.assertEqual(rc, 0)
        payload = json.loads(out.getvalue())
        scheme_checks = [c for c in payload["checks"] if c.get("check") == "scheme"]
        self.assertEqual(len(scheme_checks), 1)
        sc = scheme_checks[0]
        self.assertEqual(sc["status"], "warn")
        self.assertEqual(sc["filter"], "secret")
        self.assertIn("could not be determined", sc["detail"])

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_human_v1_scheme_prints_warn_and_exit_still_zero(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        self.key_manager.get_scheme_info.return_value = ("v1", True)
        mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
        out = io.StringIO()
        with patch("os.path.exists", return_value=True), patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                rc = self.manager.doctor()
        self.assertEqual(rc, 0)  # v1 warn must NOT fail doctor
        self.assertIn("[WARN]", out.getvalue())
        self.assertIn("v1", out.getvalue())

    # ----- status/doctor: unknown scheme is reported as unknown, never rounded -----

    def test_status_json_scheme_read_failure_reports_unknown_and_exits_nonzero(self):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["enc.txt"]
        self.key_manager.get_scheme.side_effect = AesKeyError("no credentials")
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                with self.assertRaises(SystemExit) as ctx:
                    self.manager.status()
        self.assertNotEqual(ctx.exception.code, 0)
        payload = json.loads(out.getvalue())
        entry = payload["filters"][0]
        self.assertEqual(entry["scheme"], "unknown")
        self.assertIn("no credentials", entry["scheme_error"])

    def test_status_human_scheme_read_failure_prints_reason_and_exits_nonzero(self):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["enc.txt"]
        self.key_manager.get_scheme.side_effect = AesKeyError("no credentials")
        out = io.StringIO()
        with patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                with self.assertRaises(SystemExit) as ctx:
                    self.manager.status()
        self.assertNotEqual(ctx.exception.code, 0)
        text = out.getvalue()
        self.assertIn("scheme: unknown", text)
        self.assertIn("no credentials", text)

    def test_status_json_unrecognized_scheme_value_is_not_rounded_to_v2(self):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["enc.txt"]
        self.key_manager.get_scheme.return_value = "v3"
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                self.manager.status()
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["filters"][0]["scheme"], "v3")

    def test_status_all_schemes_readable_exits_zero_regression_guard(self):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["enc.txt"]
        self.key_manager.get_scheme.return_value = "v2"
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                self.manager.status()  # must not raise SystemExit
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["filters"][0]["scheme"], "v2")

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_doctor_json_scheme_check_unrecognized_value_is_not_rounded_to_v2(
        self, mock_run
    ):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        self.key_manager.get_scheme_info.return_value = ("v3", True)
        mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
        out = io.StringIO()
        self.manager.output = Output(json=True)
        with patch("os.path.exists", return_value=True), patch.object(
            self.manager, "_EncryptionManager__is_encrypted", return_value=True
        ):
            with contextlib.redirect_stdout(out):
                self.manager.doctor()
        payload = json.loads(out.getvalue())
        scheme_checks = [c for c in payload["checks"] if c.get("check") == "scheme"]
        self.assertEqual(len(scheme_checks), 1)
        # Before the fix, rounding turned "v3" into "v2" and this check reported
        # "ok" (authenticated scheme v2) - a false-positive for an unread scheme.
        # The rounding gone, an unrecognized value must never produce "ok".
        self.assertNotEqual(scheme_checks[0]["status"], "ok")

    @patch("git_secret_protector.crypto.aes_key_manager.get_settings")
    @patch("git_secret_protector.crypto.aes_key_manager.StorageManagerFactory.create")
    def test_pull_aes_key_with_corrupt_cache_fetches_and_caches_backend(
        self, mock_create, mock_get_settings
    ):
        # Corrupt cache must not prevent pull-aes-key from fetching the backend
        # and storing a valid new cache. The corrupt cache is treated as absent
        # for the changed comparison only; errors from backend or post-refresh
        # reads must still surface.
        from git_secret_protector.core.output import Output

        filter_name = "secret"
        key_settings = MagicMock()
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        key_settings.cache_dir = temp_dir.name
        key_settings.module_name = "git-secret-protector"
        key_settings.storage_type = MagicMock(value="AWS_SSM")
        mock_get_settings.return_value = key_settings

        mock_storage_manager = MagicMock()
        mock_create.return_value = mock_storage_manager
        mock_storage_manager.parameter_name.return_value = f"/enc/{filter_name}"

        real_key_manager = AesKeyManager()
        # Seed cache with truncated/corrupt JSON
        corrupt_blob = b'{"key": "trunc'
        real_key_manager.cache_key_iv_locally(
            filter_name, corrupt_blob.decode("utf-8", errors="replace")
        )

        # Backend returns a valid v2 blob
        backend_blob = {
            "aes_key": base64.b64encode(secrets.token_bytes(32)).decode("utf-8"),
            "iv": base64.b64encode(secrets.token_bytes(16)).decode("utf-8"),
            "version": 2,
        }
        mock_storage_manager.retrieve.return_value = json.dumps(backend_blob)

        self.manager.key_manager = real_key_manager
        self.manager.output = Output(json=True)
        out = io.StringIO()
        # Should not raise or sys.exit despite corrupt cache
        with contextlib.redirect_stdout(out):
            self.manager.pull_aes_key(filter_name)

        # Cache is now valid and holds the backend blob
        cached = real_key_manager.load_key_iv_from_cache(filter_name)
        self.assertEqual(cached["version"], 2)
        self.assertIn("aes_key", cached)
        self.assertIn("iv", cached)

        # JSON envelope reports ok and changed
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scheme"], "v2")
        self.assertTrue(payload["changed"])

    # ----- end Task-6 tests -----


class TestMain(unittest.TestCase):
    @patch("git_secret_protector.main.EncryptionManager.show_project_version")
    @patch("git_secret_protector.main.manager", None)
    def test_show_project_version_does_not_require_manager(
        self, mock_show_project_version
    ):
        show_project_version(None)

        mock_show_project_version.assert_called_once_with(None, None)


class TestInitConfig(unittest.TestCase):
    """Unit tests for EncryptionManager.init_config staticmethod."""

    def _make_mock_settings(self, tmp_dir):
        """Return a mock Settings pointing at tmp_dir."""
        mock_settings = MagicMock()
        module_dir = os.path.join(tmp_dir, ".git_secret_protector")
        mock_settings.base_dir = tmp_dir
        mock_settings.module_dir = module_dir
        mock_settings.config_file = os.path.join(module_dir, "config.ini")
        return mock_settings

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def test_init_config_writes_config_when_none_exists(self, mock_get_settings):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mock_get_settings.return_value = self._make_mock_settings(tmp_dir)
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                rc = EncryptionManager.init_config(
                    backend="GCP_SECRET", module_name="x", assume_yes=True
                )

            self.assertEqual(rc, 0)
            config_file = os.path.join(tmp_dir, ".git_secret_protector", "config.ini")
            self.assertTrue(os.path.exists(config_file))
            cfg = configparser.ConfigParser()
            cfg.read(config_file)
            self.assertEqual(cfg["DEFAULT"]["storage_type"], "GCP_SECRET")
            self.assertEqual(cfg["DEFAULT"]["module_name"], "x")
            self.assertIn("Initialized", stdout.getvalue())

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def test_init_config_assume_yes_no_force_skips_existing(self, mock_get_settings):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mock_settings = self._make_mock_settings(tmp_dir)
            mock_get_settings.return_value = mock_settings
            # Pre-create config
            module_dir = mock_settings.module_dir
            os.makedirs(module_dir, exist_ok=True)
            config_file = mock_settings.config_file
            original_content = "[DEFAULT]\nmodule_name = original\n"
            with open(config_file, "w") as f:
                f.write(original_content)

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = EncryptionManager.init_config(assume_yes=True, force=False)

            self.assertEqual(rc, 0)
            # File must not have been modified
            with open(config_file) as f:
                self.assertEqual(f.read(), original_content)
            self.assertIn("--force", stderr.getvalue())

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def test_init_config_force_overwrites_existing(self, mock_get_settings):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mock_settings = self._make_mock_settings(tmp_dir)
            mock_get_settings.return_value = mock_settings
            module_dir = mock_settings.module_dir
            os.makedirs(module_dir, exist_ok=True)
            config_file = mock_settings.config_file
            with open(config_file, "w") as f:
                f.write("[DEFAULT]\nmodule_name = old\n")

            rc = EncryptionManager.init_config(
                backend="GCP_SECRET",
                module_name="new-module",
                assume_yes=True,
                force=True,
            )

            self.assertEqual(rc, 0)
            cfg = configparser.ConfigParser()
            cfg.read(config_file)
            self.assertEqual(cfg["DEFAULT"]["module_name"], "new-module")
            self.assertEqual(cfg["DEFAULT"]["storage_type"], "GCP_SECRET")

    @patch("builtins.input", side_effect=EOFError)
    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def test_init_config_interactive_eof_declines_overwrite(
        self, mock_get_settings, mock_input
    ):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mock_settings = self._make_mock_settings(tmp_dir)
            mock_get_settings.return_value = mock_settings
            module_dir = mock_settings.module_dir
            os.makedirs(module_dir, exist_ok=True)
            config_file = mock_settings.config_file
            original_content = "[DEFAULT]\nmodule_name = original\n"
            with open(config_file, "w") as f:
                f.write(original_content)

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = EncryptionManager.init_config(assume_yes=False, force=False)

            self.assertEqual(rc, 0)
            with open(config_file) as f:
                self.assertEqual(f.read(), original_content)
            self.assertIn("Keeping existing config", stderr.getvalue())

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def test_init_config_invalid_explicit_backend_returns_1(self, mock_get_settings):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mock_get_settings.return_value = self._make_mock_settings(tmp_dir)
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                rc = EncryptionManager.init_config(
                    backend="INVALID_BACKEND", assume_yes=True
                )

            self.assertEqual(rc, 1)
            self.assertIn("INVALID_BACKEND", stderr.getvalue())


class TestUpgradeScheme(unittest.TestCase):
    """Tests for EncryptionManager.upgrade_scheme."""

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def setUp(self, mock_get_settings):
        mock_settings = MagicMock()
        mock_settings.magic_header = generate_random_string()
        mock_settings.storage_type.value = "AWS_SSM"
        mock_settings.module_name = "git-secret-protector"
        mock_settings.base_dir = "/repo/root"
        mock_settings.encryption_scheme = "v2"
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

        # Preflight is exercised in its own tests (TestGitPreflightIntegration /
        # tests/unit/test_git_preflight.py). Default it to clear here so every
        # other test in this class isn't also asserting repo-safety behavior.
        self.preflight_patcher = patch(
            "git_secret_protector.services.encryption_manager.check_repo_preflight",
            return_value=[],
        )
        self.mock_preflight = self.preflight_patcher.start()
        self.addCleanup(self.preflight_patcher.stop)

    def test_idempotent_already_v2(self):
        """get_scheme -> 'v2': no-op, set_scheme NOT called, counts.reencrypted==0."""
        from git_secret_protector.core.output import Output

        self.key_manager.get_scheme.return_value = "v2"
        self.git_attributes_parser.get_files_for_filter.return_value = [
            "a.txt",
            "b.txt",
        ]
        out = io.StringIO()
        self.manager.output = Output(json=True)

        with contextlib.redirect_stdout(out):
            self.manager.upgrade_scheme("secret")

        self.key_manager.set_scheme.assert_not_called()
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "upgrade-scheme")
        self.assertEqual(payload["counts"]["reencrypted"], 0)
        self.assertEqual(payload["counts"]["total"], 2)

    @patch("builtins.input", side_effect=EOFError)
    def test_decline_on_eof_aborts_without_changes(self, mock_input):
        """EOF on confirm prompt -> aborted, set_scheme NOT called."""
        self.key_manager.get_scheme.return_value = "v1"
        self.git_attributes_parser.get_files_for_filter.return_value = [
            "a.txt",
            "b.txt",
        ]
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            self.manager.upgrade_scheme("secret", assume_yes=False)

        self.key_manager.set_scheme.assert_not_called()
        self.assertIn("Aborted", stderr.getvalue())

    def test_v1_to_v2_reencrypts_files_then_sets_scheme(self):
        """v1 -> v2: re-encrypts each file with v2 handler, set_scheme called AFTER."""
        aes_key = b"\x00" * 32
        iv = b"\x01" * 16
        self.key_manager.get_scheme.return_value = "v1"
        self.key_manager.retrieve_key_and_iv.return_value = (aes_key, iv)
        self.git_attributes_parser.get_files_for_filter.return_value = [
            "a.txt",
            "b.txt",
        ]

        call_order = []
        magic_header = self.manager.magic_header
        v2_byte = b"\x02"

        mock_handler = MagicMock(spec=["decrypt_file", "encrypt_file", "decrypt_data"])
        mock_handler.decrypt_file.side_effect = lambda f: call_order.append(
            ("decrypt", f)
        )
        mock_handler.encrypt_file.side_effect = lambda f: call_order.append(
            ("encrypt", f)
        )
        # Constant plaintext for the before/after content checksum: this test is
        # about call ordering, not content verification, so both files hashing
        # equal (and equal to themselves before/after) keeps that check a no-op.
        mock_handler.decrypt_data.return_value = b"same-plaintext-both-files"
        self.key_manager.set_scheme.side_effect = lambda f, s: call_order.append(
            ("set_scheme", f, s)
        )

        def fake_open(path, mode="r", **kwargs):
            if "b" in mode and "w" not in mode:
                return io.BytesIO(magic_header + v2_byte + b"rest")
            raise RuntimeError("unexpected open call in test")

        from git_secret_protector.crypto.aes_encryption_handler import (
            AesEncryptionHandler as RealHandler,
        )

        from git_secret_protector.core.output import Output

        self.manager.output = Output(json=True)

        with patch.object(
            self.manager,
            "_EncryptionManager__is_encrypted",
            return_value=True,
        ), patch("builtins.open", side_effect=fake_open), patch(
            "git_secret_protector.services.encryption_manager.AesEncryptionHandler",
            side_effect=lambda **kw: mock_handler,
            **{"V2": RealHandler.V2},
        ):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.manager.upgrade_scheme("secret", assume_yes=True)

        # decrypt + encrypt called for each file
        self.assertEqual(
            [(op, f) for op, f in [c[:2] for c in call_order if c[0] != "set_scheme"]],
            [
                ("decrypt", "a.txt"),
                ("encrypt", "a.txt"),
                ("decrypt", "b.txt"),
                ("encrypt", "b.txt"),
            ],
        )
        # set_scheme called after all re-encryptions
        set_scheme_idx = next(
            i for i, c in enumerate(call_order) if c[0] == "set_scheme"
        )
        last_encrypt_idx = max(i for i, c in enumerate(call_order) if c[0] == "encrypt")
        self.assertGreater(set_scheme_idx, last_encrypt_idx)
        self.key_manager.set_scheme.assert_called_once_with("secret", "v2")

        payload = json.loads(out.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["counts"]["reencrypted"], 2)
        self.assertEqual(payload["counts"]["total"], 2)

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def test_upgrade_scheme_v1_calls_print_context(self, mock_get_settings):
        """upgrade_scheme calls _print_context with the filter name on the v1->v2 path."""
        mock_settings = MagicMock()
        mock_settings.storage_type.value = "AWS_SSM"
        mock_settings.module_name = "git-secret-protector"
        mock_settings.base_dir = "/repo/root"
        mock_get_settings.return_value = mock_settings

        self.key_manager.get_scheme.return_value = "v1"
        self.key_manager.retrieve_key_and_iv.return_value = (b"\x00" * 32, b"\x01" * 16)
        self.git_attributes_parser.get_files_for_filter.return_value = []

        with patch.object(self.manager, "_print_context") as mock_print_ctx:
            # No files to re-encrypt; assume_yes skips the confirm prompt.
            # set_scheme is called with no files - that's fine, we only care about
            # _print_context being called before anything else.
            self.manager.upgrade_scheme("secret", assume_yes=True)

        mock_print_ctx.assert_called_once_with("secret")

    @patch("git_secret_protector.services.encryption_manager.AesEncryptionHandler")
    def test_verify_after_failure_exits_1(self, mock_handler_cls):
        """If post-upgrade verify finds a file not v2: sys.exit(1) AND set_scheme NOT called (blob stays v1)."""
        aes_key = b"\x00" * 32
        iv = b"\x01" * 16
        self.key_manager.get_scheme.return_value = "v1"
        self.key_manager.retrieve_key_and_iv.return_value = (aes_key, iv)
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]

        handler = MagicMock()
        mock_handler_cls.return_value = handler
        # Content checksum runs before and after the (mocked, no-op) re-encrypt
        # loop; this test is about the version-byte verify, so a constant
        # decrypt result keeps the checksum comparison a no-op.
        handler.decrypt_data.return_value = b"same-plaintext"

        magic_header = self.manager.magic_header
        # Version byte is v1 (not 0x02) - simulate failed upgrade
        v1_content = magic_header + b"plain-base64-v1"

        def fake_open(path, mode="r", **kwargs):
            if "b" in mode and "w" not in mode:
                return io.BytesIO(v1_content)
            raise RuntimeError("unexpected open call in test")

        with patch.object(
            self.manager,
            "_EncryptionManager__is_encrypted",
            return_value=True,
        ), patch("builtins.open", side_effect=fake_open):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    self.manager.upgrade_scheme("secret", assume_yes=True)

        self.assertEqual(ctx.exception.code, 1)
        # Blob must stay v1 on verify failure - set_scheme must NOT have been called.
        self.key_manager.set_scheme.assert_not_called()

    def test_preflight_refusal_blocks_before_any_file_is_touched(self):
        """A preflight refusal exits 1 before re-encrypting and never calls set_scheme."""
        self.mock_preflight.return_value = ["HEAD is detached at abc1234."]
        self.key_manager.get_scheme.return_value = "v1"
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                self.manager.upgrade_scheme("secret", assume_yes=True)

        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("HEAD is detached", stderr.getvalue())
        self.key_manager.set_scheme.assert_not_called()
        self.key_manager.retrieve_key_and_iv.assert_not_called()

    def test_skip_preflight_does_not_call_check(self):
        """skip_preflight=True (the --all delegation path) never calls check_repo_preflight."""
        self.key_manager.get_scheme.return_value = "v1"
        self.key_manager.retrieve_key_and_iv.return_value = (b"\x00" * 32, b"\x01" * 16)
        self.git_attributes_parser.get_files_for_filter.return_value = []

        self.manager.upgrade_scheme("secret", assume_yes=True, skip_preflight=True)

        self.mock_preflight.assert_not_called()


class TestUpgradeSchemeContent(unittest.TestCase):
    """Content-verification and tree-restore behavior of upgrade_scheme, using
    real crypto over real temp files rather than byte-level mocking - the
    thing under test is whether the decrypted bytes survive the round trip."""

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def setUp(self, mock_get_settings):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

        mock_settings = MagicMock()
        mock_settings.magic_header = "ENCRYPTED"
        mock_settings.storage_type.value = "AWS_SSM"
        mock_settings.module_name = "git-secret-protector"
        mock_settings.base_dir = self.tmpdir
        mock_settings.encryption_scheme = "v2"
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

        self.aes_key = secrets.token_bytes(32)
        self.iv = secrets.token_bytes(16)
        self.key_manager.retrieve_key_and_iv.return_value = (self.aes_key, self.iv)
        self.key_manager.get_scheme.return_value = "v1"

        self.preflight_patcher = patch(
            "git_secret_protector.services.encryption_manager.check_repo_preflight",
            return_value=[],
        )
        self.preflight_patcher.start()
        self.addCleanup(self.preflight_patcher.stop)

    def _write_v1_ciphertext(self, name, plaintext):
        path = os.path.join(self.tmpdir, name)
        v1_handler = AesEncryptionHandler(
            aes_key=self.aes_key,
            iv=self.iv,
            magic_header=self.manager.magic_header,
            scheme="v1",
        )
        with open(path, "wb") as fh:
            fh.write(v1_handler.encrypt_data(plaintext))
        return path

    def _write_plaintext(self, name, plaintext):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as fh:
            fh.write(plaintext)
        return path

    def test_happy_path_calls_set_scheme_once_after_both_checks(self):
        path = self._write_v1_ciphertext("a.txt", b"super-secret-value")
        self.git_attributes_parser.get_files_for_filter.return_value = [path]

        self.manager.upgrade_scheme("secret", assume_yes=True)

        self.key_manager.set_scheme.assert_called_once_with("secret", "v2")

    def test_ciphertext_at_rest_ends_ciphertext(self):
        path = self._write_v1_ciphertext("a.txt", b"super-secret-value")
        self.git_attributes_parser.get_files_for_filter.return_value = [path]

        self.manager.upgrade_scheme("secret", assume_yes=True)

        with open(path, "rb") as fh:
            content = fh.read()
        self.assertTrue(content.startswith(self.manager.magic_header))

    def test_success_path_never_uses_git_checkout(self):
        """The success and abort restores must stay DIFFERENT: success must
        leave the freshly re-encrypted v2 content in place (that content IS
        the intended change to be committed), never revert it via `git
        checkout` the way the abort path now does."""
        path = self._write_v1_ciphertext("a.txt", b"super-secret-value")
        self.git_attributes_parser.get_files_for_filter.return_value = [path]

        with patch.object(
            self.manager,
            "_EncryptionManager__git_checkout_files",
            side_effect=AssertionError("git checkout must not run on success"),
        ):
            self.manager.upgrade_scheme("secret", assume_yes=True)  # must not raise

        self.key_manager.set_scheme.assert_called_once_with("secret", "v2")
        with open(path, "rb") as fh:
            content = fh.read()
        self.assertTrue(content.startswith(self.manager.magic_header))

    def test_plaintext_at_rest_ends_plaintext(self):
        path = self._write_plaintext("a.txt", b"super-secret-value")
        self.git_attributes_parser.get_files_for_filter.return_value = [path]

        self.manager.upgrade_scheme("secret", assume_yes=True)

        self.key_manager.set_scheme.assert_called_once_with("secret", "v2")
        with open(path, "rb") as fh:
            content = fh.read()
        self.assertFalse(content.startswith(self.manager.magic_header))
        self.assertEqual(content, b"super-secret-value")

    def test_success_path_restore_failure_is_reported_as_error_not_ok(self):
        """The scheme flip succeeding does not make the upgrade reportable as
        ok if restoring the tree to plaintext afterward fails: this is a
        successful upgrade with an incomplete restore, and both facts must
        survive into the envelope - distinctly from a plain failure."""
        path = self._write_plaintext("a.txt", b"super-secret-value")
        self.git_attributes_parser.get_files_for_filter.return_value = [path]

        real_decrypt_file = AesEncryptionHandler.decrypt_file
        call_count = {"n": 0}

        def flaky_decrypt_file(self_handler, file_path):
            call_count["n"] += 1
            # 1st call: the main re-encrypt loop's decrypt (succeeds, no-op
            # on plaintext). 2nd call: the post-set_scheme restore attempt -
            # this is the one that must fail without undoing the flip.
            if call_count["n"] == 2:
                raise IOError("disk full")
            real_decrypt_file(self_handler, file_path)

        from git_secret_protector.core.output import Output

        out = io.StringIO()
        stderr = io.StringIO()
        self.manager.output = Output(json=True)

        with patch.object(AesEncryptionHandler, "decrypt_file", flaky_decrypt_file):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    self.manager.upgrade_scheme("secret", assume_yes=True)

        # Non-zero exit, never the plain-failure code either - an automated
        # caller must not mistake this for "nothing to do" (0) or treat it
        # exactly like a verify/content failure (1).
        self.assertNotEqual(ctx.exception.code, 0)

        # The scheme flip genuinely succeeded.
        self.key_manager.set_scheme.assert_called_once_with("secret", "v2")

        payload = json.loads(out.getvalue())
        self.assertFalse(payload["ok"])
        self.assertTrue(payload.get("scheme_flip_succeeded"))
        self.assertIn(path, payload.get("restore_failed_files", []))

        stderr_text = stderr.getvalue()
        self.assertIn("v2", stderr_text)
        self.assertIn("no-op", stderr_text)
        self.assertIn("decrypt-files", stderr_text)

    def test_content_mismatch_blocks_set_scheme_and_names_file(self):
        """If the re-encrypted file's decrypted content differs from the
        baseline, set_scheme must never be called and the error must name the
        file - without ever printing the plaintext itself."""
        path = self._write_v1_ciphertext("a.txt", b"super-secret-value")
        self.git_attributes_parser.get_files_for_filter.return_value = [path]

        real_encrypt_file = AesEncryptionHandler.encrypt_file
        call_count = {"n": 0}

        def tampering_encrypt_file(self_handler, file_path):
            # Re-encrypt normally, then simulate the migration itself losing
            # content: overwrite with a validly-formatted v2 blob for
            # DIFFERENT plaintext, so the version-byte check still passes and
            # only the content checksum comparison can catch it.
            real_encrypt_file(self_handler, file_path)
            call_count["n"] += 1
            if call_count["n"] == 1:
                tampered = self_handler.encrypt_data(b"different-content")
                with open(file_path, "wb") as fh:
                    fh.write(tampered)

        with patch.object(AesEncryptionHandler, "encrypt_file", tampering_encrypt_file):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    self.manager.upgrade_scheme("secret", assume_yes=True)

        self.assertEqual(ctx.exception.code, 1)
        self.key_manager.set_scheme.assert_not_called()
        stderr_text = stderr.getvalue()
        self.assertIn(path, stderr_text)
        self.assertNotIn("super-secret-value", stderr_text)
        self.assertNotIn("different-content", stderr_text)

    def test_set_scheme_failure_restores_plaintext_tree_and_reports_error(self):
        """set_scheme raising (e.g. no backend credentials) must not escape as
        a traceback: the tree, found as plaintext, must be restored to
        plaintext and the outcome reported as an error envelope."""
        path = self._write_plaintext("a.txt", b"super-secret-value")
        self.git_attributes_parser.get_files_for_filter.return_value = [path]
        self.key_manager.set_scheme.side_effect = AesKeyError("no backend credentials")

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                self.manager.upgrade_scheme("secret", assume_yes=True)

        self.assertEqual(ctx.exception.code, 1)
        stderr_text = stderr.getvalue()
        self.assertNotIn("Traceback", stderr_text)
        self.assertIn("no backend credentials", stderr_text)

        with open(path, "rb") as fh:
            content = fh.read()
        self.assertFalse(content.startswith(self.manager.magic_header))
        self.assertEqual(content, b"super-secret-value")

    def test_set_scheme_failure_leaves_ciphertext_tree_as_ciphertext(self):
        """Found-as-ciphertext variant: after a set_scheme failure the tree
        (already re-encrypted to v2 ciphertext by the loop) is left as
        ciphertext, since that is the state it was found in."""
        path = self._write_v1_ciphertext("a.txt", b"super-secret-value")
        self.git_attributes_parser.get_files_for_filter.return_value = [path]
        self.key_manager.set_scheme.side_effect = AesKeyError("no backend credentials")

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                self.manager.upgrade_scheme("secret", assume_yes=True)

        self.assertEqual(ctx.exception.code, 1)
        self.assertNotIn("Traceback", stderr.getvalue())

        with open(path, "rb") as fh:
            content = fh.read()
        self.assertTrue(content.startswith(self.manager.magic_header))


class TestUpgradeSchemeAbortRestoresCommittedBytes(unittest.TestCase):
    """DEFECT A regression, run against a REAL git repo (this is the one
    thing a tmpdir-without-git fixture cannot exercise, and the one thing
    the old crypto-based abort restore got wrong).

    Measured on a tree found as ciphertext - no filters configured in
    .git/config, the service-olympus shape - the old abort restore called
    the v2 handler's encrypt_file again, producing FRESH v2 ciphertext with
    no committed blob behind it: `git status` showed the file modified, its
    sha differed from HEAD, and the key blob was still v1 - a declared-
    scheme-vs-stored-bytes divergence, reported as a clean abort and
    committable. `git checkout -- <file>` is the only restore that cannot
    diverge from the committed blob, because it returns exactly those
    bytes."""

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def setUp(self, mock_get_settings):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

        subprocess.run(["git", "init", "-q"], cwd=self.tmpdir, check=True)
        subprocess.run(
            ["git", "config", "user.email", "t@example.com"],
            cwd=self.tmpdir,
            check=True,
        )
        subprocess.run(["git", "config", "user.name", "T"], cwd=self.tmpdir, check=True)

        mock_settings = MagicMock()
        mock_settings.magic_header = "ENCRYPTED"
        mock_settings.storage_type.value = "AWS_SSM"
        mock_settings.module_name = "git-secret-protector"
        mock_settings.base_dir = self.tmpdir
        mock_settings.encryption_scheme = "v2"
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

        self.aes_key = secrets.token_bytes(32)
        self.iv = secrets.token_bytes(16)
        self.key_manager.retrieve_key_and_iv.return_value = (self.aes_key, self.iv)
        self.key_manager.get_scheme.return_value = "v1"

        self.preflight_patcher = patch(
            "git_secret_protector.services.encryption_manager.check_repo_preflight",
            return_value=[],
        )
        self.preflight_patcher.start()
        self.addCleanup(self.preflight_patcher.stop)

        # v1 ciphertext, committed - the "no filters configured in
        # .git/config" / found-as-ciphertext shape.
        self.path = os.path.join(self.tmpdir, "a.secret")
        v1_handler = AesEncryptionHandler(
            aes_key=self.aes_key,
            iv=self.iv,
            magic_header=self.manager.magic_header,
            scheme="v1",
        )
        with open(self.path, "wb") as fh:
            fh.write(v1_handler.encrypt_data(b"super-secret-value"))

        subprocess.run(["git", "add", "a.secret"], cwd=self.tmpdir, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "secret"], cwd=self.tmpdir, check=True
        )

        self.git_attributes_parser.get_files_for_filter.return_value = [self.path]

    def _head_blob_sha256(self):
        result = subprocess.run(
            ["git", "show", "HEAD:a.secret"],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )
        return hashlib.sha256(result.stdout).hexdigest()

    def test_abort_restores_tree_byte_identical_to_head(self):
        real_encrypt_file = AesEncryptionHandler.encrypt_file
        call_count = {"n": 0}

        def tampering_encrypt_file(self_handler, file_path):
            # Re-encrypt normally, then simulate content loss so the
            # content-verification check aborts the run.
            real_encrypt_file(self_handler, file_path)
            call_count["n"] += 1
            if call_count["n"] == 1:
                tampered = self_handler.encrypt_data(b"different-content")
                with open(file_path, "wb") as fh:
                    fh.write(tampered)

        with patch.object(AesEncryptionHandler, "encrypt_file", tampering_encrypt_file):
            with self.assertRaises(SystemExit) as ctx:
                self.manager.upgrade_scheme("secret", assume_yes=True)

        self.assertEqual(ctx.exception.code, 1)
        self.key_manager.set_scheme.assert_not_called()

        with open(self.path, "rb") as fh:
            disk_bytes = fh.read()
        self.assertEqual(
            hashlib.sha256(disk_bytes).hexdigest(), self._head_blob_sha256()
        )

        status = subprocess.run(
            ["git", "status", "--porcelain", "--", "a.secret"],
            cwd=self.tmpdir,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(status.stdout.strip(), "")

    def test_successful_checkout_is_never_second_guessed(self):
        """A successful `git checkout` must be trusted, whatever at-rest state
        it produces, and the crypto restore must not run after it.

        An earlier version compared the post-checkout state against the found
        state and fell back to the crypto restore on a mismatch. That
        reintroduced the defect this class covers: on a checkout with filters
        configured whose files nonetheless sat as ciphertext at rest, checkout
        correctly smudges them to plaintext, the comparison reads that as a
        mismatch, and the fallback re-encrypts to fresh v2 bytes under a v1
        blob. Whatever checkout produces is the canonical state for that
        checkout's configuration; a found state disagreeing with it was the
        anomaly.
        """
        restore = self.manager._EncryptionManager__restore_on_abort
        checkout = "_EncryptionManager__git_checkout_files"
        crypto = "_EncryptionManager__restore_to_found_state"

        # found_ciphertext is deliberately the OPPOSITE of what the file is left
        # as, so a state comparison would read "mismatch" and fall back.
        with open(self.path, "wb") as fh:
            fh.write(b"plaintext-after-checkout")

        with patch.object(self.manager, checkout, return_value=True) as mock_checkout:
            with patch.object(self.manager, crypto) as mock_crypto:
                failures = restore([self.path], MagicMock(), found_ciphertext=True)

        mock_checkout.assert_called_once()
        mock_crypto.assert_not_called()
        self.assertEqual(failures, [])

    def test_failed_checkout_falls_back_to_the_crypto_restore(self):
        restore = self.manager._EncryptionManager__restore_on_abort
        checkout = "_EncryptionManager__git_checkout_files"
        crypto = "_EncryptionManager__restore_to_found_state"

        with patch.object(self.manager, checkout, return_value=False):
            with patch.object(self.manager, crypto, return_value=[]) as mock_crypto:
                restore([self.path], MagicMock(), found_ciphertext=True)

        mock_crypto.assert_called_once()


class TestUpgradeSchemeAllSetSchemeFailure(unittest.TestCase):
    """Regression coverage for the real-CLI defects found against a mixed
    v1/v2 fixture: a set_scheme failure (no backend credentials) must not
    escape --all as a traceback, must stop before the next filter, and must
    restore the failed filter's already-re-encrypted file to the state it
    was found in."""

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def setUp(self, mock_get_settings):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

        mock_settings = MagicMock()
        mock_settings.magic_header = "ENCRYPTED"
        mock_settings.storage_type.value = "AWS_SSM"
        mock_settings.module_name = "git-secret-protector"
        mock_settings.base_dir = self.tmpdir
        mock_settings.encryption_scheme = "v2"
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

        self.key_manager.retrieve_key_and_iv.return_value = (
            secrets.token_bytes(32),
            secrets.token_bytes(16),
        )
        self.key_manager.get_scheme.return_value = "v1"
        self.key_manager.set_scheme.side_effect = AesKeyError("no backend credentials")

        self.preflight_patcher = patch(
            "git_secret_protector.services.encryption_manager.check_repo_preflight",
            return_value=[],
        )
        self.preflight_patcher.start()
        self.addCleanup(self.preflight_patcher.stop)

        # Sorted order runs "app-dev" before "app-prod-never-reached", so the
        # failure on the first must stop the run before the second is ever
        # touched.
        self.git_attributes_parser.get_filter_names.return_value = [
            "app-prod-never-reached",
            "app-dev",
        ]

        self.dev_path = os.path.join(self.tmpdir, "secrets.auto.tfvars")
        with open(self.dev_path, "wb") as fh:
            fh.write(b"plaintext-secret-value")

        self.other_path = os.path.join(self.tmpdir, "other.tfvars")
        with open(self.other_path, "wb") as fh:
            fh.write(b"other-plaintext")

        def files_for_filter(name):
            return [self.dev_path] if name == "app-dev" else [self.other_path]

        self.git_attributes_parser.get_files_for_filter.side_effect = files_for_filter

    def test_set_scheme_failure_reports_per_filter_and_stops_without_traceback(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                self.manager.upgrade_scheme_all(assume_yes=True)

        self.assertEqual(ctx.exception.code, 1)
        stderr_text = stderr.getvalue()
        self.assertNotIn("Traceback", stderr_text)
        self.assertIn("app-dev", stderr_text)
        self.assertIn("app-prod-never-reached", stderr_text)

        # the never-reached filter's file must be untouched
        with open(self.other_path, "rb") as fh:
            self.assertEqual(fh.read(), b"other-plaintext")

        # the failed filter's file, found as plaintext, must be restored
        with open(self.dev_path, "rb") as fh:
            content = fh.read()
        self.assertFalse(content.startswith(self.manager.magic_header))
        self.assertEqual(content, b"plaintext-secret-value")


class TestUpgradeSchemeAllRestoreIncomplete(unittest.TestCase):
    """Regression coverage for the pre-PR review defect: a filter that
    upgrades to v2 successfully but whose post-flip restore fails must stop
    the --all run (the tree needs a human) and must be reported distinctly
    from a plain upgrade failure - the first filter WAS upgraded."""

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def setUp(self, mock_get_settings):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

        mock_settings = MagicMock()
        mock_settings.magic_header = "ENCRYPTED"
        mock_settings.storage_type.value = "AWS_SSM"
        mock_settings.module_name = "git-secret-protector"
        mock_settings.base_dir = self.tmpdir
        mock_settings.encryption_scheme = "v2"
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

        self.key_manager.retrieve_key_and_iv.return_value = (
            secrets.token_bytes(32),
            secrets.token_bytes(16),
        )
        self.key_manager.get_scheme.return_value = "v1"
        # set_scheme succeeds this time - the flip itself is fine.

        self.preflight_patcher = patch(
            "git_secret_protector.services.encryption_manager.check_repo_preflight",
            return_value=[],
        )
        self.preflight_patcher.start()
        self.addCleanup(self.preflight_patcher.stop)

        # Sorted order runs "filter-a" before "filter-b-never-reached".
        self.git_attributes_parser.get_filter_names.return_value = [
            "filter-b-never-reached",
            "filter-a",
        ]

        self.a_path = os.path.join(self.tmpdir, "a.secret")
        with open(self.a_path, "wb") as fh:
            fh.write(b"plaintext-secret-value")

        self.b_path = os.path.join(self.tmpdir, "b.secret")
        with open(self.b_path, "wb") as fh:
            fh.write(b"other-plaintext")

        def files_for_filter(name):
            return [self.a_path] if name == "filter-a" else [self.b_path]

        self.git_attributes_parser.get_files_for_filter.side_effect = files_for_filter

        # decrypt_file call #1 is the main re-encrypt loop for filter-a's one
        # file (succeeds); call #2 is the post-flip restore attempt for that
        # same file (fails). filter-b is never reached, so no further calls.
        self._real_decrypt_file = AesEncryptionHandler.decrypt_file
        self._call_count = {"n": 0}

        def flaky_decrypt_file(self_handler, file_path):
            self._call_count["n"] += 1
            if self._call_count["n"] == 2:
                raise IOError("disk full")
            self._real_decrypt_file(self_handler, file_path)

        self.decrypt_patcher = patch.object(
            AesEncryptionHandler, "decrypt_file", flaky_decrypt_file
        )
        self.decrypt_patcher.start()
        self.addCleanup(self.decrypt_patcher.stop)

    def test_run_stops_filter_two_untouched_and_report_distinguishes_outcome(self):
        from git_secret_protector.core.output import Output

        out = io.StringIO()
        stderr = io.StringIO()
        self.manager.output = Output(json=True)

        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                self.manager.upgrade_scheme_all(assume_yes=True)

        # Not the plain-failure code, and not success.
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertNotEqual(ctx.exception.code, 1)

        # filter-a's scheme flip genuinely succeeded.
        self.key_manager.set_scheme.assert_called_once_with("filter-a", "v2")

        # filter-b was never attempted.
        with open(self.b_path, "rb") as fh:
            self.assertEqual(fh.read(), b"other-plaintext")

        # upgrade_scheme emits its own per-filter envelope first; the --all
        # level envelope (the one asserted here) is the last line.
        lines = [line for line in out.getvalue().splitlines() if line.strip()]
        payload = json.loads(lines[-1])
        self.assertFalse(payload["ok"])
        self.assertTrue(payload.get("scheme_flip_succeeded"))
        self.assertEqual(payload.get("restore_incomplete_filter"), "filter-a")
        self.assertIn("filter-a", payload.get("upgraded", []))
        self.assertIn("filter-b-never-reached", payload.get("not_attempted", []))
        # Must not be describable as a plain failure.
        self.assertNotIn("failed", payload)

        stderr_text = stderr.getvalue()
        self.assertIn("filter-a", stderr_text)
        self.assertIn("filter-b-never-reached", stderr_text)
        self.assertIn("not a failed upgrade", stderr_text)


class TestUpgradeSchemeAll(unittest.TestCase):
    """Tests for EncryptionManager.upgrade_scheme_all."""

    @patch("git_secret_protector.services.encryption_manager.get_settings")
    def setUp(self, mock_get_settings):
        mock_settings = MagicMock()
        mock_settings.magic_header = generate_random_string()
        mock_settings.storage_type.value = "AWS_SSM"
        mock_settings.module_name = "git-secret-protector"
        mock_settings.base_dir = "/repo/root"
        mock_settings.encryption_scheme = "v2"
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

        self.preflight_patcher = patch(
            "git_secret_protector.services.encryption_manager.check_repo_preflight",
            return_value=[],
        )
        self.mock_preflight = self.preflight_patcher.start()
        self.addCleanup(self.preflight_patcher.stop)

    def test_nothing_to_do_is_success_not_error(self):
        self.git_attributes_parser.get_filter_names.return_value = ["a", "b"]
        self.key_manager.get_scheme.side_effect = lambda name: "v2"
        from git_secret_protector.core.output import Output

        out = io.StringIO()
        self.manager.output = Output(json=True)

        with contextlib.redirect_stdout(out):
            self.manager.upgrade_scheme_all(assume_yes=True)

        self.key_manager.set_scheme.assert_not_called()
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["ok"])

    def test_mixed_filters_upgrades_only_v1_ones(self):
        self.git_attributes_parser.get_filter_names.return_value = [
            "v1filter",
            "v2filter",
        ]
        self.git_attributes_parser.get_files_for_filter.return_value = []
        self.key_manager.get_scheme.side_effect = lambda name: (
            "v1" if name == "v1filter" else "v2"
        )

        with patch.object(self.manager, "upgrade_scheme") as mock_upgrade:
            self.manager.upgrade_scheme_all(assume_yes=True)

        mock_upgrade.assert_called_once_with(
            "v1filter", assume_yes=True, skip_preflight=True
        )

    def test_stops_on_first_failure_and_does_not_touch_later_filters(self):
        self.git_attributes_parser.get_filter_names.return_value = ["a", "b", "c"]
        self.git_attributes_parser.get_files_for_filter.return_value = []
        self.key_manager.get_scheme.return_value = "v1"

        def fake_upgrade(name, assume_yes=False, skip_preflight=False):
            if name == "b":
                sys.exit(1)

        with patch.object(
            self.manager, "upgrade_scheme", side_effect=fake_upgrade
        ) as mock_upgrade:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit):
                    self.manager.upgrade_scheme_all(assume_yes=True)

        called_filters = [c.args[0] for c in mock_upgrade.call_args_list]
        self.assertEqual(called_filters, ["a", "b"])  # never reached "c"
        self.assertIn("c", stderr.getvalue())  # named as not attempted

    def test_all_plus_filter_name_rejected_at_cli_layer(self):
        # EncryptionManager.upgrade_scheme_all itself takes no filter name -
        # the --all/filter_name contradiction is rejected in main.py before
        # the manager is ever called. See test_main_cli.py.
        self.assertFalse(hasattr(self.manager.upgrade_scheme_all, "filter_name"))

    def test_preflight_refusal_blocks_before_any_filter_is_touched(self):
        self.git_attributes_parser.get_filter_names.return_value = ["a"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["x.txt"]
        self.key_manager.get_scheme.return_value = "v1"
        self.mock_preflight.return_value = ["matched file(s) are not tracked"]

        with patch.object(self.manager, "upgrade_scheme") as mock_upgrade:
            with self.assertRaises(SystemExit):
                self.manager.upgrade_scheme_all(assume_yes=True)

        mock_upgrade.assert_not_called()

    def test_get_scheme_failure_during_enumeration_is_a_controlled_abort(self):
        """DEFECT B regression: get_scheme(name) runs BEFORE the try/except
        that wraps the upgrade loop, and for a repo where most filters have
        no locally cached key (measured: 50 of 198 in the estate audit),
        hitting the backend during enumeration is the NORMAL first action of
        --all, not an edge case. A failure there must not escape as a raw
        traceback - it must be reported, name the filter, say nothing was
        touched, and exit non-zero."""
        self.git_attributes_parser.get_filter_names.return_value = ["a", "b"]
        self.key_manager.get_scheme.side_effect = AesKeyError(
            "no cached key and backend unreachable"
        )

        with patch.object(self.manager, "upgrade_scheme") as mock_upgrade:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    self.manager.upgrade_scheme_all(assume_yes=True)

        self.assertNotEqual(ctx.exception.code, 0)
        mock_upgrade.assert_not_called()
        stderr_text = stderr.getvalue()
        self.assertNotIn("Traceback", stderr_text)
        self.assertIn("a", stderr_text)
        self.assertIn("nothing was touched", stderr_text.lower())


class TestUpgradeSchemeExitCodes(unittest.TestCase):
    """The three outcomes of upgrade-scheme must stay distinguishable by exit code
    alone, because that is how an automated caller tells them apart.

    This pins the values rather than the behaviour: when the restore-incomplete code
    was introduced it was set to 2, which argparse already uses for a usage error
    (reachable here via `upgrade-scheme <filter> --all`). That made the most urgent
    outcome - the migration half-landed and a working tree needs a human - read
    identically to someone mistyping the flags. Changing it to 3 broke no test,
    which is why this one exists.
    """

    def test_restore_incomplete_code_collides_with_nothing(self):
        from git_secret_protector.services import encryption_manager as em

        code = em._RESTORE_INCOMPLETE_EXIT_CODE
        self.assertNotEqual(code, 0, "must not read as success")
        self.assertNotEqual(code, 1, "must be distinguishable from a plain failure")
        self.assertNotEqual(code, 2, "argparse uses 2 for a usage error")
        self.assertGreater(code, 2)


class TestRestoreToFoundStateJudgesDiskNotIntent(unittest.TestCase):
    """The restore must judge each file by its CURRENT state on disk, never by
    assuming the re-encrypt loop completed.

    That loop decrypts and then re-encrypts each file in turn, so a failure
    between those two writes leaves that one file as PLAINTEXT. An earlier
    version returned early for a found-as-ciphertext tree on the reasoning that
    such a tree is already where it started - true only of a completed loop. The
    cost of the gap was plaintext secrets sitting in a repo that stores
    ciphertext, reported as a clean abort and committable.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.handler = AesEncryptionHandler(
            aes_key=os.urandom(32),
            iv=os.urandom(16),
            magic_header=b"ENCRYPTED",
            scheme="v2",
        )
        self.manager = EncryptionManager(
            git_attributes_parser=MagicMock(),
            key_manager=MagicMock(),
            key_rotator=MagicMock(),
        )

    def _write(self, name, body, encrypted):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as fh:
            fh.write(body)
        if encrypted:
            self.handler.encrypt_file(path)
        return path

    def _restore(self, files, found_ciphertext):
        return self.manager._EncryptionManager__restore_to_found_state(
            files, self.handler, found_ciphertext
        )

    def _is_encrypted(self, path):
        with open(path, "rb") as fh:
            return fh.read(9) == b"ENCRYPTED"

    def test_found_ciphertext_reencrypts_a_file_left_plaintext_mid_loop(self):
        done = self._write("done.env", "A=1\n", encrypted=True)
        interrupted = self._write("interrupted.env", "B=2\n", encrypted=False)

        failures = self._restore([done, interrupted], found_ciphertext=True)

        self.assertEqual(failures, [])
        self.assertTrue(self._is_encrypted(done))
        self.assertTrue(
            self._is_encrypted(interrupted),
            "a file left plaintext by an interrupted loop must be re-encrypted, "
            "not silently left as readable secrets",
        )

    def test_found_plaintext_still_decrypts_back(self):
        encrypted = self._write("secrets.env", "C=3\n", encrypted=True)

        failures = self._restore([encrypted], found_ciphertext=False)

        self.assertEqual(failures, [])
        self.assertFalse(self._is_encrypted(encrypted))

    def test_restore_failure_is_reported_not_raised(self):
        missing = os.path.join(self.tmp, "gone.env")

        failures = self._restore([missing], found_ciphertext=True)

        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0][0], missing)


if __name__ == "__main__":
    unittest.main()
