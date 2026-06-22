import base64
import contextlib
import io
import json
import os
import secrets
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
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

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
        ):
            with patch("sys.stdin", stdin), patch("sys.stdout", stdout):
                self.manager.encrypt_stdin("secrets.env")

        self.assertEqual(stdout_buffer.getvalue(), b"ciphertext")

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
            MagicMock(stdout="git-secret-protector decrypt %f\n"),
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

    def test_decrypt_stdin_does_not_exit_when_decryption_raises(self):
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
                self.manager.decrypt_stdin("secrets.env")

        self.assertEqual(stdout_buffer.getvalue(), encrypted_data)

    @patch("git_secret_protector.services.encryption_manager.subprocess.run")
    def test_setup_filters_sets_required_for_existing_filter(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        mock_run.side_effect = [
            MagicMock(stdout="git-secret-protector encrypt %f\n"),
            MagicMock(stdout="git-secret-protector decrypt %f\n"),
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
        mock_run.assert_called_with(
            ["git", "config", "filter.secret.required", "true"],
            check=True,
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
                "message": "Successfully set up AES key for filter: secret",
            },
        )

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


class TestMain(unittest.TestCase):
    @patch("git_secret_protector.main.EncryptionManager.show_project_version")
    @patch("git_secret_protector.main.manager", None)
    def test_show_project_version_does_not_require_manager(
        self, mock_show_project_version
    ):
        show_project_version(None)

        mock_show_project_version.assert_called_once_with(None, None)


if __name__ == "__main__":
    unittest.main()
