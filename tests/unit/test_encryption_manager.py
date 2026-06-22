import base64
import configparser
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

    def test_status_json_schema(self):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = [
            "enc.txt",
            "plain.txt",
        ]
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
                "scheme": "v2",
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
        mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
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
        self.assertIn(
            "[ OK ] all tracked secret files are encrypted for 'secret'", text
        )

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
        self.key_manager.get_scheme.return_value = "v1"
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
    def test_doctor_json_scheme_check_v2_is_ok(self, mock_run):
        from git_secret_protector.core.output import Output

        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        self.key_manager.get_scheme.return_value = "v2"
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
    def test_doctor_human_v1_scheme_prints_warn_and_exit_still_zero(self, mock_run):
        self.git_attributes_parser.get_filter_names.return_value = ["secret"]
        self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
        self.key_manager.is_cached.return_value = True
        self.key_manager.resolve_parameter_name.return_value = "/path"
        self.key_manager.get_scheme.return_value = "v1"
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
        mock_get_settings.return_value = mock_settings

        self.git_attributes_parser = MagicMock(spec=GitAttributesParser)
        self.key_manager = MagicMock()
        self.key_rotator = MagicMock()
        self.manager = EncryptionManager(
            git_attributes_parser=self.git_attributes_parser,
            key_manager=self.key_manager,
            key_rotator=self.key_rotator,
        )

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

        mock_handler = MagicMock(spec=["decrypt_file", "encrypt_file"])
        mock_handler.decrypt_file.side_effect = lambda f: call_order.append(
            ("decrypt", f)
        )
        mock_handler.encrypt_file.side_effect = lambda f: call_order.append(
            ("encrypt", f)
        )
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


if __name__ == "__main__":
    unittest.main()
