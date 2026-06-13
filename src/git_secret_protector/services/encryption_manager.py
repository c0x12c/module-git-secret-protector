import logging
import os
import subprocess
import sys
from pathlib import Path

import injector

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.core.settings import get_settings
from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler
from git_secret_protector.crypto.aes_key_manager import AesKeyManager
from git_secret_protector.services.key_rotator import KeyRotator
from git_secret_protector.utils.project_version import get_project_version_from_metadata

logger = logging.getLogger(__name__)


class EncryptionManager:
    @injector.inject
    def __init__(
        self,
        git_attributes_parser: GitAttributesParser,
        key_manager: AesKeyManager,
        key_rotator: KeyRotator,
    ):
        self.git_attributes_parser = git_attributes_parser
        self.key_manager = key_manager
        self.key_rotator = key_rotator
        self.magic_header = get_settings().magic_header.encode()

    def _print_context(self, filter_name=None):
        settings = get_settings()
        print(f"Backend:   {settings.storage_type.value}", file=sys.stderr)
        print(f"Module:    {settings.module_name}", file=sys.stderr)
        print(f"Repo root: {settings.base_dir}", file=sys.stderr)

        if filter_name is not None:
            try:
                path = self.key_manager.resolve_parameter_name(filter_name)
                print(f"Namespace: {path}", file=sys.stderr)
            except Exception:
                pass

    def _require_filter(self, filter_name):
        if filter_name:
            return filter_name
        try:
            available = self.git_attributes_parser.get_filter_names()
        except Exception:
            available = []
        if available:
            msg = (
                f"a filter name is required. Available filters: {', '.join(available)}"
            )
        else:
            msg = (
                "a filter name is required. No filters defined "
                "(.gitattributes missing or empty)."
            )
        print(f"Error: {msg}", file=sys.stderr)
        sys.exit(1)

    def setup_aes_key(self, filter_name: str):
        filter_name = self._require_filter(filter_name)
        self._print_context(filter_name)
        try:
            logger.info("Setting up AES key for filter: %s", filter_name)
            self.key_manager.setup_aes_key_and_iv(filter_name)
            logger.info("Successfully set up AES key for filter: %s", filter_name)
            print(f"Successfully set up AES key for filter: {filter_name}")
        except Exception as e:
            logger.error(f"AES key setup command failed: {e}", exc_info=True)
            print(f"AES key setup command failed: {e}", file=sys.stderr)
            sys.exit(1)

    def setup_filters(self):
        logger.info("Setting up filters")
        filter_names = self.git_attributes_parser.get_filter_names()
        for filter_name in filter_names:
            self.__init_filter(filter_name=filter_name)
        logger.info("Successfully set up filters")
        print("Successfully set up filters")

    def pull_aes_key(self, filter_name: str):
        filter_name = self._require_filter(filter_name)
        self._print_context(filter_name)
        try:
            logger.info("Pulling AES key for filter: %s", filter_name)
            self.key_manager.retrieve_key_and_iv(filter_name=filter_name)
            logger.info("Successfully pulled AES key for filter: %s", filter_name)
            print(f"Successfully pulled AES key for filter: {filter_name}")
        except Exception as e:
            logger.error(f"Pull AES key command failed: {e}", exc_info=True)
            print(f"Pull AES key command failed: {e}", file=sys.stderr)
            sys.exit(1)

    def encrypt_files(self, filter_name: str):
        filter_name = self._require_filter(filter_name)
        try:
            logger.info("Encrypting files for filter: %s", filter_name)
            files_to_encrypt = self.git_attributes_parser.get_files_for_filter(
                filter_name=filter_name
            )
            if not files_to_encrypt:
                logging.info(f"No files to encrypt for filter: {filter_name}")
                return

            self.__get_encryption_handler(filter_name=filter_name).encrypt_files(
                files=files_to_encrypt
            )
            logging.info(f"Successfully encrypted files for filter: {filter_name}")
            print(f"Successfully encrypted files for filter: {filter_name}")
        except Exception as e:
            logger.error(f"Encrypt files command failed: {e}", exc_info=True)
            print(f"Encrypt files command failed: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def decrypt_files(self, filter_name: str):
        filter_name = self._require_filter(filter_name)
        try:
            logger.info("Decrypting files for filter: %s", filter_name)
            files_to_decrypt = self.git_attributes_parser.get_files_for_filter(
                filter_name=filter_name
            )
            if not files_to_decrypt:
                logging.info(f"No files to decrypt for filter: {filter_name}")
                return

            self.__get_encryption_handler(filter_name=filter_name).decrypt_files(
                files=files_to_decrypt
            )
            logging.info(f"Successfully decrypted files for filter: {filter_name}")
            print(f"Successfully decrypted files for filter: {filter_name}")
        except Exception as e:
            logger.error(f"Decrypt files command failed: {e}", exc_info=True)
            print(f"Decrypt files command failed: {e}", file=sys.stderr)
            sys.exit(1)

    def encrypt_stdin(self, file_name):
        logging.info(f"Encrypting data from stdin for file: {file_name}")
        input_data = sys.stdin.buffer.read()

        if not input_data:
            logging.error("No data provided on stdin")
            return

        try:
            filter_name = self.git_attributes_parser.get_filter_name_for_file(
                file_name=file_name
            )
            logger.debug("Found filter_name to decrypt: %s", filter_name)

            if filter_name is None:
                logger.error("No filter found for file: %s", file_name)
                sys.exit(1)

            encrypted_data = self.__get_encryption_handler(
                filter_name=filter_name
            ).encrypt_data(input_data)

            sys.stdout.buffer.write(encrypted_data)
            sys.stdout.buffer.flush()
            logging.info(
                f"Successfully encrypted data from stdin for file: {file_name}"
            )
        except Exception as e:
            logging.error(f"Encrypt data command failed: {e}", exc_info=True)
            sys.exit(1)

    def decrypt_stdin(self, file_name):
        logging.info(f"Decrypting data from stdin for file: {file_name}")
        encrypted_data = sys.stdin.buffer.read()

        if not encrypted_data:
            logging.error("No data provided on stdin")
            return

        try:
            filter_name = self.git_attributes_parser.get_filter_name_for_file(file_name)
            logger.debug("Found filter_name to decrypt: %s", filter_name)

            if filter_name is None:
                logger.error("No filter found for file: %s", file_name)
                return

            decrypted_data = self.__get_encryption_handler(
                filter_name=filter_name
            ).decrypt_data(encrypted_data)
            logger.debug("Decrypted file: %s", file_name)

            sys.stdout.buffer.write(decrypted_data)
            sys.stdout.buffer.flush()
            logging.info(
                f"Successfully decrypted data from stdin for file: {file_name}"
            )
        except Exception as e:
            logging.error(f"Decrypt data command failed: {e}", exc_info=True)
            sys.stdout.buffer.write(encrypted_data)
            sys.stdout.buffer.flush()

    def rotate_keys(self, filter_name: str, assume_yes: bool = False):
        filter_name = self._require_filter(filter_name)
        self._print_context(filter_name)
        try:
            if not assume_yes:
                answer = input(
                    f"Rotate key for filter '{filter_name}'? This re-encrypts ALL matched files and retires the current key. [y/N] "
                )
                if answer.strip().lower() not in {"y", "yes"}:
                    print("Aborted.", file=sys.stderr)
                    return
            rotator = KeyRotator(self.key_manager, self.git_attributes_parser)
            rotator.rotate_key(filter_name)
            logger.info("Key rotation complete for filter: %s", filter_name)
            print(f"Key rotation complete for filter: {filter_name}")
        except Exception as e:
            logger.error(f"Rotate keys command failed: {e}", exc_info=True)
            print(f"Rotate keys command failed: {e}", file=sys.stderr)
            sys.exit(1)

    def clean_filter(self, filter_name: str):
        filter_name = self._require_filter(filter_name)
        try:
            logger.info("Cleaning staged data for filter: %s", filter_name)

            try:
                self.encrypt_files(filter_name=filter_name)
            except Exception as e:
                logger.warning(
                    "Failed to encrypt files for filter '%s': %s", filter_name, e
                )

            self.key_manager.remove_key_iv_from_cache(filter_name=filter_name)
            logger.info("Successfully cleaned staged data for filter: %s", filter_name)
            print(f"Successfully cleaned staged data for filter: {filter_name}")
        except Exception as e:
            logger.error(f"Clean filter command failed: {e}", exc_info=True)
            print(f"Clean filter command failed: {e}", file=sys.stderr)
            sys.exit(1)

    def status(self):
        self._print_context()
        try:
            filter_names = self.git_attributes_parser.get_filter_names()
            for filter_name in filter_names:
                print(f"Filter: {filter_name}")
                files = self.git_attributes_parser.get_files_for_filter(filter_name)
                if files:
                    for file in files:
                        encrypted = self.__is_encrypted(file_path=file)
                        status = "Encrypted" if encrypted else "⚠ PLAINTEXT"
                        print(f"  {file}: {status}")
                else:
                    print("  No files found for this filter.")
        except Exception as e:
            print(f"Status command failed: {e}", file=sys.stderr)
            sys.exit(1)

    def doctor(self) -> int:
        settings = get_settings()
        failed = False

        print("[ OK ] Repository context")
        print(f"  base_dir: {settings.base_dir}")
        print(f"  backend: {settings.storage_type.value}")
        print(f"  module_name: {settings.module_name}")

        if os.path.exists(settings.config_file):
            print(f"[ OK ] config.ini found at {settings.config_file}")
        else:
            print("[WARN] config.ini not found (defaults in use)")

        filter_names = []
        try:
            filter_names = self.git_attributes_parser.get_filter_names()
        except Exception:
            pass

        if not filter_names:
            print("[WARN] no filters defined in .gitattributes")
            return 1 if failed else 0

        print(f"[ OK ] filters declared: {', '.join(filter_names)}")

        for filter_name in filter_names:
            check_clean = subprocess.run(
                ["git", "config", "--get", f"filter.{filter_name}.clean"],
                capture_output=True,
                text=True,
            ).stdout.strip()
            check_smudge = subprocess.run(
                ["git", "config", "--get", f"filter.{filter_name}.smudge"],
                capture_output=True,
                text=True,
            ).stdout.strip()

            if check_clean and check_smudge:
                print(f"[ OK ] filter '{filter_name}' configured in .git/config")
            else:
                print(
                    f"[WARN] filter '{filter_name}' not configured in .git/config (run setup-filters)"
                )

            if self.key_manager.is_cached(filter_name):
                print(f"[ OK ] local key cache exists for '{filter_name}'")
            else:
                print(
                    f"[WARN] no local key cache for '{filter_name}' (run pull-aes-key)"
                )

        try:
            self.key_manager.resolve_parameter_name(filter_names[0])
            print("[ OK ] backend reachable")
        except Exception:
            print("[WARN] backend not reachable / no credentials (offline ok)")

        for filter_name in filter_names:
            files = self.git_attributes_parser.get_files_for_filter(filter_name)
            plaintext_files = []

            for file_path in files:
                if not self.__is_encrypted(file_path):
                    plaintext_files.append(file_path)
                    failed = True
                    print(
                        f"[FAIL] {file_path} is tracked as secret but is PLAINTEXT in the working tree"
                    )

            if not plaintext_files:
                print(
                    f"[ OK ] all tracked secret files are encrypted for '{filter_name}'"
                )

        return 1 if failed else 0

    @staticmethod
    def show_project_version():
        try:
            version = get_project_version_from_metadata()
            print(f"git-secret-protector version: {version}")
        except Exception as e:
            logger.error(f"Failed to get project version: {e}", exc_info=True)
            print(f"Failed to get project version: {str(e)}", file=sys.stderr)

    @staticmethod
    def _get_poetry_root_path():
        # Start from the current directory and look for pyproject.toml upward
        current_path = Path(__file__).resolve()
        for parent in current_path.parents:
            if (parent / "pyproject.toml").exists():
                return parent

    @staticmethod
    def __init_filter(filter_name: str):
        # Check for existing Git filters
        check_clean = subprocess.run(
            ["git", "config", "--get", f"filter.{filter_name}.clean"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        check_smudge = subprocess.run(
            ["git", "config", "--get", f"filter.{filter_name}.smudge"],
            capture_output=True,
            text=True,
        ).stdout.strip()

        logger.info("Setting up Git filters for '%s'", filter_name)
        if check_clean or check_smudge:
            subprocess.run(
                ["git", "config", f"filter.{filter_name}.required", "true"], check=True
            )
            sys.stdout.buffer.write(
                f"Git filters for '{filter_name}' already exist. Skipping filter setup.".encode(
                    "utf-8"
                )
                + b"\n"
            )
            sys.stdout.buffer.flush()
            return

        # Set Git filters
        subprocess.run(
            [
                "git",
                "config",
                f"filter.{filter_name}.clean",
                "git-secret-protector encrypt %f",
            ],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "config",
                f"filter.{filter_name}.smudge",
                "git-secret-protector decrypt %f",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "config", f"filter.{filter_name}.required", "true"], check=True
        )
        logger.debug(
            "Git clean & smudge filters for '%s' have been set up successfully.",
            filter_name,
        )

    def __get_encryption_handler(self, filter_name: str):
        aes_key, iv = self.key_manager.retrieve_key_and_iv(filter_name)
        return AesEncryptionHandler(
            aes_key=aes_key, iv=iv, magic_header=self.magic_header
        )

    def __is_encrypted(self, file_path: str):
        try:
            with open(file_path, "rb") as file:
                header = file.read(len(self.magic_header))
                return header == self.magic_header
        except IOError:
            logger.error(f"Error reading file: {file_path}")
            return False
