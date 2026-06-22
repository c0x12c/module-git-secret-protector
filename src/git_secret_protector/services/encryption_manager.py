import configparser
import logging
import os
import subprocess
import sys
from pathlib import Path

import injector

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.core.output import Output
from git_secret_protector.core.settings import StorageType, get_settings
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
        output: Output = None,
    ):
        self.git_attributes_parser = git_attributes_parser
        self.key_manager = key_manager
        self.key_rotator = key_rotator
        self.output = output if output is not None else Output()
        self.magic_header = get_settings().magic_header.encode()

    def _envelope_ok(self, command, **fields):
        return {"ok": True, "command": command, **fields}

    def _envelope_err(self, command, error, **fields):
        return {"ok": False, "command": command, "error": error, **fields}

    def _print_context(self, filter_name=None):
        if self.output.quiet:
            return
        settings = get_settings()
        self.output.error(f"Backend:   {settings.storage_type.value}")
        self.output.error(f"Module:    {settings.module_name}")
        self.output.error(f"Repo root: {settings.base_dir}")

        if filter_name is not None:
            try:
                path = self.key_manager.resolve_parameter_name(filter_name)
                self.output.error(f"Namespace: {path}")
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
        self.output.error(f"Error: {msg}")
        sys.exit(1)

    def setup_aes_key(self, filter_name: str, scheme: str = "v2"):
        filter_name = self._require_filter(filter_name)
        self._print_context(filter_name)
        try:
            logger.info("Setting up AES key for filter: %s", filter_name)
            self.key_manager.setup_aes_key_and_iv(filter_name, scheme=scheme)
            logger.info("Successfully set up AES key for filter: %s", filter_name)
            if scheme == "v1":
                self.output.error(
                    f"WARNING: filter '{filter_name}' uses the legacy v1 scheme "
                    f"(unauthenticated AES-CBC). Use only for repos with pre-1.4.0 "
                    f"clients; run 'upgrade-scheme {filter_name}' once they are upgraded."
                )
            msg = f"Successfully set up AES key for filter: {filter_name}"
            self.output.info(msg)
            self.output.result(
                self._envelope_ok(
                    "setup-aes-key", filter=filter_name, scheme=scheme, message=msg
                )
            )
        except Exception as e:
            logger.error(f"AES key setup command failed: {e}", exc_info=True)
            self.output.error(f"AES key setup command failed: {e}")
            self.output.result(
                self._envelope_err("setup-aes-key", str(e), filter=filter_name)
            )
            sys.exit(1)

    def setup_filters(self):
        try:
            logger.info("Setting up filters")
            filter_names = self.git_attributes_parser.get_filter_names()
            for filter_name in filter_names:
                self.__init_filter(filter_name=filter_name)
            logger.info("Successfully set up filters")
            msg = "Successfully set up filters"
            self.output.info(msg)
            self.output.result(self._envelope_ok("setup-filters", message=msg))
        except Exception as e:
            logger.error(f"Setup filters command failed: {e}", exc_info=True)
            self.output.error(f"Setup filters command failed: {e}")
            self.output.result(self._envelope_err("setup-filters", str(e)))
            sys.exit(1)

    def pull_aes_key(self, filter_name: str):
        filter_name = self._require_filter(filter_name)
        self._print_context(filter_name)
        try:
            logger.info("Pulling AES key for filter: %s", filter_name)
            self.key_manager.retrieve_key_and_iv(filter_name=filter_name)
            logger.info("Successfully pulled AES key for filter: %s", filter_name)
            msg = f"Successfully pulled AES key for filter: {filter_name}"
            self.output.info(msg)
            self.output.result(
                self._envelope_ok("pull-aes-key", filter=filter_name, message=msg)
            )
        except Exception as e:
            logger.error(f"Pull AES key command failed: {e}", exc_info=True)
            self.output.error(f"Pull AES key command failed: {e}")
            self.output.result(
                self._envelope_err("pull-aes-key", str(e), filter=filter_name)
            )
            sys.exit(1)

    def encrypt_files(self, filter_name: str, emit: bool = True):
        filter_name = self._require_filter(filter_name)
        try:
            logger.info("Encrypting files for filter: %s", filter_name)
            files = self.git_attributes_parser.get_files_for_filter(
                filter_name=filter_name
            )
            if not files:
                logging.info(f"No files to encrypt for filter: {filter_name}")
                if emit:
                    msg = f"No files to encrypt for filter: {filter_name}"
                    self.output.info(msg)
                    self.output.result(
                        self._envelope_ok(
                            "encrypt-files",
                            filter=filter_name,
                            counts={"encrypted": 0, "skipped": 0, "total": 0},
                            files=[],
                            message=msg,
                        )
                    )
                return {"encrypted": 0, "skipped": 0, "total": 0}

            handler = self.__get_encryption_handler(filter_name=filter_name)
            total = len(files)
            results = []
            counts = {"encrypted": 0, "skipped": 0, "total": total}
            for i, file in enumerate(files, 1):
                self.output.progress(f"[{i}/{total}] {file}")
                was_encrypted = self.__is_encrypted(file_path=file)
                handler.encrypt_file(file)
                action = "skipped" if was_encrypted else "encrypted"
                counts[action] += 1
                results.append({"path": file, "action": action})

            logging.info(f"Successfully encrypted files for filter: {filter_name}")
            if emit:
                msg = f"Successfully encrypted files for filter: {filter_name}"
                self.output.info(msg)
                self.output.result(
                    self._envelope_ok(
                        "encrypt-files",
                        filter=filter_name,
                        counts=counts,
                        files=results,
                        message=msg,
                    )
                )
            return counts
        except Exception as e:
            logger.error(f"Encrypt files command failed: {e}", exc_info=True)
            self.output.error(f"Encrypt files command failed: {str(e)}")
            if emit:
                self.output.result(
                    self._envelope_err("encrypt-files", str(e), filter=filter_name)
                )
            sys.exit(1)

    def decrypt_files(self, filter_name: str, emit: bool = True):
        filter_name = self._require_filter(filter_name)
        try:
            logger.info("Decrypting files for filter: %s", filter_name)
            files = self.git_attributes_parser.get_files_for_filter(
                filter_name=filter_name
            )
            if not files:
                logging.info(f"No files to decrypt for filter: {filter_name}")
                if emit:
                    msg = f"No files to decrypt for filter: {filter_name}"
                    self.output.info(msg)
                    self.output.result(
                        self._envelope_ok(
                            "decrypt-files",
                            filter=filter_name,
                            counts={"decrypted": 0, "skipped": 0, "total": 0},
                            files=[],
                            message=msg,
                        )
                    )
                return {"decrypted": 0, "skipped": 0, "total": 0}

            handler = self.__get_encryption_handler(filter_name=filter_name)
            total = len(files)
            results = []
            counts = {"decrypted": 0, "skipped": 0, "total": total}
            for i, file in enumerate(files, 1):
                self.output.progress(f"[{i}/{total}] {file}")
                is_encrypted = self.__is_encrypted(file_path=file)
                handler.decrypt_file(file)
                action = "decrypted" if is_encrypted else "skipped"
                counts[action] += 1
                results.append({"path": file, "action": action})

            logging.info(f"Successfully decrypted files for filter: {filter_name}")
            if emit:
                msg = f"Successfully decrypted files for filter: {filter_name}"
                self.output.info(msg)
                self.output.result(
                    self._envelope_ok(
                        "decrypt-files",
                        filter=filter_name,
                        counts=counts,
                        files=results,
                        message=msg,
                    )
                )
            return counts
        except Exception as e:
            logger.error(f"Decrypt files command failed: {e}", exc_info=True)
            self.output.error(f"Decrypt files command failed: {e}")
            if emit:
                self.output.result(
                    self._envelope_err("decrypt-files", str(e), filter=filter_name)
                )
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
                try:
                    answer = input(
                        f"Rotate key for filter '{filter_name}'? This re-encrypts ALL matched files and retires the current key. [y/N] "
                    )
                except EOFError:
                    # No TTY (CI / piped stdin) and no explicit consent - treat as
                    # a decline so a destructive rotation never runs unconfirmed.
                    answer = ""
                if answer.strip().lower() not in {"y", "yes"}:
                    self.output.error(
                        "Aborted (no confirmation; pass -y/--yes for non-interactive use)."
                    )
                    self.output.result(
                        self._envelope_ok(
                            "rotate-key",
                            filter=filter_name,
                            message="aborted",
                            ok=False,
                        )
                    )
                    return
            rotator = KeyRotator(self.key_manager, self.git_attributes_parser)
            rotator.rotate_key(filter_name)
            logger.info("Key rotation complete for filter: %s", filter_name)
            msg = f"Key rotation complete for filter: {filter_name}"
            self.output.info(msg)
            self.output.result(
                self._envelope_ok("rotate-key", filter=filter_name, message=msg)
            )
        except Exception as e:
            logger.error(f"Rotate keys command failed: {e}", exc_info=True)
            self.output.error(f"Rotate keys command failed: {e}")
            self.output.result(
                self._envelope_err("rotate-key", str(e), filter=filter_name)
            )
            sys.exit(1)

    def clean_filter(self, filter_name: str):
        filter_name = self._require_filter(filter_name)
        try:
            logger.info("Cleaning staged data for filter: %s", filter_name)

            try:
                self.encrypt_files(filter_name=filter_name, emit=False)
            except SystemExit:
                logger.warning(
                    "Failed to encrypt files for filter '%s' during clean", filter_name
                )

            self.key_manager.remove_key_iv_from_cache(filter_name=filter_name)
            logger.info("Successfully cleaned staged data for filter: %s", filter_name)
            msg = f"Successfully cleaned staged data for filter: {filter_name}"
            self.output.info(msg)
            self.output.result(
                self._envelope_ok("clean-filter", filter=filter_name, message=msg)
            )
        except Exception as e:
            logger.error(f"Clean filter command failed: {e}", exc_info=True)
            self.output.error(f"Clean filter command failed: {e}")
            self.output.result(
                self._envelope_err("clean-filter", str(e), filter=filter_name)
            )
            sys.exit(1)

    def status(self):
        self._print_context()
        try:
            settings = get_settings()
            filter_names = self.git_attributes_parser.get_filter_names()
            data = {
                "repo_root": settings.base_dir,
                "backend": settings.storage_type.value,
                "module_name": settings.module_name,
                "filters": [],
            }
            for filter_name in filter_names:
                files = self.git_attributes_parser.get_files_for_filter(filter_name)
                file_entries = [
                    {"path": f, "encrypted": self.__is_encrypted(file_path=f)}
                    for f in files
                ]
                data["filters"].append({"name": filter_name, "files": file_entries})

            if self.output.json:
                self.output.result(data)
                return

            for entry in data["filters"]:
                print(f"Filter: {entry['name']}")
                if entry["files"]:
                    for f in entry["files"]:
                        status = "Encrypted" if f["encrypted"] else "⚠ PLAINTEXT"
                        print(f"  {f['path']}: {status}")
                else:
                    print("  No files found for this filter.")
        except Exception as e:
            if self.output.json:
                self.output.result(self._envelope_err("status", str(e)))
            else:
                self.output.error(f"Status command failed: {e}")
            sys.exit(1)

    def doctor(self) -> int:
        settings = get_settings()
        failed = False
        checks = []

        # Repository context - stored as a special multi-line block in detail
        repo_lines = (
            f"Repository context\n"
            f"  base_dir: {settings.base_dir}\n"
            f"  backend: {settings.storage_type.value}\n"
            f"  module_name: {settings.module_name}"
        )
        checks.append(
            {"check": "repository_context", "status": "ok", "detail": repo_lines}
        )

        if os.path.exists(settings.config_file):
            checks.append(
                {
                    "check": "config_ini",
                    "status": "ok",
                    "detail": f"config.ini found at {settings.config_file}",
                }
            )
        else:
            checks.append(
                {
                    "check": "config_ini",
                    "status": "warn",
                    "detail": "config.ini not found (defaults in use)",
                }
            )

        filter_names = []
        try:
            filter_names = self.git_attributes_parser.get_filter_names()
        except Exception:
            pass

        if not filter_names:
            checks.append(
                {
                    "check": "filters_declared",
                    "status": "warn",
                    "detail": "no filters defined in .gitattributes",
                }
            )
            exit_code = 1 if failed else 0
            self._doctor_emit(checks, failed, exit_code)
            return exit_code

        checks.append(
            {
                "check": "filters_declared",
                "status": "ok",
                "detail": f"filters declared: {', '.join(filter_names)}",
            }
        )

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
                checks.append(
                    {
                        "check": "git_config",
                        "status": "ok",
                        "detail": f"filter '{filter_name}' configured in .git/config",
                        "filter": filter_name,
                    }
                )
            else:
                checks.append(
                    {
                        "check": "git_config",
                        "status": "warn",
                        "detail": f"filter '{filter_name}' not configured in .git/config (run setup-filters)",
                        "filter": filter_name,
                    }
                )

            if self.key_manager.is_cached(filter_name):
                checks.append(
                    {
                        "check": "key_cache",
                        "status": "ok",
                        "detail": f"local key cache exists for '{filter_name}'",
                        "filter": filter_name,
                    }
                )
            else:
                checks.append(
                    {
                        "check": "key_cache",
                        "status": "warn",
                        "detail": f"no local key cache for '{filter_name}' (run pull-aes-key)",
                        "filter": filter_name,
                    }
                )

        # Resolving the parameter name forces credential/region resolution
        # (e.g. an STS call for AWS SSM). It confirms creds + config resolve,
        # not that the key parameter exists or that a full fetch would succeed.
        try:
            self.key_manager.resolve_parameter_name(filter_names[0])
            checks.append(
                {
                    "check": "backend_credentials",
                    "status": "ok",
                    "detail": "backend credentials/region resolved",
                }
            )
        except Exception:
            checks.append(
                {
                    "check": "backend_credentials",
                    "status": "warn",
                    "detail": "backend credentials/region unresolved (offline ok)",
                }
            )

        for filter_name in filter_names:
            files = self.git_attributes_parser.get_files_for_filter(filter_name)
            plaintext_files = []

            for file_path in files:
                if not self.__is_encrypted(file_path):
                    plaintext_files.append(file_path)
                    failed = True
                    checks.append(
                        {
                            "check": "plaintext_scan",
                            "status": "fail",
                            "detail": f"{file_path} is tracked as secret but is PLAINTEXT in the working tree",
                            "filter": filter_name,
                        }
                    )

            if not plaintext_files:
                checks.append(
                    {
                        "check": "plaintext_scan",
                        "status": "ok",
                        "detail": f"all tracked secret files are encrypted for '{filter_name}'",
                        "filter": filter_name,
                    }
                )

        exit_code = 1 if failed else 0
        self._doctor_emit(checks, failed, exit_code)
        return exit_code

    def _doctor_emit(self, checks, failed, exit_code):
        if self.output.json:
            self.output.result(
                {"ok": not failed, "exit_code": exit_code, "checks": checks}
            )
            return
        # Human mode: render each check with its label; repository_context gets
        # its first line as the label target and sub-lines printed as-is.
        label_map = {"ok": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}
        for c in checks:
            label = label_map[c["status"]]
            detail = c["detail"]
            if c["check"] == "repository_context":
                # detail is "Repository context\n  line2\n  line3\n  line4"
                lines = detail.split("\n")
                print(f"{label} {lines[0]}")
                for sub in lines[1:]:
                    print(sub)
            else:
                print(f"{label} {detail}")

    @staticmethod
    def show_project_version(_=None, output=None):
        output = output if output is not None else Output()
        try:
            version = get_project_version_from_metadata()
            output.info(f"git-secret-protector version: {version}")
            output.result({"version": version})
        except Exception as e:
            logger.error(f"Failed to get project version: {e}", exc_info=True)
            output.error(f"Failed to get project version: {str(e)}")
            output.result({"ok": False, "command": "version", "error": str(e)})

    @staticmethod
    def init_config(
        backend=None, module_name=None, assume_yes=False, force=False
    ) -> int:
        """Write .git_secret_protector/config.ini interactively or non-interactively.

        Returns 0 on success or non-destructive skip, 1 on invalid input.
        """
        settings = get_settings()
        pre_existing = os.path.exists(settings.config_file)

        if pre_existing and not force:
            if assume_yes:
                print(
                    "config.ini already exists; pass --force to overwrite.",
                    file=sys.stderr,
                )
                return 0
            # Interactive: mirror the EOF-safe pattern from rotate_keys.
            try:
                answer = input(
                    f"config.ini already exists at {settings.config_file}. Overwrite? [y/N] "
                )
            except EOFError:
                answer = ""
            if answer.strip().lower() not in {"y", "yes"}:
                print("Keeping existing config.", file=sys.stderr)
                return 0

        # Resolve backend.
        valid_backends = {m.value for m in StorageType}
        if backend is not None:
            if backend not in valid_backends:
                print(
                    f"Error: invalid backend '{backend}'. Choose from: {', '.join(sorted(valid_backends))}",
                    file=sys.stderr,
                )
                return 1
        elif assume_yes:
            backend = "AWS_SSM"
        else:
            try:
                raw = input("Storage backend [AWS_SSM/GCP_SECRET] (default AWS_SSM): ")
            except EOFError:
                raw = ""
            backend = raw.strip() or "AWS_SSM"
            if backend not in valid_backends:
                # One reprompt.
                try:
                    raw2 = input(
                        f"Invalid backend '{backend}'. Choose AWS_SSM or GCP_SECRET: "
                    )
                except EOFError:
                    raw2 = ""
                backend = raw2.strip() or ""
                if backend not in valid_backends:
                    print(
                        f"Error: invalid backend '{backend}'. Choose from: {', '.join(sorted(valid_backends))}",
                        file=sys.stderr,
                    )
                    return 1

        # Resolve module_name.
        if module_name is not None:
            pass  # use as-is
        elif assume_yes:
            module_name = "git-secret-protector"
        else:
            try:
                raw = input("Module name (default git-secret-protector): ")
            except EOFError:
                raw = ""
            module_name = raw.strip() or "git-secret-protector"

        # Create directories.
        module_dir = Path(settings.module_dir)
        (module_dir / "cache").mkdir(parents=True, exist_ok=True)
        (module_dir / "logs").mkdir(parents=True, exist_ok=True)

        # Write config.
        cfg = configparser.ConfigParser()
        cfg["DEFAULT"] = {
            "module_name": module_name,
            "storage_type": backend,
            "log_level": "WARN",
            "log_max_size": "1048576",
        }
        with open(settings.config_file, "w") as fh:
            cfg.write(fh)

        print(f"Initialized git-secret-protector config at {settings.config_file}")
        print(f"  backend: {backend}\n  module_name: {module_name}")
        return 0

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
        scheme = self.key_manager.get_scheme(filter_name)
        return AesEncryptionHandler(
            aes_key=aes_key, iv=iv, magic_header=self.magic_header, scheme=scheme
        )

    def __is_encrypted(self, file_path: str):
        try:
            with open(file_path, "rb") as file:
                header = file.read(len(self.magic_header))
                return header == self.magic_header
        except IOError:
            logger.error(f"Error reading file: {file_path}")
            return False
