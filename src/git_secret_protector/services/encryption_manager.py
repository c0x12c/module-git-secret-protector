import configparser
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import injector

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.core.git_preflight import check_repo_preflight
from git_secret_protector.core.output import Output, safe_print
from git_secret_protector.core.settings import StorageType, get_settings
from git_secret_protector.core import tree_state
from git_secret_protector.crypto.aes_encryption_handler import (
    AesEncryptionHandler,
    SUPPORTED_SCHEMES,
)
from git_secret_protector.crypto.aes_key_manager import AesKeyManager
from git_secret_protector.error.unsupported_format_error import UnsupportedFormatError
from git_secret_protector.services.key_rotator import KeyRotator
from git_secret_protector.utils.project_version import get_project_version_from_metadata

logger = logging.getLogger(__name__)


class _UpgradeAbort(Exception):
    """Internal signal for a controlled upgrade_scheme failure (as opposed to
    an unexpected exception from set_scheme or the crypto calls) - carries the
    envelope fields the caller should report alongside the restore outcome."""

    def __init__(self, error, **fields):
        super().__init__(error)
        self.error = error
        self.fields = fields


# sys.exit() code reserved for "the scheme flip succeeded, but restoring the
# working tree to its found state afterward failed" - distinct from the
# ordinary failure exit(1) used everywhere else in upgrade_scheme. This is a
# SUCCESSFUL upgrade with an INCOMPLETE restore, not a failed upgrade: the key
# blob is already v2 and must never be re-flipped, so it cannot be reported
# (or retried) the same way a real failure is. upgrade_scheme_all inspects
# this exit code to tell the two apart without parsing output.
#
# 3, NOT 2: argparse already exits 2 for a usage error, which this CLI reaches on
# `upgrade-scheme <filter> --all` (the mutually-exclusive case). Reusing 2 would make
# the most urgent state in this command - the migration half-landed, a tree needs a
# human - indistinguishable to a caller from someone mistyping the flags.
_RESTORE_INCOMPLETE_EXIT_CODE = 3


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
        settings = get_settings()
        self.magic_header = settings.magic_header.encode()
        self.base_dir = settings.base_dir

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

    def setup_aes_key(self, filter_name: str, scheme: Optional[str] = None):
        # Precedence: explicit --scheme flag > config encryption_scheme > built-in v2.
        if scheme is None:
            scheme = get_settings().encryption_scheme
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

    def setup_filters(self, use_process: bool = False):
        try:
            logger.info("Setting up filters")
            filter_names = self.git_attributes_parser.get_filter_names()
            for filter_name in filter_names:
                self.__init_filter(filter_name=filter_name, use_process=use_process)
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
            # force=True: pull-aes-key's whole job is to refresh a stale cache, so
            # it must always contact the backend rather than returning a cache hit.
            try:
                # Treat unreadable pre-refresh cache as absent for the changed comparison.
                before = self.key_manager.load_key_iv_from_cache(
                    filter_name=filter_name
                )
            except (OSError, ValueError):
                before = None
            self.key_manager.retrieve_key_and_iv(filter_name=filter_name, force=True)
            after = self.key_manager.load_key_iv_from_cache(filter_name=filter_name)
            changed = before != after
            scheme = self.key_manager.get_scheme(filter_name=filter_name)
            logger.info("Successfully pulled AES key for filter: %s", filter_name)
            msg = f"Successfully pulled AES key for filter: {filter_name}"
            self.output.info(msg)
            self.output.result(
                self._envelope_ok(
                    "pull-aes-key",
                    filter=filter_name,
                    scheme=scheme,
                    changed=changed,
                    message=msg,
                )
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

    def _encrypt_bytes(self, filter_name: str, data: bytes) -> bytes:
        """Raising helper shared by encrypt_stdin and the filter-process loop.

        Owns none of the error policy - callers decide what to do on failure, since
        a long-running process must never let an exception here kill the whole
        checkout the way encrypt_stdin's sys.exit(1) would.
        """
        return self.__get_encryption_handler(
            filter_name=filter_name, cache_only=True
        ).encrypt_data(data)

    def _decrypt_bytes(self, filter_name: str, data: bytes) -> bytes:
        """Raising counterpart to _encrypt_bytes; see its docstring."""
        return self.__get_encryption_handler(
            filter_name=filter_name, cache_only=True
        ).decrypt_data(data)

    def run_filter_process(self, filter_name: str) -> int:
        from git_secret_protector.services.filter_process import run_filter_process

        return run_filter_process(filter_name, self)

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

            encrypted_data = self._encrypt_bytes(filter_name, input_data)

            sys.stdout.buffer.write(encrypted_data)
            sys.stdout.buffer.flush()
            logging.info(
                f"Successfully encrypted data from stdin for file: {file_name}"
            )
        except BrokenPipeError:
            # The reader closing the pipe is not an application error; main() handles it.
            raise
        except Exception as e:
            logging.error(f"Encrypt data command failed: {e}", exc_info=True)
            # stderr is safe for git filters (stdout carries the binary payload) and,
            # unlike the file logger, is shown by git - so the cache-miss
            # 'run pull-aes-key' hint actually reaches the user.
            print(f"git-secret-protector: {e}", file=sys.stderr)
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

            decrypted_data = self._decrypt_bytes(filter_name, encrypted_data)
            logger.debug("Decrypted file: %s", file_name)

            sys.stdout.buffer.write(decrypted_data)
            sys.stdout.buffer.flush()
            logging.info(
                f"Successfully decrypted data from stdin for file: {file_name}"
            )
        except BrokenPipeError:
            # The reader closing the pipe is not an application error; main() handles it.
            raise
        except UnsupportedFormatError as e:
            # Newer/unknown wire or key format: fail closed. Do NOT pass the ciphertext
            # through as if it were content (that would silently land encrypted bytes in
            # the working tree) - abort the checkout so the skew is visible.
            logging.error(f"Decrypt data command failed: {e}", exc_info=True)
            print(f"git-secret-protector: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            logging.error(f"Decrypt data command failed: {e}", exc_info=True)
            # Fail closed - never land ciphertext in the working tree as plaintext.
            # A cache-miss key error is recoverable via pull-aes-key; this stderr
            # line (git shows it) is the only place that hint reaches the user.
            print(f"git-secret-protector: {e}", file=sys.stderr)
            sys.exit(1)

    def upgrade_scheme(
        self,
        filter_name: str,
        assume_yes: bool = False,
        skip_preflight: bool = False,
    ):
        filter_name = self._require_filter(filter_name)
        self._print_context(filter_name)
        scheme = self.key_manager.get_scheme(filter_name)
        files = self.git_attributes_parser.get_files_for_filter(filter_name)
        total = len(files)

        if scheme == "v2":
            msg = f"Filter '{filter_name}' is already on scheme v2; nothing to do."
            self.output.info(msg)
            self.output.result(
                self._envelope_ok(
                    "upgrade-scheme",
                    filter=filter_name,
                    message=msg,
                    counts={"reencrypted": 0, "total": total},
                )
            )
            return

        if not skip_preflight and files:
            filter_map = {f: filter_name for f in files}
            plaintext_of = self.__plaintext_of_resolver(filter_map)
            notes = []
            refusals = check_repo_preflight(
                files, cwd=self.base_dir, plaintext_of=plaintext_of, notes=notes
            )
            for note in notes:
                self.output.info(f"upgrade-scheme: {note}")
            if refusals:
                for refusal in refusals:
                    self.output.error(f"upgrade-scheme: refusing - {refusal}")
                self.output.result(
                    self._envelope_err(
                        "upgrade-scheme",
                        "preflight refused",
                        filter=filter_name,
                        refusals=refusals,
                        notes=notes,
                    )
                )
                sys.exit(1)

        if not assume_yes:
            try:
                answer = input(
                    f"Upgrade filter '{filter_name}' from v1 to v2? "
                    f"This re-encrypts ALL matched files. [y/N] "
                )
            except EOFError:
                answer = ""
            if answer.strip().lower() not in {"y", "yes"}:
                self.output.error("Aborted.")
                return

        aes_key, iv = self.key_manager.retrieve_key_and_iv(filter_name)
        v2_handler = AesEncryptionHandler(
            aes_key=aes_key, iv=iv, magic_header=self.magic_header, scheme="v2"
        )

        # Record, before touching anything, whether the tree was found at rest
        # as plaintext or ciphertext - the upgrade must hand it back in that
        # state. Mixed counts as ciphertext: re-encrypting is the reversible
        # direction (decrypt-files recovers plaintext at any time), whereas
        # leaving plaintext in a repo that stores ciphertext is the state that
        # gets committed by mistake.
        found_ciphertext = any(self.__is_encrypted(f) for f in files)

        # Baseline plaintext checksums, taken before any file is touched. A
        # mismatch against this baseline is the one thing the version-byte
        # check below cannot see.
        before_hashes = self.__plaintext_checksums(files, v2_handler)

        # Everything from here on may leave the working tree re-encrypted
        # before failing - the re-encrypt loop writes ciphertext to disk
        # immediately, well before set_scheme is reached. PR #127's shell
        # harness restores on failure for exactly this reason: a failed
        # migration must never leave ciphertext where a found-as-plaintext
        # repo expects plaintext, since that is how a failed migration
        # becomes an outage. So ANY failure past this point - format verify,
        # content verify, or set_scheme itself raising (e.g. no backend
        # credentials) - goes through the same restore-then-report path.
        try:
            for i, file in enumerate(files, 1):
                self.output.progress(f"[{i}/{total}] {file}")
                v2_handler.decrypt_file(file)
                v2_handler.encrypt_file(file)

            # Verify-after: each file must be encrypted and have the v2
            # version byte. This proves the FORMAT changed; it cannot see
            # content loss, which is what the checksum comparison below is
            # for.
            v2_byte = AesEncryptionHandler.V2
            failed_files = []
            for file in files:
                if not self.__is_encrypted(file):
                    failed_files.append(file)
                    continue
                try:
                    with open(file, "rb") as fh:
                        fh.read(len(self.magic_header))  # skip magic header
                        byte = fh.read(1)
                    if byte != v2_byte:
                        failed_files.append(file)
                except IOError:
                    failed_files.append(file)

            if failed_files:
                raise _UpgradeAbort(
                    f"verify failed - {len(failed_files)} file(s) not v2 "
                    f"after re-encryption: {failed_files}",
                    failed_files=failed_files,
                )

            # Content verification: decrypt every file again and compare
            # against the baseline. A mismatch is a hard failure - set_scheme
            # is NOT called, so the blob stays v1 and the committed blob
            # (never touched by this command) stays the recovery path. Never
            # logs a plaintext byte: checksums and paths only.
            after_hashes = self.__plaintext_checksums(files, v2_handler)
            mismatched = sorted(
                f for f in files if before_hashes.get(f) != after_hashes.get(f)
            )
            if mismatched:
                raise _UpgradeAbort(
                    f"content verification failed - decrypted content "
                    f"changed for {len(mismatched)} file(s): {mismatched}",
                    mismatched_files=mismatched,
                )

            # Fail-safe: flip the blob to v2 only after both checks pass.
            self.key_manager.set_scheme(filter_name, "v2")
        except _UpgradeAbort as e:
            self.__abort_upgrade(
                filter_name, files, v2_handler, found_ciphertext, e.error, **e.fields
            )
        except Exception as e:
            # Anything else - most commonly set_scheme raising because the
            # backend is unreachable (no credentials, network) - must never
            # surface as a raw traceback. --all depends on this to report a
            # per-filter outcome instead of crashing mid-run.
            self.__abort_upgrade(
                filter_name,
                files,
                v2_handler,
                found_ciphertext,
                f"upgrade failed: {e}",
            )

        # Restore the tree to the state it was found in. The re-encrypt loop
        # above always leaves ciphertext; a tree found as plaintext must end
        # decrypted. A failure here does NOT undo the (already successful)
        # scheme flip - the blob is v2 and staying v2 is correct - but it
        # must never be reported as a plain success: an automated --json
        # caller, or upgrade_scheme_all, must be able to see that the tree
        # still needs attention.
        restore_failures = self.__restore_to_found_state(
            files, v2_handler, found_ciphertext
        )

        if restore_failures:
            failed_paths = [f for f, _ in restore_failures]
            self.output.error(
                f"upgrade-scheme: filter '{filter_name}' upgraded to v2 "
                f"successfully - the key blob IS v2 now, and re-running "
                f"upgrade-scheme on '{filter_name}' is a no-op - but "
                f"restoring the working tree to plaintext failed for "
                f"{len(failed_paths)} file(s): {failed_paths}. Do NOT "
                f"re-run the migration. Fix the tree, not the key, with: "
                f"git-secret-protector decrypt-files {filter_name}"
            )
            self.output.result(
                self._envelope_err(
                    "upgrade-scheme",
                    f"upgraded to v2, but failed to restore the working "
                    f"tree for {len(failed_paths)} file(s)",
                    filter=filter_name,
                    scheme_flip_succeeded=True,
                    restore_failed_files=failed_paths,
                )
            )
            sys.exit(_RESTORE_INCOMPLETE_EXIT_CODE)

        msg = f"Successfully upgraded filter '{filter_name}' to scheme v2"
        self.output.info(msg)
        self.output.result(
            self._envelope_ok(
                "upgrade-scheme",
                filter=filter_name,
                message=msg,
                counts={"reencrypted": total, "total": total},
            )
        )

    def upgrade_scheme_all(self, assume_yes: bool = False):
        filter_names = sorted(self.git_attributes_parser.get_filter_names())

        # Enumeration itself can fail: get_scheme reads the key blob, which
        # for an uncached filter means hitting the backend - and a repo's
        # whole point is that most filters are NOT locally cached (measured:
        # 50 of 198 sensitive filters in the estate audit have no local
        # cache). That makes an uncached key the NORMAL first action of
        # --all, not an edge case, so this gets the same controlled-abort
        # handling as the upgrade loop itself: no traceback, name the
        # filter, say plainly that nothing was touched yet (no file has been
        # read or re-encrypted at this point), and stop.
        pending = []
        for name in filter_names:
            try:
                scheme = self.key_manager.get_scheme(name)
            except Exception as e:
                self.output.error(
                    f"upgrade-scheme --all: could not read filter '{name}'s "
                    f"scheme: {e}. Nothing was touched."
                )
                self.output.result(
                    self._envelope_err(
                        "upgrade-scheme",
                        f"could not read filter '{name}'s scheme: {e}",
                        filter="--all",
                        failed_filter=name,
                    )
                )
                sys.exit(1)
            if scheme == "v2":
                self.output.info(f"Filter '{name}' is already on scheme v2; skipping.")
                continue
            pending.append(name)

        if not pending:
            msg = "No v1 filters found; nothing to upgrade."
            self.output.info(msg)
            self.output.result(
                self._envelope_ok(
                    "upgrade-scheme", filter="--all", message=msg, upgraded=[]
                )
            )
            return

        all_files = []
        filter_map = {}
        for name in pending:
            files_for_name = self.git_attributes_parser.get_files_for_filter(name)
            all_files.extend(files_for_name)
            # --all spans MULTIPLE KEYS, so each path must resolve to the
            # filter that actually owns it - a single shared handler would be
            # wrong here, unlike the single-filter upgrade_scheme above.
            for f in files_for_name:
                filter_map[f] = name

        # Preflight runs ONCE, before any filter is touched, over every file
        # that will actually be re-encrypted by this run.
        if all_files:
            plaintext_of = self.__plaintext_of_resolver(filter_map)
            notes = []
            refusals = check_repo_preflight(
                all_files, cwd=self.base_dir, plaintext_of=plaintext_of, notes=notes
            )
            for note in notes:
                self.output.info(f"upgrade-scheme --all: {note}")
            if refusals:
                for refusal in refusals:
                    self.output.error(f"upgrade-scheme --all: refusing - {refusal}")
                self.output.result(
                    self._envelope_err(
                        "upgrade-scheme",
                        "preflight refused",
                        filter="--all",
                        refusals=refusals,
                        notes=notes,
                    )
                )
                sys.exit(1)

        if not assume_yes:
            try:
                answer = input(
                    f"Upgrade {len(pending)} filter(s) from v1 to v2 "
                    f"({', '.join(pending)}; {len(all_files)} file(s) total)? "
                    f"This re-encrypts ALL matched files. [y/N] "
                )
            except EOFError:
                answer = ""
            if answer.strip().lower() not in {"y", "yes"}:
                self.output.error("Aborted.")
                return

        upgraded = []
        failed = []
        restore_incomplete_filter = None
        for name in pending:
            try:
                self.upgrade_scheme(name, assume_yes=True, skip_preflight=True)
            except SystemExit as e:
                if e.code == _RESTORE_INCOMPLETE_EXIT_CODE:
                    # Not a failed upgrade: the scheme flip for this filter
                    # DID succeed. Counted as upgraded, but the run still
                    # stops here - the tree needs a human, not the next
                    # filter.
                    upgraded.append(name)
                    restore_incomplete_filter = name
                else:
                    # The expected failure shape: upgrade_scheme itself
                    # already restored the tree and reported that filter's
                    # error envelope.
                    failed.append(name)
                break
            except Exception as e:
                # Defense in depth: upgrade_scheme is expected to catch and
                # report every failure itself, but --all must never let a
                # traceback escape and skip the per-filter report even if
                # that containment has a gap.
                self.output.error(
                    f"upgrade-scheme --all: filter '{name}' raised unexpectedly: {e}"
                )
                self.output.result(
                    self._envelope_err(
                        "upgrade-scheme",
                        f"filter '{name}' raised unexpectedly: {e}",
                        filter=name,
                    )
                )
                failed.append(name)
                break
            upgraded.append(name)

        if restore_incomplete_filter:
            not_attempted = [n for n in pending if n not in upgraded]
            self.output.error(
                f"upgrade-scheme --all: stopping after '{restore_incomplete_filter}' "
                f"upgraded to v2 successfully, but its working tree restore "
                f"failed - this is a human follow-up on the WORKING TREE, "
                f"not a failed upgrade; the key blob for "
                f"'{restore_incomplete_filter}' is already v2. "
                f"Upgraded: {upgraded}. Not attempted: {not_attempted or 'none'}."
            )
            self.output.result(
                self._envelope_err(
                    "upgrade-scheme",
                    f"filter '{restore_incomplete_filter}' upgraded to v2, "
                    f"but its working tree restore failed",
                    filter="--all",
                    upgraded=upgraded,
                    scheme_flip_succeeded=True,
                    restore_incomplete_filter=restore_incomplete_filter,
                    not_attempted=not_attempted,
                )
            )
            sys.exit(_RESTORE_INCOMPLETE_EXIT_CODE)

        if failed:
            not_attempted = [
                n for n in pending if n not in upgraded and n not in failed
            ]
            self.output.error(
                f"upgrade-scheme --all: stopped after '{failed[0]}' failed. "
                f"Upgraded: {upgraded or 'none'}. "
                f"Not attempted: {not_attempted or 'none'}."
            )
            self.output.result(
                self._envelope_err(
                    "upgrade-scheme",
                    f"filter '{failed[0]}' failed",
                    filter="--all",
                    upgraded=upgraded,
                    failed=failed,
                    not_attempted=not_attempted,
                )
            )
            sys.exit(1)

        msg = (
            f"Successfully upgraded {len(upgraded)} filter(s) to scheme v2: "
            f"{', '.join(upgraded)}"
        )
        self.output.info(msg)
        self.output.result(
            self._envelope_ok(
                "upgrade-scheme", filter="--all", message=msg, upgraded=upgraded
            )
        )

    def rotate_keys(self, filter_name: str, assume_yes: bool = False):
        filter_name = self._require_filter(filter_name)
        self._print_context(filter_name)
        try:
            files = self.git_attributes_parser.get_files_for_filter(filter_name)

            if files:
                filter_map = {f: filter_name for f in files}
                plaintext_of = self.__plaintext_of_resolver(filter_map)
                notes = []
                refusals = check_repo_preflight(
                    files, cwd=self.base_dir, plaintext_of=plaintext_of, notes=notes
                )
                for note in notes:
                    self.output.info(f"rotate-key: {note}")
                if refusals:
                    for refusal in refusals:
                        self.output.error(f"rotate-key: refusing - {refusal}")
                    self.output.result(
                        self._envelope_err(
                            "rotate-key",
                            "preflight refused",
                            filter=filter_name,
                            refusals=refusals,
                            notes=notes,
                        )
                    )
                    sys.exit(1)

            if not assume_yes:
                try:
                    answer = input(
                        f"Rotate key for filter '{filter_name}'? This re-encrypts ALL "
                        f"matched files. The current key becomes UNRECOVERABLE once "
                        f"rotation writes the new one - any clone holding the old "
                        f"cache must run pull-aes-key afterward. [y/N] "
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
            self.key_rotator.rotate_key(filter_name)
            logger.info("Key rotation complete for filter: %s", filter_name)
            msg = f"Key rotation complete for filter: {filter_name}"
            self.output.info(msg)
            self.output.result(
                self._envelope_ok("rotate-key", filter=filter_name, message=msg)
            )
        except Exception as e:
            logger.error(f"Rotate keys command failed: {e}", exc_info=True)
            self.output.error(f"Rotate keys command failed: {e}")
            fields = dict(getattr(e, "fields", {}) or {})
            if fields.get("rotation_succeeded"):
                # The blob IS already rotated - this is a human follow-up on the
                # WORKING TREE, not a failed rotation. Re-running would rotate again.
                self.output.error(
                    f"rotate-key: filter '{filter_name}' rotation succeeded - do "
                    f"NOT re-run it - but restoring the working tree failed."
                )
            self.output.result(
                self._envelope_err(
                    "rotate-key",
                    str(getattr(e, "error", e)),
                    filter=filter_name,
                    **fields,
                )
            )
            sys.exit(
                _RESTORE_INCOMPLETE_EXIT_CODE if fields.get("rotation_succeeded") else 1
            )

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
            scheme_unknown = False
            for filter_name in filter_names:
                files = self.git_attributes_parser.get_files_for_filter(filter_name)
                file_entries = [
                    {"path": f, "encrypted": self.__is_encrypted(file_path=f)}
                    for f in files
                ]
                entry = {"name": filter_name, "files": file_entries}
                try:
                    # Report whatever get_scheme actually returned - never round an
                    # unrecognized value to v2. v2 means "already migrated, skip",
                    # so rounding here is how a scheme read failure silently
                    # under-counts the migration estate.
                    entry["scheme"] = self.key_manager.get_scheme(filter_name)
                except Exception as e:
                    entry["scheme"] = "unknown"
                    entry["scheme_error"] = str(e)
                    scheme_unknown = True
                data["filters"].append(entry)

            if self.output.json:
                self.output.result(data)
                if scheme_unknown:
                    sys.exit(1)
                return

            for entry in data["filters"]:
                safe_print(f"Filter: {entry['name']}")
                safe_print(f"  scheme: {entry['scheme']}")
                if entry.get("scheme_error"):
                    safe_print(f"  scheme_error: {entry['scheme_error']}")
                if entry["files"]:
                    for f in entry["files"]:
                        status = "Encrypted" if f["encrypted"] else "⚠ PLAINTEXT"
                        safe_print(f"  {f['path']}: {status}")
                else:
                    safe_print("  No files found for this filter.")

            if scheme_unknown:
                sys.exit(1)
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

        # Surface which schemes this client can read/produce so version skew across a
        # team is diagnosable here, before a mismatched blob breaks someone's checkout.
        checks.append(
            {
                "check": "supported_schemes",
                "status": "ok",
                "detail": (
                    f"this client supports schemes: {', '.join(SUPPORTED_SCHEMES)} "
                    f"(new-key default: {settings.encryption_scheme})"
                ),
            }
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
            # One call covering all three keys (not the previous separate get-per-key
            # calls): doctor reports which mode is ACTIVE, and both clean/smudge and
            # process will be present by design once a repo adopts the process
            # filter - a single read is enough to derive active mode from precedence.
            config_out = subprocess.run(
                [
                    "git",
                    "config",
                    "--get-regexp",
                    f"^filter\\.{filter_name}\\.(clean|smudge|process)$",
                ],
                capture_output=True,
                text=True,
            ).stdout
            configured = {}
            for line in config_out.splitlines():
                key, sep, value = line.partition(" ")
                if sep:
                    configured[key.rsplit(".", 1)[-1]] = value

            check_clean = configured.get("clean", "")
            check_smudge = configured.get("smudge", "")
            check_process = configured.get("process", "")

            # gitattributes(5): a configured process filter always takes precedence
            # over clean/smudge, so `process` present means that IS the active mode
            # regardless of whether clean/smudge are also present (they always are,
            # by design - see setup_filters).
            if check_process:
                checks.append(
                    {
                        "check": "git_config",
                        "status": "ok",
                        "detail": f"filter '{filter_name}' active mode: process ({check_process})",
                        "filter": filter_name,
                    }
                )
            elif check_clean and check_smudge:
                checks.append(
                    {
                        "check": "git_config",
                        "status": "ok",
                        "detail": f"filter '{filter_name}' active mode: clean/smudge",
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

        for filter_name in filter_names:
            try:
                scheme, version_present = self.key_manager.get_scheme_info(filter_name)
            except Exception as e:
                checks.append(
                    {
                        "check": "scheme",
                        "status": "warn",
                        "detail": (
                            f"filter '{filter_name}' scheme could not be determined: {e}"
                        ),
                        "filter": filter_name,
                    }
                )
                continue
            if scheme == "v2":
                checks.append(
                    {
                        "check": "scheme",
                        "status": "ok",
                        "detail": f"filter '{filter_name}' uses authenticated scheme v2",
                        "filter": filter_name,
                    }
                )
            elif version_present:
                checks.append(
                    {
                        "check": "scheme",
                        "status": "warn",
                        "detail": (
                            f"filter '{filter_name}' uses legacy unauthenticated scheme v1 "
                            f"(run upgrade-scheme once all clients are >=1.4.0)"
                        ),
                        "filter": filter_name,
                    }
                )
            else:
                checks.append(
                    {
                        "check": "scheme",
                        "status": "warn",
                        "detail": (
                            f"filter '{filter_name}' key blob has no version field; "
                            f"treating as legacy unauthenticated v1. Run "
                            f"'upgrade-scheme {filter_name}' to adopt authenticated v2."
                        ),
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
                # Working-tree plaintext is the correct, smudged state - the
                # working tree alone can never tell a healthy repo from a leak.
                # Only a HEAD comparison can: committed ciphertext means the
                # filter did its job, committed plaintext means it never ran.
                if self.__is_encrypted(file_path):
                    continue

                head_content = self.__read_head_bytes(file_path)
                if head_content is None:
                    checks.append(
                        {
                            "check": "plaintext_scan",
                            "status": "warn",
                            "detail": f"{file_path} is plaintext and not yet committed; it will be encrypted on add",
                            "filter": filter_name,
                        }
                    )
                elif not head_content.startswith(self.magic_header):
                    plaintext_files.append(file_path)
                    failed = True
                    checks.append(
                        {
                            "check": "plaintext_scan",
                            "status": "fail",
                            "detail": f"{file_path} is COMMITTED AS PLAINTEXT: the blob in HEAD is not encrypted, so the secret is in git history. Re-encrypt it and rewrite the affected commits; rotate the credential, since it is already pushed.",
                            "filter": filter_name,
                        }
                    )

            if not plaintext_files:
                checks.append(
                    {
                        "check": "plaintext_scan",
                        "status": "ok",
                        "detail": f"no unencrypted commits found for '{filter_name}'",
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
                safe_print(f"{label} {lines[0]}")
                for sub in lines[1:]:
                    safe_print(sub)
            else:
                safe_print(f"{label} {detail}")

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
                safe_print(
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
                safe_print("Keeping existing config.", file=sys.stderr)
                return 0

        # Resolve backend.
        valid_backends = {m.value for m in StorageType}
        if backend is not None:
            if backend not in valid_backends:
                safe_print(
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
                    safe_print(
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
            "encryption_scheme": "v2",  # v2 = authenticated (default); v1 = legacy AES-CBC, opt-down for pre-1.4.0 clients
            "log_level": "WARN",
            "log_max_size": "1048576",
        }
        with open(settings.config_file, "w") as fh:
            cfg.write(fh)

        safe_print(f"Initialized git-secret-protector config at {settings.config_file}")
        safe_print(f"  backend: {backend}\n  module_name: {module_name}")
        return 0

    @staticmethod
    def _get_poetry_root_path():
        # Start from the current directory and look for pyproject.toml upward
        current_path = Path(__file__).resolve()
        for parent in current_path.parents:
            if (parent / "pyproject.toml").exists():
                return parent

    @staticmethod
    def __init_filter(filter_name: str, use_process: bool = False):
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
            if use_process:
                # gitattributes(5): a configured process filter always takes
                # precedence over clean/smudge, so writing `process` here while
                # leaving clean/smudge untouched keeps them as the rollback path.
                subprocess.run(
                    [
                        "git",
                        "config",
                        f"filter.{filter_name}.process",
                        f"git-secret-protector filter-process {filter_name}",
                    ],
                    check=True,
                )
            else:
                # Declarative: config must match the flags given. Best-effort
                # unset (exits non-zero if nothing was set) so a plain re-run
                # is the escape hatch for anyone left with `process` from a
                # prior default-on setup.
                unset_result = subprocess.run(
                    ["git", "config", "--unset", f"filter.{filter_name}.process"],
                    capture_output=True,
                    text=True,
                )
                if unset_result.returncode == 0:
                    logger.info("Removed filter.%s.process (opt-in only)", filter_name)
                    sys.stdout.buffer.write(
                        f"Removed existing filter.{filter_name}.process "
                        "(opt-in only; re-run with --process to re-enable).".encode(
                            "utf-8"
                        )
                        + b"\n"
                    )
                    sys.stdout.buffer.flush()
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
        if use_process:
            subprocess.run(
                [
                    "git",
                    "config",
                    f"filter.{filter_name}.process",
                    f"git-secret-protector filter-process {filter_name}",
                ],
                check=True,
            )
        subprocess.run(
            ["git", "config", f"filter.{filter_name}.required", "true"], check=True
        )
        logger.debug(
            "Git clean, smudge & filters for '%s' have been set up successfully.",
            filter_name,
        )

    def __get_encryption_handler(self, filter_name: str, cache_only: bool = False):
        aes_key, iv = self.key_manager.retrieve_key_and_iv(
            filter_name, cache_only=cache_only
        )
        scheme = self.key_manager.get_scheme(filter_name)
        return AesEncryptionHandler(
            aes_key=aes_key, iv=iv, magic_header=self.magic_header, scheme=scheme
        )

    def __plaintext_of_resolver(self, filter_map):
        """Build the `plaintext_of` callback check_repo_preflight calls to
        decrypt a ciphertext difference down to a content comparison.

        Mirrors __plaintext_checksums's own magic-header test: decrypt only
        when the bytes are actually ciphertext, else return them unchanged
        (a matched file is not required to be encrypted at every point in
        its history). Uses `_decrypt_bytes`, which is `cache_only=True` -
        an uncached key raises, and the gate must report that as
        cannot-compare rather than silently fetching the key itself.
        """

        def plaintext_of(path, data):
            if not data.startswith(self.magic_header):
                return data
            return self._decrypt_bytes(filter_map[path], data)

        return plaintext_of

    def __plaintext_checksums(self, files, handler):
        return tree_state.plaintext_checksums(files, handler, self.magic_header)

    def __restore_to_found_state(self, files, handler, found_ciphertext):
        return tree_state.restore_to_found_state(
            files, handler, found_ciphertext, self.magic_header
        )

    def __git_checkout_files(self, files):
        return tree_state.git_checkout_files(files, self.base_dir)

    def __restore_on_abort(self, files, handler, found_ciphertext):
        return tree_state.restore_on_abort(
            files,
            handler,
            found_ciphertext,
            self.magic_header,
            self.output.error,
            self.base_dir,
            checkout=self.__git_checkout_files,
            restore=self.__restore_to_found_state,
        )

    def __abort_upgrade(
        self, filter_name, files, handler, found_ciphertext, error, **fields
    ):
        """Shared failure path once the re-encrypt loop has started: restore
        the tree to the state it was found in, report the error envelope, and
        exit. The key blob is never flipped before this point is reached, so
        it stays at v1 - recoverable - no matter which check failed.
        """
        self.output.error(f"upgrade-scheme: {error}")
        restore_failures = self.__restore_on_abort(files, handler, found_ciphertext)
        if restore_failures:
            failed_paths = [f for f, _ in restore_failures]
            self.output.error(
                f"upgrade-scheme: FAILED TO RESTORE the working tree for "
                f"{len(failed_paths)} file(s) - they may be left as "
                f"ciphertext where this repo expects plaintext. Intervene by "
                f"hand: {failed_paths}"
            )
            fields = {**fields, "restore_failed_files": failed_paths}
        self.output.result(
            self._envelope_err("upgrade-scheme", error, filter=filter_name, **fields)
        )
        sys.exit(1)

    def __is_encrypted(self, file_path: str):
        return tree_state.is_encrypted(file_path, self.magic_header)

    def __read_head_bytes(self, file_path: str):
        """Return file_path's committed bytes at HEAD, or None if it isn't there.

        A missing HEAD (fresh repo, no commits) and a path not yet committed
        both surface as a non-zero git exit here, and both mean "not in HEAD" -
        neither is a leak. Never logged: the return value is a secret's bytes.
        """
        rel_path = os.path.relpath(file_path, self.base_dir)
        try:
            result = subprocess.run(
                ["git", "show", f"HEAD:{rel_path}"],
                cwd=self.base_dir,
                capture_output=True,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout
