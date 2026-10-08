import logging
import os

import injector

from git_secret_protector.core import tree_state
from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.core.output import Output
from git_secret_protector.core.settings import get_settings
from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler
from git_secret_protector.crypto.aes_key_manager import AesKeyManager

logger = logging.getLogger(__name__)


class _RotationAbort(Exception):
    """Internal signal for a controlled rotate_key failure before the blob is
    replaced (as opposed to an unexpected exception) - carries the envelope
    fields rotate_keys should report alongside the restore outcome."""

    def __init__(self, error, **fields):
        super().__init__(error)
        self.error = error
        self.fields = fields


class KeyRotator:
    @injector.inject
    def __init__(
        self,
        key_manager: AesKeyManager,
        git_attributes_parser: GitAttributesParser,
        output: Output = None,
    ):
        self.aes_key_manager = key_manager
        self.git_attributes_parser = git_attributes_parser
        self.output = output if output is not None else Output()
        settings = get_settings()
        self.magic_header = settings.magic_header.encode()
        self.base_dir = settings.base_dir

    def rotate_key(self, filter_name: str):
        logger.info("Starting key and IV rotation for filter: %s", filter_name)

        # Step 1: Read the CURRENT key from the backend, not the cache - the cache can
        # be stale, and since the magic header is not key-derived, a wrong-key v1
        # decrypt below would yield garbage silently instead of raising.
        old_key, old_iv = self.aes_key_manager.retrieve_key_and_iv(
            filter_name=filter_name, force=True
        )

        # Step 2: Read the scheme now that the cache the read above refreshed is
        # correct - rotation preserves whatever scheme the filter is on today.
        scheme = self.aes_key_manager.get_scheme(filter_name)

        files = self.git_attributes_parser.get_files_for_filter(filter_name=filter_name)

        if not files:
            # A filter with no matched files is legitimate - still rotate the key,
            # there is nothing on disk to transform or verify.
            self.aes_key_manager.replace_key_and_iv(
                filter_name=filter_name, scheme=scheme
            )
            logger.info(
                "Key and IV rotation complete for filter: %s (no matched files)",
                filter_name,
            )
            return

        # Handler scheme defaults to v2, but decryption is version-byte-authoritative
        # so this was only caught by the abort fallback re-encrypting with the wrong scheme.
        old_handler = AesEncryptionHandler(
            aes_key=old_key, iv=old_iv, magic_header=self.magic_header, scheme=scheme
        )

        # Record, before touching anything, whether the tree was found at rest as
        # plaintext or ciphertext, and a content baseline to verify against later.
        found_ciphertext = any(
            tree_state.is_encrypted(f, self.magic_header) for f in files
        )
        before = tree_state.plaintext_checksums(files, old_handler, self.magic_header)

        # New key material generated IN MEMORY ONLY - nothing is stored until step 8
        # below (replace_key_and_iv), once the re-encrypt is proven, not before.
        new_key = os.urandom(AesKeyManager.AES_KEY_SIZE)
        new_iv = os.urandom(AesKeyManager.IV_SIZE)
        new_handler = AesEncryptionHandler(
            aes_key=new_key, iv=new_iv, magic_header=self.magic_header, scheme=scheme
        )

        converted = []
        was_encrypted = {}
        in_flight = None

        # Define the restore function for the abort paths: restore converted files
        # to their original state (encrypted or plaintext) using the old key.
        def restore_converted_files(files_to_restore, handler, found_ciphertext_state):
            failures = []
            for file in files_to_restore:
                # open(..., "wb") truncates before the write, so a mid-write failure
                # leaves the file truncated or half-written. Re-encrypting truncated
                # bytes would cement the corruption. Report it instead, routing to
                # restore_failed_files so the operator is told to recover via checkout.
                if file == in_flight:
                    failures.append(
                        (
                            file,
                            "file was interrupted mid-write and is unrecoverable by "
                            "re-encryption - bytes are not recoverable. Recovery: "
                            f"run `git checkout -- {file}` to restore from the committed blob",
                        )
                    )
                    continue
                if file not in converted:
                    # File was never transformed - leave it alone.
                    continue
                try:
                    with open(file, "rb") as fh:
                        data = fh.read()
                    if data.startswith(self.magic_header):
                        data = new_handler.decrypt_data(data)
                    if was_encrypted[file]:
                        data = old_handler.encrypt_data(data)
                    with open(file, "wb") as fh:
                        fh.write(data)
                except Exception as err:
                    failures.append((file, str(err)))
            return failures

        try:
            for file in files:
                with open(file, "rb") as fh:
                    data = fh.read()
                was_encrypted[file] = data.startswith(self.magic_header)
                if was_encrypted[file]:
                    data = old_handler.decrypt_data(data)
                data = new_handler.encrypt_data(data)
                in_flight = file
                with open(file, "wb") as fh:
                    fh.write(data)
                converted.append(file)
                in_flight = None

            # Verify: re-read from disk and compare decrypted content against the
            # baseline. Scoped honestly - both sides are the same scheme in one
            # process, so this catches a truncated/failed write or a key mix-up,
            # NOT an encryption defect.
            after = tree_state.plaintext_checksums(
                files, new_handler, self.magic_header
            )
            mismatched = sorted(f for f in files if before.get(f) != after.get(f))
            if mismatched:
                raise _RotationAbort(
                    f"verify failed - decrypted content changed for "
                    f"{len(mismatched)} file(s) after rotation: {mismatched}",
                    mismatched_files=mismatched,
                )
        except Exception as e:
            if not isinstance(e, _RotationAbort):
                e = _RotationAbort(f"rotation failed before the key was replaced: {e}")

            restore_failures = tree_state.restore_on_abort(
                files,
                new_handler,
                found_ciphertext,
                self.magic_header,
                self.output.error,
                base_dir=self.base_dir,
                restore=restore_converted_files,
            )
            if restore_failures:
                e.fields["restore_failed_files"] = [f for f, _ in restore_failures]
            raise e

        # The ONLY backend write, and only now that the re-encrypt is proven. After
        # this the old key is unrecoverable - pass the EXACT material the files were
        # just encrypted with, never a freshly generated one.
        try:
            self.aes_key_manager.replace_key_and_iv(
                filter_name=filter_name, scheme=scheme, aes_key=new_key, iv=new_iv
            )
        except Exception as blob_error:
            # Ambiguity: generate_and_store does store(...) then cache_key_iv_locally(...),
            # so "it raised" covers both blob-not-replaced and blob-replaced-but-cache-failed.
            # Discriminate by asking the backend what it now holds.
            try:
                current_key, _ = self.aes_key_manager.retrieve_key_and_iv(
                    filter_name=filter_name, force=True
                )
            except Exception as retrieve_error:
                # Backend state is unknown - do NOT guess and do NOT touch the tree.
                raise _RotationAbort(
                    f"rotate-key: filter '{filter_name}' could not verify whether the key "
                    f"blob was replaced after a write failure. State is unknown. Recovery: "
                    f"(1) `git-secret-protector pull-aes-key {filter_name}` to re-sync the "
                    f"local cache; (2) `git checkout -- {' '.join(files[:3])}{'...' if len(files) > 3 else ''}` "
                    f"to restore the working tree if needed. Original error: {blob_error}",
                    rotation_succeeded=None,
                )

            # Compare the retrieved key to the new key.
            if current_key == new_key:
                # Blob IS live. Treat like post-write success: restore and report
                # that the rotation IS done and re-running is WRONG.
                restore_failures = tree_state.restore_to_found_state(
                    files, new_handler, found_ciphertext, self.magic_header
                )
                failed_paths = (
                    [f for f, _ in restore_failures] if restore_failures else []
                )
                raise _RotationAbort(
                    f"rotate-key: filter '{filter_name}' rotated successfully - the "
                    f"key blob IS rotated, and re-running rotation is wrong"
                    + (
                        f" - but restoring the working tree failed for {len(failed_paths)} "
                        f"file(s): {failed_paths}"
                        if failed_paths
                        else ""
                    ),
                    rotation_succeeded=True,
                    restore_failed_files=failed_paths,
                )
            else:
                # Blob was NOT replaced. Run the pre-write abort restore.
                restore_failures = tree_state.restore_on_abort(
                    files,
                    new_handler,
                    found_ciphertext,
                    self.magic_header,
                    self.output.error,
                    base_dir=self.base_dir,
                    restore=restore_converted_files,
                )
                raise _RotationAbort(
                    f"rotate-key: filter '{filter_name}' key blob was NOT replaced - "
                    f"working tree restore in progress",
                    rotation_succeeded=False,
                    restore_failed_files=(
                        [f for f, _ in restore_failures] if restore_failures else []
                    ),
                )

        # Hand the tree back in the state it was found in.
        restore_failures = tree_state.restore_to_found_state(
            files, new_handler, found_ciphertext, self.magic_header
        )
        if restore_failures:
            failed_paths = [f for f, _ in restore_failures]
            raise _RotationAbort(
                f"rotate-key: filter '{filter_name}' rotated successfully - the "
                f"key blob IS rotated, and re-running rotation is wrong - but "
                f"restoring the working tree failed for {len(failed_paths)} "
                f"file(s): {failed_paths}",
                rotation_succeeded=True,
                restore_failed_files=failed_paths,
            )

        logger.info(
            "Key and IV rotation and re-encryption complete for filter: %s",
            filter_name,
        )
