import logging
import subprocess

logger = logging.getLogger(__name__)


def is_encrypted(file_path: str, magic_header: bytes) -> bool:
    try:
        with open(file_path, "rb") as file:
            header = file.read(len(magic_header))
            return header == magic_header
    except IOError:
        logger.error(f"Error reading file: {file_path}")
        return False


def git_checkout_files(files, base_dir: str = None) -> bool:
    """`git checkout -- <files>`, never raising. Returns True on success.

    Relies on every matched file being tracked - the untracked-file
    preflight gate exists precisely so this is always viable on the
    abort path, and pays for nothing if it is never used.
    """
    if not files:
        return True
    try:
        result = subprocess.run(
            ["git", "checkout", "--", *files],
            cwd=base_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def restore_to_found_state(files, handler, found_ciphertext: bool, magic_header: bytes):
    """Best-effort: hand the tree back in the state it was found in.

    Called on BOTH the success and failure paths, since the files are
    already re-encrypted by the time any later check can fail (PR #127's
    lesson: a failed migration must never leave ciphertext where a
    found-as-plaintext repo expects plaintext).

    Each file is judged by its CURRENT state on disk, never by assuming the
    re-encrypt loop ran to completion. That loop decrypts and then
    re-encrypts each file in turn, so a failure BETWEEN those two writes -
    a full disk, an I/O error - leaves that one file as PLAINTEXT. An
    earlier version returned early for a found-as-ciphertext tree, on the
    reasoning that such a tree is already where it started; that is only
    true of a completed loop, and the cost of the gap was plaintext secrets
    sitting in a repo that stores ciphertext, reported as a clean abort and
    committable.

    Returns a list of (file, error) for any file that could not be
    restored - those need a human. Never raises.
    """
    failures = []
    for file in files:
        try:
            file_is_encrypted = is_encrypted(file, magic_header)
            if found_ciphertext and not file_is_encrypted:
                handler.encrypt_file(file)
            elif not found_ciphertext and file_is_encrypted:
                handler.decrypt_file(file)
        except Exception as e:
            failures.append((file, str(e)))
    return failures


def restore_on_abort(
    files,
    handler,
    found_ciphertext: bool,
    magic_header: bytes,
    on_error,
    base_dir: str = None,
    checkout=None,
    restore=None,
):
    """Restore used ONLY on ABORT - deliberately different from the
    success-path restore (restore_to_found_state), which must leave
    freshly re-encrypted v2 content in place because that IS the
    intended change. On abort there is no intended change: the files
    must come back exactly as committed.

    `git checkout -- <files>` returns the exact committed bytes and, on
    its own, lands the correct at-rest state in both shapes - where
    filters are configured the smudge filter decrypts on checkout; where
    they are not, the raw committed ciphertext comes back untouched. A
    crypto-based re-encrypt of a found-as-ciphertext tree cannot do
    this: it produces FRESH v2 bytes with no committed blob behind them,
    diverging from a v1-declared blob - the declared-scheme-vs-stored-
    bytes bug CLAUDE.md records for the 1.9.0 regression, now showing up
    on the abort path instead.

    A SUCCESSFUL checkout is trusted, and deliberately NOT second-guessed
    against the found at-rest state. An earlier version compared the two
    and fell back to the crypto restore on a mismatch, which reintroduced
    the very bug this method exists to fix: on a checkout with filters
    configured whose files nonetheless sat as ciphertext at rest (someone
    ran encrypt-files by hand), checkout correctly smudges them back to
    plaintext, the comparison reads that as a mismatch, and the fallback
    re-encrypts to fresh v2 bytes under a v1 blob. Measured, not reasoned
    about. Whatever checkout produces IS the canonical state for that
    checkout's configuration; a found state disagreeing with it was itself
    the anomaly.

    The crypto restore remains the fallback for the one case that needs
    it: checkout itself failing.
    """
    if checkout is None:

        def checkout(fs):
            return git_checkout_files(fs, base_dir)

    if restore is None:

        def restore(fs, h, fc):
            return restore_to_found_state(fs, h, fc, magic_header)

    if checkout(files):
        return []
    on_error(
        "upgrade-scheme: git checkout failed while restoring the "
        "working tree; falling back to decrypt/encrypt-based restore."
    )
    return restore(files, handler, found_ciphertext)
