"""Repo-level safety gates for destructive, repo-wide crypto operations.

Ported from scripts/migration/verify-upgrade-scheme.sh (merged in PRs #127 and
#128) rather than reinvented - that script's comments record the incident
each gate closes. This module owns only the DECISION (refuse or not); the
caller decides how to report and what to do next.

check_repo_preflight() returns a list of human-readable refusal strings. An
empty list means clear. Every refusal names what to do about it, not just
what is wrong.
"""

import hashlib
import os
import subprocess

DEFAULT_MAX_BEHIND = 0
_GIT_TIMEOUT_SECS = 15

# The only two modes a `git diff --raw` blob side can carry that this gate
# treats as "a regular file, nothing mode-wise happened to it". Anything else
# - 120000 (symlink) or 160000 (gitlink/submodule) in particular - is a type
# change this gate must never wave through on plaintext equality alone.
_REGULAR_BLOB_MODES = {"100644", "100755"}


def _run_git(args, cwd):
    """subprocess.run wrapper that never raises - a failed git call becomes a
    non-zero CompletedProcess so callers can fail closed without a try/except
    at every call site."""
    try:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECS,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(
            args=args, returncode=1, stdout="", stderr=str(e)
        )


def _run_git_bytes(args, cwd):
    """Same never-raises contract as _run_git, but reads stdout as raw bytes.

    `_run_git` is `text=True`, which universal-newline-decodes stdout - that
    would silently alter CRLF plaintext inside a secret blob. Every `git
    show` read of blob content goes through this instead.
    """
    try:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECS,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(
            args=args, returncode=1, stdout=b"", stderr=str(e).encode()
        )


def _relpath_for_git_show(path, cwd):
    """Repo-relative path for a `git show :<path>` / `git show HEAD:<path>`
    spec, or (None, reason) when one cannot be built.

    The real caller (get_files_for_filter) hands this module ABSOLUTE paths.
    `git show :/abs/path` is not a pathspec to git - a leading `:/` is its
    COMMIT-MESSAGE SEARCH syntax - so an absolute path here makes the blob
    read fail with exit 128 on every call, which reads as "cannot read the
    indexed blob" and refuses a perfectly safe scheme-mismatch tree. Only the
    blob-spec reads need this; the worktree file open and the plaintext_of
    resolver keep the original path, since they already cope with it.
    """
    if not os.path.isabs(path):
        # Already relative - nothing to rewrite, and rewriting it would
        # re-resolve against the process's real cwd rather than the
        # caller-supplied one (which in tests is often not a real directory).
        return path, None
    try:
        rel = os.path.relpath(path, cwd)
    except ValueError as e:
        # Different drive on Windows - os.path.relpath cannot express it.
        return None, f"cannot build a repo-relative path for git show: {e}"
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return (
            None,
            "path is outside the repo root, cannot build a git show spec for it",
        )
    return rel, None


def _unstaged_bases(path, cwd):
    """(indexed_blob, worktree_bytes, error) for the unstaged comparison."""
    rel, err = _relpath_for_git_show(path, cwd)
    if err is not None:
        return None, None, err
    indexed = _run_git_bytes(["show", f":{rel}"], cwd)
    if indexed.returncode != 0:
        return None, None, "cannot read the indexed blob"
    try:
        with open(os.path.join(cwd, path), "rb") as fh:
            worktree_bytes = fh.read()
    except OSError:
        return None, None, "the worktree file is missing"
    return indexed.stdout, worktree_bytes, None


def _staged_bases(path, cwd):
    """(HEAD_blob, indexed_blob, error) for the staged comparison.

    Deliberately never reads the worktree - a staged change is judged
    against what is in the index, not what is on disk.
    """
    rel, err = _relpath_for_git_show(path, cwd)
    if err is not None:
        return None, None, err
    head = _run_git_bytes(["show", f"HEAD:{rel}"], cwd)
    if head.returncode != 0:
        return None, None, "cannot read the HEAD blob"
    indexed = _run_git_bytes(["show", f":{rel}"], cwd)
    if indexed.returncode != 0:
        return None, None, "cannot read the indexed blob"
    return head.stdout, indexed.stdout, None


def _diff_raw_modes(scope, path, cwd):
    """(old_mode, new_mode) strings for one path in one diff scope, parsed
    from `git diff --raw`, or None if the output could not be parsed.

    Format: ":<oldmode> <newmode> <oldsha> <newsha> <status>\\t<path>". This
    is the only way to tell a mode-only or type change (chmod, or regular
    file <-> symlink) apart from a real content change - `git diff --quiet`
    reports both as dirty, and a plaintext-equality check alone cannot see
    the mode at all.
    """
    result = _run_git([*scope, "--raw", "--", path], cwd)
    if result.returncode != 0:
        return None
    line = result.stdout.strip()
    if not line:
        return None
    header = line.split("\t", 1)[0]
    parts = header.split()
    if len(parts) < 2:
        return None
    old_mode = parts[0].lstrip(":")
    new_mode = parts[1]
    if not (old_mode.isdigit() and new_mode.isdigit()):
        return None
    return old_mode, new_mode


def check_repo_preflight(
    matched_files, cwd=None, max_behind=None, plaintext_of=None, notes=None
):
    """Return refusal strings for a repo-wide re-encrypt; empty = safe to proceed.

    matched_files are the paths about to be re-encrypted in place.

    plaintext_of(path, data: bytes) -> bytes is a caller-supplied resolver
    this module never imports crypto to perform itself - it is how a
    ciphertext difference gets decrypted down to a content comparison. A
    file that is dirty only because it was committed under one encryption
    scheme while its key blob declares the other decrypts to identical
    plaintext on both sides and is NOT a real edit; callers that pass
    nothing keep the old all-ciphertext-is-an-edit behaviour.

    notes, if given, is a list this function APPENDS human-readable notes
    to (the return value is still the refusal list only).
    """
    cwd = cwd or os.getcwd()
    refusals = []

    if max_behind is None:
        raw = os.environ.get("UPGRADE_SCHEME_MAX_BEHIND")
        if raw is None or raw == "":
            max_behind = DEFAULT_MAX_BEHIND
        else:
            try:
                max_behind = int(raw)
            except ValueError:
                # A garbled override must refuse with a readable message, not
                # raise. An unhandled traceback out of a safety gate reads as a
                # bug in the tool, which is how someone talks themselves into
                # working around the gate instead of fixing the value.
                refusals.append(
                    f"UPGRADE_SCHEME_MAX_BEHIND is set to {raw!r}, which is not "
                    "a whole number. Unset it or give it an integer."
                )
                max_behind = DEFAULT_MAX_BEHIND
            else:
                if max_behind < 0:
                    refusals.append(
                        f"UPGRADE_SCHEME_MAX_BEHIND is {max_behind}, which is "
                        "negative. Unset it or give it zero or more."
                    )
                    max_behind = DEFAULT_MAX_BEHIND

    # A commit from a detached HEAD goes nowhere while the key blob stays
    # flipped, so there is no way to land the migration from here.
    branch_result = _run_git(["symbolic-ref", "--short", "-q", "HEAD"], cwd)
    branch = branch_result.stdout.strip() if branch_result.returncode == 0 else ""
    if not branch:
        head = _run_git(["rev-parse", "--short", "HEAD"], cwd)
        head_sha = (
            head.stdout.strip()
            if head.returncode == 0 and head.stdout.strip()
            else "unknown"
        )
        refusals.append(
            f"HEAD is detached at {head_sha}. Check out the branch you intend to "
            "migrate - a commit from here goes nowhere while the key blob stays "
            "flipped."
        )

    if branch:
        # Resolved from config, never `git rev-parse --abbrev-ref @{upstream}`:
        # that does not fail when the tracked ref is missing, it echoes the
        # literal string "@{upstream}" and exits 0.
        remote_result = _run_git(["config", "--get", f"branch.{branch}.remote"], cwd)
        merge_result = _run_git(["config", "--get", f"branch.{branch}.merge"], cwd)
        remote_name = (
            remote_result.stdout.strip() if remote_result.returncode == 0 else ""
        )
        merge_ref = merge_result.stdout.strip() if merge_result.returncode == 0 else ""

        if not remote_name or not merge_ref:
            # No upstream configured at all is not fatal - a local-only branch
            # is a legitimate place to stage this - but staleness cannot be
            # measured, so this is a warning the caller may surface, not a
            # refusal.
            pass
        else:
            merge_branch = merge_ref
            prefix = "refs/heads/"
            if merge_branch.startswith(prefix):
                merge_branch = merge_branch[len(prefix) :]
            upstream = f"{remote_name}/{merge_branch}"

            # Best-effort: a failed fetch is a warning, not a refusal - the
            # check still runs against the last-known remote ref.
            _run_git(["fetch", "--quiet", remote_name], cwd)

            behind_result = _run_git(["rev-list", "--count", f"HEAD..{upstream}"], cwd)
            behind_str = behind_result.stdout.strip()
            # FAIL CLOSED: a missing ref, an unreadable object, or any other
            # measurement failure must refuse, not assume the safe answer.
            if behind_result.returncode != 0 or not behind_str.isdigit():
                refusals.append(
                    f"cannot measure how far {branch} is behind {upstream}. "
                    "Refusing rather than assuming it is current."
                )
            else:
                behind = int(behind_str)
                if behind > max_behind:
                    refusals.append(
                        f"{branch} is {behind} commit(s) behind {upstream}. "
                        "Re-encrypting from a stale checkout commits OLD secret "
                        "content over current master. Pull first "
                        "(UPGRADE_SCHEME_MAX_BEHIND raises the bar if the gap is "
                        "known to be irrelevant)."
                    )

    # UNCOMMITTED CONTENT in a matched file is a hard refusal, because the abort
    # path restores with `git checkout -- <files>` and that DISCARDS local edits
    # irrecoverably. Measured: an uncommitted line added to a secret file was gone
    # after an aborted run, with nothing reported. The shell harness this module was
    # ported from carries the same gate for exactly this reason - the port took the
    # destructive restore without its precondition.
    #
    # `git diff`, NOT `git status --porcelain`: on a tree whose files sit as
    # ciphertext at rest, porcelain reports every matched file as modified while the
    # bytes are identical to the committed blob and diff reports no change. Gating on
    # porcelain would refuse to run on exactly the trees this is for.
    _run_git(["update-index", "--refresh"], cwd)
    for scope, label, bases_fn in (
        (["diff"], "uncommitted", _unstaged_bases),
        (["diff", "--cached"], "staged", _staged_bases),
    ):
        probe = _run_git([*scope, "--quiet", "--", *matched_files], cwd)
        if probe.returncode == 0:
            continue
        if probe.returncode > 1:
            # Fail closed: an unreadable index is not evidence the tree is clean.
            refusals.append(
                f"cannot determine whether matched file(s) have {label} changes. "
                "Refusing rather than assuming they are clean."
            )
            continue

        # probe.returncode == 1: at least one matched file differs in this
        # scope. Without a resolver there is no way to tell a real edit from
        # a scheme-mismatch artifact, so keep the original fail-closed
        # refusal verbatim - this is the pre-existing behaviour for every
        # caller that does not pass plaintext_of.
        if plaintext_of is None:
            refusals.append(
                f"matched file(s) have {label} changes. The abort path restores with "
                "`git checkout`, which would discard them. Commit or stash first."
            )
            continue

        # Probe each file INDIVIDUALLY - not `--name-only`, which has path-
        # quoting edge cases - so a per-file failure stays per-file.
        content_differs = []
        cannot_compare = []
        no_content_change = []
        mode_or_type_changed = []
        for f in matched_files:
            file_probe = _run_git([*scope, "--quiet", "--", f], cwd)
            if file_probe.returncode == 0:
                continue
            if file_probe.returncode > 1:
                cannot_compare.append((f, "cannot determine whether it changed"))
                continue

            base_bytes, other_bytes, err = bases_fn(f, cwd)
            if err is not None:
                cannot_compare.append((f, err))
                continue
            try:
                # decryption is what turns a raw ciphertext difference into a
                # real content comparison - a file committed under one
                # scheme while its blob declares the other decrypts to
                # identical plaintext on both sides.
                base_plain = plaintext_of(f, base_bytes)
                other_plain = plaintext_of(f, other_bytes)
            except Exception as e:
                cannot_compare.append((f, f"plaintext_of raised: {e}"))
                continue

            if (
                hashlib.sha256(base_plain).digest()
                == hashlib.sha256(other_plain).digest()
            ):
                # Equal plaintext is not proof nothing happened: `git diff
                # --quiet` also reports dirty for a mode-only change (chmod)
                # or a type change (regular file <-> symlink), and the abort
                # path's `git checkout -- ` would reset that mode later and
                # silently discard it if this were admitted.
                modes = _diff_raw_modes(scope, f, cwd)
                if modes is None:
                    cannot_compare.append(
                        (f, "cannot determine whether its mode or type changed")
                    )
                elif (
                    modes[0] != modes[1]
                    or modes[0] not in _REGULAR_BLOB_MODES
                    or modes[1] not in _REGULAR_BLOB_MODES
                ):
                    mode_or_type_changed.append(f)
                else:
                    no_content_change.append(f)
            else:
                content_differs.append(f)

        if cannot_compare:
            # Distinct message from the plaintext-differs refusal below: a
            # misleading "you have uncommitted edits" when the real cause is
            # an uncached key is this gate's own complaint in a new shape.
            refusals.append(
                f"cannot compare plaintext for matched file(s) with {label} "
                "changes, so refusing rather than assuming they are clean: "
                + ", ".join(f"{path} ({why})" for path, why in cannot_compare)
            )
        if content_differs:
            refusals.append(
                f"matched file(s) have {label} content changes. The abort path "
                "restores with `git checkout`, which would discard them. Commit "
                "or stash first: " + ", ".join(content_differs)
            )
        if mode_or_type_changed:
            # Distinct from both other refusals: a plaintext-equal file whose
            # mode or type changed (chmod, or regular file <-> symlink) is
            # neither a content edit nor an unreadable comparison - it is a
            # third thing the operator needs named so a chmod is what they
            # go fix, not a scheme they go hunt for.
            refusals.append(
                f"matched file(s) have a {label} mode or type change (e.g. "
                "chmod, or regular file <-> symlink), not a content change. "
                "The abort path restores with `git checkout`, which would "
                "discard it. Commit or stash first: " + ", ".join(mode_or_type_changed)
            )
        if no_content_change and notes is not None:
            notes.append(
                "tree is dirty but carries no content change for: "
                + ", ".join(no_content_change)
                + " - this is a scheme-mismatch artifact (committed under one "
                "encryption scheme while the key blob declares the other); "
                "`upgrade-scheme` repairs it, not an edit to commit or stash."
            )

    # An untracked matched file has no committed blob to recover from, and
    # `git checkout -- <paths>` rejects the WHOLE pathspec if any element is
    # untracked - so the recovery path would silently do nothing for every
    # file, not just this one.
    untracked = []
    for f in matched_files:
        result = _run_git(["ls-files", "--error-unmatch", "--", f], cwd)
        if result.returncode != 0:
            untracked.append(f)
    if untracked:
        refusals.append(
            "matched file(s) are not tracked by git, so they have no committed "
            "blob to recover from: " + ", ".join(untracked)
        )

    return refusals
