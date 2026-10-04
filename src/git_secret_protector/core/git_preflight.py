"""Repo-level safety gates for destructive, repo-wide crypto operations.

Ported from scripts/migration/verify-upgrade-scheme.sh (merged in PRs #127 and
#128) rather than reinvented - that script's comments record the incident
each gate closes. This module owns only the DECISION (refuse or not); the
caller decides how to report and what to do next.

check_repo_preflight() returns a list of human-readable refusal strings. An
empty list means clear. Every refusal names what to do about it, not just
what is wrong.
"""

import os
import subprocess

DEFAULT_MAX_BEHIND = 0
_GIT_TIMEOUT_SECS = 15


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


def check_repo_preflight(matched_files, cwd=None, max_behind=None):
    """Return refusal strings for a repo-wide re-encrypt; empty = safe to proceed.

    matched_files are the paths about to be re-encrypted in place.
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
    for scope, label in ((["diff"], "uncommitted"), (["diff", "--cached"], "staged")):
        probe = _run_git([*scope, "--quiet", "--", *matched_files], cwd)
        if probe.returncode == 1:
            refusals.append(
                f"matched file(s) have {label} changes. The abort path restores with "
                "`git checkout`, which would discard them. Commit or stash first."
            )
        elif probe.returncode > 1:
            # Fail closed: an unreadable index is not evidence the tree is clean.
            refusals.append(
                f"cannot determine whether matched file(s) have {label} changes. "
                "Refusing rather than assuming they are clean."
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
