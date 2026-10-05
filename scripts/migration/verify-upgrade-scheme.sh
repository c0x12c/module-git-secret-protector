#!/usr/bin/env bash
# Verify an upgrade-scheme v1->v2 migration did not change any file's CONTENT.
#
# WHY THIS EXISTS
# upgrade-scheme re-encrypts every file a filter matches. The files it rewrites are
# routinely the only copy of a production signing key or a tfstate holding database
# passwords, and the diff it produces is pure ciphertext churn that no human can read.
# So "the command exited 0" is not evidence the content survived. This compares the
# decrypted plaintext by checksum before and after, and reports per file.
#
# It never prints a plaintext byte: only sha256 checksums and path names.
#
# TWO FACTS ABOUT upgrade-scheme THAT DRIVE THIS SCRIPT'S SHAPE
#
# 1. It operates on the file AS IT SITS ON DISK, and a normal checkout holds
#    PLAINTEXT there (git's smudge filter decrypts on checkout). Both halves are
#    magic-header guarded and therefore idempotent - decrypt_file on plaintext is a
#    no-op, encrypt_file on ciphertext is a no-op - so the command works from either
#    state. But starting from the normal plaintext state it LEAVES CIPHERTEXT in the
#    working tree. Anything reading those files in place (terraform, an app) then
#    reads ciphertext. Restoring the tree is a required step, not a tidy-up, and it
#    is why this script ends with decrypt-files.
#
# 2. Rollback is INCOMPLETE and no CLI covers it. On success the key blob is flipped
#    to v2 (set_scheme, last). git checkout restores the files, but nothing sets the
#    blob back to v1. A v2 blob against v1-committed ciphertext still DECRYPTS (the
#    decrypt path dispatches on the wire version byte, not the blob), so nothing
#    breaks loudly - instead the clean filter starts emitting v2 for files committed
#    as v1 and every matched file shows as permanently modified. Recovering from that
#    means restoring the blob by hand. Read the RECOVERY section this script prints
#    before running --apply against anything you cannot afford to break.
#
# Usage:
#   verify-upgrade-scheme.sh <repo-path> <filter>            # dry run, changes nothing
#   verify-upgrade-scheme.sh <repo-path> <filter> --apply    # migrate + verify + restore
#
# Env:
#   GSP  path to the git-secret-protector entrypoint (default: git-secret-protector)

set -uo pipefail

REPO="${1:-}"
FILTER="${2:-}"
MODE="${3:-}"
GSP="${GSP:-git-secret-protector}"

die() { printf 'verify-upgrade-scheme: %s\n' "$*" >&2; exit 1; }

[ -n "$REPO" ] && [ -n "$FILTER" ] || die "usage: $0 <repo-path> <filter> [--apply]"
[ -d "$REPO" ] || die "not a directory: $REPO"
REPO=$(cd "$REPO" && pwd -P) || die "cannot resolve $REPO"
git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || die "not a git repo: $REPO"
command -v "$GSP" >/dev/null 2>&1 || die "git-secret-protector not found (set GSP=<path>)"

cd "$REPO" || die "cannot cd $REPO"

# Matched files and the current scheme both come from `status --json`, i.e. the tool's
# own parser - never a reimplementation of the glob rules here. A second implementation
# would disagree with the migration about which files are in scope, which is the one
# thing this check cannot afford to get wrong.
STATUS_ERR_FILE=$(mktemp) || die "cannot make a temp file for status stderr"
STATUS=$("$GSP" status --json 2>"$STATUS_ERR_FILE")
STATUS_RC=$?
STATUS_ERR=$(cat "$STATUS_ERR_FILE" 2>/dev/null)
rm -f "$STATUS_ERR_FILE"
# status now exits non-zero on an unreadable scheme but still prints the payload,
# so only an empty result is a hard failure here - unknown scheme is handled below.
[ -n "$STATUS" ] || die "status --json failed in $REPO (exit $STATUS_RC): ${STATUS_ERR:-no output; likely an unreadable scheme or missing credentials}"

read_status() { printf '%s' "$STATUS" | python3 "$@"; }

# Re-queries the CLI rather than reusing $STATUS, which was captured before the
# upgrade ran and would report the pre-upgrade scheme.
read_status_fresh() {
  "$GSP" status --json 2>/dev/null | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for f in d.get("filters") or []:
    if f.get("name") == sys.argv[1]:
        print(f.get("scheme") or "unknown"); break
' "$1"
}

FILTER_FOUND=$(read_status -c '
import json,sys
d = json.load(sys.stdin)
names = [f.get("name") for f in d.get("filters") or []]
print("yes" if sys.argv[1] in names else "no:" + ",".join(n for n in names if n))
' "$FILTER")
case "$FILTER_FOUND" in
  yes) ;;
  no:*) die "filter '$FILTER' not defined in $REPO (defined: ${FILTER_FOUND#no:})" ;;
  *)   die "could not parse status --json from $REPO" ;;
esac

# NOT mapfile: /bin/bash on macOS is 3.2, where mapfile does not exist and would
# leave FILES empty - an empty list reads as "filter matched nothing" and the script
# would exit without ever checking anything.
FILES=()
while IFS= read -r _line; do
  [ -n "$_line" ] && FILES+=("$_line")
done < <(read_status -c '
import json,sys,os
d = json.load(sys.stdin)
root = d.get("repo_root") or os.getcwd()
for f in d.get("filters") or []:
    if f.get("name") == sys.argv[1]:
        for e in f.get("files") or []:
            p = e.get("path") if isinstance(e, dict) else e
            if p:
                print(os.path.relpath(p, root))
' "$FILTER")

SCHEME=$(read_status -c '
import json,sys
d = json.load(sys.stdin)
for f in d.get("filters") or []:
    if f.get("name") == sys.argv[1]:
        print(f.get("scheme") or "unknown"); break
else:
    print("unknown")
' "$FILTER")

[ "$SCHEME" != "unknown" ] || die "filter '$FILTER' scheme could not be read; refusing to migrate blind (run '$GSP status' for the reason)"

[ "${#FILES[@]}" -gt 0 ] || die "filter '$FILTER' matched no files in $REPO"

printf 'repo:   %s\n' "$REPO"
printf 'filter: %s (%d file(s))\n' "$FILTER" "${#FILES[@]}"

# A matched file with uncommitted CONTENT changes would put unsaved work into the
# checksum baseline, and the comparison could then not tell a migration bug from an
# unsaved edit. So this refuses to run - but it must ask the right question.
#
# NOT `git status --porcelain`: measured on a tree whose files sit as ciphertext at
# rest (a normal mid-migration state), porcelain reports every matched file as " M"
# while the worktree bytes are IDENTICAL to the committed blob and `git diff` reports
# no change at all. Gating on porcelain therefore refuses to run on exactly the trees
# this script exists to repair. `git diff` compares content through the filter, which
# is the question being asked.
# Every matched file must be TRACKED. Two reasons, and the second is the dangerous
# one: `git diff` says nothing about an untracked file, so it would slip through the
# gate below; and `git checkout -- "${FILES[@]}"` rejects the ENTIRE pathspec when any
# element is untracked, so the failure-path restore would silently do nothing for all
# files, not just the untracked one. An untracked matched file also has no committed
# blob to recover from at all.
# A STALE OR DETACHED checkout must not be migrated, and no other gate here can see
# it. Measured on c0x12c-internal/service-insight: detached HEAD, 328 commits behind
# origin/master, and ZERO dirty matched files - so the clean-tree gate below passes
# and the run would have proceeded. What it would then do is re-encrypt the secrets
# as they existed 328 commits ago, recover (on failure) from that old blob, and - if
# committed - silently revert those secrets to their old content. A commit from a
# detached HEAD also goes nowhere, so the migration would be lost while the key blob
# stayed flipped.
if ! BRANCH=$(git symbolic-ref --short -q HEAD); then
  die "HEAD is detached at $(git rev-parse --short HEAD). Check out the branch you intend to migrate - a commit from here goes nowhere while the key blob stays flipped."
fi
printf 'branch: %s\n' "$BRANCH"

# `git rev-parse --abbrev-ref --symbolic-full-name @{upstream}` does NOT fail when the
# tracked remote ref is missing - it echoes the literal string "@{upstream}" and exits
# 0. Taken at face value that becomes the remote name too, so the gate ends up naming
# "@{upstream}" in its own diagnostics instead of the branch. Resolve against the
# config instead, which either names a real ref or is empty.
UPSTREAM=""
_up_remote=$(git config --get "branch.$BRANCH.remote" 2>/dev/null || true)
_up_merge=$(git config --get "branch.$BRANCH.merge" 2>/dev/null || true)
if [ -n "$_up_remote" ] && [ -n "$_up_merge" ]; then
  UPSTREAM="$_up_remote/${_up_merge#refs/heads/}"
fi
if [ -z "$UPSTREAM" ]; then
  # No upstream is not fatal - a local-only branch is a legitimate place to stage this
  # - but it must be said out loud, because the staleness check below cannot run.
  printf 'WARNING: %s has no upstream; staleness NOT checked.\n' "$BRANCH" >&2
else
  # The remote comes from the upstream ref, not a hardcoded "origin" - a branch
  # tracking a fork or a second remote would otherwise be measured against a ref
  # nobody fetched.
  REMOTE="$_up_remote"
  git fetch --quiet "$REMOTE" 2>/dev/null \
    || printf 'WARNING: git fetch %s failed; staleness is measured against the last-known remote ref.\n' "$REMOTE" >&2
  # FAIL CLOSED. An earlier revision ended this with `|| echo 0`, so any rev-list
  # error - a missing ref, an unreadable object - reported "0 commits behind" and the
  # stale-checkout gate passed. A safety gate that cannot measure must refuse, not
  # assume the safe answer.
  if ! BEHIND=$(git rev-list --count "HEAD..$UPSTREAM" 2>/dev/null); then
    die "cannot measure how far $BRANCH is behind $UPSTREAM. Refusing rather than assuming it is current."
  fi
  case "$BEHIND" in
    ''|*[!0-9]*) die "unexpected commit count '$BEHIND' for HEAD..$UPSTREAM; refusing to run" ;;
  esac
  printf 'upstream: %s (%s commit(s) behind)\n' "$UPSTREAM" "$BEHIND"
  MAX_BEHIND="${UPGRADE_SCHEME_MAX_BEHIND:-0}"
  if [ "$BEHIND" -gt "$MAX_BEHIND" ]; then
    die "$BRANCH is $BEHIND commit(s) behind $UPSTREAM. Re-encrypting from a stale checkout commits OLD secret content over current master. Pull first (UPGRADE_SCHEME_MAX_BEHIND raises the bar if you know the gap is irrelevant)."
  fi
fi

UNTRACKED=""
for f in "${FILES[@]}"; do
  git ls-files --error-unmatch -- "$f" >/dev/null 2>&1 || UNTRACKED="$UNTRACKED $f"
done
[ -z "$UNTRACKED" ] || die "matched file(s) are not tracked by git, so they have no committed blob to recover from:$UNTRACKED"

state_of() {
  # Header probe only. Reads 9 bytes, never the payload.
  if head -c 9 "$1" 2>/dev/null | grep -q ENCRYPTED; then echo ciphertext; else echo plaintext; fi
}

# Resolved once, at startup, and PROVEN against a known value. The failure being
# guarded is the worst kind this script can have: if the hasher is missing, a naive
# hash_of returns "" for every file, BEFORE and AFTER both become lists of empty
# hashes, they compare equal, and a data-loss check prints PASS having verified
# nothing. An empty hash must never be able to mean "identical".
HASHER=""
if command -v shasum >/dev/null 2>&1; then HASHER="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then HASHER="sha256sum"
else die "no sha256 tool found (need shasum or sha256sum)"
fi
_probe=$(printf 'x' | $HASHER 2>/dev/null | cut -d' ' -f1)
[ "$_probe" = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881" ] \
  || die "$HASHER did not produce the expected sha256 of a known input; refusing to run"

hash_of() {
  local h
  h=$($HASHER "$1" 2>/dev/null | cut -d' ' -f1)
  # 64 hex chars or nothing - a short or empty result is a broken measurement, not
  # a value to compare.
  case "$h" in
    ????????????????????????????????????????????????????????????????) printf '%s' "$h" ;;
    *) return 1 ;;
  esac
}

git update-index --refresh >/dev/null 2>&1 || true

# "Dirty" and "has a content change" are not the same question: a file
# committed under one scheme while its blob declares the other reads as
# modified (git diff cleans the worktree through the CURRENT blob) with no
# edit behind it. The batch check stays the cheap binary fast path; per-file
# comparison - mirroring git_preflight.py's check_repo_preflight, and always
# decrypting via "$GSP" rather than a shell reimplementation of the crypto, so
# the two gates cannot disagree - runs only when the batch check finds dirt.
GATE_WORK=$(mktemp -d) || die "cannot make a temp dir for the clean-tree content check"
chmod 700 "$GATE_WORK"
trap 'rm -rf "$GATE_WORK"' EXIT

# $1=path $2=indexed|head|worktree $3=output file. Raw bytes, no text-mode
# transform - command substitution would strip a trailing-newline-only edit.
fetch_raw() {
  case "$2" in
    indexed)  git show ":$1" > "$3" 2>/dev/null ;;
    head)     git show "HEAD:$1" > "$3" 2>/dev/null ;;
    worktree) cat -- "$1" > "$3" 2>/dev/null ;;
    *) return 1 ;;
  esac
}

# Always delegates - decrypt already header-guards with the CONFIGURED
# magic_header and passes non-ciphertext through unchanged.
decrypt_to_plaintext() {
  "$GSP" decrypt "$3" < "$1" > "$2" 2>/dev/null || return 1
  [ -s "$2" ] # two empty outputs would hash equal and ADMIT the file
}

GATE_CANNOT_COMPARE=()
GATE_CONTENT_DIFFERS=()
GATE_NO_CONTENT_CHANGE=()
GATE_MODE_OR_TYPE_CHANGED=()

# Checked against `git diff --raw`'s two mode fields. Anything else -
# 120000 (symlink) or 160000 (gitlink/submodule) in particular - is a type
# change this gate must never wave through on plaintext equality alone.
_is_regular_blob_mode() {
  case "$1" in
    100644|100755) return 0 ;;
    *) return 1 ;;
  esac
}

# $1=path, remaining args are the scope's own diff flags (none, or --cached).
# Equal plaintext does not prove nothing happened: `git diff --quiet` also
# reports dirty for a mode-only change (chmod) or a type change (regular
# file <-> symlink), and the failure path's `git checkout -- ` would reset
# that mode later and silently discard it if this were admitted. Format:
# ":<oldmode> <newmode> <oldsha> <newsha> <status>\t<path>".
gate_mode_changed() {
  local f="$1"; shift
  local raw old_mode new_mode
  raw=$(git diff "$@" --raw -- "$f" 2>/dev/null)
  [ -n "$raw" ] || return 2  # cannot parse - fail closed, never an admit
  local header="${raw%%$'\t'*}"
  old_mode=$(printf '%s\n' "$header" | awk '{print $1}')
  old_mode="${old_mode#:}"
  new_mode=$(printf '%s\n' "$header" | awk '{print $2}')
  case "$old_mode" in ''|*[!0-9]*) return 2 ;; esac
  case "$new_mode" in ''|*[!0-9]*) return 2 ;; esac
  if [ "$old_mode" != "$new_mode" ]; then
    return 0
  fi
  if ! _is_regular_blob_mode "$old_mode" || ! _is_regular_blob_mode "$new_mode"; then
    return 0
  fi
  return 1
}

# $1=path $2=uncommitted|staged $3=base-which $4=other-which, remaining args
# are the scope's own diff flags (none, or --cached) - needed again here to
# probe the mode.
gate_compare_file() {
  local f="$1" label="$2" base_which="$3" other_which="$4"; shift 4
  local base_raw="$GATE_WORK/base.raw" other_raw="$GATE_WORK/other.raw"
  local base_plain="$GATE_WORK/base.plain" other_plain="$GATE_WORK/other.plain"
  rm -f "$base_raw" "$other_raw" "$base_plain" "$other_plain"

  fetch_raw "$f" "$base_which" "$base_raw" \
    || { GATE_CANNOT_COMPARE+=("$f (cannot read the $base_which blob)"); return; }
  fetch_raw "$f" "$other_which" "$other_raw" \
    || { GATE_CANNOT_COMPARE+=("$f (cannot read the $other_which content)"); return; }
  decrypt_to_plaintext "$base_raw" "$base_plain" "$f" \
    || { GATE_CANNOT_COMPARE+=("$f ($base_which side could not be decrypted)"); return; }
  decrypt_to_plaintext "$other_raw" "$other_plain" "$f" \
    || { GATE_CANNOT_COMPARE+=("$f ($other_which side could not be decrypted)"); return; }

  local bh oh
  bh=$(hash_of "$base_plain") \
    || { GATE_CANNOT_COMPARE+=("$f (cannot checksum $base_which plaintext)"); return; }
  oh=$(hash_of "$other_plain") \
    || { GATE_CANNOT_COMPARE+=("$f (cannot checksum $other_which plaintext)"); return; }

  if [ "$bh" = "$oh" ]; then
    gate_mode_changed "$f" "$@"
    case "$?" in
      0) GATE_MODE_OR_TYPE_CHANGED+=("$f ($label)") ;;
      1) GATE_NO_CONTENT_CHANGE+=("$f ($label)") ;;
      *) GATE_CANNOT_COMPARE+=("$f (cannot determine whether its mode or type changed)") ;;
    esac
  else
    GATE_CONTENT_DIFFERS+=("$f ($label)")
  fi
}

# Probes each file INDIVIDUALLY - not `--name-only`, which has path-quoting
# edge cases - so a per-file failure stays per-file, same as git_preflight.py.
gate_scope() {
  local label="$1" base_which="$2" other_which="$3"; shift 3
  git diff "$@" --quiet -- "${FILES[@]}" 2>/dev/null && return 0
  local batch_rc=$?
  if [ "$batch_rc" -gt 1 ]; then
    GATE_CANNOT_COMPARE+=("all matched files ($label: cannot determine whether they changed)")
    return
  fi
  local f file_rc
  for f in "${FILES[@]}"; do
    git diff "$@" --quiet -- "$f" 2>/dev/null && continue
    file_rc=$?
    if [ "$file_rc" -gt 1 ]; then
      GATE_CANNOT_COMPARE+=("$f (cannot determine whether it changed)")
      continue
    fi
    gate_compare_file "$f" "$label" "$base_which" "$other_which" "$@"
  done
}

gate_scope uncommitted indexed worktree
gate_scope staged head indexed --cached

# Distinct messages: a misleading "you have uncommitted edits" when the real
# cause is an uncached key, or the reverse, is this gate's own complaint again.
if [ "${#GATE_CANNOT_COMPARE[@]}" -gt 0 ]; then
  die "cannot compare plaintext for matched file(s), so refusing rather than assuming they are clean: $(printf '%s; ' "${GATE_CANNOT_COMPARE[@]}")"
fi
if [ "${#GATE_CONTENT_DIFFERS[@]}" -gt 0 ]; then
  die "matched file(s) have content changes. The abort path restores with \`git checkout\`, which would discard them. Commit or stash first: $(printf '%s; ' "${GATE_CONTENT_DIFFERS[@]}")"
fi
if [ "${#GATE_MODE_OR_TYPE_CHANGED[@]}" -gt 0 ]; then
  # Distinct from both other refusals: a plaintext-equal file whose mode or
  # type changed (chmod, or regular file <-> symlink) is neither a content
  # edit nor an unreadable comparison - it is a third thing the operator
  # needs named so a chmod is what they go fix, not a scheme mismatch.
  die "matched file(s) have a mode or type change (e.g. chmod, or regular file <-> symlink), not a content change. The abort path restores with \`git checkout\`, which would discard it. Commit or stash first: $(printf '%s; ' "${GATE_MODE_OR_TYPE_CHANGED[@]}")"
fi
if [ "${#GATE_NO_CONTENT_CHANGE[@]}" -gt 0 ]; then
  printf 'tree is dirty but carries no content change for: %s- this is a scheme-mismatch artifact (committed under one encryption scheme while the key blob declares the other); upgrade-scheme repairs it, not an edit to commit or stash.\n' \
    "$(printf '%s; ' "${GATE_NO_CONTENT_CHANGE[@]}")"
fi

rm -rf "$GATE_WORK"
trap - EXIT

record_hashes() { # $1 = output manifest
  local out="$1" f h
  for f in "${FILES[@]}"; do
    h=$(hash_of "$f") || die "cannot checksum $f - refusing to report a result"
    printf '%s  %s\n' "$h" "$f" >> "$out"
  done
}

PLAIN=0 CIPHER=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || die "matched file missing from the working tree: $f"
  if [ "$(state_of "$f")" = plaintext ]; then PLAIN=$((PLAIN+1)); else CIPHER=$((CIPHER+1)); fi
done
printf 'at rest: %d plaintext, %d ciphertext\n' "$PLAIN" "$CIPHER"

# The run normalises to plaintext to make the comparison meaningful, but it must hand
# the checkout back in the state it was FOUND in. Measured on spartan-stratos/service-
# olympus: filters are not configured in .git/config there, so its matched file sits as
# CIPHERTEXT and an unconditional restore-to-plaintext would leave the owner a checkout
# they did not choose. Mixed is treated as ciphertext: re-encrypting is the reversible
# direction (decrypt-files recovers plaintext at any time), whereas leaving plaintext
# on disk in a repo that stores ciphertext is the state that gets committed by mistake.
if [ "$CIPHER" -gt 0 ]; then FOUND_STATE=ciphertext; else FOUND_STATE=plaintext; fi
printf 'found state: %s (the run will restore to this)\n' "$FOUND_STATE"

# The comparison is only meaningful if both sides measure the SAME representation.
# The run always ends with the tree in plaintext, so a tree that starts with any
# ciphertext must be normalised first - otherwise "before" hashes ciphertext,
# "after" hashes plaintext, and every such file reports a spurious content change.
# A mixed tree is normal mid-migration, so this is not an edge case.
NORMALISED=no

if [ "$MODE" != "--apply" ]; then
  cat <<EOF

DRY RUN - nothing was changed.

What --apply would do, in order:
  1. if any file is at rest as ciphertext, decrypt-files first so the
     before/after comparison measures the same representation
  2. checksum the plaintext of all ${#FILES[@]} file(s)
  3. $GSP upgrade-scheme $FILTER --yes   (re-encrypts every file, then flips the key blob)
  4. assert every file now carries the v2 version byte
  5. $GSP decrypt-files $FILTER          (plaintext, so step 6 can compare)
  6. re-checksum and compare against step 2, per file
  7. restore the tree to $FOUND_STATE, the state it was found in

The run FAILS if any checksum differs. Content changing is a data-loss bug, not a
migration; the key blob's own verify step cannot see it because it only checks the
version byte.

RECOVERY, if step 6 reports a mismatch:
  git -C $REPO checkout -- <the named files>
  The committed blob is untouched until you commit, so the files are recoverable.
  The key blob, however, is already v2 and NO CLI sets it back. Until it is restored
  by hand, the clean filter emits v2 for v1-committed files and every matched file
  reads as permanently modified. Restore the blob before doing anything else.
EOF
  exit 0
fi

printf 'scheme before: %s\n' "$SCHEME"

WORK=$(mktemp -d) || die "cannot make a temp dir"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
BEFORE="$WORK/before.sha" AFTER="$WORK/after.sha"

if [ "$CIPHER" -gt 0 ]; then
  printf 'normalising %d ciphertext file(s) to plaintext before baselining...\n' "$CIPHER"
  "$GSP" decrypt-files "$FILTER" >/dev/null || die "decrypt-files failed while normalising; cannot establish a comparable baseline"
  NORMALISED=yes
  for f in "${FILES[@]}"; do
    [ "$(state_of "$f")" = plaintext ] || die "still ciphertext after normalising: $f"
  done
fi

record_hashes "$BEFORE"
printf 'baseline: %d plaintext checksum(s) recorded%s\n' "${#FILES[@]}" \
  "$([ "$NORMALISED" = yes ] && printf ' (after normalising)' || true)"

printf '\n-- upgrade-scheme --\n'
if ! "$GSP" upgrade-scheme "$FILTER" --yes; then
  # MEASURED failure mode: the blob flip (set_scheme) is the LAST step, so a failure
  # there leaves the files already re-encrypted as v2 on disk while the blob is still
  # v1. The tree then holds ciphertext where an app expects plaintext, and every
  # matched file reads as modified. git checkout restores it exactly - the committed
  # blob never moved - so the restore is attempted here rather than left to whoever
  # reads the error. Not restoring is how a failed migration becomes an outage.
  printf '\nupgrade-scheme FAILED. Restoring the working tree from git...\n' >&2
  if git checkout -- "${FILES[@]}" 2>/dev/null; then
    left=0
    for f in "${FILES[@]}"; do
      [ "$(state_of "$f")" = ciphertext ] && left=$((left+1))
    done
    if [ "$left" -eq 0 ]; then
      printf 'restored: all %d file(s) are plaintext again; the key blob was never flipped (still %s).\n' \
        "${#FILES[@]}" "$SCHEME" >&2
    else
      printf 'WARNING: %d file(s) still hold ciphertext after checkout - restore them by hand NOW.\n' \
        "$left" >&2
    fi
  else
    printf 'WARNING: git checkout failed. The working tree holds CIPHERTEXT. Do not run terraform or any app against this checkout until it is restored.\n' >&2
  fi
  die "upgrade-scheme failed for '$FILTER'; the key blob is flipped only after its own verify passes, so the filter should still be $SCHEME. Confirm with: $GSP status --json"
fi

printf '\n-- scheme check --\n'
# Asks the KEY BLOB what scheme the filter is on, not the bytes on disk.
#
# This used to scan each file for the v2 version byte in place. That assertion only
# held while upgrade-scheme left ciphertext behind unconditionally. From the version
# that restores the working tree to the state it was found in, a successful upgrade
# of a found-as-plaintext tree ends with PLAINTEXT on disk - which this step read as
# "NOT ENCRYPTED" for every file and failed on. A check that fails on success is
# worse than no check: it teaches the operator to ignore the one tool standing
# between them and a corrupted secret.
#
# The blob is the right thing to ask anyway. It is what the clean filter consults to
# decide which scheme to write, and the CLI flips it only after its own per-file
# verification passes - so blob == v2 means every file was confirmed v2 at the moment
# it mattered. Works against both the pre- and post-restore CLI.
BAD=0
SCHEME_AFTER=$(read_status_fresh "$FILTER")
if [ "$SCHEME_AFTER" = "v2" ]; then
  printf 'filter %s is on scheme v2\n' "$FILTER"
else
  printf 'FILTER NOT ON V2 (scheme=%s)\n' "${SCHEME_AFTER:-unknown}"
  BAD=1
fi

printf '\n-- restore the working tree to plaintext --\n'
"$GSP" decrypt-files "$FILTER" || die "decrypt-files failed - the working tree still holds CIPHERTEXT. Do not run terraform or any app against this checkout until it is restored."

record_hashes "$AFTER"

printf '\n-- content comparison --\n'
if diff -q "$BEFORE" "$AFTER" >/dev/null 2>&1; then
  if [ "$FOUND_STATE" = ciphertext ]; then
  printf 'restoring the tree to ciphertext, the state it was found in...\n'
  "$GSP" encrypt-files "$FILTER" >/dev/null || die "content verified, but re-encrypting the tree failed - it currently holds PLAINTEXT where this repo keeps ciphertext. Restore before committing anything."
  for f in "${FILES[@]}"; do
    [ "$(state_of "$f")" = ciphertext ] || die "content verified, but $f is still plaintext after re-encrypting - restore by hand before committing."
  done
fi

printf 'PASS: decrypted content identical for all %d file(s)\n' "${#FILES[@]}"
  [ "$BAD" -eq 0 ] || { printf 'but %d file(s) failed the version-byte check\n' "$BAD"; exit 1; }
  printf '\nNext: review the diff (ciphertext churn only) and open a PR.\n'
  exit 0
fi

printf 'FAIL: decrypted content CHANGED for:\n'
join -j 2 -o 0 <(sort -k2 "$BEFORE") <(sort -k2 "$AFTER") >/dev/null 2>&1
python3 - "$BEFORE" "$AFTER" <<'PY'
import sys
def load(p):
    out = {}
    for line in open(p):
        h, _, f = line.strip().partition("  ")
        out[f] = h
    return out
b, a = load(sys.argv[1]), load(sys.argv[2])
for f in sorted(set(b) | set(a)):
    if b.get(f) != a.get(f):
        print(f"  {f}")
PY
cat <<EOF

RECOVERY - do this before anything else:
  git -C $REPO checkout -- <the files named above>
The committed blob is untouched until you commit, so the content is recoverable from
git. The key blob is already v2 and no CLI sets it back; restore it by hand or every
matched file will read as permanently modified.
EOF
exit 1
