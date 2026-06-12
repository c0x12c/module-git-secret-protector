# Design: Guardrails + Frictionless Onboarding

**Date:** 2026-06-11
**Status:** Approved (design) — pending implementation plan
**Scope:** One cohesive feature bundle. Crypto/format hardening (AES-GCM, audit log, key versioning) is explicitly deferred to a separate spec.

## Problem

`git-secret-protector` transparently encrypts secret files through git clean/smudge filters. Two end-user gaps reduce its value:

1. **Onboarding friction.** A new team member must run, per filter, `pull-aes-key`, then `setup-filters`, then `decrypt-files`. With several filters this is many manual steps and easy to get wrong.
2. **Leak risk with no guardrail.** If filters are not configured (a common new-member mistake), git stages the *plaintext* of matched files and they get committed in the clear. Nothing currently blocks this.

A related correctness issue: the existing `status` command checks the **working-tree** copy of each file for the magic header. After the smudge filter runs, working-tree files are decrypted, so this check does not reflect what is actually committed. Leak detection must inspect the **staged blob** (`git cat-file blob :<path>`) — the content git will commit.

## Goals

- Reduce new-member setup to a single command.
- Make it hard to commit a secret in plaintext.
- Give a single command that diagnoses configuration, key availability, and encryption state, usable both locally and in CI.

## Non-goals

- No change to the encryption format or algorithm (still AES-CBC with the `magic_header` prefix).
- No new storage backends.
- No audit logging or key-version tracking.

## Three new CLI commands

All three are composed from the existing `EncryptionManager`, `GitAttributesParser`, and `AesKeyManager`, plus two small new units (`DoctorService`, `GitHookInstaller`).

### 1. `unlock`

One-shot onboarding. For every filter discovered in `.gitattributes`:

1. Pull the AES key + IV from the configured storage backend (reuses `pull-aes-key` logic).
2. Configure git clean/smudge filters once (reuses `setup-filters`).
3. Decrypt the filter's matched files (reuses `decrypt-files`).

Behavior:
- Idempotent — safe to re-run.
- Continue-on-error per filter; a failure on one filter does not abort the others.
- Prints a per-filter summary (`✓ <filter>` / `✗ <filter>: <reason>`).
- Exit code non-zero if any filter failed.

### 2. `doctor`

Health and leak diagnosis via a new `DoctorService`. Per filter, three checks:

| Check | Pass condition |
|---|---|
| Filters wired | `filter.<name>.clean`, `.smudge`, and `.required` all set in git config |
| Key available | key+IV retrievable from local cache or the storage backend |
| Files encrypted | for each matched file, the **staged blob** begins with the magic header |

Output: a `✓` / `⚠` / `✗` report grouped by filter. **Exit code non-zero if any check FAILs**, so the same command works as a CI guard. `doctor` never raises — it collects findings and reports them.

`doctor` supersedes `status` for safety purposes. `status` keeps its current behavior; we add a one-line caveat to its output noting it reflects the working tree, not the committed content.

### 3. `install-hooks`

Installs a git `pre-commit` hook via a new `GitHookInstaller`.

Hook logic: for each staged file whose path matches a filter pattern, read the staged blob (`git cat-file blob :<path>`) and verify it starts with the magic header. If any matched file is staged as plaintext, the hook **blocks the commit** and prints a fix-it message pointing at `git-secret-protector unlock`.

Installer behavior:
- If no `pre-commit` hook exists, write one.
- If a managed hook (one we previously wrote, identified by a marker comment) exists, overwrite it.
- If an unmanaged `pre-commit` hook exists, **chain** onto it (invoke the existing hook, then our check) rather than clobbering; refuse to overwrite without `--force`.

## Component boundaries

- **`DoctorService`** — pure diagnosis. Input: filters + parser + key manager. Output: a list of structured findings (filter, check, status, detail). No printing inside; the CLI handler formats. Independently testable.
- **`GitHookInstaller`** — owns hook file content, marker detection, and chaining. Independently testable against a temp git repo.
- **CLI handlers** in `main.py` — thin: parse args, call the service, format output, set exit code.
- The staged-blob magic-header check is shared logic (used by both `doctor` and the hook script); factor it into one helper rather than duplicating.

## Error handling

- `unlock`: per-filter try/except, aggregate report, non-zero exit on any failure.
- `doctor`: total isolation — one bad filter or unreadable file becomes a finding, never an exception.
- `install-hooks`: never destroys an unmanaged hook silently; `--force` required to replace one.

## Testing

- **Temp-git-repo fixture** for staged-blob checks: stage encrypted and plaintext files, assert `doctor` and the hook detect each correctly using real `git cat-file`.
- **`unlock`**: mock `EncryptionManager` methods; assert per-filter orchestration, continue-on-error, and exit codes.
- **`GitHookInstaller`**: assert fresh install, managed overwrite, unmanaged chaining, and `--force` semantics.
- **Hook script**: test its plaintext-detection logic directly against staged blobs.
- Named failure modes the suite must cover: filter not configured (plaintext staged), key missing, partially-encrypted filter, existing unmanaged pre-commit hook.

## Deferred (separate spec — "Trust hardening")

- AES-GCM authenticated encryption with a versioned magic header and a migration path for repos already encrypted with AES-CBC.
- Key access / rotation audit log.
- Key-version tracking.
