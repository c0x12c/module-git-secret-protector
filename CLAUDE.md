# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> Local-only rules, machine paths, AWS profiles, and work-in-progress notes live in `CLAUDE.local.md` (gitignored). Keep this committed file team-shareable; keep anything personal or machine-specific out of it.

## Commands

```bash
# Install dependencies
poetry install

# Run all tests
poetry run pytest

# Run a single test file
poetry run pytest tests/unit/test_encryption_manager.py

# Run a specific test
poetry run pytest tests/unit/test_encryption_manager.py::TestEncryptionManager::test_decrypt_data

# Format code (enforced by pre-commit)
poetry run black src/ tests/

# Run the CLI locally
poetry run git-secret-protector --help
```

Integration tests (`tests/integration/`) hit real cloud secret stores — run manually, never in CI.

## CLI surface

The product is the `git-secret-protector` CLI (entry `main:main`). Subcommands are defined in `main.py`:
- `setup-filters` — write clean/smudge filters into `.git/config` from `.gitattributes`.
- `setup-aes-key <filter>` / `pull-aes-key <filter>` / `rotate-key <filter>` — key lifecycle against the storage backend.
- `encrypt-files <filter>` / `decrypt-files <filter>` / `clean-filter <filter>` — bulk operations over a filter's matched files.
- `encrypt <file>` / `decrypt <file>` — stdin↔stdout, invoked by git's clean/smudge filters per file.
- `status` / `version`.

## Architecture

The tool is a CLI that integrates with git's smudge/clean filter mechanism to transparently encrypt/decrypt files on commit/checkout.

**Entry point:** `src/git_secret_protector/main.py`
- Module-level eager initialization (`inj`, `manager`) runs before `main()` — this causes a crash when run outside a git repo (even for `--help`).
- `init_module_folder()` creates `.git_secret_protector/{cache,logs}/` and a default `config.ini` on first run.

**Configuration** (`core/settings.py`):
- `Settings` is a singleton loaded at import time via `get_settings()`.
- It walks up the directory tree looking for `.git/` to find the repo root — raises `FileNotFoundError` if not in a git repo.
- `storage_type` in `config.ini` controls the backend: `AWS_SSM` (default) or `GCP_SECRET`.

**Dependency injection** (`context/module.py`):
- `GitSecretProtectorModule` uses the `injector` library to wire `AesKeyManager` and `GitAttributesParser` as singletons.
- `EncryptionManager` is the top-level service injected into the CLI handlers.

**Crypto layer** (`crypto/`):
- `AesKeyManager` — fetches/stores AES key+IV from the configured storage backend; caches locally in `.git_secret_protector/cache/`.
- `AesEncryptionHandler` — authenticated deterministic encryption. HKDF-SHA256 derives domain-separated enc/mac/iv subkeys from the stored key; IV is content-derived (`HMAC(iv_key, plaintext)[:16]`) so identical plaintext yields identical ciphertext (git-stable); AES-256-CTR + encrypt-then-HMAC-SHA256. Wire format `magic_header(default ENCRYPTED) + 0x02 + base64(iv||ct||tag)`. Decrypt dispatches on the version byte: v2 (this scheme) vs v1 (legacy AES-CBC, still readable).
- `KeyRotator` (`services/key_rotator.py`) — generates a new key, re-encrypts all matched files, stores the new key.

**Storage backends** (`storage/`):
- All backends implement `StorageManagerInterface` (`store`, `retrieve`, `delete`).
- `StorageManagerFactory` selects `AwsSsmStorageManager` or `GcpSecretStorageManager` based on `settings.storage_type`.
- `AwsSsmStorageManager` uses a hierarchical SSM path including AWS account ID + abbreviated region + module name + filter name. Includes legacy path migration logic (`_handle_legacy_parameter`) for paths without the region component.

**Git integration** (`core/git_attributes_parser.py`):
- Reads `.gitattributes` to map file glob patterns → filter names.
- `get_filter_names()` returns all unique filter names; `get_files_for_filter(name)` globs matching files.

## Maintaining this file

Treat CLAUDE.md as a high-leverage cache, not documentation. Every line is re-read each session, so each line must earn its place.

- **Only the big picture.** Record what spans multiple files and can't be grasped by reading one of them (the eager-init crash, the singleton `Settings` repo-root walk, the storage-factory dispatch). Skip anything one `Read` or `grep` reveals.
- **Non-obvious over comprehensive.** Don't enumerate files, classes, or the full directory tree — those are discoverable. Capture surprises, gotchas, and the "why."
- **Don't duplicate the README.** End-user install/usage lives in `README.md`; link, don't copy. This file is for *operating on the code*.
- **Update on architecture change, not on every commit.** When a refactor changes a load-bearing fact here (e.g. the encryption scheme moving from v1 CBC to v2 CTR+HMAC), edit the affected line in the same change. A stale line is worse than a missing one.
- **Route by audience.** Team-shareable + committed → here. Personal, machine-specific, or work-in-progress → `CLAUDE.local.md`.
