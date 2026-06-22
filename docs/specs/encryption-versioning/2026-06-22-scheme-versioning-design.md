# Encryption scheme versioning for backward compatibility

Status: approved design (direction confirmed; ships as a minor release)
Date: 2026-06-22

## Goal

Let v1.2.x clients (which only understand the legacy unauthenticated AES-CBC scheme) and
v1.4.0+ clients (authenticated AES-CTR + HMAC, "v2") coexist on the same repo. Make the
encryption scheme a property of the stored key blob:

- New keys default to authenticated **v2**.
- `setup-aes-key --scheme v1` opts a filter down to the legacy scheme for repos that still
  have un-upgradeable old clients.
- `upgrade-scheme <filter>` performs a one-way v1 -> v2 migration (confirm-gated,
  idempotent, verify-after; no runtime downgrade).
- `status` / `doctor` surface the active scheme; v1 is flagged as a security warning.

## Versioning decision

This is **additive** and ships as a **minor** release (1.5.0), not 2.0.0. Existing v2 users
see no behavior change (v2 remains the default; decrypt already reads both formats). The
ticket's "2.0.0" framing predates the finding that nothing breaks. The actual release is
triggered separately and is out of scope for the implementation PR.

## Security framing (dominant constraint)

`--scheme v1` deliberately reintroduces **unauthenticated, fixed-IV AES-CBC** - the scheme
v2 was built to replace. This downgrade must be loud, never silent:

- `setup-aes-key --scheme v1` prints a security warning to stderr.
- `doctor` reports a v1 filter as `[WARN]` (status `warn`), not `[ OK ]`.
- `status` surfaces the scheme per filter.
- The PR description and commit messages carry the security caveat (the release CHANGELOG
  is auto-generated from git log by the release workflow; do not hand-edit CHANGELOG).

## Architecture

### Decrypt stays version-byte-authoritative (unchanged)

`AesEncryptionHandler._perform_decryption` already dispatches on the file's wire bytes:
a `0x02` version byte after the magic header => v2 (CTR+HMAC); otherwise => v1 (CBC).
This is independent of the key blob's scheme, so a v2 key blob still decrypts on-disk v1
files mid-migration. Do not couple decrypt to the blob scheme.

### Encrypt becomes scheme-driven

`AesEncryptionHandler` gains a `scheme` parameter (default `"v2"`), and `_perform_encryption`
branches on it:

- `scheme == "v2"` (default): current behavior - `magic_header + 0x02 + base64(iv||ct||tag)`,
  content-derived IV, HKDF subkeys, AES-256-CTR, encrypt-then-HMAC.
- `scheme == "v1"`: legacy CBC - `magic_header + base64(AES-CBC(pad(plaintext), aes_key, iv))`
  using the **stored** iv (fixed, so identical plaintext -> identical ciphertext, preserving
  git determinism). No `0x02` version byte (the decrypt v1 path is the no-version-byte branch).
  The already-encrypted short-circuit (`data.startswith(magic_header) -> return data`) applies
  to both schemes.

Default `scheme="v2"` keeps every existing constructor call site working unchanged
(`key_rotator.py`, tests).

### Scheme stored in the key blob

The blob already contains `"version": 2`. Reuse it as the authoritative **encrypt** scheme
selector (values `1` or `2`); do not add a redundant key.

- `AesKeyManager.setup_aes_key_and_iv(filter_name, scheme="v2")` writes
  `"version": 2` or `1` accordingly.
- New method `AesKeyManager.get_scheme(filter_name) -> "v1" | "v2"`: reads the blob (cache
  first, same path as `retrieve_key_and_iv`), maps `version` 1->"v1", 2/absent->"v2"
  (absent defaults to v2: a 1.4.0-written blob always has it; only hypothetical hand-written
  blobs would lack it, and v2 is the safe authenticated default).
- New method `AesKeyManager.set_scheme(filter_name, scheme)`: rewrites the stored blob's
  `version` field (used by `upgrade-scheme`), preserving `aes_key`/`iv`, in both storage
  backend and local cache.

A 1.2.4 client ignores the `version` field and always does CBC; that is exactly correct for
a v1-scheme filter (files are CBC) and is the incompatibility we are fixing for v2-scheme
filters (don't point old clients at v2 filters).

### Handler construction reads the scheme

`EncryptionManager.__get_encryption_handler(filter_name)` passes the scheme:

```python
def __get_encryption_handler(self, filter_name):
    aes_key, iv = self.key_manager.retrieve_key_and_iv(filter_name)
    scheme = self.key_manager.get_scheme(filter_name)
    return AesEncryptionHandler(aes_key=aes_key, iv=iv,
                                magic_header=self.magic_header, scheme=scheme)
```

`retrieve_key_and_iv`'s `(key, iv)` signature is unchanged (key_rotator keeps working).

## Commands

### `setup-aes-key --scheme {v1,v2}`

Default `v2`. Add `--scheme` to the subparser. `EncryptionManager.setup_aes_key` gains a
`scheme="v2"` param, passed to `key_manager.setup_aes_key_and_iv`. On `v1`, emit a security
warning via `self.output.error(...)` (stderr) before the success line, e.g.
`"WARNING: filter '<f>' uses the legacy v1 scheme (unauthenticated AES-CBC). Use only for
repos with pre-1.4.0 clients; run 'upgrade-scheme <f>' once they are upgraded."`
JSON envelope success includes `"scheme": "v1"`.

### `rotate-key` preserves the filter's scheme

`KeyRotator.rotate_key` currently generates a new key and re-encrypts. It must preserve the
existing filter scheme: read `get_scheme(filter_name)` before rotation; the new key blob is
written with the same scheme, and re-encryption uses a handler constructed with that scheme.
(Without this, rotating a v1 filter would silently upgrade it to v2 and break old clients.)

### `upgrade-scheme <filter>`

One-way v1 -> v2 migration:

1. `scheme = get_scheme(filter)`. If already `v2`: print idempotent no-op message
   (`"Filter '<f>' is already on scheme v2; nothing to do."`), return 0.
2. Confirm-gate (skip with `-y/--yes`), EOF-safe decline (mirror `rotate_keys`):
   `"Upgrade filter '<f>' from v1 to v2? This re-encrypts ALL matched files. [y/N] "`.
3. Re-encrypt every matched file to v2: decrypt with the v1 handler (or rely on
   version-byte decrypt), then write back with a v2 handler. Reuse the existing per-file
   bulk path with progress.
4. `set_scheme(filter, "v2")` AFTER all files are re-encrypted (fail-safe ordering: a crash
   mid-run leaves version=1 and a mix of v1/v2 files, all still decryptable by version byte).
5. Verify-after: assert every matched file is now v2-encrypted (`__is_encrypted` and the
   version byte == 0x02); on mismatch, error + nonzero exit.
6. No downgrade path (no v2 -> v1).
   JSON envelope: `{ok, command:"upgrade-scheme", filter, counts:{reencrypted,total}}`.

### `status` / `doctor` surface the scheme

- `status` JSON: each filter object gains `"scheme": "v1"|"v2"`. Human output adds a
  `  scheme: v1|v2` line under each `Filter:` header.
- `doctor`: add a per-filter scheme check `{check:"scheme.<filter>", status, detail, filter}`
  - `v2` -> status `ok`, detail `"filter '<f>' uses authenticated scheme v2"`.
  - `v1` -> status `warn`, detail `"filter '<f>' uses legacy unauthenticated scheme v1
    (run upgrade-scheme once all clients are >=1.4.0)"`.
  Human render uses the existing `[ OK ]`/`[WARN]` label mapping.

## Affected files

- `src/git_secret_protector/crypto/aes_encryption_handler.py` - `scheme` param + v1 encrypt branch.
- `src/git_secret_protector/crypto/aes_key_manager.py` - `setup_aes_key_and_iv(scheme=...)`,
  `get_scheme`, `set_scheme`.
- `src/git_secret_protector/services/encryption_manager.py` - pass scheme to handler;
  `setup_aes_key(scheme=...)` + warning; `upgrade_scheme`; status/doctor scheme surfacing.
- `src/git_secret_protector/services/key_rotator.py` - preserve scheme across rotation.
- `src/git_secret_protector/main.py` - `--scheme` on setup-aes-key; `upgrade-scheme` subcommand.
- Tests across `tests/unit/`.

## Testing

- Handler: v1 encrypt round-trips through v1 decrypt; v1 ciphertext is deterministic for the
  same plaintext; v2 path unchanged; the magic-header short-circuit holds for both.
- Cross-scheme: a v1-encrypted file decrypts, and the decrypt path is selected by the wire
  byte regardless of blob scheme.
- key_manager: setup with scheme v1 writes version 1; get_scheme maps version<->scheme and
  defaults absent->v2; set_scheme rewrites version preserving key/iv (cache + backend).
- setup-aes-key --scheme v1 emits the stderr warning and the JSON scheme field.
- rotate-key on a v1 filter keeps scheme v1 (new blob version 1; re-encrypted files are v1).
- upgrade-scheme: idempotent no-op on v2; v1->v2 re-encrypts all files, sets version 2,
  verify-after passes; EOF/decline aborts without changing files or blob; crash-safety
  ordering (blob updated last) is exercised by asserting files are v2 before the blob flip is
  observable, or by unit-testing the ordering.
- status/doctor: scheme surfaced in JSON and human; v1 -> doctor warn (not ok).
- Guard-rail (existing): encrypt/decrypt filter stdout stays pure bytes - must still pass.

Test command: `poetry run pytest tests/unit/`.

## Out of scope

- The 1.5.0 release trigger (held for explicit go-ahead; irreversible PyPI publish).
- #1981 (CI image bump) - separate ticket, credential-blocked.
