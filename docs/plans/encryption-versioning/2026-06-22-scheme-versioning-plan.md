# Encryption Scheme Versioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Make the encryption scheme (v1 legacy CBC / v2 authenticated) a property of the stored key blob so 1.2.x and 1.4.0+ clients coexist; add `setup-aes-key --scheme`, `upgrade-scheme`, and scheme surfacing in status/doctor.

**Design source:** `docs/specs/encryption-versioning/2026-06-22-scheme-versioning-design.md` (read it for full rationale).

**Tech Stack:** Python 3.9, pycryptodome (AES/HMAC/HKDF - already a dep), argparse, injector.

## Global Constraints

- Python 3.9; no new dependencies. Formatter `black` pinned `24.8.0` (format only touched files).
- DECRYPT stays version-byte-authoritative (`_perform_decryption` dispatch on the wire `0x02` byte) and is INDEPENDENT of the key blob scheme. Do not couple them.
- The `encrypt`/`decrypt` stdin filter path stays stdout-pure (binary payload only) - the existing guard-rail test must still pass.
- v1 is unauthenticated AES-CBC: the downgrade must be LOUD (warn on setup, `[WARN]` in doctor, surfaced in status). Never silent.
- New keys default to v2; `AesEncryptionHandler` `scheme` param defaults to `"v2"` so existing call sites are unchanged.
- Human-mode output of existing commands stays byte-identical except for the NEW additive scheme lines.
- Test command: `poetry run pytest tests/unit/`.
- AES key is 32 bytes, IV 16 bytes (valid for AES-256-CBC).

---

### Task 1: Scheme-aware `AesEncryptionHandler` (v1 encrypt branch)

**Files:**
- Modify: `src/git_secret_protector/crypto/aes_encryption_handler.py`
- Test: `tests/unit/test_encryption_handler.py` (or the existing handler test file - inspect; the crypto tests live in `tests/unit/test_encryption_manager.py` `TestEncryptionManager` and possibly a dedicated file. Add to whichever holds `AesEncryptionHandler` unit tests; create `tests/unit/test_encryption_handler.py` if none).

**Interfaces:**
- Produces: `AesEncryptionHandler(aes_key, iv, magic_header, scheme="v2")`. `_perform_encryption` branches on `self.scheme`.

- [ ] **Step 1: Write failing tests**

```python
# v1 encrypt must round-trip through the existing v1 decrypt path, be deterministic,
# and NOT carry the 0x02 version byte. v2 path must be unchanged.
import secrets
from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler

MH = b"ENCRYPTED"

def _h(scheme):
    return AesEncryptionHandler(aes_key=secrets.token_bytes(32), iv=secrets.token_bytes(16),
                                magic_header=MH, scheme=scheme)

def test_v1_roundtrip_and_deterministic():
    h = _h("v1")
    data = b"super-secret-value"
    ct1 = h.encrypt_data(data)
    ct2 = h.encrypt_data(data)
    assert ct1.startswith(MH)
    assert ct1[len(MH):len(MH)+1] != b"\x02"   # v1 has no version byte
    assert ct1 == ct2                            # deterministic (fixed stored IV)
    assert h.decrypt_data(ct1) == data           # decrypt dispatches via wire bytes

def test_v2_still_default_and_authenticated():
    h = _h("v2")
    data = b"abc"
    ct = h.encrypt_data(data)
    assert ct[len(MH):len(MH)+1] == b"\x02"
    assert h.decrypt_data(ct) == data

def test_scheme_defaults_to_v2():
    h = AesEncryptionHandler(aes_key=secrets.token_bytes(32), iv=secrets.token_bytes(16), magic_header=MH)
    assert h.encrypt_data(b"x")[len(MH):len(MH)+1] == b"\x02"

def test_magic_header_short_circuit_both_schemes():
    for s in ("v1", "v2"):
        h = _h(s)
        already = MH + b"whatever"
        assert h.encrypt_data(already) == already
```

- [ ] **Step 2: Run -> fail** (`scheme` kwarg unknown / v1 produces v2)

Run: `poetry run pytest tests/unit/test_encryption_handler.py -v`

- [ ] **Step 3: Implement**

In `__init__` add `scheme="v2"` and store `self.scheme = scheme`. Split `_perform_encryption`:

```python
def _perform_encryption(self, data: bytes) -> bytes:
    if data.startswith(self.magic_header):
        logger.info("Data already contains MAGIC_HEADER. Skipping encryption.")
        return data
    if self.scheme == "v1":
        return self._encrypt_v1(data)
    return self._encrypt_v2(data)

def _encrypt_v1(self, data: bytes) -> bytes:
    from Crypto.Util.Padding import pad  # already imported at top; reuse existing import
    ciphertext = AES.new(self.aes_key, AES.MODE_CBC, self.iv).encrypt(pad(data, AES.block_size))
    return self.magic_header + base64.b64encode(ciphertext)

def _encrypt_v2(self, data: bytes) -> bytes:
    iv = HMAC.new(self._iv_key, data, SHA256).digest()[:16]
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    ciphertext = AES.new(self._enc_key, AES.MODE_CTR, counter=ctr).encrypt(data)
    tag = HMAC.new(self._mac_key, iv + ciphertext, SHA256).digest()
    return self.magic_header + self.V2 + base64.b64encode(iv + ciphertext + tag)
```

(Move the existing v2 body verbatim into `_encrypt_v2`. `pad` is already imported at module top - do not re-import; the inline import above is illustrative, use the top-level one.) Leave `_perform_decryption` untouched.

- [ ] **Step 4: Run -> pass**; then full suite `poetry run pytest tests/unit/`.
- [ ] **Step 5: Format + commit** `feat(crypto): scheme-aware encryption handler with v1 legacy encrypt`

---

### Task 2: Key blob scheme - `setup_aes_key_and_iv(scheme)`, `get_scheme`, `set_scheme`

**Files:**
- Modify: `src/git_secret_protector/crypto/aes_key_manager.py`
- Test: `tests/unit/test_aes_key_manager.py` (inspect existing; add if absent)

**Interfaces:**
- `setup_aes_key_and_iv(self, filter_name, scheme="v2")` - writes `"version": 1` if scheme=="v1" else `2`.
- `get_scheme(self, filter_name) -> "v1"|"v2"` - reads the blob (cache-first via the same path `retrieve_key_and_iv` uses), maps `version` 1->"v1" else "v2" (absent->"v2").
- `set_scheme(self, filter_name, scheme)` - rewrites the stored blob's `version` (preserving aes_key/iv) in BOTH the storage backend and the local cache.

- [ ] **Step 1: Write failing tests** - mock the storage manager + use a tmp cache dir (mirror existing key-manager test setup; if none, patch `get_settings` to a tmp dir and patch `_get_storage_manager`). Cover:
  - setup with scheme="v1" writes a blob whose `version` == 1; default writes 2.
  - get_scheme returns "v1" for version 1, "v2" for version 2, "v2" when version absent.
  - set_scheme(filter, "v2") rewrites version to 2 while preserving aes_key/iv (assert by reloading), updates both backend store and cache.

- [ ] **Step 2: Run -> fail.**

- [ ] **Step 3: Implement.**
  - In `setup_aes_key_and_iv`, accept `scheme="v2"`, set `"version": 1 if scheme == "v1" else 2` in `data`.
  - `get_scheme`: load blob via `load_key_iv_from_cache` first, else backend `retrieve` + `json.loads`; `v = data.get("version", 2)`; return `"v1" if v == 1 else "v2"`. Wrap in the existing error->AesKeyError style only if a read fails in a way callers expect; otherwise default safely to "v2" on a malformed/missing version field (do NOT crash status/doctor on a read miss - but a missing KEY entirely should still raise as today).
  - `set_scheme`: read current blob (backend authoritative), set `data["version"] = 2 if scheme=="v2" else 1`, `store(parameter_name, json.dumps(data))`, then `cache_key_iv_locally(filter_name, json.dumps(data))`.

- [ ] **Step 4: Run -> pass; full suite.**
- [ ] **Step 5: Format + commit** `feat(keys): store encryption scheme in key blob (setup/get/set_scheme)`

---

### Task 3: Wire scheme into handler + `setup-aes-key --scheme` + warning

**Files:**
- Modify: `src/git_secret_protector/services/encryption_manager.py` (`__get_encryption_handler`, `setup_aes_key`)
- Modify: `src/git_secret_protector/main.py` (`--scheme` on setup-aes-key; pass through)
- Test: `tests/unit/test_encryption_manager.py`, `tests/unit/test_main_cli.py`

**Interfaces:**
- `__get_encryption_handler` builds the handler with `scheme=self.key_manager.get_scheme(filter_name)`.
- `setup_aes_key(self, filter_name, scheme="v2")` -> passes scheme to `key_manager.setup_aes_key_and_iv`; on v1 emits the security warning via `self.output.error(...)`; JSON envelope includes `"scheme"`.
- main: setup-aes-key subparser gains `--scheme` choices `v1`,`v2` default `v2`; `setup_aes_key` handler passes `args.scheme`.

- [ ] **Step 1: Failing tests**
  - `__get_encryption_handler` constructs handler with the filter's scheme (patch get_scheme -> "v1", assert handler.scheme == "v1"). Access via the name-mangled method.
  - `setup_aes_key(scheme="v1")` calls `key_manager.setup_aes_key_and_iv(filter_name, scheme="v1")` and writes a stderr line containing "WARNING" and "v1"; JSON envelope has `scheme=="v1"`.
  - CLI: `setup-aes-key <f> --scheme v1` parses and reaches the manager with scheme v1 (can assert via a mock or via the warning text in stderr in a subprocess test with a seeded backend; if backend calls are unavoidable, keep this as a unit test on the handler function instead).

- [ ] **Step 2-4:** implement, run, full suite.
- [ ] **Step 5: commit** `feat(cli): setup-aes-key --scheme with v1 security warning; handler reads scheme`

---

### Task 4: `rotate-key` preserves the filter's scheme

**Files:**
- Modify: `src/git_secret_protector/services/key_rotator.py`
- Test: `tests/unit/` (key rotator tests / `test_encryption_manager.py` rotate tests)

**Interfaces:**
- `KeyRotator.rotate_key` reads `get_scheme(filter_name)` before rotation; writes the new key blob with the same scheme and re-encrypts using a handler built with that scheme.

- [ ] **Step 1: Failing test** - rotating a v1 filter keeps scheme v1: mock key_manager so `get_scheme -> "v1"`; assert the new-key setup is called with `scheme="v1"` (or that set_scheme/setup writes version 1) and the encryption handler used for re-encrypt has scheme "v1". Mirror the existing rotate test structure.

- [ ] **Step 2-4:** implement (read scheme; thread it through the new-key creation and the re-encrypt handler construction in key_rotator), run, full suite.

  Note: inspect `key_rotator.py` rotate_key flow - it calls `retrieve_key_and_iv` then builds `AesEncryptionHandler(...)` twice (decrypt-old, encrypt-new). The encrypt-new handler must use the preserved scheme; the decrypt-old handler can stay default (decrypt is version-byte-authoritative). The new key's blob must be written with the preserved scheme.

- [ ] **Step 5: commit** `fix(rotate): preserve filter encryption scheme across key rotation`

---

### Task 5: `upgrade-scheme <filter>` command

**Files:**
- Modify: `src/git_secret_protector/services/encryption_manager.py` (`upgrade_scheme`)
- Modify: `src/git_secret_protector/main.py` (subcommand + handler)
- Test: `tests/unit/test_encryption_manager.py`, `tests/unit/test_main_cli.py`

**Interfaces:**
- `EncryptionManager.upgrade_scheme(self, filter_name, assume_yes=False)`:
  1. `scheme = key_manager.get_scheme(filter)`; if `"v2"` -> info "already on v2", JSON `{ok, command:"upgrade-scheme", filter, message, counts:{reencrypted:0,total:N}}`, return.
  2. confirm-gate (EOF-safe, skip with assume_yes), mirror `rotate_keys`.
  3. re-encrypt every matched file to v2: read each file, decrypt (version-byte handler), write back with a v2 handler; emit per-file progress (reuse the bulk progress pattern). Practically: temporarily get a v2 handler (build `AesEncryptionHandler(key, iv, magic_header, scheme="v2")`) and for each file: decrypt with a default handler then encrypt with the v2 handler, OR simpler: since files are v1 on disk, `decrypt_file` (version-byte) then `encrypt_file` with the v2 handler. Implement via the handler's per-file methods.
  4. `key_manager.set_scheme(filter, "v2")` AFTER all files re-encrypted (fail-safe ordering).
  5. verify-after: every matched file `__is_encrypted` and its post-magic byte == 0x02; on any failure -> error + sys.exit(1).
  6. JSON envelope `{ok, command:"upgrade-scheme", filter, counts:{reencrypted, total}}`; human success line.
- main: `upgrade-scheme` subparser with `filter_name` (nargs="?") + `-y/--yes`, `parents=[common]`; handler `upgrade_scheme(args)` calls `manager.upgrade_scheme(args.filter_name, assume_yes=args.yes)`. Apply `_require_filter`.

- [ ] **Step 1: Failing tests**
  - idempotent: get_scheme->"v2" -> no-op, returns, set_scheme NOT called, counts.reencrypted==0.
  - v1->v2: get_scheme->"v1", two matched files; assume_yes=True; asserts files re-encrypted to v2 (mock handler/`__is_encrypted`), `set_scheme(filter,"v2")` called AFTER re-encryption, JSON counts.reencrypted==2.
  - decline: assume_yes=False, input raises EOFError -> aborts, set_scheme NOT called, no re-encryption.
  - verify-after failure -> sys.exit(1) (simulate a file still v1 after re-encrypt).
- [ ] **Step 2-4:** implement, run, full suite.
- [ ] **Step 5: commit** `feat(cli): upgrade-scheme command for one-way v1->v2 migration`

---

### Task 6: Surface scheme in `status` and `doctor`

**Files:**
- Modify: `src/git_secret_protector/services/encryption_manager.py` (`status`, `doctor`)
- Test: `tests/unit/test_encryption_manager.py`

**Interfaces:**
- `status`: each filter dict gains `"scheme": get_scheme(name)`; human adds a `  scheme: <s>` line under the `Filter:` header. (Wrap get_scheme in try/except -> default "v2" or omit on read error, so status never crashes.)
- `doctor`: per filter add a check `{"check": "scheme", "status": "ok"|"warn", "detail": ..., "filter": name}` - v2 ok, v1 warn. Human render via the existing label map.

- [ ] **Step 1: Failing tests**
  - status json: filter has `scheme` field (patch get_scheme).
  - status human: `  scheme: v1` line present for a v1 filter; existing status assertions unchanged.
  - doctor json: a v1 filter yields a scheme check with status "warn" and a `filter` key; v2 yields "ok".
  - doctor human: v1 filter prints a `[WARN]` scheme line; existing doctor substring assertions unchanged; exit code semantics unchanged (a v1 warn does NOT make doctor return 1 - only plaintext does).
- [ ] **Step 2-4:** implement (build into the existing status/doctor dict-then-fork structure from the prior feature), run, full suite.
- [ ] **Step 5: commit** `feat(status,doctor): surface per-filter encryption scheme (v1 flagged warn)`

---

### Task 7: README documentation

**Files:** Modify `README.md`

- [ ] Document `setup-aes-key --scheme {v1,v2}` (with the v1 = unauthenticated-legacy security note), `upgrade-scheme <filter>`, and that status/doctor now show the scheme. Match existing heading style; plain hyphens only; no emojis.
- [ ] Commit `docs: document encryption scheme versioning (setup --scheme, upgrade-scheme)`

---

## Self-Review

**Spec coverage:** scheme-in-blob (T2), scheme-aware encrypt with v1 reintroduced (T1), handler wiring + setup --scheme + warning (T3), rotate preserves scheme (T4), upgrade-scheme one-way migration (T5), status/doctor surfacing with v1 warn (T6), docs (T7). Decrypt left version-byte-authoritative (untouched across all tasks). Guard-rail stdout-purity test untouched.

**Type consistency:** scheme is the string `"v1"`/`"v2"` everywhere at the service layer; the key blob stores int `version` 1/2; `get_scheme`/`set_scheme` are the only translation boundary. `AesEncryptionHandler(scheme=...)` default `"v2"`.

**Security:** v1 paths are warned at setup (T3), flagged warn in doctor/status (T6), documented as a security caveat (T7, PR body). v1 reintroduction is encrypt-only; decrypt already supported v1.

**Release:** version bump + publish are NOT in this plan (held for go-ahead). Do not edit pyproject version or CHANGELOG.
