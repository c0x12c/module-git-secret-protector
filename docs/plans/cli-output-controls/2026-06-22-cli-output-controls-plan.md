# CLI Output Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--quiet` / `--verbose` / `--json` global flags and bulk progress to the `git-secret-protector` CLI.

**Architecture:** A single `Output` object (`core/output.py`), configured once in `main()` from parsed flags and injector-bound, centralizes stdout/stderr/json routing. The `encrypt`/`decrypt` clean/smudge filter path is exempt (stdout is binary data). `status`/`doctor` build a structured dict and fork at the end on `output.json`.

**Tech Stack:** Python 3.9, argparse, injector, stdlib json/logging. No new dependencies.

## Global Constraints

- Python 3.9 compatible; no new dependencies (no `tqdm`).
- Formatter: `black` pinned `24.8.0`. Format only touched files.
- `encrypt`/`decrypt` (stdin filter path) stdout MUST remain pure payload bytes under every flag combination. Never route their stdout through `Output`.
- Human-mode output text of every command MUST stay byte-identical to current strings (snapshot-locked).
- `--json` output is atomic: build the full dict, then dump once. Errors in json mode emit `{ok:false,...}` to stdout + nonzero exit.
- Verbose console log handler MUST target `sys.stderr` explicitly, never stdout.
- Test command: `poetry run pytest tests/unit/`.

---

## File Structure

- Create `src/git_secret_protector/core/output.py` - the `Output` class.
- Create `tests/unit/test_output.py` - Output unit tests.
- Modify `src/git_secret_protector/utils/configure_logging.py` - optional stderr console handler.
- Modify `src/git_secret_protector/context/module.py` - bind `Output`.
- Modify `src/git_secret_protector/main.py` - parent parser, flag parse, mode resolve, build+bind Output.
- Modify `src/git_secret_protector/services/encryption_manager.py` - route output via `Output`; dicts for status/doctor; envelopes; bulk progress.
- Modify `tests/unit/test_encryption_manager.py` - update for Output, add json/progress/snapshot tests.
- Modify `tests/unit/test_main_cli.py` - flag parsing + guard-rail stdout-purity tests.
- Modify `README.md` - document the new flags.

---

### Task 1: `Output` class

**Files:**
- Create: `src/git_secret_protector/core/output.py`
- Test: `tests/unit/test_output.py`

**Interfaces:**
- Produces: `Output(quiet=False, verbose=False, json=False)` with methods
  `info(message: str) -> None`, `error(message: str) -> None`, `progress(message: str) -> None`,
  `result(obj: dict) -> None`, and property `json -> bool`.
- Routing: `info`/`progress` suppressed when `quiet` or `json`; `info` -> stdout, `progress` -> stderr.
  `error` -> stderr always. `result` -> `json.dumps(obj)` + newline to stdout only when `json`, else no-op.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_output.py
import contextlib
import io
import json
import unittest

from git_secret_protector.core.output import Output


class TestOutput(unittest.TestCase):
    def _capture(self, fn):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            fn()
        return out.getvalue(), err.getvalue()

    def test_normal_info_to_stdout(self):
        out, err = self._capture(lambda: Output().info("hi"))
        self.assertEqual(out, "hi\n")
        self.assertEqual(err, "")

    def test_error_to_stderr_always(self):
        out, err = self._capture(lambda: Output(quiet=True).error("boom"))
        self.assertEqual(out, "")
        self.assertEqual(err, "boom\n")

    def test_quiet_suppresses_info_and_progress(self):
        out, err = self._capture(lambda: (Output(quiet=True).info("x"),
                                          Output(quiet=True).progress("p")))
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_progress_to_stderr_in_normal(self):
        out, err = self._capture(lambda: Output().progress("[1/2] a"))
        self.assertEqual(out, "")
        self.assertEqual(err, "[1/2] a\n")

    def test_json_result_to_stdout(self):
        out, err = self._capture(lambda: Output(json=True).result({"ok": True}))
        self.assertEqual(json.loads(out), {"ok": True})
        self.assertEqual(err, "")

    def test_json_suppresses_info_and_progress(self):
        out, err = self._capture(lambda: (Output(json=True).info("x"),
                                          Output(json=True).progress("p")))
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_result_noop_in_human_mode(self):
        out, err = self._capture(lambda: Output().result({"ok": True}))
        self.assertEqual(out, "")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/unit/test_output.py -v`
Expected: FAIL with `ModuleNotFoundError: ... core.output`

- [ ] **Step 3: Write minimal implementation**

```python
# src/git_secret_protector/core/output.py
import json as _json
import sys


class Output:
    """Centralized CLI output router. Never used for the encrypt/decrypt
    filter path, whose stdout carries binary file payload."""

    def __init__(self, quiet=False, verbose=False, json=False):
        self._quiet = quiet
        self._verbose = verbose
        self._json = json

    @property
    def json(self):
        return self._json

    @property
    def verbose(self):
        return self._verbose

    def info(self, message):
        if self._quiet or self._json:
            return
        print(message)

    def error(self, message):
        print(message, file=sys.stderr)

    def progress(self, message):
        if self._quiet or self._json:
            return
        print(message, file=sys.stderr)

    def result(self, obj):
        if not self._json:
            return
        print(_json.dumps(obj), file=sys.stdout)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/unit/test_output.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/git_secret_protector/core/output.py tests/unit/test_output.py
git commit -m "feat(output): add Output router for CLI output modes"
```

---

### Task 2: Verbose stderr log handler

**Files:**
- Modify: `src/git_secret_protector/utils/configure_logging.py`
- Test: `tests/unit/test_configure_logging.py` (create)

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces: `configure_logging(verbose: bool = False) -> None`. When `verbose`, adds a
  `logging.StreamHandler(sys.stderr)` at `logging.DEBUG` in addition to the rotating file handler.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_configure_logging.py
import logging
import sys
import unittest
from unittest.mock import patch, MagicMock

from git_secret_protector.utils.configure_logging import configure_logging


class TestConfigureLogging(unittest.TestCase):
    @patch("git_secret_protector.utils.configure_logging.get_settings")
    def _run(self, verbose, mock_get_settings, tmp_log="/tmp/gsp-test.log"):
        s = MagicMock()
        s.log_file = tmp_log
        s.log_level = "WARN"
        s.log_max_size = 1048576
        s.log_backup_count = 1
        mock_get_settings.return_value = s
        root = logging.getLogger()
        root.handlers = []
        configure_logging(verbose=verbose)
        return root.handlers

    def test_verbose_adds_stderr_stream_handler(self):
        handlers = self._run(True)
        stream = [h for h in handlers if isinstance(h, logging.StreamHandler)
                  and not isinstance(h, logging.handlers.RotatingFileHandler)]
        self.assertTrue(stream)
        self.assertIs(stream[0].stream, sys.stderr)

    def test_non_verbose_has_no_extra_stream_handler(self):
        handlers = self._run(False)
        stream = [h for h in handlers if type(h) is logging.StreamHandler]
        self.assertEqual(stream, [])
```

- [ ] **Step 2: Run to verify it fails**

Run: `poetry run pytest tests/unit/test_configure_logging.py -v`
Expected: FAIL with `TypeError: configure_logging() got an unexpected keyword argument 'verbose'`

- [ ] **Step 3: Implement**

```python
# src/git_secret_protector/utils/configure_logging.py
import logging
import logging.handlers
import os
import sys

from git_secret_protector.core.settings import get_settings


def configure_logging(verbose=False):
    settings = get_settings()
    log_file = settings.log_file
    log_level = settings.log_level
    log_max_size = settings.log_max_size
    log_backup_count = settings.log_backup_count

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=log_max_size, backupCount=log_backup_count
    )
    handler.setFormatter(formatter)

    handlers = [handler]
    if verbose:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(formatter)
        console.setLevel(logging.DEBUG)
        handlers.append(console)

    logging.basicConfig(level=log_level, handlers=handlers)
```

- [ ] **Step 4: Run to verify it passes**

Run: `poetry run pytest tests/unit/test_configure_logging.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add src/git_secret_protector/utils/configure_logging.py tests/unit/test_configure_logging.py
git commit -m "feat(logging): add opt-in verbose stderr console handler"
```

---

### Task 3: Flags, mode resolution, injector binding in `main()`

**Files:**
- Modify: `src/git_secret_protector/context/module.py`
- Modify: `src/git_secret_protector/main.py:120-256`
- Test: `tests/unit/test_main_cli.py`

**Interfaces:**
- Consumes: `Output` (Task 1), `configure_logging(verbose=...)` (Task 2).
- Produces: a parent parser exposing `--quiet`, `--verbose`, `--json`, `--repo-root`, inherited by
  every subparser via `parents=[common]`; `main()` builds `Output(quiet, verbose, json)`, rejects
  `--quiet --verbose`, binds the instance into the injector, and resolves `EncryptionManager` from it.
- `GitSecretProtectorModule.set_output(output)` stores an instance bound via `binder.bind(Output, to=output)`.

- [ ] **Step 1: Write the failing test** (append to `tests/unit/test_main_cli.py`)

```python
def test_quiet_and_verbose_conflict_exits_2(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".gitattributes").write_text("*.secret filter=secret\n")
    result = _run_main(["--repo-root", str(repo), "--quiet", "--verbose", "status"], tmp_path)
    assert result.returncode == 2
    assert "quiet" in result.stderr.lower()


def test_json_flag_after_subcommand_parses(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".gitattributes").write_text("*.secret filter=secret\n")
    result = _run_main(["--repo-root", str(repo), "status", "--json"], tmp_path)
    assert result.returncode == 0
    import json
    json.loads(result.stdout)  # stdout is a valid JSON document
```

(Reuse the existing `_run_main` / `_init_git_repo` helpers in this file. `_run_main` invokes the CLI in a subprocess; confirm its signature before writing and adapt argument passing.)

- [ ] **Step 2: Run to verify it fails**

Run: `poetry run pytest tests/unit/test_main_cli.py -k "conflict or json_flag_after" -v`
Expected: FAIL (flags unknown / non-zero schema)

- [ ] **Step 3: Implement module binding**

```python
# src/git_secret_protector/context/module.py
import injector

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.core.output import Output
from git_secret_protector.crypto.aes_key_manager import AesKeyManager


class GitSecretProtectorModule(injector.Module):
    _injector = None
    _output = None

    def configure(self, binder):
        binder.bind(AesKeyManager, to=AesKeyManager, scope=injector.singleton)
        binder.bind(
            GitAttributesParser, to=GitAttributesParser, scope=injector.singleton
        )
        binder.bind(Output, to=self._output or Output(), scope=injector.singleton)

    @classmethod
    def set_output(cls, output):
        cls._output = output
        cls._injector = None  # force rebuild so the binding picks up the instance

    @classmethod
    def get_injector(cls):
        if cls._injector is None:
            cls._injector = injector.Injector(GitSecretProtectorModule())
        return cls._injector
```

- [ ] **Step 4: Implement main() parent parser + mode resolution**

In `src/git_secret_protector/main.py`, add imports:

```python
from git_secret_protector.core.output import Output
```

Replace the parser construction (lines 121-153) so a shared parent parser defines the global flags, and `subparsers` is created normally. Add to the parent:

```python
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo-root", type=str, default=None, help=(
        "Repo root to operate on (overrides auto-detection; same as the "
        "SECRET_PROTECTOR_BASE_DIR env var)."))
    common.add_argument("--quiet", action="store_true",
                        help="Suppress success/info output (errors still shown).")
    common.add_argument("--verbose", action="store_true",
                        help="Show internal logs on stderr.")
    common.add_argument("--json", action="store_true",
                        help="Emit machine-readable JSON (status/doctor/version and "
                             "action results; ignored for encrypt/decrypt).")
```

Add `parents=[common]` to the top-level parser AND to every `subparsers.add_parser(...)` call so the
flags parse both before and after the subcommand. (Top-level keeps `-V/--version`.)

Replace the dispatch block (lines 232-255) with:

```python
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return

    if getattr(args, "quiet", False) and getattr(args, "verbose", False):
        print("Error: --quiet and --verbose are mutually exclusive.", file=sys.stderr)
        sys.exit(2)

    output = Output(
        quiet=getattr(args, "quiet", False),
        verbose=getattr(args, "verbose", False),
        json=getattr(args, "json", False),
    )

    try:
        if args.func is not show_project_version:
            if args.repo_root:
                repo_root = Path(args.repo_root).resolve()
                if not repo_root.is_dir():
                    print(
                        f"Error: --repo-root points to a missing directory: {args.repo_root}",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                os.environ[Settings.BASE_DIR_ENV_VAR] = str(repo_root)
                os.chdir(repo_root)
            init_module_folder()
            configure_logging(verbose=output.verbose)
            GitSecretProtectorModule.set_output(output)
            global manager
            manager = GitSecretProtectorModule.get_injector().get(EncryptionManager)
        else:
            show_project_version(args, output)
            return
        args.func(args)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
```

Note: `show_project_version` gains an `output` param in Task 4; until then keep its current
call form. Implement Task 4 in the same wave to avoid a broken intermediate.

- [ ] **Step 5: Run to verify it passes**

Run: `poetry run pytest tests/unit/test_main_cli.py -v`
Expected: PASS (existing + 2 new). If `version`/`status` json assertions fail, they are completed in Tasks 4/6 - run those tasks in the same wave.

- [ ] **Step 6: Commit**

```bash
git add src/git_secret_protector/context/module.py src/git_secret_protector/main.py tests/unit/test_main_cli.py
git commit -m "feat(cli): add --quiet/--verbose/--json flags and Output wiring"
```

---

> Tasks 4-8 modify `encryption_manager.py`. They share the constructor change below; apply it once in Task 4 and the later tasks build on it. Run Tasks 3-7 as one wave (they are interdependent through `main()` and the manager constructor).

---

### Task 4: Manager constructor + action-command output routing

**Files:**
- Modify: `src/git_secret_protector/services/encryption_manager.py`
- Modify: `tests/unit/test_encryption_manager.py`

**Interfaces:**
- Consumes: `Output` (Task 1).
- Produces: `EncryptionManager.__init__(self, git_attributes_parser, key_manager, key_rotator, output: Output = None)`
  storing `self.output = output if output is not None else Output()`. Action commands route human text
  through `self.output.info`/`self.output.error` and emit envelopes via `self.output.result`.
- Envelope helper (private): `self._envelope_ok(command, **fields)` -> dict `{"ok": True, "command": command, **fields}`;
  `self._envelope_err(command, error, **fields)` -> `{"ok": False, "command": command, "error": error, **fields}`.
- `show_project_version` becomes an instance-aware static taking `output`: `show_project_version(_, output)`.

- [ ] **Step 1: Write the failing test** (add to `TestEncryptionManagerService`)

```python
def test_setup_aes_key_json_envelope(self):
    from git_secret_protector.core.output import Output
    out = io.StringIO()
    self.manager.output = Output(json=True)
    with contextlib.redirect_stdout(out):
        self.manager.setup_aes_key("secret")
    payload = json.loads(out.getvalue())
    self.assertEqual(payload, {"ok": True, "command": "setup-aes-key",
                               "filter": "secret",
                               "message": "Successfully set up AES key for filter: secret"})

def test_setup_aes_key_json_error_envelope_and_exit(self):
    from git_secret_protector.core.output import Output
    self.key_manager.setup_aes_key_and_iv.side_effect = RuntimeError("boom")
    out = io.StringIO()
    self.manager.output = Output(json=True)
    with contextlib.redirect_stdout(out):
        with self.assertRaises(SystemExit) as ctx:
            self.manager.setup_aes_key("secret")
    self.assertEqual(ctx.exception.code, 1)
    payload = json.loads(out.getvalue())
    self.assertFalse(payload["ok"])
    self.assertEqual(payload["command"], "setup-aes-key")
    self.assertIn("boom", payload["error"])

def test_setup_aes_key_human_text_unchanged(self):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        self.manager.setup_aes_key("secret")
    self.assertIn("Successfully set up AES key for filter: secret", out.getvalue())
```

- [ ] **Step 2: Run to verify it fails**

Run: `poetry run pytest tests/unit/test_encryption_manager.py -k setup_aes_key_json -v`
Expected: FAIL (no envelope; plain text printed)

- [ ] **Step 3: Implement**

Add the import and constructor change:

```python
from git_secret_protector.core.output import Output
```

```python
    @injector.inject
    def __init__(self, git_attributes_parser, key_manager, key_rotator, output: Output = None):
        self.git_attributes_parser = git_attributes_parser
        self.key_manager = key_manager
        self.key_rotator = key_rotator
        self.output = output if output is not None else Output()
        self.magic_header = get_settings().magic_header.encode()

    def _envelope_ok(self, command, **fields):
        return {"ok": True, "command": command, **fields}

    def _envelope_err(self, command, error, **fields):
        return {"ok": False, "command": command, "error": error, **fields}
```

Convert `_print_context` to suppress under quiet (it already targets stderr):

```python
    def _print_context(self, filter_name=None):
        if self.output._quiet:
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
```

Convert each action command. Pattern for `setup_aes_key` (apply the same shape to
`pull_aes_key`, `setup_filters`, `clean_filter`, `rotate_keys`):

```python
    def setup_aes_key(self, filter_name: str):
        filter_name = self._require_filter(filter_name)
        self._print_context(filter_name)
        try:
            logger.info("Setting up AES key for filter: %s", filter_name)
            self.key_manager.setup_aes_key_and_iv(filter_name)
            logger.info("Successfully set up AES key for filter: %s", filter_name)
            msg = f"Successfully set up AES key for filter: {filter_name}"
            self.output.info(msg)
            self.output.result(self._envelope_ok("setup-aes-key", filter=filter_name, message=msg))
        except Exception as e:
            logger.error(f"AES key setup command failed: {e}", exc_info=True)
            self.output.error(f"AES key setup command failed: {e}")
            self.output.result(self._envelope_err("setup-aes-key", str(e), filter=filter_name))
            sys.exit(1)
```

Map command names: `pull-aes-key`, `setup-filters` (no filter field), `clean-filter`, `rotate-key`.
For `rotate_keys` the abort-on-no-confirmation path emits `info`/`result` with
`{"ok": False, "command": "rotate-key", "filter": ..., "message": "aborted"}` and returns (exit 0).
`_require_filter` keeps `print(..., file=sys.stderr); sys.exit(1)` -> change its two `print` calls to
`self.output.error(...)`; in json mode also emit `self.output.result(self._envelope_err(<cmd>, msg))`
is NOT possible there (no command context) - leave `_require_filter` as a plain stderr error + exit
(documented exception: pre-dispatch validation has no command envelope).

Update `show_project_version`:

```python
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
```

In `main.py`, `show_project_version(_)` handler wrapper becomes:

```python
def show_project_version(args):
    EncryptionManager.show_project_version(args, _version_output(args))
```

where `_version_output(args)` builds `Output(quiet=..., verbose=..., json=...)` from args (version
runs before the injector is wired). Simpler: inline the Output construction in the dispatch block
already done in Task 3 (`show_project_version(args, output)`) - keep that single call site and drop
the standalone handler's reliance on a global.

- [ ] **Step 4: Run to verify it passes**

Run: `poetry run pytest tests/unit/test_encryption_manager.py -v`
Expected: PASS (existing + 3 new). Existing human-text assertions must still pass unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/git_secret_protector/services/encryption_manager.py src/git_secret_protector/main.py tests/unit/test_encryption_manager.py
git commit -m "feat(output): route action commands through Output with JSON envelopes"
```

---

### Task 5: Bulk encrypt/decrypt - counts, per-file actions, progress

**Files:**
- Modify: `src/git_secret_protector/services/encryption_manager.py:98-138,230-248`
- Modify: `tests/unit/test_encryption_manager.py`

**Interfaces:**
- Consumes: Task 4 constructor + envelopes; `self.__is_encrypted(path)`; handler `encrypt_file`/`decrypt_file`.
- Produces: `encrypt_files(filter_name, emit=True)` and `decrypt_files(filter_name, emit=True)` that
  iterate file-by-file, emit `progress` per file, tally `{"encrypted"/"decrypted", "skipped", "total"}`,
  and (when `emit`) call `self.output.info` + `self.output.result(envelope)`. `clean_filter` calls
  `self.encrypt_files(filter_name, emit=False)` to avoid a nested envelope.

- [ ] **Step 1: Write the failing test**

```python
def test_encrypt_files_progress_and_counts_json(self):
    from git_secret_protector.core.output import Output
    self.git_attributes_parser.get_files_for_filter.return_value = ["a.secret", "b.secret"]
    out, err = io.StringIO(), io.StringIO()
    self.manager.output = Output(json=True)
    with patch.object(self.manager, "_EncryptionManager__get_encryption_handler") as h, \
         patch.object(self.manager, "_EncryptionManager__is_encrypted", side_effect=[False, True]):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.manager.encrypt_files("secret")
    payload = json.loads(out.getvalue())
    self.assertEqual(payload["counts"], {"encrypted": 1, "skipped": 1, "total": 2})
    self.assertEqual(err.getvalue(), "")  # progress suppressed under json

def test_encrypt_files_progress_to_stderr_in_normal(self):
    self.git_attributes_parser.get_files_for_filter.return_value = ["a.secret", "b.secret"]
    err = io.StringIO()
    with patch.object(self.manager, "_EncryptionManager__get_encryption_handler"), \
         patch.object(self.manager, "_EncryptionManager__is_encrypted", return_value=False):
        with contextlib.redirect_stderr(err):
            self.manager.encrypt_files("secret")
    self.assertIn("[1/2] a.secret", err.getvalue())
    self.assertIn("[2/2] b.secret", err.getvalue())

def test_clean_filter_no_nested_envelope(self):
    from git_secret_protector.core.output import Output
    self.git_attributes_parser.get_files_for_filter.return_value = ["a.secret"]
    out = io.StringIO()
    self.manager.output = Output(json=True)
    with patch.object(self.manager, "_EncryptionManager__get_encryption_handler"), \
         patch.object(self.manager, "_EncryptionManager__is_encrypted", return_value=False):
        with contextlib.redirect_stdout(out):
            self.manager.clean_filter("secret")
    payload = json.loads(out.getvalue())
    self.assertEqual(payload["command"], "clean-filter")  # not encrypt-files
```

- [ ] **Step 2: Run to verify it fails**

Run: `poetry run pytest tests/unit/test_encryption_manager.py -k "progress or nested_envelope" -v`
Expected: FAIL

- [ ] **Step 3: Implement**

```python
    def encrypt_files(self, filter_name: str, emit: bool = True):
        filter_name = self._require_filter(filter_name)
        try:
            files = self.git_attributes_parser.get_files_for_filter(filter_name=filter_name)
            if not files:
                logging.info(f"No files to encrypt for filter: {filter_name}")
                if emit:
                    msg = f"No files to encrypt for filter: {filter_name}"
                    self.output.info(msg)
                    self.output.result(self._envelope_ok(
                        "encrypt-files", filter=filter_name,
                        counts={"encrypted": 0, "skipped": 0, "total": 0},
                        files=[], message=msg))
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
                self.output.result(self._envelope_ok(
                    "encrypt-files", filter=filter_name, counts=counts,
                    files=results, message=msg))
            return counts
        except Exception as e:
            logger.error(f"Encrypt files command failed: {e}", exc_info=True)
            self.output.error(f"Encrypt files command failed: {str(e)}")
            if emit:
                self.output.result(self._envelope_err("encrypt-files", str(e), filter=filter_name))
            sys.exit(1)
```

Mirror for `decrypt_files` (count key `decrypted`; action `decrypted`/`skipped`; decide skipped via
`not self.__is_encrypted(file)` meaning already plaintext -> "skipped"). Command name `decrypt-files`.

In `clean_filter`, change the internal call:

```python
            try:
                self.encrypt_files(filter_name=filter_name, emit=False)
            except SystemExit:
                logger.warning("Failed to encrypt files for filter '%s' during clean", filter_name)
```

(Note: `encrypt_files` now `sys.exit(1)` on failure; clean_filter must catch `SystemExit` instead of
`Exception` for the internal call, preserving its current best-effort behavior. The final
`clean-filter` success envelope/message stays as in Task 4.)

- [ ] **Step 4: Run to verify it passes**

Run: `poetry run pytest tests/unit/test_encryption_manager.py -v`
Expected: PASS. The existing `test_guarded_methods_require_filter_and_list_available_filters` still
passes (require_filter unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/git_secret_protector/services/encryption_manager.py tests/unit/test_encryption_manager.py
git commit -m "feat(output): bulk encrypt/decrypt counts, per-file progress, JSON envelope"
```

---

### Task 6: `status --json`

**Files:**
- Modify: `src/git_secret_protector/services/encryption_manager.py:250-266`
- Modify: `tests/unit/test_encryption_manager.py`

**Interfaces:**
- Consumes: Task 4 `self.output`.
- Produces: `status()` builds the full dict, then forks: `if self.output.json: self.output.result(dict)`
  else the existing human prints (byte-identical). On exception in json mode, emit error envelope.

- [ ] **Step 1: Write the failing test**

```python
def test_status_json_schema(self):
    from git_secret_protector.core.output import Output
    self.git_attributes_parser.get_filter_names.return_value = ["secret"]
    self.git_attributes_parser.get_files_for_filter.return_value = ["enc.txt", "plain.txt"]
    out = io.StringIO()
    self.manager.output = Output(json=True)
    with patch.object(self.manager, "_EncryptionManager__is_encrypted", side_effect=[True, False]):
        with contextlib.redirect_stdout(out):
            self.manager.status()
    payload = json.loads(out.getvalue())
    self.assertEqual(payload["backend"], "AWS_SSM")
    self.assertEqual(payload["filters"][0]["name"], "secret")
    self.assertEqual(payload["filters"][0]["files"],
                     [{"path": "enc.txt", "encrypted": True},
                      {"path": "plain.txt", "encrypted": False}])

def test_status_human_text_unchanged(self):
    self.git_attributes_parser.get_filter_names.return_value = ["secret"]
    self.git_attributes_parser.get_files_for_filter.return_value = ["enc.txt", "plain.txt"]
    out = io.StringIO()
    with patch.object(self.manager, "_EncryptionManager__is_encrypted", side_effect=[True, False]):
        with contextlib.redirect_stdout(out):
            self.manager.status()
    self.assertIn("  enc.txt: Encrypted", out.getvalue())
    self.assertIn("  plain.txt: ⚠ PLAINTEXT", out.getvalue())
```

- [ ] **Step 2: Run to verify it fails**

Run: `poetry run pytest tests/unit/test_encryption_manager.py -k status_json -v`
Expected: FAIL

- [ ] **Step 3: Implement**

```python
    def status(self):
        self._print_context()
        try:
            settings = get_settings()
            filter_names = self.git_attributes_parser.get_filter_names()
            data = {"repo_root": settings.base_dir,
                    "backend": settings.storage_type.value,
                    "module_name": settings.module_name,
                    "filters": []}
            for filter_name in filter_names:
                files = self.git_attributes_parser.get_files_for_filter(filter_name)
                file_entries = [{"path": f, "encrypted": self.__is_encrypted(file_path=f)}
                                for f in files]
                data["filters"].append({"name": filter_name, "files": file_entries})

            if self.output.json:
                self.output.result(data)
                return

            for entry in data["filters"]:
                print(f"Filter: {entry['name']}")
                if entry["files"]:
                    for f in entry["files"]:
                        status = "Encrypted" if f["encrypted"] else "⚠ PLAINTEXT"
                        print(f"  {f['path']}: {status}")
                else:
                    print("  No files found for this filter.")
        except Exception as e:
            if self.output.json:
                self.output.result(self._envelope_err("status", str(e)))
            else:
                self.output.error(f"Status command failed: {e}")
            sys.exit(1)
```

Keep the human `print(...)` calls (not `output.info`) so behavior is byte-identical and independent
of quiet for `status` (matches current; status is a report command). If quiet-suppression of the
filter listing is desired later, that is a separate change.

- [ ] **Step 4: Run to verify it passes**

Run: `poetry run pytest tests/unit/test_encryption_manager.py -k status -v`
Expected: PASS (existing `test_status_marks_plaintext_files` + 2 new).

- [ ] **Step 5: Commit**

```bash
git add src/git_secret_protector/services/encryption_manager.py tests/unit/test_encryption_manager.py
git commit -m "feat(status): add --json structured output"
```

---

### Task 7: `doctor --json`

**Files:**
- Modify: `src/git_secret_protector/services/encryption_manager.py:268-346`
- Modify: `tests/unit/test_encryption_manager.py`

**Interfaces:**
- Consumes: Task 4 `self.output`.
- Produces: `doctor()` builds a `checks` list of `{"check", "status": "ok|warn|fail", "detail"}` and the
  return code, then forks on `self.output.json`. Returns the int exit code in both modes; `main()`'s
  `doctor_command` still `sys.exit`s with it.

- [ ] **Step 1: Write the failing test**

```python
@patch("git_secret_protector.services.encryption_manager.subprocess.run")
def test_doctor_json_schema_and_exit(self, mock_run):
    from git_secret_protector.core.output import Output
    self.git_attributes_parser.get_filter_names.return_value = ["secret"]
    self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
    self.key_manager.is_cached.return_value = True
    self.key_manager.resolve_parameter_name.return_value = "/path"
    mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
    out = io.StringIO()
    self.manager.output = Output(json=True)
    with patch("os.path.exists", return_value=True), \
         patch.object(self.manager, "_EncryptionManager__is_encrypted", return_value=False):
        with contextlib.redirect_stdout(out):
            rc = self.manager.doctor()
    self.assertEqual(rc, 1)
    payload = json.loads(out.getvalue())
    self.assertFalse(payload["ok"])
    self.assertEqual(payload["exit_code"], 1)
    self.assertTrue(any(c["status"] == "fail" for c in payload["checks"]))
```

- [ ] **Step 2: Run to verify it fails**

Run: `poetry run pytest tests/unit/test_encryption_manager.py -k doctor_json -v`
Expected: FAIL

- [ ] **Step 3: Implement**

Refactor `doctor()` to accumulate `checks.append({"check","status","detail"})` for each existing
check (repository_context, config_ini, filters_declared / no filters, per-filter git_config + key_cache,
backend_credentials, per-filter plaintext_scan), keep `failed` for any `fail`, compute
`exit_code = 1 if failed else 0`, then:

```python
        if self.output.json:
            self.output.result({"ok": not failed, "exit_code": exit_code, "checks": checks})
            return exit_code
        # human mode: print each check with its existing label
        for c in checks:
            label = {"ok": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}[c["status"]]
            print(f"{label} {c['detail']}")
        return exit_code
```

Preserve the exact human lines: build each check's `detail` to equal the current printed text minus the
label prefix (e.g. repository_context emits a multi-line block; keep it by appending the sub-lines into
`detail` or by special-casing the human render for that check). Snapshot test below locks this.

- [ ] **Step 4: Add human snapshot test + run**

```python
@patch("git_secret_protector.services.encryption_manager.subprocess.run")
def test_doctor_human_text_unchanged(self, mock_run):
    self.git_attributes_parser.get_filter_names.return_value = ["secret"]
    self.git_attributes_parser.get_files_for_filter.return_value = ["a.txt"]
    self.key_manager.is_cached.return_value = True
    self.key_manager.resolve_parameter_name.return_value = "/path"
    mock_run.side_effect = [MagicMock(stdout="x\n"), MagicMock(stdout="y\n")]
    out = io.StringIO()
    with patch("os.path.exists", return_value=True), \
         patch.object(self.manager, "_EncryptionManager__is_encrypted", return_value=True):
        with contextlib.redirect_stdout(out):
            self.manager.doctor()
    text = out.getvalue()
    self.assertIn("[ OK ] filters declared: secret", text)
    self.assertIn("[ OK ] all tracked secret files are encrypted for 'secret'", text)
```

Run: `poetry run pytest tests/unit/test_encryption_manager.py -k doctor -v`
Expected: PASS (all existing doctor tests + 2 new). The existing tests assert substrings like
`[ OK ]`, `[FAIL]`, `[WARN] backend`, `PLAINTEXT` - the `detail` strings MUST keep those substrings.

- [ ] **Step 5: Commit**

```bash
git add src/git_secret_protector/services/encryption_manager.py tests/unit/test_encryption_manager.py
git commit -m "feat(doctor): add --json structured output, preserve exit code"
```

---

### Task 8: Guard-rail - encrypt/decrypt stdout purity under all flags

**Files:**
- Modify: `tests/unit/test_main_cli.py` (subprocess-level, exercises real flag parsing + filter path)

**Interfaces:**
- Consumes: full CLI. Asserts `encrypt`/`decrypt` stdout is exact payload bytes for flag combos
  `[]`, `--json`, `--quiet`, `--verbose`.

- [ ] **Step 1: Write the test**

```python
import itertools
import subprocess

def _run_main_stdin(argv, cwd, stdin_bytes):
    return subprocess.run(
        ["poetry", "run", "git-secret-protector", *argv],
        cwd=str(cwd), input=stdin_bytes, capture_output=True,
    )

def test_encrypt_decrypt_stdout_is_pure_bytes_under_all_flags(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".gitattributes").write_text("*.secret filter=secret\n")
    # set up a local key for the 'secret' filter via the CLI (or seed the cache fixture
    # the other CLI tests use; reuse this file's existing key-setup helper if present).
    flag_sets = [[], ["--json"], ["--quiet"], ["--verbose"]]
    for flags in flag_sets:
        enc = _run_main_stdin([*flags, "encrypt", "x.secret"], repo, b"hello-secret")
        assert enc.returncode == 0, enc.stderr
        # round-trip: decrypt the ciphertext, stdout must equal original plaintext
        dec = _run_main_stdin([*flags, "decrypt", "x.secret"], repo, enc.stdout)
        assert dec.returncode == 0, dec.stderr
        assert dec.stdout == b"hello-secret", (flags, dec.stdout[:40])
```

If `test_main_cli.py` lacks a key-setup path that works offline, gate this test with the same
mechanism the existing CLI tests use to provide a key (inspect the file first). The invariant under
test - no flag perturbs `encrypt`/`decrypt` stdout - is the load-bearing assertion.

- [ ] **Step 2: Run**

Run: `poetry run pytest tests/unit/test_main_cli.py -k stdout_is_pure -v`
Expected: PASS for all four flag sets.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_main_cli.py
git commit -m "test(cli): guard encrypt/decrypt stdout purity under all output flags"
```

---

### Task 9: README flag documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a "Output control" section** documenting `--quiet`, `--verbose`, `--json`
  (with a `status --json` and `doctor --json` example and the note that `--json` is ignored for the
  git-invoked `encrypt`/`decrypt` filters). Match the README's existing heading style.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document --quiet/--verbose/--json output flags"
```

---

## Self-Review

**Spec coverage:**
- `--quiet`/`--verbose`/`--json` flags -> Task 3. Verbose logging -> Task 2. Output layer -> Task 1.
- stdout-purity carve-out -> exempt paths untouched (Tasks 4-7 never touch `encrypt_stdin`/`decrypt_stdin`); guard-rail -> Task 8.
- JSON schemas: status -> Task 6, doctor -> Task 7, version -> Task 4, action envelopes -> Task 4, bulk -> Task 5.
- JSON error contract -> Tasks 4-7 (envelope + nonzero exit / preserved doctor code).
- Bulk progress -> Task 5. Flag placement (parent parser) -> Task 3. `_print_context` quiet-suppress -> Task 4.
- Tests enumerated in the spec's Testing section all map to Task steps.

**Type consistency:** `Output(quiet, verbose, json)`, `.info/.error/.progress/.result/.json` used consistently across tasks. `encrypt_files(filter_name, emit=True)` signature matches its `clean_filter` caller. `_envelope_ok/_envelope_err` used identically in Tasks 4-7.

**Known follow-ups (not blocking):** `_require_filter` stays a plain stderr-error+exit even in json mode (no command context pre-dispatch) - documented exception in Task 4.

