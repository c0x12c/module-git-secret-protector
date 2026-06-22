# CLI output controls: `--quiet` / `--verbose` / `--json` + bulk progress

Status: approved design
Date: 2026-06-22

## Goal

Add global output-control flags to the `git-secret-protector` CLI:

- `--quiet` - suppress success/info lines on stdout (errors and exit codes unchanged).
- `--verbose` - surface internal logs to the terminal (logging is file-only today).
- `--json` - machine-readable structured output for the report commands, with a
  uniform result envelope for action commands.

Also add progress feedback for bulk `encrypt-files` / `decrypt-files` over many files.

## Critical constraint: stdout is a binary data channel for `encrypt` / `decrypt`

The `encrypt` and `decrypt` subcommands are git's clean/smudge filters. They write the
file payload (ciphertext / plaintext bytes) to `sys.stdout.buffer`, and git stores
whatever lands on stdout as the file content. Any extra byte written to stdout during a
filter invocation silently corrupts the committed or checked-out file.

Therefore:

- The `encrypt` / `decrypt` (stdin) code path is **exempt** from the output layer.
  stdout carries data only. Informational messages and errors go to stderr or to logging.
- `--json`, `--quiet`, `--verbose` do **not** alter `encrypt` / `decrypt` stdout. `--json`
  is a no-op for these two commands (they are machine-invoked by git, never human-facing).
- A guard-rail test asserts that `encrypt` / `decrypt` stdout is exactly the expected
  payload bytes under every flag combination (`--json`, `--quiet`, `--verbose`, none).

This is the single most important invariant of the feature.

## Output modes

Two orthogonal axes, resolved once in `main()` from the parsed flags:

1. Verbosity: `quiet` | `normal` | `verbose`.
   - `quiet` suppresses info/success lines and bulk progress.
   - `verbose` attaches a stderr console log handler (INFO/DEBUG) in addition to the
     existing rotating file handler.
   - `--quiet` together with `--verbose` is rejected with a clear error (contradictory).
2. Format: `human` (default) | `json` (`--json`).

Composition rules:

- `--json` implies no human chatter on stdout; the only stdout content is the JSON
  document. Logs and progress, when enabled, go to stderr - stdout stays pure JSON.
- `_print_context` (the Backend/Module/Repo-root/Namespace banner, already on stderr) is
  suppressed under `--quiet`. It never reaches stdout, so it does not affect `--json`.

## Output layer: `core/output.py`

A single `Output` object holds the resolved mode and centralizes routing decisions that
are currently scattered across `print(...)` / `print(..., file=sys.stderr)` calls.

```
class Output:
    def __init__(self, *, quiet=False, verbose=False, json=False): ...

    def info(self, message: str) -> None
        # human success/info line -> stdout, unless quiet or json

    def error(self, message: str) -> None
        # error line -> stderr (always; independent of quiet)

    def progress(self, message: str) -> None
        # progress line -> stderr, unless quiet or json

    def result(self, obj: dict) -> None
        # json mode: json.dumps(obj) -> stdout
        # human mode: no-op (human rendering already done via info())

    @property
    def json(self) -> bool
```

Configuration and wiring:

- `main()` constructs the `Output` from parsed flags and binds it into the injector
  (`GitSecretProtectorModule`) before resolving `EncryptionManager`, so the manager
  receives it by constructor injection. Tests bind a capturing fake the same way.
- Command methods keep their existing control flow. We do **not** refactor them to
  "return data, render at the edge" - that fights the existing `print(...); sys.exit(1)`
  error exits. Instead:
  - Replace human `print()` calls with `output.info(...)` / `output.error(...)`.
  - For `status` and `doctor`, build a structured dict during the existing pass and add a
    localized terminal fork: `if output.json: output.result(dict)` else the human prints.

The `encrypt` / `decrypt` stdin methods do not use `output` for stdout. They may use
`output.error(...)` (stderr) or logging for diagnostics only.

## JSON schemas

Report commands (rich, stable schemas):

```
version --json -> {"version": "1.4.0"}

status  --json -> {
  "repo_root": "/abs/path",
  "backend": "AWS_SSM",
  "module_name": "git-secret-protector",
  "filters": [
    {"name": "secretfilter",
     "files": [{"path": "a.secret", "encrypted": true}, ...]}
  ]
}

doctor  --json -> {
  "ok": true,
  "exit_code": 0,
  "checks": [
    {"check": "repository_context", "status": "ok",   "detail": "base_dir=..."},
    {"check": "config_ini",         "status": "warn", "detail": "not found, defaults in use"},
    {"check": "filter.secretfilter.git_config", "status": "ok",   "detail": "..."},
    {"check": "filter.secretfilter.key_cache",  "status": "warn", "detail": "..."},
    {"check": "backend_credentials", "status": "ok", "detail": "resolved"},
    {"check": "plaintext_scan.secretfilter", "status": "fail", "detail": "x.secret is PLAINTEXT"}
  ]
}
```

`doctor` `status` values are `ok | warn | fail`. The process still calls `sys.exit` with
doctor's return code (0 clean, 1 when any tracked secret is plaintext) in both human and
JSON modes; `exit_code` mirrors that in the object.

Action commands (uniform envelope): `setup-aes-key`, `pull-aes-key`, `rotate-key`,
`setup-filters`, `clean-filter`, `encrypt-files`, `decrypt-files`.

```
success -> {"ok": true,  "command": "setup-aes-key", "filter": "x", "message": "..."}
error   -> {"ok": false, "command": "setup-aes-key", "filter": "x", "error": "..."}
```

Bulk commands extend the success envelope with counts and per-file results (this data is
free from the existing loop):

```
encrypt-files --json -> {
  "ok": true, "command": "encrypt-files", "filter": "x",
  "counts": {"encrypted": 3, "skipped": 1, "total": 4},
  "files": [{"path": "a.secret", "action": "encrypted"},
            {"path": "b.secret", "action": "skipped"}]
}
```

### JSON error contract

In `--json` mode, errors emit the error envelope `{"ok": false, "command", "error", ...}`
to **stdout** (so a script parsing stdout always gets a document) and the process keeps
its nonzero exit code. In human mode, errors stay on stderr as today.

## Bulk progress

`encrypt-files` / `decrypt-files` emit `[i/N] <path>` lines via `output.progress(...)`
(stderr). Suppressed under `--quiet` and under `--json`. No new dependency (no `tqdm`).

## Flag placement

A shared parent parser (`argparse.ArgumentParser(add_help=False)`) defines
`--quiet`, `--verbose`, `--json`, and `--repo-root`. Each subparser is created with
`parents=[common]` so the flags read naturally after the subcommand
(`git-secret-protector status --json`). The flags are also accepted before the subcommand
for backward compatibility with the existing `--repo-root` placement.

## Affected files

- `src/git_secret_protector/core/output.py` (new) - the `Output` class.
- `src/git_secret_protector/context/module.py` - bind `Output` in the injector.
- `src/git_secret_protector/main.py` - parse flags, resolve mode, configure verbose
  logging, build + bind `Output`, parent parser.
- `src/git_secret_protector/utils/configure_logging.py` - optional stderr console handler
  when verbose.
- `src/git_secret_protector/services/encryption_manager.py` - route human output through
  `Output`; build structured dicts for `status` / `doctor`; envelopes for action
  commands; bulk progress. `encrypt`/`decrypt` stdin paths stay stdout-pure.

## Testing

- Guard-rail: `encrypt` / `decrypt` stdout is exact payload bytes under all flag combos.
- `status --json` / `doctor --json` produce the documented schema; `doctor` exit code
  preserved in both modes.
- Action envelope success and error shapes for a representative action command.
- `--quiet` suppresses info + progress but not errors; exit codes unchanged.
- `--verbose` adds stderr log output; stdout unaffected.
- `--quiet --verbose` rejected.
- Bulk progress counter present in normal mode, absent under `--quiet` / `--json`.

Test command: `poetry run pytest tests/unit/`.
