# src/git_secret_protector/core/output.py
import json as _json
import os
import sys


def silence_stdio():
    """Point stdout/stderr at /dev/null so the interpreter's shutdown flush cannot
    raise again - a BrokenPipeError caught here still has bytes in the buffer, and
    that final flush is outside any try block."""
    try:
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull_fd, sys.stdout.fileno())
            os.dup2(devnull_fd, sys.stderr.fileno())
        finally:
            os.close(devnull_fd)
    except Exception:
        pass


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

    @property
    def quiet(self):
        return self._quiet

    def _write(self, message, *, file=None):
        try:
            print(message, file=file)
        except BrokenPipeError:
            silence_stdio()
            # SystemExit bypasses generic `except Exception` handlers, so a closed
            # pipe exits quietly instead of being reported as a command failure.
            raise SystemExit(141)

    def info(self, message):
        if self._quiet or self._json:
            return
        self._write(message)

    def error(self, message):
        self._write(message, file=sys.stderr)

    def progress(self, message):
        if self._quiet or self._json:
            return
        self._write(message, file=sys.stderr)

    def result(self, obj):
        if not self._json:
            return
        self._write(_json.dumps(obj), file=sys.stdout)
