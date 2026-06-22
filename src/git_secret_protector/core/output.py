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

    @property
    def quiet(self):
        return self._quiet

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
