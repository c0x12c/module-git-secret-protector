"""git long-running filter process (gitattributes(5), filter.<name>.process).

Replaces one interpreter spawn per file with one process per git command. The key
is resolved lazily (never during the handshake) so a cold cache never causes git to
restart this process once per remaining file - see the plan doc for why. Nothing may
be written to stdout except protocol bytes; all diagnostics go to stderr.
"""

from __future__ import annotations

import sys

from git_secret_protector.core import pktline
from git_secret_protector.error.aes_key_error import AesKeyError
from git_secret_protector.error.unsupported_format_error import UnsupportedFormatError

CLIENT_WELCOME = "git-filter-client"
SERVER_WELCOME = "git-filter-server"
PROTOCOL_VERSION = "version=2"


class _HandshakeError(Exception):
    pass


class _TrackingReader:
    """Wraps a stream and remembers the length of the first read() since reset().

    Used only to tell a clean EOF (git closing the pipe between commands) apart from
    a genuine truncated-stream error - both surface as a short header read inside
    pktline.read_packet, and pktline itself does not distinguish the two.
    """

    def __init__(self, stream):
        self._stream = stream
        self._reads = 0
        self.first_read_len = None

    def reset(self):
        self._reads = 0
        self.first_read_len = None

    def read(self, n):
        data = self._stream.read(n)
        self._reads += 1
        if self._reads == 1:
            self.first_read_len = len(data)
        return data


def _read_text_packet(reader):
    payload = pktline.read_packet(reader)
    if payload is None:
        return None
    text = payload.decode("utf-8")
    return text[:-1] if text.endswith("\n") else text


def _read_text_list(reader):
    values = []
    while True:
        payload = pktline.read_packet(reader)
        if payload is None:
            return values
        text = payload.decode("utf-8")
        if text.endswith("\n"):
            text = text[:-1]
        values.append(text)


def _handshake(reader, out_stream):
    welcome = _read_text_packet(reader)
    if welcome != CLIENT_WELCOME:
        raise _HandshakeError(f"unexpected client welcome: {welcome!r}")

    version = _read_text_packet(reader)
    if version != PROTOCOL_VERSION:
        raise _HandshakeError(f"client did not offer {PROTOCOL_VERSION}: {version!r}")

    flush = pktline.read_packet(reader)
    if flush is not None:
        raise _HandshakeError("expected flush after client welcome")

    pktline.write_packet_line(out_stream, f"{SERVER_WELCOME}\n")
    pktline.write_packet_line(out_stream, f"{PROTOCOL_VERSION}\n")
    pktline.write_flush(out_stream)
    # git blocks reading this before sending capabilities - each half is its own
    # round trip, so an unflushed buffer here deadlocks both sides.
    out_stream.flush()

    # Capabilities repeat the same key, so a dict (read_packet_list) would collapse
    # them - read as a plain list instead.
    _read_text_list(reader)
    pktline.write_packet_line(out_stream, "capability=clean\n")
    pktline.write_packet_line(out_stream, "capability=smudge\n")
    pktline.write_flush(out_stream)
    out_stream.flush()


def _send_response(out_stream, status, content):
    pktline.write_packet_line(out_stream, f"status={status}\n")
    pktline.write_flush(out_stream)
    pktline.write_packet_data(out_stream, content)
    pktline.write_flush(out_stream)
    pktline.write_flush(out_stream)
    out_stream.flush()


def run_filter_process(filter_name, manager, in_stream=None, out_stream=None) -> int:
    in_stream = sys.stdin.buffer if in_stream is None else in_stream
    out_stream = sys.stdout.buffer if out_stream is None else out_stream
    reader = _TrackingReader(in_stream)

    try:
        _handshake(reader, out_stream)
    except Exception as exc:
        print(
            f"git-secret-protector: filter-process handshake failed: {exc}",
            file=sys.stderr,
        )
        return 1

    aborted_reason = None

    while True:
        reader.reset()
        try:
            request = pktline.read_packet_list(reader)
        except pktline.PktLineError as exc:
            if reader.first_read_len == 0:
                return 0
            print(f"git-secret-protector: filter-process: {exc}", file=sys.stderr)
            return 1

        if not request:
            return 0

        command = request.get("command")
        pathname = request.get("pathname", "<unknown>")
        content = pktline.read_packet_data(reader)

        if aborted_reason is not None:
            _send_response(out_stream, "abort", b"")
            continue

        if command == "clean":
            try:
                result = manager._encrypt_bytes(filter_name, content)
                _send_response(out_stream, "success", result)
            except AesKeyError as exc:
                aborted_reason = str(exc)
                print(f"git-secret-protector: {pathname}: {exc}", file=sys.stderr)
                _send_response(out_stream, "abort", b"")
            except Exception as exc:
                print(f"git-secret-protector: {pathname}: {exc}", file=sys.stderr)
                _send_response(out_stream, "error", b"")
        elif command == "smudge":
            try:
                result = manager._decrypt_bytes(filter_name, content)
                _send_response(out_stream, "success", result)
            except AesKeyError as exc:
                aborted_reason = str(exc)
                print(f"git-secret-protector: {pathname}: {exc}", file=sys.stderr)
                _send_response(out_stream, "abort", b"")
            except UnsupportedFormatError as exc:
                print(f"git-secret-protector: {pathname}: {exc}", file=sys.stderr)
                _send_response(out_stream, "error", b"")
            except Exception as exc:
                # Fail closed like the AesKeyError/UnsupportedFormatError branches
                # above - never report ciphertext as a successful smudge.
                print(f"git-secret-protector: {pathname}: {exc}", file=sys.stderr)
                _send_response(out_stream, "error", b"")
        else:
            print(
                f"git-secret-protector: unknown command {command!r} for {pathname}",
                file=sys.stderr,
            )
            _send_response(out_stream, "error", b"")
