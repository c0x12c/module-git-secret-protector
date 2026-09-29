"""Pure byte plumbing for git's pkt-line wire format (gitattributes(5), long-running filter process).

No project imports, no stdio, no logging of payload content - a caller owns the stream and the
protocol semantics. This module only knows how to frame and unframe bytes.
"""

from __future__ import annotations

MAX_PAYLOAD = 65516  # git's LARGE_PACKET_MAX (65520) minus the 4-byte length header
HEADER_LEN = 4


class PktLineError(Exception):
    pass


def write_packet(stream, payload: bytes) -> None:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(
            f"payload of {len(payload)} bytes exceeds max pkt-line payload {MAX_PAYLOAD}"
        )
    length = HEADER_LEN + len(payload)
    stream.write(f"{length:04x}".encode("ascii"))
    stream.write(payload)


def write_packet_data(stream, data: bytes) -> None:
    for offset in range(0, len(data), MAX_PAYLOAD):
        write_packet(stream, data[offset : offset + MAX_PAYLOAD])


def write_flush(stream) -> None:
    stream.write(b"0000")


def write_packet_line(stream, text: str) -> None:
    write_packet(stream, text.encode("utf-8"))


def read_packet(stream) -> bytes | None:
    header = stream.read(HEADER_LEN)
    if len(header) < HEADER_LEN:
        raise PktLineError(
            f"truncated pkt-line header: got {len(header)} of {HEADER_LEN} bytes"
        )
    try:
        length = int(header, 16)
    except ValueError as exc:
        raise PktLineError(f"malformed pkt-line length header: {header!r}") from exc
    if length == 0:
        return None
    if length < HEADER_LEN:
        raise PktLineError(
            f"impossible pkt-line length {length}: must be 0 or >= {HEADER_LEN}"
        )
    payload_len = length - HEADER_LEN
    payload = stream.read(payload_len)
    if len(payload) < payload_len:
        raise PktLineError(
            f"truncated pkt-line payload: got {len(payload)} of {payload_len} bytes"
        )
    return payload


def read_packet_list(stream) -> dict[str, str]:
    result: dict[str, str] = {}
    while True:
        payload = read_packet(stream)
        if payload is None:
            return result
        text = payload.decode("utf-8")
        if text.endswith("\n"):
            text = text[:-1]
        key, sep, value = text.partition("=")
        if not sep:
            raise PktLineError(f"pkt-line text packet missing '=': {text!r}")
        result[key] = value


def read_packet_data(stream) -> bytes:
    chunks: list[bytes] = []
    while True:
        payload = read_packet(stream)
        if payload is None:
            return b"".join(chunks)
        chunks.append(payload)
