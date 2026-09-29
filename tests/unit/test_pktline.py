import io

import pytest

from git_secret_protector.core.pktline import (
    MAX_PAYLOAD,
    PktLineError,
    read_packet,
    read_packet_data,
    read_packet_list,
    write_flush,
    write_packet,
    write_packet_data,
)


def test_max_payload_value_is_pinned():
    # Every chunking test below sizes its input from MAX_PAYLOAD, so they all pass
    # for a wrong value. git rejects an over-long packet at runtime, where the only
    # symptom is a desynced stream, so pin the number itself against the spec.
    assert MAX_PAYLOAD == 65516


def test_round_trip_short_payload():
    stream = io.BytesIO()
    write_packet(stream, b"hello")
    stream.seek(0)
    assert read_packet(stream) == b"hello"


def test_exact_wire_bytes_pins_header_format():
    stream = io.BytesIO()
    write_packet(stream, b"hello")
    assert stream.getvalue() == b"0009hello"


def test_write_flush_emits_exact_bytes_and_reads_as_none():
    stream = io.BytesIO()
    write_flush(stream)
    assert stream.getvalue() == b"0000"
    stream.seek(0)
    assert read_packet(stream) is None


def test_chunking_at_max_payload_emits_one_packet():
    data = b"a" * MAX_PAYLOAD
    stream = io.BytesIO()
    write_packet_data(stream, data)
    write_flush(stream)
    stream.seek(0)
    packets = []
    while True:
        payload = read_packet(stream)
        if payload is None:
            break
        packets.append(payload)
    assert len(packets) == 1
    assert b"".join(packets) == data


def test_chunking_over_max_payload_emits_two_packets_and_reassembles():
    data = b"b" * (MAX_PAYLOAD + 1)
    stream = io.BytesIO()
    write_packet_data(stream, data)
    write_flush(stream)
    stream.seek(0)
    packets = []
    while True:
        payload = read_packet(stream)
        if payload is None:
            break
        packets.append(payload)
    assert len(packets) == 2
    reassembled = b"".join(packets)
    assert reassembled == data

    stream2 = io.BytesIO()
    write_packet_data(stream2, data)
    write_flush(stream2)
    stream2.seek(0)
    assert read_packet_data(stream2) == data


def test_write_packet_over_max_payload_raises_value_error():
    stream = io.BytesIO()
    with pytest.raises(ValueError):
        write_packet(stream, b"c" * (MAX_PAYLOAD + 1))


def test_write_packet_data_empty_writes_nothing():
    stream = io.BytesIO()
    write_packet_data(stream, b"")
    assert stream.getvalue() == b""


def test_read_packet_list_parses_key_value_pairs():
    stream = io.BytesIO()
    write_packet(stream, b"command=smudge\n")
    write_packet(stream, b"pathname=a/b.txt\n")
    write_flush(stream)
    stream.seek(0)
    result = read_packet_list(stream)
    assert result == {"command": "smudge", "pathname": "a/b.txt"}


def test_read_packet_list_value_containing_equals_splits_on_first_only():
    stream = io.BytesIO()
    write_packet(stream, b"pathname=dir/a=b.txt\n")
    write_flush(stream)
    stream.seek(0)
    result = read_packet_list(stream)
    assert result == {"pathname": "dir/a=b.txt"}


def test_read_packet_list_retains_unknown_keys():
    stream = io.BytesIO()
    write_packet(stream, b"can-delay=1\n")
    write_flush(stream)
    stream.seek(0)
    result = read_packet_list(stream)
    assert result == {"can-delay": "1"}


def test_read_packet_truncated_stream_raises():
    stream = io.BytesIO(b"0020short")
    with pytest.raises(PktLineError):
        read_packet(stream)


def test_read_packet_malformed_non_hex_length_raises():
    stream = io.BytesIO(b"zzzzpayload")
    with pytest.raises(PktLineError):
        read_packet(stream)


def test_read_packet_impossible_short_length_raises():
    stream = io.BytesIO(b"0001")
    with pytest.raises(PktLineError):
        read_packet(stream)
