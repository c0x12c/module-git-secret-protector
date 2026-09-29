import io

from unittest.mock import MagicMock

from git_secret_protector.core import pktline
from git_secret_protector.error.aes_key_error import AesKeyError
from git_secret_protector.error.unsupported_format_error import UnsupportedFormatError
from git_secret_protector.services.filter_process import run_filter_process


def _client_handshake(capabilities=("clean", "smudge", "delay")):
    buf = io.BytesIO()
    pktline.write_packet_line(buf, "git-filter-client\n")
    pktline.write_packet_line(buf, "version=2\n")
    pktline.write_flush(buf)
    for cap in capabilities:
        pktline.write_packet_line(buf, f"capability={cap}\n")
    pktline.write_flush(buf)
    return buf.getvalue()


def _client_file_command(command, pathname, content, extra=None):
    buf = io.BytesIO()
    pktline.write_packet_line(buf, f"command={command}\n")
    pktline.write_packet_line(buf, f"pathname={pathname}\n")
    for key, value in (extra or {}).items():
        pktline.write_packet_line(buf, f"{key}={value}\n")
    pktline.write_flush(buf)
    pktline.write_packet_data(buf, content)
    pktline.write_flush(buf)
    return buf.getvalue()


def _expected_handshake_reply():
    buf = io.BytesIO()
    pktline.write_packet_line(buf, "git-filter-server\n")
    pktline.write_packet_line(buf, "version=2\n")
    pktline.write_flush(buf)
    pktline.write_packet_line(buf, "capability=clean\n")
    pktline.write_packet_line(buf, "capability=smudge\n")
    pktline.write_flush(buf)
    return buf.getvalue()


def _skip_handshake_reply(stream):
    while pktline.read_packet(stream) is not None:
        pass
    while pktline.read_packet(stream) is not None:
        pass


def _read_one_response(stream):
    status_list = pktline.read_packet_list(stream)
    content = pktline.read_packet_data(stream)
    second_list = pktline.read_packet_list(stream)
    return status_list, content, second_list


def test_handshake_produces_exact_server_reply_and_advertises_only_clean_and_smudge():
    in_stream = io.BytesIO(_client_handshake())
    out_stream = io.BytesIO()
    manager = MagicMock()

    result = run_filter_process("secret", manager, in_stream, out_stream)

    assert result == 0
    assert out_stream.getvalue() == _expected_handshake_reply()
    assert b"capability=delay" not in out_stream.getvalue()


def test_clean_request_round_trips_with_encrypted_content():
    manager = MagicMock()
    manager._encrypt_bytes.return_value = b"CIPHERTEXT"
    payload = _client_handshake() + _client_file_command(
        "clean", "secrets.env", b"plaintext"
    )
    in_stream = io.BytesIO(payload)
    out_stream = io.BytesIO()

    result = run_filter_process("secret", manager, in_stream, out_stream)

    assert result == 0
    manager._encrypt_bytes.assert_called_once_with("secret", b"plaintext")
    out_stream.seek(0)
    _skip_handshake_reply(out_stream)
    status_list, content, second_list = _read_one_response(out_stream)
    assert status_list == {"status": "success"}
    assert content == b"CIPHERTEXT"
    assert second_list == {}


def test_byte_exact_full_response_including_mandatory_trailing_flush():
    manager = MagicMock()
    manager._encrypt_bytes.return_value = b"CIPHERTEXT"
    payload = _client_handshake() + _client_file_command(
        "clean", "secrets.env", b"plaintext"
    )
    in_stream = io.BytesIO(payload)
    out_stream = io.BytesIO()

    run_filter_process("secret", manager, in_stream, out_stream)

    expected_response = io.BytesIO()
    pktline.write_packet_line(expected_response, "status=success\n")
    pktline.write_flush(expected_response)
    pktline.write_packet_data(expected_response, b"CIPHERTEXT")
    pktline.write_flush(expected_response)
    pktline.write_flush(expected_response)

    expected = _expected_handshake_reply() + expected_response.getvalue()
    assert out_stream.getvalue() == expected


def test_clean_error_yields_status_error_and_loop_continues_to_next_file():
    manager = MagicMock()
    manager._encrypt_bytes.side_effect = [RuntimeError("boom"), b"CIPHERTEXT-2"]
    payload = (
        _client_handshake()
        + _client_file_command("clean", "a.env", b"a-plain")
        + _client_file_command("clean", "b.env", b"b-plain")
    )
    in_stream = io.BytesIO(payload)
    out_stream = io.BytesIO()

    result = run_filter_process("secret", manager, in_stream, out_stream)

    assert result == 0
    assert manager._encrypt_bytes.call_count == 2
    out_stream.seek(0)
    _skip_handshake_reply(out_stream)

    status_list_1, content_1, _ = _read_one_response(out_stream)
    assert status_list_1 == {"status": "error"}
    assert content_1 == b""

    status_list_2, content_2, _ = _read_one_response(out_stream)
    assert status_list_2 == {"status": "success"}
    assert content_2 == b"CIPHERTEXT-2"


def test_missing_key_yields_status_abort():
    manager = MagicMock()
    manager._encrypt_bytes.side_effect = AesKeyError(
        "AES key for filter 'secret' is not cached locally."
    )
    payload = _client_handshake() + _client_file_command(
        "clean", "secrets.env", b"plaintext"
    )
    in_stream = io.BytesIO(payload)
    out_stream = io.BytesIO()

    result = run_filter_process("secret", manager, in_stream, out_stream)

    assert result == 0
    out_stream.seek(0)
    _skip_handshake_reply(out_stream)
    status_list, content, _ = _read_one_response(out_stream)
    assert status_list == {"status": "abort"}
    assert content == b""


def test_smudge_unsupported_format_error_yields_status_error():
    manager = MagicMock()
    manager._decrypt_bytes.side_effect = UnsupportedFormatError("unknown scheme")
    payload = _client_handshake() + _client_file_command(
        "smudge", "secrets.env", b"ciphertext"
    )
    in_stream = io.BytesIO(payload)
    out_stream = io.BytesIO()

    result = run_filter_process("secret", manager, in_stream, out_stream)

    assert result == 0
    out_stream.seek(0)
    _skip_handshake_reply(out_stream)
    status_list, content, _ = _read_one_response(out_stream)
    assert status_list == {"status": "error"}
    assert content == b""


def test_smudge_generic_exception_yields_status_error_and_writes_no_content():
    manager = MagicMock()
    manager._decrypt_bytes.side_effect = [
        RuntimeError("cache miss"),
        b"plaintext-two",
    ]
    payload = (
        _client_handshake()
        + _client_file_command("smudge", "secrets.env", b"original-ciphertext")
        + _client_file_command("smudge", "other.env", b"ciphertext-two")
    )
    in_stream = io.BytesIO(payload)
    out_stream = io.BytesIO()

    result = run_filter_process("secret", manager, in_stream, out_stream)

    assert result == 0
    out_stream.seek(0)
    _skip_handshake_reply(out_stream)
    status_list, content, _ = _read_one_response(out_stream)
    assert status_list == {"status": "error"}
    assert content == b""

    # A per-file error must not abort the process - the next file is still served.
    status_list_two, content_two, _ = _read_one_response(out_stream)
    assert status_list_two == {"status": "success"}
    assert content_two == b"plaintext-two"


def test_unknown_key_in_request_list_is_tolerated():
    manager = MagicMock()
    manager._encrypt_bytes.return_value = b"CIPHERTEXT"
    payload = _client_handshake() + _client_file_command(
        "clean", "secrets.env", b"plaintext", extra={"can-delay": "1"}
    )
    in_stream = io.BytesIO(payload)
    out_stream = io.BytesIO()

    result = run_filter_process("secret", manager, in_stream, out_stream)

    assert result == 0
    out_stream.seek(0)
    _skip_handshake_reply(out_stream)
    status_list, content, _ = _read_one_response(out_stream)
    assert status_list == {"status": "success"}
    assert content == b"CIPHERTEXT"
