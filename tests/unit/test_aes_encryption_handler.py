import base64
import secrets
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler
from git_secret_protector.error.unsupported_format_error import UnsupportedFormatError


class TestAesEncryptionHandler(unittest.TestCase):
    def setUp(self):
        self.magic_header = b"GSP"
        self.aes_key = secrets.token_bytes(32)
        self.iv = secrets.token_bytes(AES.block_size)
        self.handler = AesEncryptionHandler(
            aes_key=self.aes_key,
            iv=self.iv,
            magic_header=self.magic_header,
        )

    def test_round_trip_empty_bytes(self):
        plaintext = b""

        encrypted = self.handler.encrypt_data(plaintext)

        self.assertEqual(self.handler.decrypt_data(encrypted), plaintext)

    def test_round_trip_multi_block_payload(self):
        plaintext = (b"multi-block-payload-" * 8) + b"tail"

        encrypted = self.handler.encrypt_data(plaintext)

        self.assertEqual(self.handler.decrypt_data(encrypted), plaintext)

    def test_encrypt_is_deterministic_for_same_plaintext(self):
        plaintext = b"stable secret"

        self.assertEqual(
            self.handler.encrypt_data(plaintext),
            self.handler.encrypt_data(plaintext),
        )

    def test_different_plaintext_produces_different_ciphertext(self):
        self.assertNotEqual(
            self.handler.encrypt_data(b"secret-a"),
            self.handler.encrypt_data(b"secret-b"),
        )

    def test_tampered_v2_payload_fails_authentication(self):
        encrypted = self.handler.encrypt_data(b"authenticated secret")
        payload = bytearray(encrypted[len(self.magic_header) + 1 :])
        payload[-1] = 65 if payload[-1] != 65 else 66
        tampered = self.magic_header + self.handler.V2 + bytes(payload)

        with self.assertRaisesRegex(
            ValueError,
            "Authentication failed - wrong key or tampered ciphertext",
        ):
            self.handler.decrypt_data(tampered)

    def test_v2_output_starts_with_magic_header_and_version_marker(self):
        encrypted = self.handler.encrypt_data(b"format check")

        self.assertTrue(encrypted.startswith(self.magic_header + self.handler.V2))

    def test_legacy_v1_blob_still_decrypts(self):
        plaintext = b"legacy secret payload"
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        legacy_blob = self.magic_header + base64.b64encode(ciphertext)

        self.assertEqual(self.handler.decrypt_data(legacy_blob), plaintext)

    def test_encrypt_is_no_op_when_data_already_has_magic_header(self):
        already_encrypted = self.magic_header + b"\x02already-encrypted"

        self.assertIs(self.handler.encrypt_data(already_encrypted), already_encrypted)


class TestAesEncryptionHandlerScheme(unittest.TestCase):
    """Tests for scheme="v1"/"v2" parameter on AesEncryptionHandler."""

    MH = b"ENCRYPTED"

    def _h(self, scheme):
        return AesEncryptionHandler(
            aes_key=secrets.token_bytes(32),
            iv=secrets.token_bytes(16),
            magic_header=self.MH,
            scheme=scheme,
        )

    def test_v1_roundtrip_and_deterministic(self):
        h = self._h("v1")
        data = b"super-secret-value"
        ct1 = h.encrypt_data(data)
        ct2 = h.encrypt_data(data)
        self.assertTrue(ct1.startswith(self.MH))
        self.assertNotEqual(ct1[len(self.MH) : len(self.MH) + 1], b"\x02")
        self.assertEqual(ct1, ct2)
        self.assertEqual(h.decrypt_data(ct1), data)

    def test_v2_still_default_and_authenticated(self):
        h = self._h("v2")
        data = b"abc"
        ct = h.encrypt_data(data)
        self.assertEqual(ct[len(self.MH) : len(self.MH) + 1], b"\x02")
        self.assertEqual(h.decrypt_data(ct), data)

    def test_scheme_defaults_to_v2(self):
        h = AesEncryptionHandler(
            aes_key=secrets.token_bytes(32),
            iv=secrets.token_bytes(16),
            magic_header=self.MH,
        )
        self.assertEqual(h.encrypt_data(b"x")[len(self.MH) : len(self.MH) + 1], b"\x02")

    def test_magic_header_short_circuit_both_schemes(self):
        for s in ("v1", "v2"):
            with self.subTest(scheme=s):
                h = self._h(s)
                already = self.MH + b"whatever"
                self.assertIs(h.encrypt_data(already), already)


class TestAesEncryptionHandlerGoldenFixtures(unittest.TestCase):
    """Backward-compat proof: literal ciphertext bytes produced by the pre-hardening
    code (v1.5.0 master) with a hardcoded key must still decrypt under the current
    code. Regenerating these from the current code would prove nothing - they are
    frozen on purpose."""

    KEY = bytes(range(32))  # 00..1f
    IV = bytes(range(16))  # 00..0f
    MH = b"ENCRYPTED"
    PLAINTEXT = b"backward-compat golden fixture"

    V1_GOLDEN = b"ENCRYPTEDJ8fMYTUNoWdWvtiyXcSsE7tDAw0NSoUUn3P5i1YlA5c="
    V2_GOLDEN = (
        b"ENCRYPTED\x02ldLCW5bTJp/htsDSGRI3lkvFVsydpDLPItnpjFbWp7lNtPxib0cQ6B+"
        b"IC8AR2iDKOIDMZks0CM+Z067FQDsVvALrRh5QJal/FTzKZXfW"
    )

    def _handler(self):
        return AesEncryptionHandler(aes_key=self.KEY, iv=self.IV, magic_header=self.MH)

    def test_v1_golden_blob_decrypts(self):
        self.assertEqual(self._handler().decrypt_data(self.V1_GOLDEN), self.PLAINTEXT)

    def test_v2_golden_blob_decrypts(self):
        self.assertEqual(self._handler().decrypt_data(self.V2_GOLDEN), self.PLAINTEXT)

    def test_v1_output_bytes_are_frozen(self):
        h = AesEncryptionHandler(
            aes_key=self.KEY, iv=self.IV, magic_header=self.MH, scheme="v1"
        )
        self.assertEqual(h.encrypt_data(self.PLAINTEXT), self.V1_GOLDEN)

    def test_v2_output_bytes_are_frozen(self):
        h = AesEncryptionHandler(
            aes_key=self.KEY, iv=self.IV, magic_header=self.MH, scheme="v2"
        )
        self.assertEqual(h.encrypt_data(self.PLAINTEXT), self.V2_GOLDEN)


class TestAesEncryptionHandlerDispatchHardening(unittest.TestCase):
    """Fail-closed dispatch: unknown/newer wire formats must not be silently fed to
    the unauthenticated v1 CBC path, and truncated v2 payloads must fail clearly."""

    def setUp(self):
        self.magic_header = b"GSP"
        self.aes_key = secrets.token_bytes(32)
        self.iv = secrets.token_bytes(AES.block_size)
        self.handler = AesEncryptionHandler(
            aes_key=self.aes_key,
            iv=self.iv,
            magic_header=self.magic_header,
        )

    def test_unknown_version_byte_fails_closed(self):
        # 0x03 (and any control byte < 0x2B that is not 0x02) means "newer client".
        blob = self.magic_header + b"\x03" + base64.b64encode(b"whatever-payload")

        with self.assertRaisesRegex(
            UnsupportedFormatError, "newer git-secret-protector client"
        ):
            self.handler.decrypt_data(blob)

    def test_stripped_v2_version_byte_does_not_silently_cbc(self):
        # Strip the 0x02 marker; the remaining base64 first byte routes to v1 CBC
        # (the documented, unfixable-without-migration downgrade surface), and that
        # path fails authentication/padding rather than emitting silent garbage.
        v2 = self.handler.encrypt_data(b"authenticated secret")
        stripped = self.magic_header + v2[len(self.magic_header) + 1 :]

        with self.assertRaises(ValueError):
            self.handler.decrypt_data(stripped)

    def test_non_base64_first_byte_fails_closed(self):
        # 0xFF and 0x3A (':') are >= 0x2B but not base64-alphabet; they must not be
        # routed to the legacy CBC path (the >= 0x2B threshold used to let them in).
        for bad in (b"\xff", b"\x3a", b"\x2c"):
            with self.subTest(byte=bad):
                blob = self.magic_header + bad + base64.b64encode(b"payload")
                with self.assertRaisesRegex(ValueError, "unrecognized wire format"):
                    self.handler.decrypt_data(blob)

    def test_truncated_v2_payload_fails_with_clear_message(self):
        short = self.magic_header + self.handler.V2 + base64.b64encode(b"tooshort")

        with self.assertRaisesRegex(ValueError, "truncated"):
            self.handler.decrypt_data(short)

    def test_empty_v2_plaintext_round_trips(self):
        encrypted = self.handler.encrypt_data(b"")
        self.assertEqual(self.handler.decrypt_data(encrypted), b"")

    def test_tampered_version_byte_to_unknown_fails_closed(self):
        v2 = self.handler.encrypt_data(b"secret")
        tampered = self.magic_header + b"\x04" + v2[len(self.magic_header) + 1 :]

        with self.assertRaisesRegex(
            UnsupportedFormatError, "newer git-secret-protector client"
        ):
            self.handler.decrypt_data(tampered)

    def test_plaintext_beginning_with_magic_header_is_skipped(self):
        # Documents current idempotency behavior: a plaintext that itself begins with
        # the magic header is treated as already-encrypted and passed through.
        data = self.magic_header + b"looks encrypted but is not"
        self.assertIs(self.handler.encrypt_data(data), data)


if __name__ == "__main__":
    unittest.main()
