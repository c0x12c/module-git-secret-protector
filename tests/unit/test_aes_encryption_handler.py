import base64
import secrets
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from git_secret_protector.crypto.aes_encryption_handler import AesEncryptionHandler


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


if __name__ == "__main__":
    unittest.main()
