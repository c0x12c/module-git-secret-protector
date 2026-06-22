import base64
import logging
import os

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad

logger = logging.getLogger(__name__)


class AesEncryptionHandler:
    V2 = b"\x02"

    def __init__(
        self, aes_key: bytes, iv: bytes, magic_header: bytes, scheme: str = "v2"
    ):
        if aes_key is None or iv is None:
            raise ValueError("AES key and IV must not be None")
        self.aes_key = aes_key
        self.iv = iv
        self.magic_header = magic_header
        self.scheme = scheme
        self._enc_key = HKDF(aes_key, 32, b"", SHA256, 1, context=b"gsp:enc:v2")
        self._mac_key = HKDF(aes_key, 32, b"", SHA256, 1, context=b"gsp:mac:v2")
        self._iv_key = HKDF(aes_key, 32, b"", SHA256, 1, context=b"gsp:iv:v2")

    def encrypt_data(self, data):
        return self._perform_encryption(data)

    def decrypt_data(self, data):
        return self._perform_decryption(data)

    def encrypt_files(self, files):
        for file in files:
            self.encrypt_file(file)

    def decrypt_files(self, files):
        for file in files:
            self.decrypt_file(file)

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as f:
            plain_data = f.read()

        encrypted_data = self._perform_encryption(plain_data)
        with open(file_path, "wb") as f:
            f.write(encrypted_data)
        logger.info("File encrypted and overwritten: %s", file_path)

    def decrypt_file(self, file_path):
        logger.info("Decrypting file: %s", file_path)
        with open(os.path.abspath(file_path), "rb") as f:
            data = f.read()

        plaintext = self._perform_decryption(data)

        with open(file_path, "wb") as f:
            f.write(plaintext)

        logger.debug("Successfully decrypted and wrote back to: %s", file_path)

    def _perform_encryption(self, data: bytes) -> bytes:
        if data.startswith(self.magic_header):
            logger.info("Data already contains MAGIC_HEADER. Skipping encryption.")
            return data
        if self.scheme == "v1":
            return self._encrypt_v1(data)
        return self._encrypt_v2(data)

    def _encrypt_v1(self, data: bytes) -> bytes:
        # Legacy AES-256-CBC with fixed stored IV - deterministic for git filter stability
        ciphertext = AES.new(self.aes_key, AES.MODE_CBC, self.iv).encrypt(
            pad(data, AES.block_size)
        )
        return self.magic_header + base64.b64encode(ciphertext)

    def _encrypt_v2(self, data: bytes) -> bytes:
        # Authenticated AES-256-CTR with content-derived IV + HMAC-SHA256 tag
        iv = HMAC.new(self._iv_key, data, SHA256).digest()[:16]
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        ciphertext = AES.new(self._enc_key, AES.MODE_CTR, counter=ctr).encrypt(data)
        tag = HMAC.new(self._mac_key, iv + ciphertext, SHA256).digest()
        return self.magic_header + self.V2 + base64.b64encode(iv + ciphertext + tag)

    def _perform_decryption(self, data: bytes) -> bytes:
        if not data.startswith(self.magic_header):
            logger.info("Data does not start with MAGIC HEADER. Skipping decryption.")
            return data

        encrypted_data = data[len(self.magic_header) :]

        if encrypted_data[:1] == self.V2:
            payload = base64.b64decode(encrypted_data[1:])
            iv, tag, ciphertext = payload[:16], payload[-32:], payload[16:-32]

            try:
                HMAC.new(self._mac_key, iv + ciphertext, SHA256).verify(tag)
            except ValueError as e:
                raise ValueError(
                    "Authentication failed - wrong key or tampered ciphertext"
                ) from e

            ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
            return AES.new(self._enc_key, AES.MODE_CTR, counter=ctr).decrypt(ciphertext)

        ciphertext = base64.b64decode(encrypted_data)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)

        try:
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext
        except Exception as e:
            raise ValueError("Invalid AES key") from e
