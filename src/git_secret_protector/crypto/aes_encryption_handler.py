import base64
import logging
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from git_secret_protector.core.settings import get_settings

logger = logging.getLogger(__name__)


class AesEncryptionHandler:
    def __init__(self, aes_key, iv):
        if aes_key is None or iv is None:
            raise ValueError("AES key and IV must not be None")
        self.aes_key = aes_key
        self.iv = iv
        self.magic_header = get_settings().magic_header.encode()

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
        with open(file_path, 'rb') as f:
            plain_data = f.read()

        encrypted_data = self._perform_encryption(plain_data)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        logger.info("File encrypted and overwritten: %s", file_path)

    def decrypt_file(self, file_path):
        logger.info("Decrypting file: %s", file_path)
        with open(os.path.abspath(file_path), 'rb') as f:
            data = f.read()

        plaintext = self._perform_decryption(data)

        # Write the decrypted data back to the file
        with open(file_path, 'wb') as f:
            f.write(plaintext)

        logger.debug("Successfully decrypted and wrote back to: %s", file_path)

    def _perform_encryption(self, data: bytes) -> bytes:
        if data.startswith(self.magic_header):
            logger.warning("Data already contains MAGIC_HEADER. Skipping encryption.")
            return data

        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        return self.magic_header + base64.b64encode(ciphertext)  # Base64 encode the result

    def _perform_decryption(self, data: bytes) -> bytes:
        if not data.startswith(get_settings().magic_header.encode()):
            logger.warning("Data does not start with MAGIC HEADER. Skipping decryption.")
            return data

        encrypted_data = data[len(self.magic_header):]

        ciphertext = base64.b64decode(encrypted_data)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    def is_encrypted(self, file_path: str):
        try:
            with open(file_path, 'rb') as file:
                header = file.read(len(self.magic_header))
                return header == self.magic_header
        except IOError:
            logger.error(f"Error reading file: {file_path}")
            return False
