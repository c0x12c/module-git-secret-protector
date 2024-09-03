import base64
import logging
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from git_secret_protector.git_attributes_parser import GitAttributesParser
from git_secret_protector.aes_key_manager import AesKeyManager

logger = logging.getLogger(__name__)
MAGIC_HEADER = b'ENCRYPTED'  # Magic header to identify encrypted files


class EncryptionManager:
    def __init__(self, aes_key, iv, git_attributes_parser):
        if aes_key is None or iv is None:
            raise ValueError("AES key and IV must not be None")
        self.aes_key = aes_key
        self.iv = iv
        self.git_attributes_parser = git_attributes_parser

    def encrypt_data(self, data):
        if data.startswith(MAGIC_HEADER):
            logger.warning("Data already contains MAGIC_HEADER. Skipping encryption.")
            return data

        ciphertext = self._perform_encryption(data)
        return MAGIC_HEADER + ciphertext

    def decrypt_data(self, data):
        if not data.startswith(MAGIC_HEADER):
            logger.warning("Data does not start with MAGIC HEADER. Skipping decryption.")
            return data

        encrypted_data = data[len(MAGIC_HEADER):]
        plaintext = self._perform_decryption(encrypted_data)
        return plaintext

    def encrypt(self, filter_name):
        files_to_encrypt = self.git_attributes_parser.get_files_for_filter(filter_name=filter_name)

        for file_path in files_to_encrypt:
            encrypted_data = self.encrypt_file(file_path)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            logger.info("File encrypted: %s", file_path)

    def decrypt(self, filter_name):
        files_to_decrypt = self.git_attributes_parser.get_files_for_filter(filter_name=filter_name)

        for file_path in files_to_decrypt:
            decrypted_data = self.decrypt_file(file_path)
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
            logger.info("File decrypted: %s", file_path)

    def encrypt_file(self, file_path):
        logger.info("Encrypting file: %s", file_path)
        with open(file_path, 'rb') as f:
            data = f.read()

        if data.startswith(MAGIC_HEADER):
            logger.info("File already contains MAGIC_HEADER. Skipping encryption.")
            return data

        ciphertext = self._perform_encryption(data)
        return MAGIC_HEADER + ciphertext

    def decrypt_file(self, file_path):
        logger.info("Decrypting file: %s", file_path)
        with open(os.path.abspath(file_path), 'rb') as f:
            data = f.read()

        if not data.startswith(MAGIC_HEADER):
            logger.warning("File does not start with MAGIC HEADER. Skipping decryption.")
            return data

        encrypted_data = data[len(MAGIC_HEADER):]
        plaintext = self._perform_decryption(encrypted_data)
        return plaintext

    def _perform_encryption(self, plaintext: bytes) -> bytes:
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return base64.b64encode(ciphertext)  # Base64 encode the result

    def _perform_decryption(self, encrypted_text: bytes) -> bytes:
        ciphertext = base64.b64decode(encrypted_text)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    @classmethod
    def from_filter_name(cls, filter_name: str, git_attributes_parser: GitAttributesParser):
        key_manager = AesKeyManager()
        aes_key, iv = key_manager.retrieve_key_and_iv(filter_name)
        return cls(aes_key, iv, git_attributes_parser)
