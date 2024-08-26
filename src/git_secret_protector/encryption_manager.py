import base64

from Crypto.Cipher import AES

from git_secret_protector.git_attributes_parser import GitAttributesParser
from git_secret_protector.kms_key_manager import KMSKeyManager


class EncryptionManager:
    def __init__(self, aes_key):
        self.aes_key = aes_key

    def encrypt(self, filter_name):
        git_attributes_parser = GitAttributesParser()
        files_to_encrypt = git_attributes_parser.get_files_for_filter(filter_name=filter_name)

        for file_path in files_to_encrypt:
            self.encrypt_file(file_path)

    def decrypt(self, filter_name):
        git_attributes_parser = GitAttributesParser()
        files_to_decrypt = git_attributes_parser.get_files_for_filter(filter_name=filter_name)

        for file_path in files_to_decrypt:
            self.decrypt_file(file_path)

    def encrypt_file(self, file_path):
        with open(file_path, 'r') as f:
            plaintext = f.read()

        ciphertext = self._perform_encryption(plaintext)

        with open(f'{file_path}.enc', 'w') as f:
            f.write(ciphertext)

    def decrypt_file(self, file_path):
        with open(file_path, 'r') as f:
            encrypted_data = f.read()

        plaintext = self._perform_decryption(encrypted_data)

        decrypted_file_path = file_path.replace('.enc', '')
        with open(decrypted_file_path, 'w') as f:
            f.write(plaintext)

    def _perform_encryption(self, plaintext: str) -> str:
        cipher = AES.new(self.aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def _perform_decryption(self, encrypted_text: str) -> str:
        encrypted_data = base64.b64decode(encrypted_text)
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

    @classmethod
    def from_filter_name(cls, filter_name):
        kms_manager = KMSKeyManager()
        aes_key = kms_manager.get_aes_key(filter_name)
        return cls(aes_key)
