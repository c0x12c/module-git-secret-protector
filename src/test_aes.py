import os

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


# Helper function to pad data
def pad(data):
    padding_length = 16 - len(data) % 16
    return data + bytes([padding_length]) * padding_length


# Helper function to unpad data
def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]


# Encrypt a file with AES
def encrypt_file(file_path, password):
    # Derive a key from the password using scrypt
    salt = get_random_bytes(16)
    key = scrypt(password.encode(), salt, key_len=32, N=2 ** 14, r=8, p=1)

    # Encrypt the file
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(plaintext))

    # Save the encrypted file (prepend salt and iv for decryption)
    with open(file_path + ".enc", 'wb') as f:
        f.write(salt + iv + ciphertext)


# Decrypt a file with AES
def decrypt_file(file_path_enc, password):
    with open(file_path_enc, 'rb') as f:
        # Extract the salt, IV, and ciphertext
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    # Derive the key from the password using the same parameters
    key = scrypt(password.encode(), salt, key_len=32, N=2 ** 14, r=8, p=1)

    # Decrypt the file
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    # Save the decrypted file
    with open(file_path_enc.replace(".enc", ".dec"), 'wb') as f:
        f.write(plaintext)


# Example usage
if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    password = "mysecretpassword"

    # Encrypt a file
    encrypt_file(os.path.join(script_dir, "example.txt"), password)

    # Decrypt the file
    decrypt_file(os.path.join(script_dir, "example.txt.enc"), password)
