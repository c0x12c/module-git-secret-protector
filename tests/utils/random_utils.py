import secrets
import string

ALPHABET = string.ascii_letters + string.digits


def generate_random_string(length=8):
    return ''.join(secrets.choice(ALPHABET) for _ in range(length))
