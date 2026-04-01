import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS = 100_000


def generate_salt() -> bytes:
    return os.urandom(16)


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def make_cipher(key: bytes) -> Fernet:
    return Fernet(key)


def encrypt(cipher: Fernet, plaintext: str) -> str:
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt(cipher: Fernet, ciphertext: str) -> str:
    return cipher.decrypt(ciphertext.encode()).decode()
