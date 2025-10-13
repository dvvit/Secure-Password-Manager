import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def generate_key(master_password, salt, iterations=390000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt_password(fernet, password):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(fernet, encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

def load_vault(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    else:
        return {"salt": None, "passwords": {}}

def save_vault(filename, vault):
    with open(filename, "w") as f:
        json.dump(vault, f, indent=4)
