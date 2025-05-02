import base64
import hashlib
import secrets

from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa
import os


def hash_password(password):
    ph = PasswordHasher(
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        salt_len=16
    )

    hashed_password = ph.hash(password.encode('utf-8'))
    return hashed_password


def verify_password(password, hashed_password):
    ph = PasswordHasher(
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        salt_len=16
    )

    try:
        ph.verify(hashed_password, password.encode('utf-8'))
        return True
    except:
        return False


def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key


def hash_file_bytes(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def key_from_hash(hashed_password):
    # Generate a valid Fernet key from hashed password
    sha256 = hashlib.sha256(hashed_password.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(sha256)
    return fernet_key


def save_credentials(username, password, derived_key):
    fernet_key = key_from_hash(derived_key)
    fernet = Fernet(fernet_key)
    credentials = f"{username}:{password}"
    encrypted = fernet.encrypt(credentials.encode())

    with open("credentials.enc", "wb") as f:
        f.write(encrypted)
