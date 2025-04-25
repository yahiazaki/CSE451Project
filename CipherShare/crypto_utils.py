import base64
import secrets

from argon2 import PasswordHasher
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


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_private_key(private_key_pem: bytes, derived_key: bytes) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(private_key_pem) + padder.finalize()

    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()  # Store as string


def encrypt_file_content(data, key):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data


def decrypt_file_content(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data[16:]) + decryptor.finalize()


def hash_file_bytes(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()
