from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
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

