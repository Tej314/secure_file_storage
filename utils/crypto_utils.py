from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

def generate_key(password: str, salt: bytes) -> bytes:
    """
    Derive a secure key from the given password and salt using PBKDF2-HMAC-SHA256.
    Returns a 32-byte base64-encoded key suitable for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_data: bytes, key: bytes) -> bytes:
    """
    Encrypt the file data using the given key.
    """
    fernet = Fernet(key)
    return fernet.encrypt(file_data)

def decrypt_file(file_data: bytes, key: bytes) -> bytes:
    """
    Decrypt the file data using the given key.
    """
    fernet = Fernet(key)
    return fernet.decrypt(file_data)
