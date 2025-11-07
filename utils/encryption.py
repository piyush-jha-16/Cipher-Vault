from cryptography.fernet import Fernet
import os
import base64
from hashlib import sha256

def generate_key_from_password(password: str, salt: str) -> bytes:
    """
    Generate a Fernet key from user's account password and a salt
    """
    key = sha256((password + salt).encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_password(plain_password: str, user_password: str, salt: str) -> str:
    """
    Encrypt a password using the user's account password
    """
    key = generate_key_from_password(user_password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(plain_password.encode())
    return encrypted.decode()

def decrypt_password(encrypted_password: str, user_password: str, salt: str) -> str:
    """
    Decrypt a password using the user's account password
    """
    key = generate_key_from_password(user_password, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_password.encode())
    return decrypted.decode()

def generate_salt() -> str:
    """
    Generate a random salt for each user
    """
    return base64.urlsafe_b64encode(os.urandom(16)).decode()
