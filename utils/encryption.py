from cryptography.fernet import Fernet
import os
import base64
from hashlib import sha256

def generate_key_from_password(password: str, salt: str) -> bytes:
    """
    Generate a Fernet key from user's account password and a salt.
    
    Uses SHA-256 to hash the password combined with salt, then encodes
    it as a URL-safe base64 string for use with Fernet encryption.
    
    Args:
        password: User's account password
        salt: Random salt string for key derivation
        
    Returns:
        Base64-encoded key suitable for Fernet encryption
    """
    key = sha256((password + salt).encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_password(plain_password: str, user_password: str, salt: str) -> str:
    """
    Encrypt a password using the user's account password.
    
    Args:
        plain_password: The password to encrypt
        user_password: User's account password for key derivation
        salt: User-specific salt for key derivation
        
    Returns:
        Encrypted password as a string
    """
    key = generate_key_from_password(user_password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(plain_password.encode())
    return encrypted.decode()

def decrypt_password(encrypted_password: str, user_password: str, salt: str) -> str:
    """
    Decrypt a password using the user's account password.
    
    Args:
        encrypted_password: The encrypted password string
        user_password: User's account password for key derivation
        salt: User-specific salt for key derivation
        
    Returns:
        Decrypted password as plain text
    """
    key = generate_key_from_password(user_password, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_password.encode())
    return decrypted.decode()

def generate_salt() -> str:
    """
    Generate a random salt for each user.
    
    Creates a cryptographically secure random salt using os.urandom
    and encodes it as a URL-safe base64 string.
    
    Returns:
        Random salt string (22 characters)
    """
    return base64.urlsafe_b64encode(os.urandom(16)).decode()
