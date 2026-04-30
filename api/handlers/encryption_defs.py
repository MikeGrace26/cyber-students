from tornado.escape import json_decode

from .base import BaseHandler

import os
import base64
import keyring

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def create_key() -> bytes:
    SERVICE = "cyber-students"
    KEY_NAME = "master-key"

    key = os.urandom(32)
    key_b64 = base64.b64encode(key).decode("ascii")
    keyring.set_password(SERVICE, KEY_NAME, key_b64)
    return key

def get_key() -> bytes:
    SERVICE = "cyber-students"
    KEY_NAME = "master-key"

    key_b64 = keyring.get_password(SERVICE, KEY_NAME)

    if key_b64:
        return base64.b64decode(key_b64)

    # If no key is found create a new one
    key = create_key()
    
    return key

def create_emsalt() -> bytes:
    SERVICE = "cyber-students"
    KEY_NAME = "email-blindlink-key"

    key = os.urandom(32)
    key_b64 = base64.b64encode(key).decode("ascii")
    keyring.set_password(SERVICE, KEY_NAME, key_b64)
    return key

def get_emsalt() -> bytes:
    SERVICE = "cyber-students"
    KEY_NAME = "email-blindlink-key"

    key_b64 = keyring.get_password(SERVICE, KEY_NAME)

    if key_b64:
        return base64.b64decode(key_b64)

    # If no key is found create a new one
    key = create_emsalt()
    
    return key

def create_tokensalt() -> bytes:
    SERVICE = "cyber-students"
    KEY_NAME = "token-blindlink-key"

    key = os.urandom(32)
    key_b64 = base64.b64encode(key).decode("ascii")
    keyring.set_password(SERVICE, KEY_NAME, key_b64)
    return key

def get_tokensalt() -> bytes:
    SERVICE = "cyber-students"
    KEY_NAME = "token-blindlink-key"

    key_b64 = keyring.get_password(SERVICE, KEY_NAME)

    if key_b64:
        return base64.b64decode(key_b64)

    # If no key is found create a new one
    key = create_tokensalt()
    
    return key

def get_salt():

    salt = os.urandom(16)   # 16 bytes = 128-bit salt

    return salt

def hash_pw(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    
    passphrase_bytes = password.encode("utf-8")
    hashed_passphrase = kdf.derive(passphrase_bytes)
    password_str = hashed_passphrase.hex()

    return password_str


def encrypt_text(plaintext: str, key: bytes, textiv: bytes) -> str:
    """
    Encrypt plaintext using AES-GCM with a random 12-byte IV (nonce).
    Returns base64 token containing: iv || ciphertext (ciphertext includes auth tag).
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes for AES-128/192/256.")

    aesgcm = AESGCM(key)

    aad = b"arithmophobia"  # optional associated data (binds context); must match on decrypt
    ciphertext = aesgcm.encrypt(textiv, plaintext.encode("utf-8"), aad)

    token = base64.urlsafe_b64encode(textiv + ciphertext).decode("ascii")
    
    return token

def decrypt_text(token: str, key: bytes, iv: bytes) -> str:
    """
    Decrypt base64 token produced by encrypt_text_aes_gcm().
    """
    blob = base64.urlsafe_b64decode(token.encode("ascii"))
    iv, ciphertext = blob[:12], blob[12:]

    aesgcm = AESGCM(key)
    aad = b"arithmophobia"
    plaintext = aesgcm.decrypt(iv, ciphertext, aad)

    return plaintext.decode("utf-8")