#!/usr/bin/env python3
"""
demo_aes.py

Demonstration of AES-encrypted RSA signature extraction and decryption.
Shows both successful decryption with correct password and failure with wrong one.
"""
from dotenv import load_dotenv
load_dotenv()

import os
import base64
import sys
from pathlib import Path
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_SALT_SIZE = 16
KDF_ITERS     = 100_000

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key from the password and salt.
    :param password: password bytes
    :param salt: 16-byte salt
    :return: 32-byte AES key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(password)

def decrypt_payload(payload_b64: str, password: bytes) -> bytes:
    """
    Decrypt the Base64-encoded payload (salt||iv||ciphertext).
    :param payload_b64: Base64 string from PNG tEXt chunk
    :param password: password bytes
    :return: original RSA signature bytes
    """
    data = base64.b64decode(payload_b64)
    salt = data[:KDF_SALT_SIZE]
    iv   = data[KDF_SALT_SIZE:KDF_SALT_SIZE+16]
    ct   = data[KDF_SALT_SIZE+16:]
    key  = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def main():
    signed_path = Path("examples/signed.png")
    if not signed_path.exists():
        print(f"[-] File not found: {signed_path}")
        sys.exit(1)

    img = Image.open(signed_path)
    payload_b64 = img.info.get("Signature")
    if not payload_b64:
        print("[-] No Signature chunk found")
        sys.exit(2)
    print(f"[+] Found payload of length {len(payload_b64)} bytes (Base64)")

    correct_pwd = os.getenv("AES_PASS", "")
    if not correct_pwd:
        print("[-] Please set AES_PASS in your .env or environment")
        sys.exit(3)
    password = correct_pwd.encode()

    try:
        sig = decrypt_payload(payload_b64, password)
        print("✅ Decryption with correct password succeeded.")
        print("   Signature (first 8 bytes):", sig[:8].hex())
    except Exception as e:
        print("❌ Decryption with correct password failed:", type(e).__name__, e)

    try:
        bad_pwd = b"wrong_password"
        decrypt_payload(payload_b64, bad_pwd)
        print("❌ Decryption unexpectedly succeeded with wrong password!")
    except Exception as e:
        print("✅ Decryption with wrong password correctly failed:", type(e).__name__)

if __name__ == "__main__":
    main()
