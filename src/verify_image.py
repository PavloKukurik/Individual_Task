from dotenv import load_dotenv
load_dotenv()

import os
import hashlib
import base64
import sys
from pathlib import Path
from PIL import Image, UnidentifiedImageError
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
import argparse

KEY_PATH      = Path(__file__).resolve().parent.parent / "keys/public.pem"
KDF_SALT_SIZE = 16
KDF_ITERS     = 100_000

def load_public_key():
    """
    Load the RSA public key from PEM file.
    :return: RSAPublicKey
    """
    with open(KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive the AES key from password and salt using PBKDF2-HMAC-SHA256.
    :param password: password bytes from environment
    :param salt: 16-byte salt extracted from payload
    :return: 32-byte symmetric key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(password)

def decrypt_signature(enc_payload: bytes, password: bytes) -> bytes:
    """
    Decrypt the signature payload (salt||iv||ciphertext) using AES-256-CBC.
    :param enc_payload: concatenated salt||iv||ciphertext
    :param password: password bytes from environment
    :return: original signature bytes
    """
    salt = enc_payload[:KDF_SALT_SIZE]
    iv   = enc_payload[KDF_SALT_SIZE:KDF_SALT_SIZE+16]
    ct   = enc_payload[KDF_SALT_SIZE+16:]
    key  = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def calculate_image_hash(path: Path) -> bytes:
    """
    Compute SHA-256 hash of raw pixel data of the image.
    :param path: Path to signed image
    :return: 32-byte hash digest; exits if image invalid
    """
    try:
        with Image.open(path) as img:
            pixel_bytes = img.tobytes()
    except UnidentifiedImageError:
        print("[-] Signature is INVALID")
        sys.exit(1)
    return hashlib.sha256(pixel_bytes).digest()

def extract_encrypted_signature(path: Path) -> bytes:
    """
    Extract and Base64-decode the encrypted signature from PNG tEXt-chunk.
    :param path: Path to signed image
    :return: encrypted signature bytes; exits if missing
    """
    try:
        with Image.open(path) as img:
            b64 = img.info.get("Signature")
    except UnidentifiedImageError:
        print("[-] Signature is INVALID")
        sys.exit(1)

    if not b64:
        print("[-] Signature not found")
        sys.exit(2)
    return base64.b64decode(b64)

def verify(pub_key, sig: bytes, img_hash: bytes) -> bool:
    """
    Verify RSA signature against image hash using PKCS#1 v1.5 padding.
    :param pub_key: RSAPublicKey object
    :param sig: decrypted signature bytes
    :param img_hash: SHA-256 digest of image pixels
    :return: True if valid, False otherwise
    """
    try:
        pub_key.verify(sig, img_hash, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False

def main():
    """
    Parse arguments, load keys and password, decrypt and verify the signature.
    :return: None (exit codes: 0-valid,1-invalid,2-not found)
    """
    pwd = os.getenv("AES_PASS")
    if not pwd:
        print("[-] ERROR: set AES_PASS in .env")
        sys.exit(1)
    password = pwd.encode("utf-8")

    parser = argparse.ArgumentParser(description="Verify RSA+AES-encrypted signature in PNG")
    parser.add_argument("signed_image", type=Path, help="Path to signed image")
    args = parser.parse_args()

    pub = load_public_key()
    enc = extract_encrypted_signature(args.signed_image)
    try:
        sig = decrypt_signature(enc, password)
    except Exception:
        print("[-] Signature is INVALID")
        sys.exit(1)

    h = calculate_image_hash(args.signed_image)
    if verify(pub, sig, h):
        print("[+] Signature is VALID")
        sys.exit(0)
    else:
        print("[-] Signature is INVALID")
        sys.exit(1)

if __name__ == "__main__":
    main()
