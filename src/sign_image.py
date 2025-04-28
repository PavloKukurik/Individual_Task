from dotenv import load_dotenv
load_dotenv()

import os
import hashlib
import base64
import secrets
from pathlib import Path
from PIL import Image, PngImagePlugin
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import argparse

KEY_PATH = Path(__file__).resolve().parent.parent / "keys/private.pem"
KDF_SALT_SIZE = 16
KDF_ITERS = 100_000

def load_private_key():
    """
    Load the RSA private key from PEM file.
    :return: RSAPrivateKey
    """
    with open(KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key from password and salt using PBKDF2-HMAC-SHA256.
    :param password: password bytes from environment
    :param salt: 16-byte salt
    :return: 32-byte symmetric key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(password)

def calculate_image_hash(image_path: Path) -> bytes:
    """
    Compute SHA-256 hash of raw pixel data of the image.
    :param image_path: Path to input image
    :return: 32-byte hash digest
    """
    with Image.open(image_path) as img:
        pixel_bytes = img.tobytes()
    return hashlib.sha256(pixel_bytes).digest()

def sign_hash(hash_bytes: bytes, private_key) -> bytes:
    """
    Sign the given hash with RSA private key using PKCS#1 v1.5 padding.
    :param hash_bytes: message digest to sign
    :param private_key: RSAPrivateKey object
    :return: signature bytes
    """
    return private_key.sign(
        hash_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def encrypt_signature(sig: bytes, password: bytes) -> bytes:
    """
    Encrypt the RSA signature with AES-256-CBC using a key derived from password.
    :param sig: raw signature bytes
    :param password: password bytes from environment
    :return: concatenated bytes salt||iv||ciphertext
    """
    salt = secrets.token_bytes(KDF_SALT_SIZE)
    iv   = secrets.token_bytes(16)
    key  = derive_key(password, salt)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(sig) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    return salt + iv + ct

def embed_signature(image_path: Path, enc_sig: bytes, output_path: Path):
    """
    Embed the Base64-encoded encrypted signature into a PNG tEXt-chunk.
    :param image_path: Path to original image
    :param enc_sig: encrypted signature bytes
    :param output_path: Path to save signed image
    :return: None
    """
    image = Image.open(image_path)
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Signature", base64.b64encode(enc_sig).decode("ascii"))
    image.save(output_path, pnginfo=meta)

def main():
    """
    Parse arguments, load keys and password, then sign and embed the signature.
    :return: None
    """
    pwd = os.getenv("AES_PASS")
    if not pwd:
        print("[-] ERROR: set AES_PASS in .env")
        exit(1)
    password = pwd.encode("utf-8")

    parser = argparse.ArgumentParser(description="Sign an image with RSA + AES encrypt")
    parser.add_argument("input_image", type=Path, help="Path to input image")
    parser.add_argument("output_image", type=Path, help="Path to output signed image")
    args = parser.parse_args()

    priv = load_private_key()
    img_hash = calculate_image_hash(args.input_image)
    sig      = sign_hash(img_hash, priv)
    enc_sig  = encrypt_signature(sig, password)
    embed_signature(args.input_image, enc_sig, args.output_image)

    print(f"[+] Image signed & encrypted signature saved to {args.output_image}")

if __name__ == "__main__":
    main()
