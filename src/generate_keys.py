"""
STAGE №1 | Generating Keys
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public.pem"

def generate_rsa_key_pair():
    print("[*] Generating 4096-bit RSA key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    # Save private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    PRIVATE_KEY_PATH.write_bytes(pem_private)
    print(f"[+] Private key saved to {PRIVATE_KEY_PATH}")

    # Save public key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    PUBLIC_KEY_PATH.write_bytes(pem_public)
    print(f"[+] Public key saved to {PUBLIC_KEY_PATH}")

if __name__ == "__main__":
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    generate_rsa_key_pair()
