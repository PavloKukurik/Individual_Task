import argparse
import hashlib
import sys
from pathlib import Path
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

KEY_PATH = Path(__file__).resolve().parent.parent / "keys/public.pem"

def load_public_key():
    with open(KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def extract_signature(path: Path) -> bytes:
    img = Image.open(path)
    hex_sig = img.info.get("Signature")
    if not hex_sig:
        print("[-] Signature not found")
        sys.exit(2)
    return bytes.fromhex(hex_sig)

def calculate_image_hash(path: Path) -> bytes:
    img = Image.open(path)
    data = img.tobytes()
    return hashlib.sha256(data).digest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("signed_img", type=Path)
    args = p.parse_args()

    pub = load_public_key()
    sig = extract_signature(args.signed_img)
    h = calculate_image_hash(args.signed_img)

    try:
        pub.verify(sig, h, padding.PKCS1v15(), hashes.SHA256())
        print("[+] Signature is VALID")
        sys.exit(0)
    except InvalidSignature:
        print("[-] Signature is INVALID")
        sys.exit(1)

if __name__ == "__main__":
    main()
