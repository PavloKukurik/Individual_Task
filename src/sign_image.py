import hashlib
from pathlib import Path
from PIL import Image, PngImagePlugin
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import argparse




KEY_PATH = Path(__file__).resolve().parent.parent / "keys/private.pem"

def load_private_key():
    with open(KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

def calculate_image_hash(path: Path) -> bytes:
    img = Image.open(path)
    data = img.tobytes()
    return hashlib.sha256(data).digest()


def sign_hash(hash_bytes: bytes, private_key) -> bytes:
    return private_key.sign(
        hash_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def embed_signature(image_path: Path, signature: bytes, output_path: Path):
    image = Image.open(image_path)
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Signature", signature.hex())  # зберігаємо як hex-рядок
    image.save(output_path, pnginfo=meta)

def main():
    parser = argparse.ArgumentParser(description="Sign an image with RSA")
    parser.add_argument("input_image", type=Path, help="Path to the input image")
    parser.add_argument("output_image", type=Path, help="Path to the output image with signature")
    args = parser.parse_args()

    private_key = load_private_key()
    img_hash = calculate_image_hash(args.input_image)
    signature = sign_hash(img_hash, private_key)
    embed_signature(args.input_image, signature, args.output_image)

    print(f"[+] Image signed and saved to {args.output_image}")

if __name__ == "__main__":
    main()
