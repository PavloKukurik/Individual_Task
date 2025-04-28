# Individual Task | RSA Image Sign 

_Pavlo Kukurik | IT & BA_

---
## This repo contains

- Generate 4096-bit RSA key pairs
- Compute and RSA-sign SHA-256 hashes of image pixels
- Derive an AES-256 key from a password (PBKDF2-HMAC-SHA256) and encrypt the RSA signature using AES-256-CBC
- Embed encrypted signatures into PNG tEXt chunks while keeping the image visually unchanged
- Verify embedded signatures and report clear exit codes (0 valid, 1 invalid, 2 not found)
- Automated pytest suite for both valid and tampered scenarios
---
## How It Works

1. **Key Generation**\
   Generate a 4096-bit RSA private/public key pair in PEM format.
2. **Image Hashing**\
   Load the PNG image, extract raw pixel bytes, and compute a SHA-256 digest.
3. **RSA Signing**\
   Sign the hash with the RSA private key (PKCS#1 v1.5 padding).
4. **AES Encryption**\
   Derive a 256-bit AES key from the user’s password and a random salt via PBKDF2-HMAC-SHA256. Encrypt the RSA signature with AES-256-CBC and apply PKCS7 padding.
5. **Embedding**\
   Encode the salt, IV, and ciphertext as Base64 and insert it into a PNG tEXt chunk named "Signature". This does not alter the displayed image.
6. **Verification**\
   Extract and Base64-decode the encrypted payload, decrypt with AES to recover the RSA signature, recompute the image hash, and verify the signature with the public key.


---
## Setup

1. **Clone** the repository and navigate into it:

   ```bash
   git clone <your-repo-url>
   cd individual_task
   ```

2. **Install** dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure** your AES password:

   - Create a file named `.env` in the project root
   - Add the line:
     ```dotenv
     AES_PASS=password #12341234 - for example
     ```

## Usage
---
### 1. Generate RSA keys

```bash
python src/generate_keys.py
```

Creates `keys/private.pem` and `keys/public.pem`.
---
### 2. Sign an image

```bash
python src/sign_image.py examples/pascha.png examples/signed.png
```

Embeds an encrypted signature into `examples/signed.png`.
---
### 3. Verify a signed image

```bash
python src/verify_image.py examples/signed.png
```

Exit codes:

- `0` : signature is valid
- `1` : signature invalid or decryption failed
- `2` : signature not found

---
## Running Tests

```bash
pytest -q
```

---
## Demo: AES Payload Decryption

Before running the demo script, ensure your `.env` file is present and contains `AES_PASS`:

```dotenv
AES_PASS=password

```

Run the demonstration script:

```bash
python src/demo_aes.py
```

You should see output showing:

- Extraction of the Base64 payload
- Successful decryption with the correct password
- Failure with an incorrect password

