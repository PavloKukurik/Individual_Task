import subprocess
from pathlib import Path
import pytest

BASE = Path(__file__).resolve().parent.parent
SCRIPT_SIGN = BASE / "src" / "sign_image.py"
SCRIPT_VERIFY = BASE / "src" / "verify_image.py"
SAMPLE = Path(__file__).resolve().parent / "data" / "sample.png"

@pytest.fixture
def tmp_signed(tmp_path):
    """
    Fixture: sign the sample image and return its path.
    """
    out = tmp_path / "signed.png"
    subprocess.run(
        ["python", str(SCRIPT_SIGN), str(SAMPLE), str(out)],
        check=True
    )
    return out

def test_valid_signature(tmp_signed):
    """
    After signing, verification should pass.
    """
    result = subprocess.run(
        ["python", str(SCRIPT_VERIFY), str(tmp_signed)],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "[+] Signature is VALID" in result.stdout

def test_invalid_signature(tmp_signed, tmp_path):
    """
    If the file is tampered, verification should fail.
    """
    tampered = tmp_path / "tampered.png"
    data = bytearray(tmp_signed.read_bytes())
    data[0] ^= 0xFF
    tampered.write_bytes(data)

    result = subprocess.run(
        ["python", str(SCRIPT_VERIFY), str(tampered)],
        capture_output=True,
        text=True
    )
    assert result.returncode == 1
    assert "INVALID" in (result.stdout + result.stderr)
