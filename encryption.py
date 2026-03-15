"""
encryption.py — AES-256-CBC encryption with PBKDF2-HMAC-SHA256 key derivation.

Security properties:
  • Per-record random IV (16 bytes) — prevents IV reuse attacks
  • Random salt per vault (32 bytes) — stored in DB alongside user record
  • 600,000 PBKDF2 iterations — NIST SP 800-132 compliant
  • Key never written to disk; derived in-memory each session
"""

import os
import hashlib
import hmac
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import PBKDF2_ITERATIONS, PBKDF2_HASH, AES_KEY_LENGTH, SALT_LENGTH, IV_LENGTH


# ─── Key Derivation ───────────────────────────────────────────────────────────

def generate_salt() -> bytes:
    """Return a cryptographically secure random salt."""
    return os.urandom(SALT_LENGTH)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the master password using PBKDF2-HMAC-SHA256.

    Args:
        master_password: Plaintext master password (str)
        salt: Random per-user salt (bytes)

    Returns:
        32-byte AES key
    """
    return hashlib.pbkdf2_hmac(
        PBKDF2_HASH,
        master_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=AES_KEY_LENGTH,
    )


# ─── AES-256-CBC Encrypt / Decrypt ────────────────────────────────────────────

def encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt plaintext with AES-256-CBC.

    Stores IV prepended to ciphertext, then base64-encodes the whole blob.

    Returns:
        base64-encoded string: IV (16 bytes) || ciphertext
    """
    iv = os.urandom(IV_LENGTH)
    # PKCS7 padding
    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode("utf-8")


def decrypt(token: str, key: bytes) -> str:
    """
    Decrypt a base64-encoded AES-256-CBC token produced by `encrypt()`.

    Returns:
        Plaintext string

    Raises:
        ValueError: If decryption or unpadding fails (tampered data)
    """
    try:
        raw = base64.b64decode(token.encode("utf-8"))
        iv, ciphertext = raw[:IV_LENGTH], raw[IV_LENGTH:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding byte.")
        return data[:-pad_len].decode("utf-8")

    except Exception as exc:
        raise ValueError(f"Decryption failed: {exc}") from exc


# ─── Integrity / HMAC Helper ──────────────────────────────────────────────────

def hmac_sign(data: bytes, key: bytes) -> str:
    """Return hex HMAC-SHA256 signature for integrity verification."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(data: bytes, key: bytes, expected_sig: str) -> bool:
    """Constant-time HMAC verification."""
    actual = hmac_sign(data, key)
    return hmac.compare_digest(actual, expected_sig)
