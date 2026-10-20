import base64
import os
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultError(Exception):
    """Base exception for all cryptographic vault errors."""
    pass


class VaultKeyError(VaultError):
    """Raised when the provided encryption key is invalid."""
    pass


class VaultDecryptionError(VaultError):
    """Raised when decryption fails due to payload corruption or invalid authentication tag."""
    pass


def normalize_master_key(key: Union[bytes, str]) -> bytes:
    """
    Normalizes and validates the 32-byte (256-bit) master key.
    Accepts raw 32-byte bytes or a base64-encoded 32-byte string.
    """
    if isinstance(key, str):
        key_str = key.strip()
        try:
            decoded = base64.b64decode(key_str, validate=True)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        # Fallback to UTF-8 bytes if exactly 32 bytes
        raw_bytes = key_str.encode("utf-8")
        if len(raw_bytes) == 32:
            return raw_bytes
        raise VaultKeyError(
            f"Master key must be a 32-byte (256-bit) base64 string or 32 raw bytes; got length {len(raw_bytes)}"
        )
    elif isinstance(key, (bytes, bytearray)):
        if len(key) != 32:
            raise VaultKeyError(f"Master key must be exactly 32 bytes; got {len(key)} bytes")
        return bytes(key)
    else:
        raise VaultKeyError(f"Unsupported key type: {type(key)}")


def encrypt_secret(
    plaintext: str,
    master_key: Union[bytes, str],
    associated_data: Optional[bytes] = None,
) -> str:
    """
    Encrypts a plaintext secret using AES-256-GCM authenticated envelope encryption.

    Storage format:
    - 12 bytes: Random initialization vector / Nonce (os.urandom(12))
    - 16 bytes: Authenticated GCM tag
    - Remainder: Ciphertext
    Serialized as standard Base64 string.
    """
    key_bytes = normalize_master_key(master_key)
    aesgcm = AESGCM(key_bytes)

    # 96-bit (12-byte) cryptographically secure random nonce
    nonce = os.urandom(12)
    plaintext_bytes = plaintext.encode("utf-8")

    # In cryptography, aesgcm.encrypt returns ciphertext + 16-byte authentication tag
    raw_cipher = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
    ciphertext = raw_cipher[:-16]
    tag = raw_cipher[-16:]

    # Pack payload: nonce (12) + tag (16) + ciphertext
    payload = nonce + tag + ciphertext
    return base64.b64encode(payload).decode("ascii")


def decrypt_secret(
    encrypted_payload: str,
    master_key: Union[bytes, str],
    associated_data: Optional[bytes] = None,
) -> str:
    """
    Decrypts an AES-256-GCM envelope payload back to in-memory plaintext.

    Validates:
    - Base64 payload integrity
    - Minimum length (12-byte nonce + 16-byte tag = 28 bytes)
    - Cryptographic authentication tag (raises VaultDecryptionError if tampered)
    """
    key_bytes = normalize_master_key(master_key)
    aesgcm = AESGCM(key_bytes)

    try:
        payload = base64.b64decode(encrypted_payload.strip(), validate=True)
    except Exception as e:
        raise VaultDecryptionError(f"Malformed base64 ciphertext payload: {e}") from e

    if len(payload) < 28:
        raise VaultDecryptionError(
            f"Payload length {len(payload)} is too short (must be at least 28 bytes for nonce and tag)"
        )

    nonce = payload[:12]
    tag = payload[12:28]
    ciphertext = payload[28:]

    # Reconstruct ciphertext + tag for AESGCM
    data = ciphertext + tag

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, data, associated_data)
        return decrypted_bytes.decode("utf-8")
    except InvalidTag as e:
        raise VaultDecryptionError("Authentication tag verification failed: ciphertext is corrupt or tampered") from e
    except UnicodeDecodeError as e:
        raise VaultDecryptionError("Decrypted secret is not valid UTF-8 text") from e


def mask_secret(secret: str, is_api_key: Optional[bool] = None) -> str:
    """
    Returns a masked display representation of a secret for UI and log safety.
    - Passwords and TOTP seeds default to a fixed-length mask '••••••••' to prevent length leakage.
    - Known API key patterns display prefix and suffix (e.g. 'sk-ant...9f8').
    """
    if not secret:
        return ""

    stripped = secret.strip()
    if is_api_key is True or (
        is_api_key is None
        and (
            stripped.startswith(("sk-", "ghp_", "gho_", "xoxb-", "xoxp-", "Bearer "))
            or len(stripped) >= 32
        )
    ):
        if len(stripped) > 10:
            prefix = stripped[:6]
            suffix = stripped[-3:]
            return f"{prefix}...{suffix}"

    # Default safe password mask
    return "••••••••"

