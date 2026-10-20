import base64
import os
import pytest

from app.security.vault import (
    VaultDecryptionError,
    VaultKeyError,
    decrypt_secret,
    encrypt_secret,
    mask_secret,
    normalize_master_key,
)


@pytest.fixture
def sample_master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def sample_base64_master_key(sample_master_key: bytes) -> str:
    return base64.b64encode(sample_master_key).decode("ascii")


def test_normalize_master_key(sample_master_key: bytes, sample_base64_master_key: str):
    # Raw bytes
    assert normalize_master_key(sample_master_key) == sample_master_key

    # Base64 string
    assert normalize_master_key(sample_base64_master_key) == sample_master_key

    # Invalid key length
    with pytest.raises(VaultKeyError, match="Master key must be"):
        normalize_master_key(b"short-key")

    with pytest.raises(VaultKeyError, match="Master key must be"):
        normalize_master_key(base64.b64encode(b"short-key").decode())


def test_encryption_decryption_roundtrip(sample_master_key: bytes):
    secrets = [
        "SuperSecretPassword123!",
        "sk-ant-api03-abcdef1234567890",
        "JBSWY3DPEHPK3PXP",
        "Unicode test: 🔑🔒 Wilco agent credentials 🚀",
        "",  # Empty plaintext
        "A" * 1000,  # Long payload
    ]

    for secret in secrets:
        encrypted = encrypt_secret(secret, sample_master_key)
        assert encrypted != secret
        assert isinstance(encrypted, str)

        decrypted = decrypt_secret(encrypted, sample_master_key)
        assert decrypted == secret


def test_encryption_unique_nonces(sample_master_key: bytes):
    secret = "MyConstantSecret"
    enc1 = encrypt_secret(secret, sample_master_key)
    enc2 = encrypt_secret(secret, sample_master_key)

    # Identical plaintexts must produce distinct ciphertexts due to fresh 96-bit nonces
    assert enc1 != enc2

    # Both must decrypt to the original value
    assert decrypt_secret(enc1, sample_master_key) == secret
    assert decrypt_secret(enc2, sample_master_key) == secret


def test_tamper_detection_raises_error(sample_master_key: bytes):
    secret = "ConfidentialData"
    encrypted = encrypt_secret(secret, sample_master_key)
    raw_payload = bytearray(base64.b64decode(encrypted))

    # Tamper with the authentication tag (bytes 12..28)
    raw_payload[15] ^= 0xFF
    tampered_b64 = base64.b64encode(raw_payload).decode("ascii")

    with pytest.raises(VaultDecryptionError, match="Authentication tag verification failed"):
        decrypt_secret(tampered_b64, sample_master_key)

    # Tamper with the ciphertext (bytes 28..)
    raw_payload = bytearray(base64.b64decode(encrypted))
    raw_payload[-1] ^= 0x01
    tampered_b64_cipher = base64.b64encode(raw_payload).decode("ascii")

    with pytest.raises(VaultDecryptionError, match="Authentication tag verification failed"):
        decrypt_secret(tampered_b64_cipher, sample_master_key)


def test_malformed_payload_handling(sample_master_key: bytes):
    # Invalid Base64
    with pytest.raises(VaultDecryptionError, match="Malformed base64"):
        decrypt_secret("not-a-valid-base64!@#$", sample_master_key)

    # Truncated payload (<28 bytes)
    short_payload = base64.b64encode(b"too_short").decode()
    with pytest.raises(VaultDecryptionError, match="too short"):
        decrypt_secret(short_payload, sample_master_key)


def test_mask_secret():
    assert mask_secret("") == ""
    assert mask_secret("SimplePassword") == "••••••••"
    assert mask_secret("sk-ant-123456789abcdef") == "sk-ant...def"
    assert mask_secret("ghp_1234567890abcdefghijklmnopqrstuv") == "ghp_12...tuv"
    assert mask_secret("custom-key-that-is-very-long-1234567890", is_api_key=True) == "custom...890"


def test_settings_vault_configuration(sample_base64_master_key: str, sample_master_key: bytes):
    from app.config import Settings

    # Valid key configuration
    s = Settings(VAULT_MASTER_KEY=sample_base64_master_key)
    assert s.VAULT_MASTER_KEY == sample_base64_master_key
    assert s.vault_key_bytes == sample_master_key

    # Empty key allowed at startup but raises on vault_key_bytes property access
    s_empty = Settings(VAULT_MASTER_KEY="")
    assert s_empty.VAULT_MASTER_KEY == ""
    with pytest.raises(ValueError, match="not configured"):
        _ = s_empty.vault_key_bytes

    # Invalid key length raises validation error
    invalid_b64 = base64.b64encode(b"short").decode()
    with pytest.raises(ValueError, match="must decode to exactly 32 bytes"):
        Settings(VAULT_MASTER_KEY=invalid_b64)
