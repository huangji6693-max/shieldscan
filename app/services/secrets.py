"""Startup secrets validation and passphrase-encrypted API key storage (Drips Wave #29 pattern)."""

import base64
import hashlib
import hmac
import logging
import os
import secrets as std_secrets

from app.config import Settings

logger = logging.getLogger(__name__)

DEFAULT_ZAP_KEY = "changeme"
INSECURE_ZAP_KEYS = frozenset({"changeme", "zap", "password", "admin", ""})
ENCRYPTED_PREFIX = "enc:v1:"
PBKDF2_ITERATIONS = 100_000


def is_encrypted_secret(value: str) -> bool:
    """Return True if the secret value uses the enc:v1: encrypted envelope."""
    return bool(value and value.strip().startswith(ENCRYPTED_PREFIX))


def _derive_keys(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    if not passphrase:
        raise ValueError("Passphrase must not be empty")
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=64,
    )
    return key_material[:32], key_material[32:]


def _keystream_xor(data: bytes, enc_key: bytes, salt: bytes) -> bytes:
    out = bytearray(len(data))
    block_idx = 0
    offset = 0
    while offset < len(data):
        block = hashlib.sha256(enc_key + salt + block_idx.to_bytes(4, "big")).digest()
        chunk = data[offset : offset + 32]
        for i, b in enumerate(chunk):
            out[offset + i] = b ^ block[i]
        offset += 32
        block_idx += 1
    return bytes(out)


def encrypt_secret(plaintext: str, passphrase: str) -> str:
    """Encrypt an API key using PBKDF2-HMAC-SHA256 + authenticated keystream (enc:v1:...)."""
    if not plaintext:
        raise ValueError("Plaintext secret must not be empty")
    salt = std_secrets.token_bytes(16)
    enc_key, mac_key = _derive_keys(passphrase, salt)
    pt_bytes = plaintext.encode("utf-8")
    ct_bytes = _keystream_xor(pt_bytes, enc_key, salt)
    mac = hmac.new(mac_key, salt + ct_bytes, hashlib.sha256).digest()
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    ct_b64 = base64.urlsafe_b64encode(ct_bytes).decode("ascii")
    mac_b64 = base64.urlsafe_b64encode(mac).decode("ascii")
    return f"{ENCRYPTED_PREFIX}{salt_b64}:{ct_b64}:{mac_b64}"


def decrypt_secret(token: str, passphrase: str) -> str:
    """Decrypt an enc:v1:... encrypted secret and verify its HMAC integrity tag."""
    if not is_encrypted_secret(token):
        raise ValueError("Secret does not have enc:v1: prefix")
    body = token.strip()[len(ENCRYPTED_PREFIX) :]
    parts = body.split(":")
    if len(parts) != 3:
        raise ValueError("Malformed enc:v1: secret envelope")
    salt = base64.urlsafe_b64decode(parts[0].encode("ascii"))
    ct_bytes = base64.urlsafe_b64decode(parts[1].encode("ascii"))
    expected_mac = base64.urlsafe_b64decode(parts[2].encode("ascii"))
    enc_key, mac_key = _derive_keys(passphrase, salt)
    actual_mac = hmac.new(mac_key, salt + ct_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_mac, expected_mac):
        raise ValueError("Invalid passphrase or corrupted encrypted secret")
    pt_bytes = _keystream_xor(ct_bytes, enc_key, salt)
    return pt_bytes.decode("utf-8")


def resolve_anthropic_api_key(settings: Settings, passphrase: str | None = None) -> str:
    """Resolve ANTHROPIC_API_KEY, decrypting enc:v1: tokens when a passphrase is provided."""
    raw = (settings.anthropic_api_key or "").strip()
    if not raw:
        return ""
    if not is_encrypted_secret(raw):
        return raw
    effective_passphrase = passphrase if passphrase is not None else os.getenv("SHIELDSCAN_SECRET_PASSPHRASE", "")
    if not effective_passphrase:
        logger.warning("[secrets] ANTHROPIC_API_KEY is encrypted (enc:v1:) but SHIELDSCAN_SECRET_PASSPHRASE is not set")
        return ""
    return decrypt_secret(raw, effective_passphrase)


def validate_settings(settings: Settings) -> list[str]:
    """Return non-fatal warnings about secret configuration."""
    warnings: list[str] = []
    env = os.getenv("SHIELDSCAN_ENV", "development").lower()

    if settings.zap_api_key.lower() in INSECURE_ZAP_KEYS:
        msg = "ZAP_API_KEY is using a default or empty value"
        if env == "production":
            warnings.append(f"CRITICAL: {msg} — change before production deploy")
        else:
            warnings.append(f"WARNING: {msg} — acceptable for local lab only")

    if settings.scanner_mode == "zap" and not settings.zap_api_url:
        warnings.append("WARNING: SCANNER_MODE=zap but ZAP_API_URL is empty")

    if settings.anthropic_api_key:
        if is_encrypted_secret(settings.anthropic_api_key):
            if not os.getenv("SHIELDSCAN_SECRET_PASSPHRASE"):
                warnings.append(
                    "WARNING: ANTHROPIC_API_KEY is encrypted (enc:v1:) but SHIELDSCAN_SECRET_PASSPHRASE is missing"
                )
        elif env == "production":
            warnings.append(
                "WARNING: ANTHROPIC_API_KEY is stored in plaintext without encryption in production — "
                "use passphrase-encrypted storage (enc:v1:...)"
            )
            if settings.anthropic_api_key.startswith("sk-ant-") and len(settings.anthropic_api_key) < 20:
                warnings.append("WARNING: ANTHROPIC_API_KEY appears truncated")

    for w in warnings:
        logger.warning("[secrets] %s", w)

    return warnings
