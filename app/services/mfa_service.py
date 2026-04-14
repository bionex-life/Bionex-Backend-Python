"""
Two-Factor Authentication (2FA) using TOTP (Time-based One-Time Passwords).
Supports TOTP with authenticator apps like Google Authenticator, Authy.
"""

from __future__ import annotations

import json
import secrets
from base64 import b32encode

import pyotp

from app.models.login_attempt import TOTPSecret


def generate_totp_secret() -> tuple[str, str]:
    """
    Generate a new TOTP secret.
    Returns (secret, provisioning_uri) where provisioning_uri is for QR code.
    """
    secret = pyotp.random_base32()
    # URI format for QR code generation
    provisioning_uri = f"otpauth://totp/Bionex?secret={secret}&issuer=Bionex"
    return secret, provisioning_uri


def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate backup codes for account recovery."""
    return [
        f"{secrets.token_hex(3).upper()}-{secrets.token_hex(3).upper()}"
        for _ in range(count)
    ]


def verify_totp_token(secret: str, token: str, window: int = 1) -> bool:
    """
    Verify a TOTP token.
    window: time window in 30-second intervals (default 1 = ±30 seconds).
    """
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)
    except Exception:
        return False


def verify_backup_code(backup_codes_json: str, code: str) -> tuple[bool, str]:
    """
    Verify a backup code and return updated backup codes JSON (with used code removed).
    Returns (is_valid, updated_codes_json)
    """
    try:
        backup_codes = json.loads(backup_codes_json)
    except (json.JSONDecodeError, TypeError):
        return False, backup_codes_json
    
    code_upper = code.strip().upper()
    
    if code_upper not in backup_codes:
        return False, backup_codes_json
    
    backup_codes.remove(code_upper)
    return True, json.dumps(backup_codes)


def get_remaining_backup_codes(backup_codes_json: str) -> int:
    """Get count of remaining backup codes."""
    try:
        return len(json.loads(backup_codes_json))
    except (json.JSONDecodeError, TypeError):
        return 0
