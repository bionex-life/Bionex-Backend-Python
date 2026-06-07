"""
Security utilities for Phase 2 and Enhanced Security features.
Provides reusable security functions for account lockout, CSRF, data masking, etc.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.login_attempt import LoginAttempt, PasswordHistory
from app.models.user import User


# ─────────────────────────────────────────────────────────────────────────────
# Account Lockout Management (Enhanced Security #1)
# ─────────────────────────────────────────────────────────────────────────────

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


def record_failed_login(
    db: Session, user_id: Optional[str], phone: str, ip_address: str
) -> None:
    """Record failed login attempt and lock account if threshold exceeded."""
    import uuid

    uid = None
    if user_id:
        uid = uuid.UUID(user_id) if isinstance(user_id, str) else user_id

    attempt = LoginAttempt(
        user_id=uid,
        phone=phone,
        ip_address=ip_address,
        is_successful=False,
    )
    db.add(attempt)
    db.flush()

    if uid:
        user = db.query(User).filter(User.id == uid).first()
        if user:
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.now(timezone.utc)

            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                lockout_until = datetime.now(timezone.utc) + timedelta(
                    minutes=LOCKOUT_DURATION_MINUTES
                )
                user.is_locked = True
                user.locked_until = lockout_until
                attempt.account_locked_until = lockout_until

    db.commit()


def record_successful_login(db: Session, user_id: str, ip_address: str) -> None:
    """Record successful login and reset failed attempts."""
    import uuid

    uid = uuid.UUID(user_id) if isinstance(user_id, str) else user_id

    attempt = LoginAttempt(
        user_id=uid,
        ip_address=ip_address,
        is_successful=True,
    )
    db.add(attempt)

    user = db.query(User).filter(User.id == uid).first()
    if user:
        user.failed_login_attempts = 0
        user.is_locked = False
        user.locked_until = None

    db.commit()


def is_account_locked(user: User) -> bool:
    """Check if account is currently locked."""
    if not user.is_locked:
        return False

    if user.locked_until:
        # Ensure timezone-aware comparison
        now = datetime.now(timezone.utc)
        locked_until = user.locked_until
        # If locked_until is naive, assume it's UTC
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        if now >= locked_until:
            # Lock has expired, unlock the account
            return False

    return True


def unlock_account(db: Session, user: User) -> None:
    """Unlock a locked account."""
    user.is_locked = False
    user.locked_until = None
    user.failed_login_attempts = 0
    db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Password Management (Enhanced Security #3)
# ─────────────────────────────────────────────────────────────────────────────

MIN_PASSWORD_LENGTH = 12
PASSWORD_REUSE_COUNT = 5
PASSWORD_EXPIRY_DAYS = 90


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password meets strong requirements.
    Returns (is_valid, error_message)
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return (
            False,
            "Password must contain at least one special character (!@#$%^&*...)",
        )

    return True, ""


def is_password_reused(db: Session, user_id: str, hashed_password: str) -> bool:
    """Check if password was used in last N password changes."""
    from app.services.auth_service import verify_password

    recent_hashes = (
        db.query(PasswordHistory.hashed_password)
        .filter(PasswordHistory.user_id == user_id)
        .order_by(PasswordHistory.changed_at.desc())
        .limit(PASSWORD_REUSE_COUNT)
        .all()
    )

    for (old_hash,) in recent_hashes:
        if verify_password(hashed_password, old_hash):
            return True

    return False


def record_password_change(db: Session, user_id: str, old_hashed_password: str) -> None:
    """Record old password in history."""
    history = PasswordHistory(
        user_id=user_id,
        hashed_password=old_hashed_password,
    )
    db.add(history)
    db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Sensitive Data Masking (Enhanced Security #10)
# ─────────────────────────────────────────────────────────────────────────────


def mask_phone(phone: str) -> str:
    """Mask phone number, show only last 4 digits."""
    if len(phone) < 4:
        return "****"
    return "*" * (len(phone) - 4) + phone[-4:]


def mask_email(email: str) -> str:
    """Mask email, show only domain."""
    if "@" not in email:
        return "****@****"
    local, domain = email.split("@")
    return local[0] + "*" * (len(local) - 1) + "@" + domain


def mask_credit_card(card: str) -> str:
    """Mask credit card, show only last 4 digits."""
    card_clean = card.replace(" ", "").replace("-", "")
    if len(card_clean) < 4:
        return "****"
    return "*" * (len(card_clean) - 4) + card_clean[-4:]


def sanitize_user_data(user: User) -> dict:
    """Return user data with sensitive fields masked for logs/responses."""
    return {
        "id": str(user.id),
        "name": user.name,
        "phone": mask_phone(user.phone),
        "email": mask_email(user.email) if user.email else None,
        "role": user.role,
        "is_active": user.is_active,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CSRF Protection Utilities (Enhanced Security #9)
# ─────────────────────────────────────────────────────────────────────────────


def validate_origin_header(origin: Optional[str], allowed_origins: list[str]) -> bool:
    """Validate Origin header matches allowed origins."""
    if not origin:
        return False

    origin_lower = origin.lower().rstrip("/")
    for allowed in allowed_origins:
        allowed_lower = allowed.lower().rstrip("/")
        if origin_lower == allowed_lower:
            return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Session Management Utilities (Enhanced Security #7)
# ─────────────────────────────────────────────────────────────────────────────


def invalidate_all_user_sessions(db: Session, user_id: str) -> None:
    """
    Invalidate all active sessions for a user.
    In production, this would delete all refresh tokens from Redis.
    """
    # Placeholder for session invalidation logic
    # In a real implementation, you would:
    # 1. Delete all refresh tokens from Redis cache
    # 2. Mark all active sessions as invalidated in a sessions table
    pass


# ─────────────────────────────────────────────────────────────────────────────
# API Key Management (Enhanced Security #4)
# ─────────────────────────────────────────────────────────────────────────────


def parse_api_key_scopes(scopes_str: str) -> set[str]:
    """Parse comma-separated scopes into a set."""
    return set(s.strip() for s in scopes_str.split(",") if s.strip())


def parse_ip_whitelist(whitelist_str: str) -> list[str]:
    """Parse comma-separated IP whitelist."""
    return [ip.strip() for ip in whitelist_str.split(",") if ip.strip()]


def validate_ip_whitelist(client_ip: str, whitelist_str: str) -> bool:
    """Check if client IP is in whitelist. Empty whitelist = allow all."""
    if not whitelist_str.strip():
        return True

    whitelist = parse_ip_whitelist(whitelist_str)
    return client_ip in whitelist or any(
        client_ip.startswith(ip.replace("*", "")) for ip in whitelist if "*" in ip
    )
