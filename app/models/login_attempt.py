import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class LoginAttempt(Base):
    """Track failed login attempts for account lockout."""
    __tablename__ = "login_attempts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), index=True)  # NOT a FK, can be NULL for non-existent users
    phone = Column(String(20), index=True, nullable=True)
    ip_address = Column(String(50), nullable=True)
    is_successful = Column(Boolean, default=False, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    # If locked out, track until when
    account_locked_until = Column(DateTime, nullable=True, index=True)


class PasswordHistory(Base):
    """Track password history to prevent reuse."""
    __tablename__ = "password_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    changed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)


class APIKey(Base):
    """API keys for third-party integrations."""
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), index=True, nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    
    # Scopes: comma-separated (e.g., "read:patients,write:records")
    scopes = Column(String(500), default="", nullable=False)
    
    # IP whitelist: comma-separated IPs or empty for all
    ip_whitelist = Column(String(500), default="", nullable=False)
    
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    last_used = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=True)


class TOTPSecret(Base):
    """Two-factor authentication TOTP secrets."""
    __tablename__ = "totp_secrets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), unique=True, index=True, nullable=False)
    secret = Column(String(32), nullable=False)  # Base32 encoded Fernet key
    backup_codes = Column(String(2000), nullable=False)  # JSON array of 8 backup codes
    is_verified = Column(Boolean, default=False, nullable=False)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
