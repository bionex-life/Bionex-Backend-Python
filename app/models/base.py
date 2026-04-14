"""
Shared mixins and custom SQLAlchemy column types used across all models.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime
from sqlalchemy.types import String, TypeDecorator


class EncryptedString(TypeDecorator):
    """Fernet-encrypted string column.

    Transparently encrypts on write and decrypts on read.
    Raises error if FIELD_ENCRYPTION_KEY is not set (enforce encryption).
    """

    impl = String
    cache_ok = True

    def _fernet(self):
        from cryptography.fernet import Fernet

        key = os.environ.get("FIELD_ENCRYPTION_KEY", "").strip()
        if not key:
            raise ValueError(
                "FIELD_ENCRYPTION_KEY is required for field-level encryption of sensitive data (PII). "
                "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        return Fernet(key.encode())

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        f = self._fernet()
        if f is None:
            return value
        return f.encrypt(value.encode()).decode()

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        f = self._fernet()
        if f is None:
            return value
        try:
            return f.decrypt(value.encode()).decode()
        except Exception:
            return value


class TimestampMixin:
    """Adds created_at / updated_at columns to any model."""

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
