from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, field_validator

from app.models.user import UserRole


class UserCreate(BaseModel):
    name: str
    phone: str
    email: str | None = None
    password: str
    role: UserRole = UserRole.PATIENT

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        # E.164 format: + followed by 1-15 digits, must have + prefix
        if not re.match(r"^\+[1-9]\d{6,14}$", v):
            raise ValueError(
                "Invalid phone number — must use E.164 format with + prefix (e.g. +919876543210)"
            )
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError(
                "Password must contain at least one special character (!@#$%^&*...)"
            )
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", v):
            raise ValueError("Invalid email address")
        return v.lower()


class UserLogin(BaseModel):
    phone: str
    password: str

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        # E.164 format: + followed by 1-15 digits, must have + prefix
        if not re.match(r"^\+[1-9]\d{6,14}$", v):
            raise ValueError("Invalid phone number — use E.164 format")
        return v


class ChangePasswordRequest(BaseModel):
    """Request to change password (Phase 2 Security)."""

    old_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("New password must be at least 12 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain special character")
        return v


class TwoFASetupRequest(BaseModel):
    """Request to setup 2FA."""

    token: str  # TOTP token to verify setup


class TwoFAVerifyRequest(BaseModel):
    """Request to verify 2FA during login."""

    token: str  # TOTP token or backup code


class UserOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    name: str
    phone: str
    email: str | None
    role: UserRole
    is_active: bool
    is_locked: bool
    is_2fa_enabled: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    role: UserRole
    requires_2fa: bool = False  # If True, client must verify 2FA before using token


class TokenRefresh(BaseModel):
    refresh_token: str
