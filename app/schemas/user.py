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
        if not re.match(r"^\+?[1-9]\d{6,14}$", v):
            raise ValueError("Invalid phone number — use E.164 format e.g. +919876543210")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
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


class UserOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    name: str
    phone: str
    email: str | None
    role: UserRole
    is_active: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole


class TokenRefresh(BaseModel):
    refresh_token: str
