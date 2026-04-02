from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, field_validator


class LabTestCreate(BaseModel):
    name: str
    description: str | None = None
    category: str | None = None
    price: Decimal

    @field_validator("price")
    @classmethod
    def price_positive(cls, v: Decimal) -> Decimal:
        if v <= 0:
            raise ValueError("Price must be greater than zero")
        return v

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Name cannot be empty")
        return v.strip()


class LabTestUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    category: str | None = None
    price: Decimal | None = None
    is_active: bool | None = None


class LabTestOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    name: str
    description: str | None
    category: str | None
    price: Decimal
    is_active: bool
    created_at: datetime
    updated_at: datetime
