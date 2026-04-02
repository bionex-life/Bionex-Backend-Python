from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, field_validator


class MedicationCreate(BaseModel):
    name: str
    dosage: str | None = None
    frequency: str | None = None
    instructions: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    family_member_id: UUID | None = None

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Medication name cannot be empty")
        return v.strip()


class MedicationUpdate(BaseModel):
    name: str | None = None
    dosage: str | None = None
    frequency: str | None = None
    instructions: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    is_active: bool | None = None


class MedicationOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    patient_id: UUID
    family_member_id: UUID | None
    name: str
    dosage: str | None
    frequency: str | None
    instructions: str | None
    start_date: date | None
    end_date: date | None
    is_active: bool
    created_at: datetime
    updated_at: datetime
