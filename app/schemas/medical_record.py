from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, field_validator

from app.models.medical_record import RecordType


class MedicalRecordCreate(BaseModel):
    type: RecordType
    title: str
    notes: str | None = None
    file_url: str | None = None
    record_date: date | None = None
    family_member_id: UUID | None = None

    @field_validator("title")
    @classmethod
    def title_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Title cannot be empty")
        return v.strip()


class MedicalRecordOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    patient_id: UUID
    family_member_id: UUID | None
    type: RecordType
    title: str
    notes: str | None
    file_url: str | None
    record_date: date | None
    created_at: datetime
    updated_at: datetime
