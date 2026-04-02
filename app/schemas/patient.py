from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel

from app.models.patient import Gender


class PatientUpdate(BaseModel):
    date_of_birth: date | None = None
    gender: Gender | None = None
    blood_group: str | None = None
    address: str | None = None
    emergency_contact_name: str | None = None
    emergency_contact_phone: str | None = None


class PatientOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    user_id: UUID
    date_of_birth: date | None
    gender: Gender | None
    blood_group: str | None
    address: str | None
    emergency_contact_name: str | None
    emergency_contact_phone: str | None
    created_at: datetime
    updated_at: datetime
