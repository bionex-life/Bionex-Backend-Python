from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, field_validator

from app.models.family_member import Relation


class FamilyMemberCreate(BaseModel):
    name: str
    relation: Relation
    date_of_birth: date | None = None
    gender: str | None = None
    blood_group: str | None = None

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Name cannot be empty")
        return v.strip()


class FamilyMemberUpdate(BaseModel):
    name: str | None = None
    relation: Relation | None = None
    date_of_birth: date | None = None
    gender: str | None = None
    blood_group: str | None = None


class FamilyMemberOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    owner_patient_id: UUID
    name: str
    relation: Relation
    date_of_birth: date | None
    gender: str | None
    blood_group: str | None
    created_at: datetime
    updated_at: datetime
