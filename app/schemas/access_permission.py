from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.models.access_permission import InitiatedBy, RequestStatus


class SharingInitiate(BaseModel):
    """Patient initiates sharing — provides doctor's user_id."""

    doctor_user_id: UUID
    family_member_id: UUID | None = None
    scope: str = "records"


class DoctorAccessRequest(BaseModel):
    """Doctor requests access — provides patient's user_id (from NFC/QR)."""

    patient_user_id: UUID
    scope: str = "records"


class AccessPermissionOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    patient_id: UUID
    family_member_id: UUID | None
    granted_to_user_id: UUID
    initiated_by: InitiatedBy
    request_status: RequestStatus
    access_token: str | None
    expires_at: datetime | None
    scope: str | None
    created_at: datetime
    updated_at: datetime
