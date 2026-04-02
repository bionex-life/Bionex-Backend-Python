from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.models.lab_order import CollectionType, OrderStatus


class LabOrderCreate(BaseModel):
    lab_test_id: UUID
    collection_type: CollectionType = CollectionType.LAB
    scheduled_date: datetime | None = None
    collection_address: str | None = None
    notes: str | None = None
    family_member_id: UUID | None = None


class LabOrderStatusUpdate(BaseModel):
    status: OrderStatus
    report_url: str | None = None


class LabOrderOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    patient_id: UUID
    family_member_id: UUID | None
    lab_test_id: UUID
    status: OrderStatus
    collection_type: CollectionType
    scheduled_date: datetime | None
    collection_address: str | None
    report_url: str | None
    notes: str | None
    created_at: datetime
    updated_at: datetime
