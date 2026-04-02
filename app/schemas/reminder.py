from __future__ import annotations

from datetime import datetime
from datetime import time as TimeOfDay
from uuid import UUID

from pydantic import BaseModel

from app.models.reminder import ReminderFrequency, ReminderStatus


class ReminderCreate(BaseModel):
    medication_id: UUID
    time: TimeOfDay
    frequency: ReminderFrequency = ReminderFrequency.DAILY
    days_of_week: str | None = None


class ReminderUpdate(BaseModel):
    time: TimeOfDay | None = None
    frequency: ReminderFrequency | None = None
    days_of_week: str | None = None
    is_active: bool | None = None


class ReminderOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    medication_id: UUID
    time: TimeOfDay
    frequency: ReminderFrequency
    days_of_week: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class ReminderLogCreate(BaseModel):
    scheduled_date: str  # ISO format: "2026-04-03"
    status: ReminderStatus


class ReminderLogOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    reminder_id: UUID
    scheduled_date: str
    status: ReminderStatus
    logged_at: str | None
