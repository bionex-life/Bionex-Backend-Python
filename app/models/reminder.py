import enum
import uuid

from sqlalchemy import Boolean, Column, Enum as SAEnum, ForeignKey, String, Time
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class ReminderFrequency(str, enum.Enum):
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    CUSTOM = "CUSTOM"


class ReminderStatus(str, enum.Enum):
    TAKEN = "TAKEN"
    MISSED = "MISSED"
    SKIPPED = "SKIPPED"


class Reminder(Base, TimestampMixin):
    __tablename__ = "reminders"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    medication_id = Column(
        UUID(as_uuid=True),
        ForeignKey("medications.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    time = Column(Time, nullable=False)
    frequency = Column(
        SAEnum(ReminderFrequency), nullable=False, default=ReminderFrequency.DAILY
    )
    # Comma-separated days for WEEKLY/CUSTOM: "MON,WED,FRI"
    days_of_week = Column(String(50), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    medication = relationship("Medication", back_populates="reminders")
    logs = relationship(
        "ReminderLog", back_populates="reminder", cascade="all, delete-orphan"
    )


class ReminderLog(Base):
    __tablename__ = "reminder_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    reminder_id = Column(
        UUID(as_uuid=True),
        ForeignKey("reminders.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # ISO date string, e.g. "2026-04-03"
    scheduled_date = Column(String(20), nullable=False)
    status = Column(SAEnum(ReminderStatus), nullable=False)
    logged_at = Column(String(50), nullable=True)

    # Relationships
    reminder = relationship("Reminder", back_populates="logs")
