import uuid

from sqlalchemy import Boolean, Column, Date, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Medication(Base, TimestampMixin):
    __tablename__ = "medications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    patient_id = Column(
        UUID(as_uuid=True),
        ForeignKey("patients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    family_member_id = Column(
        UUID(as_uuid=True),
        ForeignKey("family_members.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    name = Column(String(500), nullable=False)
    dosage = Column(String(255), nullable=True)
    frequency = Column(String(255), nullable=True)
    instructions = Column(String(1000), nullable=True)
    start_date = Column(Date, nullable=True)
    end_date = Column(Date, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    patient = relationship("Patient", back_populates="medications")
    family_member = relationship("FamilyMember", back_populates="medications")
    reminders = relationship(
        "Reminder", back_populates="medication", cascade="all, delete-orphan"
    )
