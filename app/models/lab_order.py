import enum
import uuid

from sqlalchemy import Column, DateTime, Enum as SAEnum, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import EncryptedString, TimestampMixin


class OrderStatus(str, enum.Enum):
    BOOKED = "BOOKED"
    SAMPLE_COLLECTED = "SAMPLE_COLLECTED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class CollectionType(str, enum.Enum):
    HOME = "HOME"
    LAB = "LAB"


class LabOrder(Base, TimestampMixin):
    __tablename__ = "lab_orders"

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
    lab_test_id = Column(
        UUID(as_uuid=True),
        ForeignKey("lab_tests.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    status = Column(SAEnum(OrderStatus), nullable=False, default=OrderStatus.BOOKED)
    collection_type = Column(
        SAEnum(CollectionType), nullable=False, default=CollectionType.LAB
    )
    scheduled_date = Column(DateTime(timezone=True), nullable=True)
    collection_address = Column(EncryptedString(1000), nullable=True)
    report_url = Column(EncryptedString(2000), nullable=True)
    notes = Column(Text, nullable=True)

    # Relationships
    patient = relationship("Patient", back_populates="lab_orders")
    family_member = relationship("FamilyMember", back_populates="lab_orders")
    lab_test = relationship("LabTest", back_populates="orders")
    payment = relationship("Payment", back_populates="lab_order", uselist=False)
