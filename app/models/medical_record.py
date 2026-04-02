import enum
import uuid

from sqlalchemy import Column, Date, Enum as SAEnum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import EncryptedString, TimestampMixin


class RecordType(str, enum.Enum):
    PRESCRIPTION = "PRESCRIPTION"
    LAB_REPORT = "LAB_REPORT"
    DIAGNOSIS = "DIAGNOSIS"
    IMAGING = "IMAGING"
    VACCINATION = "VACCINATION"
    OTHER = "OTHER"


class MedicalRecord(Base, TimestampMixin):
    __tablename__ = "medical_records"

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
    type = Column(SAEnum(RecordType), nullable=False)
    title = Column(String(500), nullable=False)
    notes = Column(EncryptedString(5000), nullable=True)
    file_url = Column(EncryptedString(2000), nullable=True)
    record_date = Column(Date, nullable=True)

    # Relationships
    patient = relationship("Patient", back_populates="medical_records")
    family_member = relationship("FamilyMember", back_populates="medical_records")
