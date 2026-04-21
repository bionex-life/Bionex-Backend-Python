import enum
import uuid

from sqlalchemy import Column, Date, Enum as SAEnum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import EncryptedString, TimestampMixin


class Gender(str, enum.Enum):
    MALE = "MALE"
    FEMALE = "FEMALE"
    OTHER = "OTHER"


class Patient(Base, TimestampMixin):
    __tablename__ = "patients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    date_of_birth = Column(Date, nullable=True)
    gender = Column(SAEnum(Gender), nullable=True)
    blood_group = Column(String(10), nullable=True)
    address = Column(EncryptedString(1000), nullable=True)
    emergency_contact_name = Column(String(255), nullable=True)
    emergency_contact_phone = Column(EncryptedString(30), nullable=True)

    # Relationships
    user = relationship("User", back_populates="patient")
    family_members = relationship(
        "FamilyMember", back_populates="owner", cascade="all, delete-orphan"
    )
    medical_records = relationship(
        "MedicalRecord", back_populates="patient", cascade="all, delete-orphan"
    )
    medications = relationship(
        "Medication", back_populates="patient", cascade="all, delete-orphan"
    )
    lab_orders = relationship(
        "LabOrder", back_populates="patient", cascade="all, delete-orphan"
    )
    access_permissions = relationship(
        "AccessPermission",
        foreign_keys="AccessPermission.patient_id",
        back_populates="patient",
        cascade="all, delete-orphan",
    )
    doctor_access_logs = relationship(
        "DoctorAccessLog",
        foreign_keys="DoctorAccessLog.patient_id",
        back_populates="patient",
    )
    
    # ── Phase 2: Encryption Infrastructure (NEW)
    session_keys = relationship(
        "SessionKey",
        back_populates="patient",
        cascade="all, delete-orphan",
        foreign_keys="SessionKey.patient_id"
    )
    encrypted_record_vaults = relationship(
        "EncryptedRecordVault",
        back_populates="patient",
        cascade="all, delete-orphan",
        foreign_keys="EncryptedRecordVault.patient_id"
    )
