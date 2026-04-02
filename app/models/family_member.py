import enum
import uuid

from sqlalchemy import Column, Date, Enum as SAEnum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Relation(str, enum.Enum):
    FATHER = "FATHER"
    MOTHER = "MOTHER"
    SPOUSE = "SPOUSE"
    CHILD = "CHILD"
    SIBLING = "SIBLING"
    GRANDPARENT = "GRANDPARENT"
    OTHER = "OTHER"


class FamilyMember(Base, TimestampMixin):
    __tablename__ = "family_members"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    owner_patient_id = Column(
        UUID(as_uuid=True),
        ForeignKey("patients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    relation = Column(SAEnum(Relation), nullable=False)
    date_of_birth = Column(Date, nullable=True)
    gender = Column(String(10), nullable=True)
    blood_group = Column(String(10), nullable=True)

    # Relationships
    owner = relationship("Patient", back_populates="family_members")
    medical_records = relationship(
        "MedicalRecord", back_populates="family_member", cascade="all, delete-orphan"
    )
    medications = relationship(
        "Medication", back_populates="family_member", cascade="all, delete-orphan"
    )
    lab_orders = relationship("LabOrder", back_populates="family_member")
    access_permissions = relationship(
        "AccessPermission",
        foreign_keys="AccessPermission.family_member_id",
        back_populates="family_member",
    )
