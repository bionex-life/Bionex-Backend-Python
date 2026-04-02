import enum
import uuid

from sqlalchemy import Column, DateTime, Enum as SAEnum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class InitiatedBy(str, enum.Enum):
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"


class RequestStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class AccessPermission(Base, TimestampMixin):
    __tablename__ = "access_permissions"

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
    granted_to_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    initiated_by = Column(SAEnum(InitiatedBy), nullable=False)
    request_status = Column(
        SAEnum(RequestStatus), nullable=False, default=RequestStatus.PENDING
    )
    # Secure random token generated on approval; NULL until approved
    access_token = Column(String(500), unique=True, nullable=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    # Comma-separated scopes: "records,medications"
    scope = Column(String(500), nullable=True, default="records")

    # Relationships
    patient = relationship("Patient", back_populates="access_permissions")
    family_member = relationship("FamilyMember", back_populates="access_permissions")
    granted_to = relationship(
        "User",
        foreign_keys=[granted_to_user_id],
        back_populates="received_permissions",
    )
    doctor_access_log = relationship(
        "DoctorAccessLog", back_populates="access_permission", uselist=False
    )
