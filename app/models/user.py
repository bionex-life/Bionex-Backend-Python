import enum
import uuid

from sqlalchemy import Boolean, Column, Enum as SAEnum, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class UserRole(str, enum.Enum):
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"
    ADMIN = "ADMIN"


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String(255), nullable=False)
    phone = Column(String(20), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), nullable=False, default=UserRole.PATIENT)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    patient = relationship(
        "Patient", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    payments = relationship("Payment", back_populates="user")
    received_permissions = relationship(
        "AccessPermission",
        foreign_keys="AccessPermission.granted_to_user_id",
        back_populates="granted_to",
    )
    doctor_access_logs = relationship(
        "DoctorAccessLog",
        foreign_keys="DoctorAccessLog.doctor_user_id",
        back_populates="doctor",
    )
    audit_logs = relationship("AuditLog", back_populates="user")
