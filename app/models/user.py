import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum as SAEnum, Integer, String
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
    
    # ── Account Lockout (Phase 2 Security)
    is_locked = Column(Boolean, default=False, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    last_failed_login = Column(DateTime, nullable=True)
    last_password_change = Column(DateTime, nullable=True)
    password_expires_at = Column(DateTime, nullable=True)  # For password expiry policy
    
    # ── 2FA Enabled Flag
    is_2fa_enabled = Column(Boolean, default=False, nullable=False)

    # ── Email Verification (Brevo)
    is_email_verified = Column(Boolean, default=False, nullable=False)
    email_verify_token = Column(String(255), nullable=True)
    email_verify_token_expires = Column(DateTime, nullable=True)

    # ── OTP Verification (Twilio SMS + Email)
    otp_code = Column(String(6), nullable=True)
    otp_expires_at = Column(DateTime, nullable=True)
    otp_verified = Column(Boolean, default=False, nullable=False)

    # Relationships
    patient = relationship(
        "Patient", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    payments = relationship("Payment", back_populates="user")
    documents = relationship("Document", back_populates="owner")
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
