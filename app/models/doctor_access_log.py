import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class DoctorAccessLog(Base, TimestampMixin):
    """Records every doctor session opened via a sharing token."""

    __tablename__ = "doctor_access_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    doctor_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    patient_id = Column(
        UUID(as_uuid=True),
        ForeignKey("patients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    access_permission_id = Column(
        UUID(as_uuid=True),
        ForeignKey("access_permissions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    session_start = Column(DateTime(timezone=True), nullable=False)
    session_end = Column(DateTime(timezone=True), nullable=True)
    # JSON list of record IDs accessed during session
    records_accessed = Column(Text, nullable=True)

    # Relationships
    doctor = relationship(
        "User", foreign_keys=[doctor_user_id], back_populates="doctor_access_logs"
    )
    patient = relationship(
        "Patient", foreign_keys=[patient_id], back_populates="doctor_access_logs"
    )
    access_permission = relationship(
        "AccessPermission", back_populates="doctor_access_log"
    )
