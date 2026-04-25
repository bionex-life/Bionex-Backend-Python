"""
Sharing Model - Phase 5

Models for:
- Patient sharing requests to doctors
- Approval workflows
- Sharing history tracking
"""

from sqlalchemy import Column, String, DateTime, Enum, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import enum
import uuid

from app.database import Base


class SharingRequestStatus(str, enum.Enum):
    """Status of sharing request"""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class SharingRequest(Base):
    """Patient sharing requests to doctors"""

    __tablename__ = "sharing_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id = Column(String(36), ForeignKey("patients.id"), nullable=False, index=True)
    doctor_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    
    scope = Column(String(20), default="read")  # "read" or "read_write"
    status = Column(
        Enum(SharingRequestStatus),
        default=SharingRequestStatus.PENDING,
        nullable=False,
        index=True,
    )
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    approved_at = Column(DateTime, nullable=True)
    denied_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    
    # Metadata
    reason = Column(Text, nullable=True)
    denial_reason = Column(Text, nullable=True)
    revocation_reason = Column(Text, nullable=True)
    
    # Audit
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    def __repr__(self):
        return f"<SharingRequest {self.id} ({self.patient_id} → {self.doctor_id})>"

    def to_dict(self):
        return {
            "id": str(self.id),
            "patient_id": self.patient_id,
            "doctor_id": self.doctor_id,
            "scope": self.scope,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
