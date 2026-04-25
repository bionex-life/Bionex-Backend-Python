"""
Compliance Models - Phase 6

Models for:
- GDPR data exports
- Compliance reports
- Retention policies
- Audit verification records
"""

from sqlalchemy import Column, String, DateTime, Text, Boolean, Integer, LargeBinary, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, JSON
from datetime import datetime
import enum
import uuid

from app.database import Base
from app.models.base import TimestampMixin


class ComplianceExportStatus(str, enum.Enum):
    """Status of compliance export"""
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class ComplianceExportType(str, enum.Enum):
    """Type of compliance export"""
    GDPR_SAR = "GDPR_SAR"  # Subject Access Request
    GDPR_PORTABILITY = "GDPR_PORTABILITY"  # Data Portability
    AUDIT_REPORT = "AUDIT_REPORT"
    COMPLIANCE_REPORT = "COMPLIANCE_REPORT"


class ComplianceExport(Base):
    """GDPR & compliance data exports"""

    __tablename__ = "compliance_exports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    export_type = Column(
        String(50),
        nullable=False,
        index=True,
    )
    status = Column(
        String(20),
        default=ComplianceExportStatus.PENDING,
        nullable=False,
        index=True,
    )
    
    # Export metadata
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    
    # Data
    file_path = Column(String(500), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    file_hash = Column(String(128), nullable=True)
    
    # GDPR compliance
    is_encrypted = Column(Boolean, default=True)
    encryption_key_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Metadata
    record_count = Column(Integer, default=0)
    includes_audit = Column(Boolean, default=True)
    includes_records = Column(Boolean, default=True)
    export_metadata = Column(JSON, nullable=True)
    
    def __repr__(self):
        return f"<ComplianceExport {self.id} ({self.export_type})>"


class AuditLogVerification(Base):
    """Signature verification records for audit logs"""

    __tablename__ = "audit_log_verifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_log_id = Column(UUID(as_uuid=True), ForeignKey("cryptographic_audit_logs.id"), nullable=False, index=True)
    
    # Verification data
    signature_valid = Column(Boolean, nullable=False)
    verified_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    verified_by = Column(String(100), nullable=False)  # "system", "audit_service", etc.
    
    # Verification details
    public_key_used = Column(String(500), nullable=False)
    verification_algorithm = Column(String(50), default="ECDSA-SHA256")
    
    # If invalid, why?
    invalid_reason = Column(String(500), nullable=True)
    
    def __repr__(self):
        return f"<AuditLogVerification {self.id} (valid={self.signature_valid})>"


class RetentionPolicy(Base):
    """Data retention policy configuration"""

    __tablename__ = "retention_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Policy scope
    resource_type = Column(String(100), nullable=False, index=True)  # e.g., "audit_logs", "medical_records"
    jurisdiction = Column(String(50), default="UK", nullable=False)
    
    # Retention rules
    retention_years = Column(Integer, nullable=False)  # e.g., 7 for UK audit logs
    is_active = Column(Boolean, default=True, index=True)
    
    # Dates
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Policy details
    policy_description = Column(Text, nullable=True)
    requires_immutability = Column(Boolean, default=True)
    
    def __repr__(self):
        return f"<RetentionPolicy {self.resource_type} ({self.retention_years}yr)>"
