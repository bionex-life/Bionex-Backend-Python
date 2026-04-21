"""
Phase 2: Encryption Infrastructure Models

Stores cryptographic keys, session keys, and audit trails for end-to-end encryption.
All models follow production-ready patterns:
- Proper type hints and enums
- Comprehensive indexes for query performance
- JSONB for flexible event data
- Immutable audit logs with signatures
- Soft deletes where applicable
"""

import enum
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    String,
    Text,
    Boolean,
    func,
    ForeignKey,
    Enum as SAEnum,
    Index,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.models.base import TimestampMixin, Base


# ────────────────────────────────────────────────────────────────
# ENUMS
# ────────────────────────────────────────────────────────────────

class SessionKeyStatus(str, enum.Enum):
    """Lifecycle status of a session key"""
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class KeyRotationStatus(str, enum.Enum):
    """Status of key rotation operation"""
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class CryptoAuditLogStatus(str, enum.Enum):
    """Status of cryptographic operation (audit log)"""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    DENIED = "DENIED"


class ActorType(str, enum.Enum):
    """Type of actor performing cryptographic operation"""
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"
    ADMIN = "ADMIN"
    SYSTEM = "SYSTEM"


# ────────────────────────────────────────────────────────────────
# USER KEYPAIRS - Stores ECDH P-256 public keys
# ────────────────────────────────────────────────────────────────

class UserKeypair(Base, TimestampMixin):
    """
    Stores ECDH P-256 public keys for users.
    
    Private keys are NEVER stored in database - kept in HashiCorp Vault.
    Public keys are cached in Redis for fast lookups.
    
    Attributes:
        user_id: Reference to user
        public_key_pem: PEM-encoded ECDH P-256 public key
        public_key_fingerprint: SHA-256 hash of public key (unique index)
        key_algorithm: Algorithm identifier (e.g., 'ECDH_P256')
        is_revoked: Soft-delete flag for revoked keys
    """
    __tablename__ = "user_keypairs"

    # Primary Key
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # Foreign Keys
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # One keypair per user
        index=True,
    )

    # Key Material (Public Key Only)
    public_key_pem = Column(Text, nullable=False)
    public_key_fingerprint = Column(
        String(64),
        nullable=False,
        unique=True,
        index=True,  # For lookups by fingerprint
    )

    # Metadata
    key_algorithm = Column(
        String(50),
        default="ECDH_P256",
        nullable=False,
    )

    # Key Lifecycle
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    rotated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Revocation
    is_revoked = Column(Boolean, default=False, nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(255), nullable=True)

    # Relationships
    user = relationship("User", back_populates="keypair", foreign_keys=[user_id])
    session_keys_created = relationship(
        "SessionKey",
        foreign_keys="SessionKey.doctor_id",
        back_populates="doctor",
    )

    __table_args__ = (
        Index("ix_user_keypairs_user_active", "user_id", "is_revoked"),
        Index("ix_user_keypairs_created", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<UserKeypair(user_id={self.user_id}, fingerprint={self.public_key_fingerprint[:8]}...)>"


# ────────────────────────────────────────────────────────────────
# SESSION KEYS - Ephemeral keys for doctor-patient access
# ────────────────────────────────────────────────────────────────

class SessionKey(Base, TimestampMixin):
    """
    Stores ephemeral session keys for doctor-patient data sharing.
    
    Session keys are used for hybrid encryption:
    1. Doctor gets session key encrypted with their public key
    2. Medical records encrypted with session key
    3. Access can be revoked by deleting session key
    
    Key Security:
    - Session key hash stored (for validation)
    - Encrypted session key stored (decrypt requires doctor's private key)
    - Never store plaintext session key in DB
    - Auto-expire after TTL
    
    Attributes:
        patient_id: Patient owning the data
        doctor_id: Doctor granted access
        session_key_hash: SHA-256 hash (unique, indexed for fast lookup)
        encrypted_session_key: Encrypted with doctor's public key
        expires_at: Session key expiry (auto-invalidate)
    """
    __tablename__ = "session_keys"

    # Primary Key
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # Foreign Keys
    patient_id = Column(
        UUID(as_uuid=True),
        ForeignKey("patients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    doctor_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Session Key Material (NEVER plaintext)
    session_key_hash = Column(
        String(64),
        nullable=False,
        unique=True,
        index=True,  # Fast validation
    )
    encrypted_session_key = Column(Text, nullable=False)  # Encrypted with doctor's public key
    nonce = Column(String(32), nullable=False)  # For AEAD decryption
    auth_tag = Column(String(32), nullable=False)  # For AEAD authentication

    # Session State
    status = Column(
        SAEnum(SessionKeyStatus),
        default=SessionKeyStatus.ACTIVE,
        nullable=False,
        index=True,
    )
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,  # For automatic expiration queries
    )

    # Lifecycle
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(255), nullable=True)

    # Relationships
    patient = relationship("Patient", back_populates="session_keys", foreign_keys=[patient_id])
    doctor = relationship("User", foreign_keys=[doctor_id])

    __table_args__ = (
        UniqueConstraint("patient_id", "doctor_id", "session_key_hash", name="uq_session_per_doctor"),
        Index("ix_session_keys_active", "status", "expires_at"),
        Index("ix_session_keys_patient_doctor", "patient_id", "doctor_id"),
    )

    def is_valid(self) -> bool:
        """Check if session key is still valid (not expired/revoked)"""
        return (
            self.status == SessionKeyStatus.ACTIVE
            and self.expires_at > datetime.now(timezone.utc)
        )

    def __repr__(self) -> str:
        return f"<SessionKey(patient={self.patient_id}, doctor={self.doctor_id}, status={self.status})>"


# ────────────────────────────────────────────────────────────────
# ENCRYPTED RECORD VAULTS - Server-side encrypted medical records
# ────────────────────────────────────────────────────────────────

class EncryptedRecordVault(Base, TimestampMixin):
    """
    Server-side encrypted copies of medical records.
    
    Hybrid encryption model:
    1. Each patient has session keys with each doctor
    2. Medical records are encrypted with session key
    3. Encrypted blobs stored in vault
    4. Only doctors with session keys can decrypt
    
    Searchability:
    - record_type, record_date, record_title_hash are indexed (not encrypted)
    - Enables filtering without decryption
    - Supports audit compliance (find records by date range, type)
    
    Attributes:
        patient_id: Owner of encrypted data
        original_record_id: Reference to plaintext record
        ciphertext: ChaCha20-Poly1305 encrypted content
        record_type: Type (PRESCRIPTION, LAB_REPORT, etc) - NOT encrypted
        record_date: Date of record - NOT encrypted
        record_title_hash: Searchable title hash - NOT encrypted
    """
    __tablename__ = "encrypted_record_vaults"

    # Primary Key
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # Foreign Keys
    patient_id = Column(
        UUID(as_uuid=True),
        ForeignKey("patients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_record_id = Column(
        UUID(as_uuid=True),
        ForeignKey("medical_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Encrypted Content (ChaCha20-Poly1305 AEAD)
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String(32), nullable=False)
    auth_tag = Column(String(32), nullable=False)

    # Searchable Metadata (NOT encrypted)
    record_type = Column(
        String(50),
        nullable=False,
        index=True,  # e.g., PRESCRIPTION, LAB_REPORT, SCAN
    )
    record_date = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,  # Enable date-range queries
    )
    record_title = Column(String(255), nullable=True)
    record_title_hash = Column(
        String(64),
        nullable=True,
        index=True,  # For title search without decryption
    )

    # Encryption Details
    encryption_algorithm = Column(
        String(50),
        default="CHACHA20_POLY1305",
        nullable=False,
    )

    # Lifecycle
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Soft Delete
    is_deleted = Column(Boolean, default=False, nullable=False, index=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    patient = relationship("Patient", foreign_keys=[patient_id])
    medical_record = relationship("MedicalRecord", foreign_keys=[original_record_id])

    __table_args__ = (
        Index("ix_encrypted_vaults_type_date", "record_type", "record_date"),
        Index("ix_encrypted_vaults_active", "is_deleted", "patient_id"),
        Index("ix_encrypted_vaults_patient_type", "patient_id", "record_type"),
    )

    def __repr__(self) -> str:
        return f"<EncryptedRecordVault(patient={self.patient_id}, type={self.record_type}, deleted={self.is_deleted})>"


# ────────────────────────────────────────────────────────────────
# CRYPTOGRAPHIC AUDIT LOGS - Immutable audit trail
# ────────────────────────────────────────────────────────────────

class CryptographicAuditLog(Base):
    """
    Immutable, tamper-evident audit log for all cryptographic operations.
    
    This log is designed for compliance (GDPR, HIPAA, NHS):
    - Every data access is logged
    - Digital signatures prevent tampering
    - JSONB for flexible event data
    - Structured queries by action, resource, actor
    
    Immutability:
    - No UPDATE or DELETE operations on this table
    - New operations create new rows only
    - Signature is cryptographic proof
    
    Attributes:
        actor_id: User performing the action
        action: Action type (RECORD_ACCESSED, SESSION_CREATED, etc.)
        resource_type: What was accessed (MEDICAL_RECORD, SESSION_KEY)
        resource_id: ID of the resource
        event_data: Flexible JSON with operation details
        signature: ECDSA-SHA256 signature (immutability proof)
    """
    __tablename__ = "cryptographic_audit_logs"

    # Primary Key
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # Actor Information
    actor_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_type = Column(
        SAEnum(ActorType),
        nullable=False,
        index=True,
    )

    # Action Details
    action = Column(
        String(50),
        nullable=False,
        index=True,  # RECORD_ACCESSED, SESSION_CREATED, KEY_ROTATED
    )
    resource_type = Column(
        String(50),
        nullable=False,
        index=True,  # MEDICAL_RECORD, SESSION_KEY, USER_KEYPAIR
    )
    resource_id = Column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    # Event Data (Flexible Schema)
    event_data = Column(JSONB(), nullable=False)  # operation: str, details: dict, etc.

    # Digital Signature (Tamper Detection)
    signature = Column(Text, nullable=False)  # ECDSA-SHA256 signature
    signature_timestamp = Column(DateTime(timezone=True), nullable=False)

    # Request Metadata (for tracing)
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    user_agent = Column(String(255), nullable=True)
    request_id = Column(String(50), nullable=False, index=True)  # X-Request-ID for tracing

    # Operation Result
    status = Column(
        SAEnum(CryptoAuditLogStatus),
        default=CryptoAuditLogStatus.SUCCESS,
        nullable=False,
        index=True,
    )
    status_message = Column(Text, nullable=True)

    # Immutable Timestamp
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # Relationships
    actor = relationship("User", foreign_keys=[actor_id])

    __table_args__ = (
        Index("ix_audit_logs_action_status", "action", "status"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_actor", "actor_id", "actor_type"),
        Index("ix_audit_logs_created", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<CryptographicAuditLog(action={self.action}, resource={self.resource_type}, status={self.status})>"


# ────────────────────────────────────────────────────────────────
# KEY ROTATION HISTORY - Track key rotation operations
# ────────────────────────────────────────────────────────────────

class KeyRotationHistory(Base):
    """
    Tracks key rotation operations for compliance and debugging.
    
    Key Rotation Process:
    1. New key generated and stored in Vault
    2. Old key marked as rotated
    3. Session keys re-encrypted with new key
    4. Operation recorded in this table
    
    Attributes:
        user_id: User whose key was rotated
        old_key_fingerprint: SHA-256 hash of old public key
        new_key_fingerprint: SHA-256 hash of new public key
        status: PENDING, COMPLETED, or FAILED
        error_message: If status is FAILED, reason why
    """
    __tablename__ = "key_rotation_history"

    # Primary Key
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # Foreign Key
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Key Information
    old_key_fingerprint = Column(String(64), nullable=False)
    new_key_fingerprint = Column(String(64), nullable=False)
    rotation_reason = Column(
        String(255),
        nullable=False,  # SCHEDULED, SECURITY_INCIDENT, USER_REQUEST, etc.
    )

    # Rotation Status
    status = Column(
        SAEnum(KeyRotationStatus),
        default=KeyRotationStatus.PENDING,
        nullable=False,
        index=True,
    )
    error_message = Column(Text, nullable=True)  # If FAILED, why

    # Timestamps
    rotated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])

    __table_args__ = (
        Index("ix_rotation_history_status", "user_id", "status"),
        Index("ix_rotation_history_created", "rotated_at"),
    )

    def __repr__(self) -> str:
        return f"<KeyRotationHistory(user={self.user_id}, status={self.status})>"
