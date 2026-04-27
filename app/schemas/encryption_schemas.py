"""
Phase 2: Encryption Infrastructure Pydantic Schemas

Validates input/output data for:
- User keypair management
- Session key creation and management
- Encrypted record operations
- Audit log queries

All schemas include:
- Comprehensive field validation
- Type hints and documentation
- Example data for API documentation
- Config for JSON schema generation
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from uuid import UUID
from enum import Enum

from pydantic import (
    BaseModel,
    Field,
    field_validator,
    ConfigDict,
)


# ────────────────────────────────────────────────────────────────
# USER KEYPAIR SCHEMAS
# ────────────────────────────────────────────────────────────────

class UserKeypairCreate(BaseModel):
    """Schema for creating a new user keypair"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKozIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
            "key_algorithm": "ECDH_P256"
        }
    })
    
    public_key_pem: str = Field(
        ...,
        description="PEM-encoded ECDH P-256 public key",
        min_length=100,
        max_length=2000
    )
    key_algorithm: str = Field(
        default="ECDH_P256",
        description="Key algorithm identifier",
        pattern="^[A-Z_]+$"
    )
    
    @field_validator("public_key_pem")
    @classmethod
    def validate_pem_format(cls, v: str) -> str:
        """Ensure PEM format with proper headers"""
        if not v.startswith("-----BEGIN PUBLIC KEY-----"):
            raise ValueError("Invalid PEM format: must start with '-----BEGIN PUBLIC KEY-----'")
        if not v.endswith("-----END PUBLIC KEY-----"):
            raise ValueError("Invalid PEM format: must end with '-----END PUBLIC KEY-----'")
        return v


class UserKeypairResponse(BaseModel):
    """Schema for user keypair response"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "user_id": "660e8400-e29b-41d4-a716-446655440000",
            "public_key_fingerprint": "a1b2c3d4e5f6...",
            "key_algorithm": "ECDH_P256",
            "created_at": "2026-04-21T12:00:00Z",
            "is_revoked": False
        }
    })
    
    id: UUID = Field(description="Keypair ID")
    user_id: UUID = Field(description="User ID")
    public_key_fingerprint: str = Field(
        description="SHA-256 fingerprint of public key",
        min_length=64,
        max_length=64
    )
    key_algorithm: str = Field(description="Key algorithm")
    created_at: datetime = Field(description="Creation timestamp")
    is_revoked: bool = Field(description="Whether key is revoked")


# ────────────────────────────────────────────────────────────────
# SESSION KEY SCHEMAS
# ────────────────────────────────────────────────────────────────

class SessionKeyStatus(str, Enum):
    """Status of session key"""
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class SessionKeyCreate(BaseModel):
    """Schema for creating a new session key"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "patient_id": "550e8400-e29b-41d4-a716-446655440000",
            "doctor_id": "660e8400-e29b-41d4-a716-446655440001",
            "encrypted_session_key": "base64_encoded_encrypted_key",
            "nonce": "12345678901234567890123",
            "auth_tag": "12345678901234567890123",
            "expires_at": "2026-04-28T12:00:00Z"
        }
    })
    
    patient_id: UUID = Field(description="Patient ID")
    doctor_id: UUID = Field(description="Doctor ID")
    encrypted_session_key: str = Field(
        description="Session key encrypted with doctor's public key (base64)",
        min_length=50,
        max_length=5000
    )
    nonce: str = Field(
        description="Nonce for AEAD decryption (base64)",
        min_length=16,
        max_length=32
    )
    auth_tag: str = Field(
        description="Authentication tag for AEAD verification (base64)",
        min_length=16,
        max_length=32
    )
    expires_at: datetime = Field(
        description="When session key expires (must be in future)"
    )
    
    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, v: datetime) -> datetime:
        """Ensure expiry is in the future"""
        if v <= datetime.now(timezone.utc):
            raise ValueError("Expiry must be in the future")
        return v


class SessionKeyResponse(BaseModel):
    """Schema for session key response"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "patient_id": "660e8400-e29b-41d4-a716-446655440000",
            "doctor_id": "770e8400-e29b-41d4-a716-446655440000",
            "session_key_hash": "a1b2c3d4e5f6...",
            "status": "ACTIVE",
            "expires_at": "2026-04-28T12:00:00Z",
            "created_at": "2026-04-21T12:00:00Z"
        }
    })
    
    id: UUID = Field(description="Session key ID")
    patient_id: UUID = Field(description="Patient ID")
    doctor_id: UUID = Field(description="Doctor ID")
    session_key_hash: str = Field(
        description="SHA-256 hash of session key",
        min_length=64,
        max_length=64
    )
    status: SessionKeyStatus = Field(description="Session key status")
    expires_at: datetime = Field(description="Expiration timestamp")
    created_at: datetime = Field(description="Creation timestamp")


class SessionKeyRevoke(BaseModel):
    """Schema for revoking a session key"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "revocation_reason": "Doctor no longer has access to patient records"
        }
    })
    
    revocation_reason: str = Field(
        description="Reason for revocation",
        min_length=5,
        max_length=255
    )


# ────────────────────────────────────────────────────────────────
# ENCRYPTED RECORD VAULT SCHEMAS
# ────────────────────────────────────────────────────────────────

class EncryptedRecordVaultCreate(BaseModel):
    """Schema for creating encrypted record vault"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "patient_id": "550e8400-e29b-41d4-a716-446655440000",
            "original_record_id": "660e8400-e29b-41d4-a716-446655440000",
            "ciphertext": "base64_encrypted_content",
            "nonce": "12345678901234567890123",
            "auth_tag": "12345678901234567890123",
            "record_type": "PRESCRIPTION",
            "record_date": "2026-04-21T10:00:00Z",
            "record_title": "Aspirin 500mg",
            "record_title_hash": "a1b2c3d4e5f6..."
        }
    })
    
    patient_id: UUID = Field(description="Patient ID")
    original_record_id: UUID = Field(description="Original medical record ID")
    ciphertext: str = Field(
        description="Encrypted record content (base64)",
        min_length=50,
        max_length=100000
    )
    nonce: str = Field(
        description="Nonce for decryption (base64)",
        min_length=16,
        max_length=32
    )
    auth_tag: str = Field(
        description="Authentication tag (base64)",
        min_length=16,
        max_length=32
    )
    record_type: str = Field(
        description="Type of record",
        pattern="^[A-Z_]+$",
        min_length=3,
        max_length=50
    )
    record_date: datetime = Field(description="Date of record")
    record_title: Optional[str] = Field(
        default=None,
        description="Record title (searchable)",
        max_length=255
    )
    record_title_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of title (for searching)",
        min_length=64,
        max_length=64
    )


class EncryptedRecordVaultResponse(BaseModel):
    """Schema for encrypted record vault response"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "patient_id": "660e8400-e29b-41d4-a716-446655440000",
            "record_type": "PRESCRIPTION",
            "record_date": "2026-04-21T10:00:00Z",
            "record_title": "Aspirin 500mg",
            "created_at": "2026-04-21T12:00:00Z",
            "is_deleted": False
        }
    })
    
    id: UUID = Field(description="Vault ID")
    patient_id: UUID = Field(description="Patient ID")
    record_type: str = Field(description="Record type")
    record_date: datetime = Field(description="Date of record")
    record_title: Optional[str] = Field(description="Record title")
    created_at: datetime = Field(description="Creation timestamp")
    is_deleted: bool = Field(description="Whether record is deleted")


# ────────────────────────────────────────────────────────────────
# AUDIT LOG SCHEMAS
# ────────────────────────────────────────────────────────────────

class CryptoAuditLogStatus(str, Enum):
    """Status of audit log entry"""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    DENIED = "DENIED"


class ActorType(str, Enum):
    """Type of actor"""
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"
    ADMIN = "ADMIN"
    SYSTEM = "SYSTEM"


class CryptographicAuditLogCreate(BaseModel):
    """Schema for creating audit log entry"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "actor_id": "550e8400-e29b-41d4-a716-446655440000",
            "actor_type": "DOCTOR",
            "action": "RECORD_ACCESSED",
            "resource_type": "MEDICAL_RECORD",
            "resource_id": "660e8400-e29b-41d4-a716-446655440000",
            "event_data": {"operation": "read", "duration_ms": 45},
            "signature": "base64_ecdsa_signature",
            "ip_address": "203.0.113.45",
            "request_id": "req-abc123"
        }
    })
    
    actor_id: Optional[UUID] = Field(default=None, description="Actor ID (None for SYSTEM)")
    actor_type: ActorType = Field(description="Type of actor")
    action: str = Field(
        description="Action performed",
        pattern="^[A-Z_]+$",
        min_length=3,
        max_length=50
    )
    resource_type: str = Field(
        description="Type of resource",
        pattern="^[A-Z_]+$",
        min_length=3,
        max_length=50
    )
    resource_id: UUID = Field(description="Resource ID")
    event_data: Dict[str, Any] = Field(
        description="Event details (flexible JSON)"
    )
    signature: str = Field(
        description="ECDSA-SHA256 signature (base64)",
        min_length=50,
        max_length=500
    )
    ip_address: str = Field(
        description="IP address (IPv4 or IPv6)",
        min_length=7,
        max_length=45
    )
    request_id: str = Field(
        description="Request ID for tracing",
        min_length=1,
        max_length=50
    )
    status: CryptoAuditLogStatus = Field(
        default=CryptoAuditLogStatus.SUCCESS,
        description="Operation status"
    )
    status_message: Optional[str] = Field(
        default=None,
        description="Error message if failed",
        max_length=500
    )


class CryptographicAuditLogResponse(BaseModel):
    """Schema for audit log response"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "actor_type": "DOCTOR",
            "action": "RECORD_ACCESSED",
            "resource_type": "MEDICAL_RECORD",
            "status": "SUCCESS",
            "created_at": "2026-04-21T12:00:00Z"
        }
    })
    
    id: UUID = Field(description="Log entry ID")
    actor_type: ActorType = Field(description="Type of actor")
    action: str = Field(description="Action performed")
    resource_type: str = Field(description="Resource type")
    status: CryptoAuditLogStatus = Field(description="Status")
    created_at: datetime = Field(description="Creation timestamp")


# ────────────────────────────────────────────────────────────────
# QUERY/FILTER SCHEMAS
# ────────────────────────────────────────────────────────────────

class AuditLogFilter(BaseModel):
    """Filter schema for querying audit logs"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "actor_type": "DOCTOR",
            "action": "RECORD_ACCESSED",
            "resource_type": "MEDICAL_RECORD",
            "start_date": "2026-04-01T00:00:00Z",
            "end_date": "2026-04-30T23:59:59Z",
            "limit": 100
        }
    })
    
    actor_type: Optional[ActorType] = Field(default=None)
    action: Optional[str] = Field(default=None, max_length=50)
    resource_type: Optional[str] = Field(default=None, max_length=50)
    status: Optional[CryptoAuditLogStatus] = Field(default=None)
    start_date: Optional[datetime] = Field(default=None)
    end_date: Optional[datetime] = Field(default=None)
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class SessionKeyFilter(BaseModel):
    """Filter schema for querying session keys"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "patient_id": "550e8400-e29b-41d4-a716-446655440000",
            "doctor_id": "660e8400-e29b-41d4-a716-446655440000",
            "status": "ACTIVE",
            "limit": 50
        }
    })
    
    patient_id: Optional[UUID] = Field(default=None)
    doctor_id: Optional[UUID] = Field(default=None)
    status: Optional[SessionKeyStatus] = Field(default=None)
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


# ────────────────────────────────────────────────────────────────
# BULK OPERATION SCHEMAS
# ────────────────────────────────────────────────────────────────

class BulkSessionKeyRevoke(BaseModel):
    """Revoke multiple session keys at once"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "session_key_ids": [
                "550e8400-e29b-41d4-a716-446655440000",
                "660e8400-e29b-41d4-a716-446655440000"
            ],
            "revocation_reason": "Doctor left clinic"
        }
    })
    
    session_key_ids: List[UUID] = Field(
        description="List of session key IDs to revoke",
        min_items=1,
        max_items=100
    )
    revocation_reason: str = Field(
        description="Reason for bulk revocation",
        min_length=5,
        max_length=255
    )


class HealthCheckResponse(BaseModel):
    """Response for health checks"""
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "status": "healthy",
            "timestamp": "2026-04-21T12:00:00Z",
            "databases": {
                "postgresql": "connected",
                "redis": "connected",
                "vault": "connected"
            }
        }
    })
    
    status: str = Field(description="Overall health status")
    timestamp: datetime = Field(description="Check timestamp")
    databases: Dict[str, str] = Field(description="Database connection statuses")
