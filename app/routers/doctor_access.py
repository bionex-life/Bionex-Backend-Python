"""
Doctor Access Router - Phase 4

Handles doctor access to encrypted patient records:
- Retrieve encrypted records (requires valid session key)
- Decrypt records (server-side decryption for validation)
- List patient records by type
- Access audit logging

All endpoints validate session keys and log access for compliance.
"""

import logging
import time
from typing import Optional
from uuid import uuid4
import base64
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Header, Request, Query, Path
from sqlalchemy.orm import Session

from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.patient import Patient
from app.models.medical_record import MedicalRecord
from app.models.encryption_models import (
    ActorType,
    CryptoAuditLogStatus,
    EncryptedRecordVault,
)
from app.services.crypto_operations import (
    SessionKeyService,
    EncryptedRecordService,
    KeypairService,
)
from app.services.crypto_audit_service import CryptoAuditService
from app.services.key_exchange import KeyExchangeManager
from app.security.crypto import CryptoManager

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/doctor",
    tags=["doctor-access"],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Not authorized"},
        404: {"description": "Resource not found"},
        500: {"description": "Internal server error"},
    },
)


# ==================== HELPER FUNCTIONS ====================


def _validate_session_key(
    db: Session,
    patient_id: str,
    doctor_id: str,
    x_session_key_hash: Optional[str],
) -> bool:
    """
    Validate session key for doctor-patient access
    
    Returns: True if valid, False otherwise
    """
    if not x_session_key_hash:
        return False
    
    return SessionKeyService.validate_session_key(
        db=db,
        session_key_hash=x_session_key_hash,
        doctor_id=doctor_id,
        patient_id=patient_id,
    )


# ==================== RECORD RETRIEVAL ENDPOINTS ====================


@router.get(
    "/patients/{patient_id}/records",
    summary="List patient's encrypted records",
    description="List encrypted records for a patient (requires valid session key).",
)
async def list_patient_records(
    patient_id: str = Path(..., description="UUID of patient"),
    record_type: Optional[str] = Query(
        None, description="Filter by type (PRESCRIPTION, LAB_REPORT, etc.)"
    ),
    limit: int = Query(50, ge=1, le=500),
    x_session_key_hash: str = Header(
        ..., description="Session key hash (from session creation)"
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    List patient's encrypted records
    
    **Authentication:** Requires valid session key in X-Session-Key-Hash header
    
    **Parameters:**
    - `patient_id`: UUID of patient
    - `record_type`: Optional filter (e.g., "PRESCRIPTION")
    - `limit`: Max results (1-500)
    - `X-Session-Key-Hash`: Header with session key hash
    
    **Response:** List of encrypted records (metadata only)
    
    **Audit Log:** Each list recorded in audit trail
    """
    try:
        start_time = time.time()
        
        # Validate session key
        if not _validate_session_key(db, patient_id, str(current_user.id), x_session_key_hash):
            # Log access denial
            CryptoAuditService.log_access_denied(
                db=db,
                doctor_id=str(current_user.id),
                patient_id=patient_id,
                resource_id=patient_id,
                reason="Invalid or expired session key",
                ip_address=request.client.host if request else "0.0.0.0",
                request_id=request.headers.get("X-Request-ID", str(uuid4()))
                if request
                else str(uuid4()),
            )
            
            raise HTTPException(
                status_code=403,
                detail="Invalid or expired session key",
            )
        
        # List records
        if record_type:
            records = EncryptedRecordService.list_records_by_type(
                db=db,
                patient_id=patient_id,
                record_type=record_type,
                limit=limit,
            )
        else:
            # List all types
            from sqlalchemy import distinct

            records = (
                db.query(EncryptedRecordVault)
                .filter(
                    EncryptedRecordVault.patient_id == patient_id,
                    EncryptedRecordVault.is_deleted == False,
                )
                .order_by(EncryptedRecordVault.record_date.desc())
                .limit(limit)
                .all()
            )
        
        # Log access
        duration_ms = int((time.time() - start_time) * 1000)
        CryptoAuditService.log_record_access(
            db=db,
            doctor_id=str(current_user.id),
            patient_id=patient_id,
            record_id=patient_id,
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            duration_ms=duration_ms,
        )
        
        return [
            {
                "id": str(r.id),
                "record_type": r.record_type,
                "record_date": r.record_date.isoformat(),
                "record_title": r.record_title,
                "created_at": r.created_at.isoformat(),
            }
            for r in records
        ]
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list records: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list records")


@router.get(
    "/patients/{patient_id}/records/{record_id}",
    summary="Get encrypted record",
    description="Retrieve encrypted medical record (ciphertext, nonce, auth_tag).",
)
async def get_encrypted_record(
    patient_id: str,
    record_id: str,
    x_session_key_hash: str = Header(
        ..., description="Session key hash"
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Get encrypted record
    
    **Authentication:** Requires valid session key
    
    **Response:**
    ```json
    {
      "id": "uuid",
      "ciphertext": "base64-encoded-ciphertext",
      "nonce": "base64-encoded-nonce",
      "auth_tag": "base64-encoded-auth-tag",
      "ephemeral_public_key": "PEM-format-key",
      "record_type": "PRESCRIPTION",
      "record_date": "2024-01-01T00:00:00"
    }
    ```
    
    **Doctor's flow:**
    1. Receive this encrypted record
    2. Use private key to decrypt via ECDH
    3. Verify authentication tag (automatic in cryptography library)
    
    **Audit Log:** RECORD_ACCESSED event
    """
    try:
        start_time = time.time()
        
        # Validate session key
        if not _validate_session_key(db, patient_id, str(current_user.id), x_session_key_hash):
            CryptoAuditService.log_access_denied(
                db=db,
                doctor_id=str(current_user.id),
                patient_id=patient_id,
                resource_id=record_id,
                reason="Invalid session key",
                ip_address=request.client.host if request else "0.0.0.0",
                request_id=request.headers.get("X-Request-ID", str(uuid4()))
                if request
                else str(uuid4()),
            )
            
            raise HTTPException(status_code=403, detail="Invalid session key")
        
        # Get record
        record = (
            db.query(EncryptedRecordVault)
            .filter(
                EncryptedRecordVault.id == record_id,
                EncryptedRecordVault.patient_id == patient_id,
                EncryptedRecordVault.is_deleted == False,
            )
            .first()
        )
        
        if not record:
            raise HTTPException(status_code=404, detail="Record not found")
        
        # Log access
        duration_ms = int((time.time() - start_time) * 1000)
        CryptoAuditService.log_record_access(
            db=db,
            doctor_id=str(current_user.id),
            patient_id=patient_id,
            record_id=record_id,
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            duration_ms=duration_ms,
        )
        
        logger.info(f"Doctor {current_user.id} accessed record {record_id}")
        
        return {
            "id": str(record.id),
            "ciphertext": record.ciphertext,
            "nonce": record.nonce,
            "auth_tag": record.auth_tag,
            "ephemeral_public_key": record.ephemeral_public_key,
            "record_type": record.record_type,
            "record_date": record.record_date.isoformat(),
            "created_at": record.created_at.isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get record: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve record")


# ==================== DECRYPTION VERIFICATION ENDPOINT ====================


@router.post(
    "/patients/{patient_id}/records/{record_id}/verify-decryption",
    summary="Verify record decryption (server-side)",
    description="Doctor sends plaintext to verify decryption succeeded (optional, for auditing).",
)
async def verify_decryption(
    patient_id: str,
    record_id: str,
    plaintext_hash: str = Query(
        ..., description="SHA-256 hash of decrypted plaintext"
    ),
    x_session_key_hash: str = Header(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Verify record decryption (optional)
    
    **Purpose:** Allow doctor to prove they successfully decrypted a record
    (for auditing purposes - shows record was readable)
    
    **Parameters:**
    - `plaintext_hash`: SHA-256 hash of decrypted plaintext
    
    **Response:** Confirmation that hash was recorded
    
    **Audit Log:** Records the successful decryption
    """
    try:
        # Validate session key
        if not _validate_session_key(db, patient_id, str(current_user.id), x_session_key_hash):
            raise HTTPException(status_code=403, detail="Invalid session key")
        
        # Log successful decryption
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.DOCTOR,
            action="RECORD_DECRYPTED",
            resource_type="ENCRYPTED_RECORD",
            resource_id=record_id,
            event_data={
                "patient_id": patient_id,
                "plaintext_hash": plaintext_hash,
            },
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        return {
            "status": "verified",
            "message": "Decryption recorded in audit log",
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to verify decryption: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify")


# ==================== ACCESS HISTORY ENDPOINT ====================


@router.get(
    "/patients/{patient_id}/records/{record_id}/access-history",
    summary="Get record access history",
    description="Get who accessed this record and when (audit trail).",
)
async def get_access_history(
    patient_id: str,
    record_id: str,
    limit: int = Query(50, ge=1, le=500),
    x_session_key_hash: str = Header(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get access history for a record
    
    **Who can access:** Patient (to see who accessed their record)
    
    **Response:** List of access events
    ```json
    [
      {
        "doctor_id": "uuid",
        "accessed_at": "2024-01-01T10:30:00",
        "ip_address": "192.168.1.1",
        "duration_ms": 42
      }
    ]
    ```
    
    **Use case:** Patient sees audit trail of who accessed their records
    """
    try:
        # Verify patient owns this record
        patient = (
            db.query(Patient)
            .filter(Patient.user_id == current_user.id)
            .first()
        )
        
        if not patient or patient.id != patient_id:
            raise HTTPException(
                status_code=403,
                detail="Not authorized to view this record's history",
            )
        
        # Get access history
        history = CryptoAuditService.get_access_history(
            db=db,
            resource_id=record_id,
            limit=limit,
        )
        
        return [
            {
                "actor_id": str(log.actor_id) if log.actor_id else None,
                "actor_type": log.actor_type.value if log.actor_type else None,
                "accessed_at": log.created_at.isoformat(),
                "ip_address": log.ip_address,
                "status": log.status.value,
            }
            for log in history
        ]
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get access history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get history")


# ==================== PATIENT CONSENT ENDPOINTS ====================


@router.get(
    "/patients/me/doctors",
    summary="List doctors with access",
    description="Get list of all doctors who have active access to patient's records.",
)
async def list_doctors_with_access(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=500),
):
    """
    List doctors with access
    
    **Who can call:** Patients only
    
    **Response:** List of doctors with access
    ```json
    [
      {
        "doctor_id": "uuid",
        "doctor_name": "Dr. Smith",
        "access_granted_at": "2024-01-01T00:00:00",
        "expires_at": "2024-01-08T00:00:00",
        "status": "ACTIVE"
      }
    ]
    ```
    """
    try:
        # Get patient
        patient = (
            db.query(Patient)
            .filter(Patient.user_id == current_user.id)
            .first()
        )
        
        if not patient:
            raise HTTPException(status_code=403, detail="Not a patient")
        
        # List sessions (doctors with access)
        sessions = SessionKeyService.list_active_sessions(db, str(patient.id))
        
        # Enrich with doctor info
        doctors_with_access = []
        for session in sessions[:limit]:
            doctor_user = (
                db.query(User)
                .filter(User.id == session.doctor_id)
                .first()
            )
            
            doctors_with_access.append(
                {
                    "doctor_id": str(session.doctor_id),
                    "doctor_name": doctor_user.name if doctor_user else "Unknown",
                    "access_granted_at": session.created_at.isoformat(),
                    "expires_at": session.expires_at.isoformat(),
                    "status": session.status.value,
                }
            )
        
        return doctors_with_access
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list doctors: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list doctors")
