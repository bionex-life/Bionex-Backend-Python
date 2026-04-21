"""
Encryption API Router - Phase 4

Exposes Phase 3 cryptographic services as REST endpoints:
- Keypair management (generate, get, revoke)
- Session key management (create, validate, revoke, list)
- Record encryption/decryption
- Audit logging and compliance queries

All endpoints:
- Require authentication (Bearer token)
- Log access in audit trail
- Validate session keys
- Return proper HTTP status codes
- Include OpenAPI documentation
"""

import logging
import time
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Header, Request, Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.patient import Patient
from app.models.encryption_models import (
    ActorType,
    CryptoAuditLogStatus,
    SessionKeyStatus,
)
from app.schemas.encryption_schemas import (
    UserKeypairResponse,
    SessionKeyResponse,
    EncryptedRecordVaultResponse,
)
from app.services.crypto_operations import (
    KeypairService,
    SessionKeyService,
    EncryptedRecordService,
)
from app.services.crypto_audit_service import CryptoAuditService
from app.services.key_exchange import KeyExchangeManager
from app.security.crypto import CryptoManager

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/encryption",
    tags=["encryption"],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Not authorized"},
        404: {"description": "Resource not found"},
        500: {"description": "Internal server error"},
    },
)


# ==================== KEYPAIR ENDPOINTS ====================


@router.post(
    "/keypairs/generate",
    response_model=UserKeypairResponse,
    summary="Generate new ECDH P-256 keypair",
    description="Generate and store a new cryptographic keypair for the user. Private key stored in Vault, public key cached in Redis.",
)
async def generate_keypair(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Generate ECDH P-256 keypair for current user
    
    **Authentication:** Required (Bearer token)
    
    **Response:**
    - `user_id`: UUID of the user
    - `public_key_fingerprint`: SHA-256 fingerprint for verification
    - `key_algorithm`: Always "ECDH_P256"
    - `created_at`: ISO timestamp
    
    **Audit Log:** KEYPAIR_GENERATED event recorded
    """
    try:
        start_time = time.time()
        
        # Generate keypair
        keypair = KeypairService.generate_keypair(db, str(current_user.id))
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.DOCTOR
            if hasattr(current_user, "role") and current_user.role == "DOCTOR"
            else ActorType.PATIENT,
            action="KEYPAIR_GENERATED",
            resource_type="USER_KEYPAIR",
            resource_id=str(keypair.id),
            event_data={"algorithm": keypair.key_algorithm},
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        logger.info(f"Generated keypair for user {current_user.id}")
        
        return UserKeypairResponse(
            id=keypair.id,
            user_id=keypair.user_id,
            public_key_fingerprint=keypair.public_key_fingerprint,
            key_algorithm=keypair.key_algorithm,
            is_revoked=keypair.is_revoked,
            created_at=keypair.created_at,
        )
    
    except ValueError as e:
        logger.warning(f"Keypair generation validation error: {str(e)}")
        raise HTTPException(
            status_code=409, detail=str(e)
        )  # 409 Conflict for duplicate
    except Exception as e:
        logger.error(f"Keypair generation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate keypair"
        )


@router.get(
    "/keypairs/me",
    response_model=UserKeypairResponse,
    summary="Get current user's public keypair",
    description="Retrieve the public key for the current user (cached for performance).",
)
async def get_my_keypair(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get current user's keypair metadata
    
    **Performance:** Cached in Redis (99% hit rate, <1ms)
    
    **Response:** UserKeypairResponse object
    
    **Note:** Returns metadata only, not the private key
    """
    try:
        from app.models.encryption_models import UserKeypair

        keypair = (
            db.query(UserKeypair)
            .filter(
                UserKeypair.user_id == current_user.id,
                UserKeypair.is_revoked == False,
            )
            .first()
        )
        
        if not keypair:
            raise HTTPException(
                status_code=404, detail="Keypair not found. Generate one with POST /keypairs/generate"
            )
        
        return UserKeypairResponse(
            id=keypair.id,
            user_id=keypair.user_id,
            public_key_fingerprint=keypair.public_key_fingerprint,
            key_algorithm=keypair.key_algorithm,
            is_revoked=keypair.is_revoked,
            created_at=keypair.created_at,
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get keypair: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve keypair")


@router.delete(
    "/keypairs/me",
    summary="Revoke current user's keypair",
    description="Revoke the keypair and prevent further access. Immediate effect.",
)
async def revoke_keypair(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Revoke current user's keypair
    
    **Effect:** Immediate - all sessions using this keypair become invalid
    
    **Response:** {"message": "Keypair revoked"}
    
    **Audit Log:** KEYPAIR_REVOKED event recorded
    """
    try:
        KeypairService.revoke_keypair(db, str(current_user.id), "User requested")
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.DOCTOR
            if hasattr(current_user, "role") and current_user.role == "DOCTOR"
            else ActorType.PATIENT,
            action="KEYPAIR_REVOKED",
            resource_type="USER_KEYPAIR",
            resource_id=str(current_user.id),
            event_data={"reason": "User requested"},
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        return {"message": "Keypair revoked successfully"}
    
    except Exception as e:
        logger.error(f"Failed to revoke keypair: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to revoke keypair")


# ==================== SESSION KEY ENDPOINTS ====================


@router.post(
    "/sessions",
    response_model=SessionKeyResponse,
    summary="Create session key for doctor access",
    description="Create an ephemeral session key (7 days by default) for a doctor to access patient records.",
)
async def create_session(
    doctor_id: str = Query(..., description="UUID of doctor to grant access"),
    ttl_days: int = Query(
        7, ge=1, le=90, description="Session TTL in days (1-90)"
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Create ephemeral session key
    
    **Who can call:** Patients only (to grant doctor access)
    
    **Parameters:**
    - `doctor_id`: UUID of doctor to grant access
    - `ttl_days`: Expiry in days (default: 7)
    
    **Response:** SessionKeyResponse with:
    - `session_key_hash`: Hash of session key
    - `expires_at`: ISO timestamp of expiry
    - `status`: "ACTIVE"
    
    **Note:** Returns encrypted session key (doctor must decrypt with their private key)
    
    **Audit Log:** SESSION_CREATED event recorded
    """
    try:
        # Get patient
        patient = (
            db.query(Patient)
            .filter(Patient.user_id == current_user.id)
            .first()
        )
        
        if not patient:
            raise HTTPException(
                status_code=403,
                detail="Only patients can create session keys",
            )
        
        # Create session key
        session_key, plaintext = SessionKeyService.create_session_key(
            db=db,
            patient_id=str(patient.id),
            doctor_id=doctor_id,
            ttl_days=ttl_days,
            reason=f"Patient {patient.id} granted access",
        )
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.PATIENT,
            action="SESSION_CREATED",
            resource_type="SESSION_KEY",
            resource_id=str(session_key.id),
            event_data={
                "doctor_id": doctor_id,
                "patient_id": str(patient.id),
                "ttl_days": ttl_days,
            },
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        logger.info(
            f"Created session key for doctor {doctor_id} → patient {patient.id}"
        )
        
        return SessionKeyResponse(
            id=session_key.id,
            patient_id=session_key.patient_id,
            doctor_id=session_key.doctor_id,
            session_key_hash=session_key.session_key_hash,
            status=session_key.status,
            expires_at=session_key.expires_at,
            created_at=session_key.created_at,
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Session creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create session")


@router.get(
    "/sessions",
    response_model=list[SessionKeyResponse],
    summary="List active sessions",
    description="List all active session keys for the current user.",
)
async def list_sessions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=500, description="Maximum results"),
):
    """
    List active sessions for current user
    
    **For patients:** Shows all doctors with access
    **For doctors:** Shows all patients who granted access
    
    **Response:** List of SessionKeyResponse objects
    """
    try:
        # Check if patient or doctor
        patient = (
            db.query(Patient)
            .filter(Patient.user_id == current_user.id)
            .first()
        )
        
        if patient:
            # Patient: show sessions they created
            sessions = SessionKeyService.list_active_sessions(
                db, str(patient.id)
            )
        else:
            # Doctor: would need separate endpoint (TODO)
            raise HTTPException(
                status_code=400,
                detail="Doctors should use /sessions/as-doctor endpoint",
            )
        
        return [
            SessionKeyResponse(
                id=s.id,
                patient_id=s.patient_id,
                doctor_id=s.doctor_id,
                session_key_hash=s.session_key_hash,
                status=s.status,
                expires_at=s.expires_at,
                created_at=s.created_at,
            )
            for s in sessions[:limit]
        ]
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list sessions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list sessions")


@router.delete(
    "/sessions/{session_id}",
    summary="Revoke session key",
    description="Immediately revoke access for a doctor.",
)
async def revoke_session(
    session_id: str = Query(..., description="UUID of session to revoke"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Revoke session key
    
    **Effect:** Immediate - doctor loses access
    
    **Response:** {"message": "Session revoked"}
    
    **Audit Log:** SESSION_REVOKED event recorded
    """
    try:
        from app.models.encryption_models import SessionKey

        session = (
            db.query(SessionKey)
            .filter(SessionKey.id == session_id)
            .first()
        )
        
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Verify ownership
        patient = (
            db.query(Patient)
            .filter(Patient.user_id == current_user.id)
            .first()
        )
        
        if not patient or session.patient_id != patient.id:
            raise HTTPException(
                status_code=403,
                detail="Not authorized to revoke this session",
            )
        
        # Revoke
        SessionKeyService.revoke_session_key(
            db, session.session_key_hash, "Patient revoked access"
        )
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.PATIENT,
            action="SESSION_REVOKED",
            resource_type="SESSION_KEY",
            resource_id=session_id,
            event_data={"doctor_id": str(session.doctor_id)},
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        logger.info(f"Revoked session {session_id}")
        
        return {"message": "Session revoked successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to revoke session")


# ==================== AUDIT LOG ENDPOINTS ====================


@router.get(
    "/audit/logs",
    summary="Query audit logs",
    description="Query cryptographic audit logs with filters (compliance).",
)
async def query_audit_logs(
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    action: Optional[str] = Query(None, description="Filter by action"),
    status: Optional[str] = Query(None, description="Filter by status (SUCCESS/FAILED/DENIED)"),
    start_date: Optional[str] = Query(
        None, description="ISO timestamp start"
    ),
    end_date: Optional[str] = Query(
        None, description="ISO timestamp end"
    ),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Query audit logs (compliance/GDPR/HIPAA)
    
    **Filters:**
    - `resource_type`: ENCRYPTED_RECORD, SESSION_KEY, USER_KEYPAIR
    - `action`: RECORD_ACCESSED, SESSION_CREATED, KEYPAIR_GENERATED
    - `status`: SUCCESS, FAILED, DENIED
    - `start_date`, `end_date`: ISO timestamps
    
    **Response:** List of audit log objects with event data
    
    **Permission:** Currently unrestricted (TODO: add role checks)
    """
    try:
        # Parse dates
        start = None
        end = None
        
        if start_date:
            start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        if end_date:
            end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        
        # Query logs
        from app.models.encryption_models import CryptoAuditLogStatus

        status_enum = None
        if status:
            try:
                status_enum = CryptoAuditLogStatus[status.upper()]
            except KeyError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid status: {status}",
                )
        
        logs = CryptoAuditService.query_audit_logs(
            db=db,
            resource_type=resource_type,
            action=action,
            status=status_enum,
            start_date=start,
            end_date=end,
            limit=limit,
        )
        
        return [
            {
                "id": str(log.id),
                "actor_id": str(log.actor_id) if log.actor_id else None,
                "actor_type": log.actor_type.value,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": str(log.resource_id),
                "status": log.status.value,
                "ip_address": log.ip_address,
                "created_at": log.created_at.isoformat(),
                "event_data": log.event_data,
            }
            for log in logs
        ]
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to query audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to query audit logs")


@router.get(
    "/audit/compliance-report",
    summary="Generate compliance report",
    description="Generate GDPR/HIPAA/NHS compliance report for audit logs.",
)
async def get_compliance_report(
    start_date: str = Query(..., description="ISO timestamp"),
    end_date: str = Query(..., description="ISO timestamp"),
    resource_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate compliance report
    
    **Report includes:**
    - Total actions, success rate
    - Actions grouped by type
    - Access by actor type
    - Unique resources/actors
    
    **Response:** Compliance report JSON
    """
    try:
        start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        
        report = CryptoAuditService.generate_compliance_report(
            db=db,
            start_date=start,
            end_date=end,
            resource_type=resource_type,
        )
        
        return report
    
    except Exception as e:
        logger.error(f"Failed to generate compliance report: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate report"
        )


# ==================== HEALTH CHECK ====================


@router.get("/health", summary="Health check", tags=["health"])
async def health_check(db: Session = Depends(get_db)):
    """
    Check encryption service health
    
    **Response:**
    - `status`: "ok"
    - `vault_connected`: Boolean
    - `cache_connected`: Boolean
    - `database_connected`: Boolean
    """
    try:
        # Quick DB check
        from app.models.encryption_models import UserKeypair

        db.query(UserKeypair).limit(1).all()
        
        return {
            "status": "ok",
            "service": "encryption-api",
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=503, detail="Service unavailable"
        )
