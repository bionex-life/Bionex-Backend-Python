"""
Phase 5: Access Control & Session Management

Implements:
- Sharing workflows (patient grants/revokes doctor access)
- Session key rotation (automatic daily rotation)
- Permission scopes (read, read-write)
- Access approval workflows
- Token-based sharing links
"""

import logging
from typing import Optional, List
from uuid import uuid4
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.patient import Patient
from app.models.encryption_models import (
    SessionKey,
    SessionKeyStatus,
    ActorType,
    CryptoAuditLogStatus,
)
from app.services.access_control_service import AccessControlService
from app.services.sharing_service import SharingService
from app.services.session_rotation_service import SessionRotationService
from app.services.crypto_audit_service import CryptoAuditService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/access",
    tags=["access-control"],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Not authorized"},
        404: {"description": "Resource not found"},
        500: {"description": "Internal server error"},
    },
)


# ==================== SHARING REQUEST ENDPOINTS ====================


@router.post(
    "/sharing/request",
    summary="Create sharing request",
    description="Patient creates sharing request for doctor to access records.",
    status_code=201,
)
async def create_sharing_request(
    doctor_id: str = Query(..., description="UUID of doctor"),
    scope: str = Query("read", regex="^(read|read_write)$"),
    expires_in_days: int = Query(7, ge=1, le=365),
    reason: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Patient creates sharing request for doctor access
    
    **Parameters:**
    - `doctor_id`: UUID of doctor to share with
    - `scope`: "read" (view only) or "read_write" (modify allowed)
    - `expires_in_days`: Days until access expires
    - `reason`: Optional reason for audit trail
    
    **Response:**
    ```json
    {
      "request_id": "uuid",
      "doctor_id": "uuid",
      "status": "PENDING",
      "scope": "read",
      "expires_at": "2024-01-08T00:00:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
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
        
        # Create sharing request
        request_obj = SharingService.create_sharing_request(
            db=db,
            patient_id=str(patient.id),
            doctor_id=doctor_id,
            scope=scope,
            expires_in_days=expires_in_days,
            reason=reason,
        )
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.PATIENT,
            action="SHARING_REQUEST_CREATED",
            resource_type="SHARING_REQUEST",
            resource_id=str(request_obj.id),
            event_data={
                "doctor_id": doctor_id,
                "scope": scope,
                "expires_in_days": expires_in_days,
            },
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        return {
            "request_id": str(request_obj.id),
            "doctor_id": str(request_obj.doctor_id),
            "status": "PENDING",
            "scope": request_obj.scope,
            "expires_at": request_obj.expires_at.isoformat(),
            "created_at": request_obj.created_at.isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create sharing request: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create request")


@router.get(
    "/sharing/requests",
    summary="List sharing requests",
    description="List pending/approved sharing requests (patient view).",
)
async def list_sharing_requests(
    status: Optional[str] = Query(None, regex="^(PENDING|APPROVED|DENIED)$"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List sharing requests for authenticated user
    
    **For Patients:** Shows requests they created
    **For Doctors:** Shows requests sent to them
    
    **Query Parameters:**
    - `status`: Filter by PENDING, APPROVED, or DENIED
    - `limit`: Max results
    
    **Response:** List of sharing requests with status
    """
    try:
        patient = (
            db.query(Patient)
            .filter(Patient.user_id == current_user.id)
            .first()
        )
        
        if patient:
            # Patient: show requests they created
            requests_list = SharingService.get_patient_sharing_requests(
                db, str(patient.id), status, limit
            )
        else:
            # Doctor: show requests sent to them
            requests_list = SharingService.get_doctor_sharing_requests(
                db, str(current_user.id), status, limit
            )
        
        return [
            {
                "request_id": str(r.id),
                "patient_id": str(r.patient_id),
                "doctor_id": str(r.doctor_id),
                "status": r.status,
                "scope": r.scope,
                "created_at": r.created_at.isoformat(),
                "expires_at": r.expires_at.isoformat(),
            }
            for r in requests_list
        ]
    
    except Exception as e:
        logger.error(f"Failed to list sharing requests: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list requests")


@router.post(
    "/sharing/requests/{request_id}/approve",
    summary="Approve sharing request",
    description="Doctor approves patient's sharing request.",
)
async def approve_sharing_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Doctor approves sharing request
    
    **Effect:**
    - Creates active session key with specified scope
    - Patient can now revoke anytime
    - Logged in audit trail
    
    **Response:**
    ```json
    {
      "request_id": "uuid",
      "status": "APPROVED",
      "session_key_created": true,
      "approved_at": "2024-01-01T10:00:00Z"
    }
    ```
    """
    try:
        # Approve request
        approved_request = SharingService.approve_sharing_request(
            db, request_id, str(current_user.id)
        )
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.DOCTOR,
            action="SHARING_REQUEST_APPROVED",
            resource_type="SHARING_REQUEST",
            resource_id=request_id,
            event_data={
                "patient_id": str(approved_request.patient_id),
                "scope": approved_request.scope,
            },
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        return {
            "request_id": str(approved_request.id),
            "status": "APPROVED",
            "session_key_created": True,
            "approved_at": datetime.utcnow().isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to approve request: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to approve request")


@router.post(
    "/sharing/requests/{request_id}/deny",
    summary="Deny sharing request",
    description="Doctor or patient denies sharing request.",
)
async def deny_sharing_request(
    request_id: str,
    reason: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Deny sharing request
    
    **Who can call:** Doctor (to deny) or patient (to cancel)
    
    **Response:** Confirmation of denial
    """
    try:
        denied_request = SharingService.deny_sharing_request(
            db, request_id, str(current_user.id), reason
        )
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.DOCTOR,
            action="SHARING_REQUEST_DENIED",
            resource_type="SHARING_REQUEST",
            resource_id=request_id,
            event_data={"reason": reason},
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        return {
            "request_id": str(denied_request.id),
            "status": "DENIED",
            "denied_at": datetime.utcnow().isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deny request: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to deny request")


# ==================== SESSION ROTATION ENDPOINTS ====================


@router.post(
    "/sessions/{session_id}/rotate",
    summary="Rotate session key",
    description="Manually trigger session key rotation.",
)
async def rotate_session_key(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Manually rotate session key
    
    **Purpose:** 
    - Doctor can request new session key without waiting for auto-rotation
    - Patient can force rotation for security
    
    **Response:**
    ```json
    {
      "old_session_id": "uuid",
      "new_session_id": "uuid",
      "new_session_key_hash": "sha256:...",
      "expires_at": "2024-01-02T00:00:00Z"
    }
    ```
    """
    try:
        # Rotate key
        old_session, new_session = SessionRotationService.rotate_session_key(
            db, session_id, str(current_user.id)
        )
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.PATIENT,
            action="SESSION_KEY_ROTATED",
            resource_type="SESSION_KEY",
            resource_id=str(new_session.id),
            event_data={
                "old_session_id": str(old_session.id),
                "reason": "manual_rotation",
            },
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        return {
            "old_session_id": str(old_session.id),
            "new_session_id": str(new_session.id),
            "new_session_key_hash": new_session.session_key_hash,
            "expires_at": new_session.expires_at.isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to rotate session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to rotate session")


# ==================== PERMISSION SCOPE ENDPOINTS ====================


@router.get(
    "/sessions/{session_id}/scope",
    summary="Get session scope",
    description="Retrieve permission scope for a session (read, read_write).",
)
async def get_session_scope(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get permission scope for session
    
    **Response:**
    ```json
    {
      "session_id": "uuid",
      "scope": "read",
      "can_read": true,
      "can_write": false,
      "resources_allowed": ["PRESCRIPTION", "LAB_REPORT"]
    }
    ```
    """
    try:
        scope = AccessControlService.get_session_scope(
            db, session_id, str(current_user.id)
        )
        
        return {
            "session_id": session_id,
            "scope": scope["scope"],
            "can_read": scope["can_read"],
            "can_write": scope["can_write"],
            "resources_allowed": scope.get("resources", []),
        }
    
    except Exception as e:
        logger.error(f"Failed to get scope: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get scope")


@router.put(
    "/sessions/{session_id}/scope",
    summary="Update session scope",
    description="Patient updates permission scope for session.",
)
async def update_session_scope(
    session_id: str,
    new_scope: str = Query(..., regex="^(read|read_write)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Update permission scope
    
    **Who can call:** Patient only
    **Parameters:** new_scope (read or read_write)
    
    **Effect:** Immediate scope change, logged in audit
    """
    try:
        updated_session = AccessControlService.update_session_scope(
            db, session_id, str(current_user.id), new_scope
        )
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.PATIENT,
            action="SESSION_SCOPE_UPDATED",
            resource_type="SESSION_KEY",
            resource_id=session_id,
            event_data={"new_scope": new_scope},
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        return {
            "session_id": session_id,
            "new_scope": new_scope,
            "updated_at": datetime.utcnow().isoformat(),
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update scope: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update scope")


# ==================== REVOCATION ENDPOINTS ====================


@router.post(
    "/sessions/{session_id}/revoke",
    summary="Revoke session immediately",
    description="Patient revokes doctor's access immediately.",
)
async def revoke_session_immediately(
    session_id: str,
    reason: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Revoke session immediately
    
    **Effect:**
    - Doctor loses access immediately
    - Cache invalidated
    - All open connections closed
    - Logged in audit trail
    
    **Response:** Confirmation of revocation
    """
    try:
        revoked_session = AccessControlService.revoke_session_immediately(
            db, session_id, str(current_user.id), reason
        )
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.PATIENT,
            action="SESSION_REVOKED_IMMEDIATELY",
            resource_type="SESSION_KEY",
            resource_id=session_id,
            event_data={"reason": reason},
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        return {
            "session_id": session_id,
            "status": "REVOKED",
            "revoked_at": datetime.utcnow().isoformat(),
            "reason": reason,
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to revoke session")


@router.post(
    "/all-sessions/revoke",
    summary="Revoke all sessions",
    description="Patient revokes all doctor access at once.",
)
async def revoke_all_sessions(
    reason: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None,
):
    """
    Revoke all active sessions
    
    **Effect:**
    - All doctors lose access immediately
    - All caches invalidated
    - All connections closed
    - Logged in audit trail
    
    **Response:** Count of sessions revoked
    """
    try:
        count = AccessControlService.revoke_all_sessions(
            db, str(current_user.id), reason
        )
        
        # Log action
        CryptoAuditService.log_action(
            db=db,
            actor_id=str(current_user.id),
            actor_type=ActorType.PATIENT,
            action="ALL_SESSIONS_REVOKED",
            resource_type="SESSION_KEY",
            resource_id=str(current_user.id),
            event_data={"sessions_revoked": count, "reason": reason},
            ip_address=request.client.host if request else "0.0.0.0",
            request_id=request.headers.get("X-Request-ID", str(uuid4()))
            if request
            else str(uuid4()),
            status=CryptoAuditLogStatus.SUCCESS,
        )
        
        return {
            "sessions_revoked": count,
            "revoked_at": datetime.utcnow().isoformat(),
            "reason": reason,
        }
    
    except Exception as e:
        logger.error(f"Failed to revoke all sessions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to revoke sessions")
