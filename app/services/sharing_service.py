from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.access_permission import AccessPermission, InitiatedBy, RequestStatus

settings = get_settings()


def _generate_token() -> str:
    return secrets.token_urlsafe(48)


def create_patient_initiated_permission(
    db: Session,
    patient_id: uuid.UUID,
    doctor_user_id: uuid.UUID,
    family_member_id: uuid.UUID | None = None,
    scope: str = "records",
) -> AccessPermission:
    """Patient directly grants a doctor access — token issued immediately."""
    token = _generate_token()
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.SHARING_TOKEN_EXPIRE_MINUTES
    )
    perm = AccessPermission(
        patient_id=patient_id,
        family_member_id=family_member_id,
        granted_to_user_id=doctor_user_id,
        initiated_by=InitiatedBy.PATIENT,
        request_status=RequestStatus.APPROVED,
        access_token=token,
        expires_at=expires_at,
        scope=scope,
    )
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm


def create_doctor_access_request(
    db: Session,
    patient_id: uuid.UUID,
    doctor_user_id: uuid.UUID,
    scope: str = "records",
) -> AccessPermission:
    """Doctor requests access — stays PENDING until patient approves."""
    perm = AccessPermission(
        patient_id=patient_id,
        granted_to_user_id=doctor_user_id,
        initiated_by=InitiatedBy.DOCTOR,
        request_status=RequestStatus.PENDING,
        scope=scope,
    )
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm


def approve_permission(db: Session, perm: AccessPermission) -> AccessPermission:
    """Patient approves a doctor's pending request — generates the token."""
    perm.access_token = _generate_token()
    perm.expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.SHARING_TOKEN_EXPIRE_MINUTES
    )
    perm.request_status = RequestStatus.APPROVED
    db.commit()
    db.refresh(perm)
    return perm


def validate_access_token(db: Session, token: str) -> AccessPermission | None:
    """Returns the AccessPermission if the token is valid and not expired."""
    perm = (
        db.query(AccessPermission)
        .filter(
            AccessPermission.access_token == token,
            AccessPermission.request_status == RequestStatus.APPROVED,
        )
        .first()
    )
    if perm is None:
        return None
    if perm.expires_at and perm.expires_at < datetime.now(timezone.utc):
        perm.request_status = RequestStatus.EXPIRED
        db.commit()
        return None
    return perm


class SharingService:
    """Service class for sharing and access control operations."""
    
    @staticmethod
    def create_sharing_request(
        db: Session,
        patient_id: str,
        doctor_id: str,
        scope: str = "records",
        expires_in_days: int = 7,
        reason: str = "",
    ) -> AccessPermission:
        """Create a sharing request (wraps create_patient_initiated_permission)."""
        return create_patient_initiated_permission(
            db=db,
            patient_id=uuid.UUID(patient_id),
            doctor_user_id=uuid.UUID(doctor_id),
            scope=scope,
        )
    
    @staticmethod
    def get_patient_sharing_requests(
        db: Session,
        patient_id: str,
    ) -> list[AccessPermission]:
        """Get all sharing requests for a patient."""
        return (
            db.query(AccessPermission)
            .filter(AccessPermission.patient_id == uuid.UUID(patient_id))
            .all()
        )
    
    @staticmethod
    def get_doctor_sharing_requests(
        db: Session,
        doctor_user_id: str,
    ) -> list[AccessPermission]:
        """Get all sharing requests received by a doctor."""
        return (
            db.query(AccessPermission)
            .filter(AccessPermission.granted_to_user_id == uuid.UUID(doctor_user_id))
            .all()
        )
    
    @staticmethod
    def approve_sharing_request(
        db: Session,
        request_id: str,
    ) -> AccessPermission:
        """Approve a sharing request."""
        perm = db.query(AccessPermission).filter(AccessPermission.id == uuid.UUID(request_id)).first()
        if not perm:
            raise ValueError(f"Sharing request {request_id} not found")
        return approve_permission(db, perm)
    
    @staticmethod
    def deny_sharing_request(
        db: Session,
        request_id: str,
    ) -> AccessPermission:
        """Deny a sharing request."""
        perm = db.query(AccessPermission).filter(AccessPermission.id == uuid.UUID(request_id)).first()
        if not perm:
            raise ValueError(f"Sharing request {request_id} not found")
        perm.request_status = RequestStatus.DENIED
        db.commit()
        db.refresh(perm)
        return perm
