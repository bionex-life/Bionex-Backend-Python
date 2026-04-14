"""
NFC / Bluetooth sharing flow.

Patient-initiated:
  POST /sharing/initiate          → patient grants doctor access, returns token
  POST /sharing/revoke/{perm_id}  → patient revokes an active session

Doctor-initiated:
  POST /sharing/request           → doctor requests access (creates PENDING entry)
  POST /sharing/approve/{perm_id} → patient approves, token issued
  POST /sharing/reject/{perm_id}  → patient rejects

Query:
  GET  /sharing/sessions          → patient: list active/approved sessions
  GET  /sharing/requests          → patient: list incoming PENDING requests
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_patient_profile, require_doctor, require_patient
from app.models.access_permission import AccessPermission, RequestStatus
from app.models.patient import Patient
from app.models.user import User, UserRole
from app.schemas.access_permission import (
    AccessPermissionOut,
    DoctorAccessRequest,
    SharingInitiate,
)
from app.services.audit_service import log_event
from app.services.sharing_service import (
    approve_permission,
    create_doctor_access_request,
    create_patient_initiated_permission,
)

router = APIRouter()


# ── Patient-initiated ────────────────────────────────────────────────────────


@router.post("/initiate", response_model=AccessPermissionOut, status_code=status.HTTP_201_CREATED)
def initiate_sharing(
    payload: SharingInitiate,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    """Patient taps / shares with a specific doctor — token issued immediately."""
    doctor = db.query(User).filter(
        User.id == payload.doctor_user_id, User.is_active == True
    ).first()
    if not doctor or doctor.role != UserRole.DOCTOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only active doctors can be granted access"
        )

    perm = create_patient_initiated_permission(
        db,
        patient_id=patient.id,
        doctor_user_id=payload.doctor_user_id,
        family_member_id=payload.family_member_id,
        scope=payload.scope,
    )
    ip = request.client.host if request.client else None
    log_event(db, "SHARING_INITIATED", "AccessPermission", str(perm.id), current_user.id, ip_address=ip)
    return perm


@router.post("/revoke/{perm_id}", response_model=AccessPermissionOut)
def revoke_sharing(
    perm_id: UUID,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    """Patient revokes an active sharing session."""
    perm = db.query(AccessPermission).filter(
        AccessPermission.id == perm_id,
        AccessPermission.patient_id == patient.id,
    ).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    if perm.request_status not in (RequestStatus.APPROVED, RequestStatus.PENDING):
        raise HTTPException(status_code=400, detail="Nothing to revoke")

    perm.request_status = RequestStatus.REVOKED
    perm.access_token = None
    db.commit()
    db.refresh(perm)
    ip = request.client.host if request.client else None
    log_event(db, "SHARING_REVOKED", "AccessPermission", str(perm_id), current_user.id, ip_address=ip)
    return perm


# ── Doctor-initiated ─────────────────────────────────────────────────────────


@router.post("/request", response_model=AccessPermissionOut, status_code=status.HTTP_201_CREATED)
def doctor_request_access(
    payload: DoctorAccessRequest,
    request: Request,
    current_user: User = Depends(require_doctor),
    db: Session = Depends(get_db),
):
    """Doctor sends an access request to a patient (from NFC/QR patient_user_id)."""
    patient = db.query(Patient).filter(
        Patient.user_id == payload.patient_user_id
    ).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    perm = create_doctor_access_request(
        db,
        patient_id=patient.id,
        doctor_user_id=current_user.id,
        scope=payload.scope,
    )
    ip = request.client.host if request.client else None
    log_event(db, "ACCESS_REQUESTED", "AccessPermission", str(perm.id), current_user.id, ip_address=ip)
    return perm


# ── Patient approves / rejects doctor requests ───────────────────────────────


@router.post("/approve/{perm_id}", response_model=AccessPermissionOut)
def approve_request(
    perm_id: UUID,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    perm = db.query(AccessPermission).filter(
        AccessPermission.id == perm_id,
        AccessPermission.patient_id == patient.id,
        AccessPermission.request_status == RequestStatus.PENDING,
    ).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Pending request not found")

    perm = approve_permission(db, perm)
    ip = request.client.host if request.client else None
    log_event(db, "ACCESS_APPROVED", "AccessPermission", str(perm_id), current_user.id, ip_address=ip)
    return perm


@router.post("/reject/{perm_id}", response_model=AccessPermissionOut)
def reject_request(
    perm_id: UUID,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    perm = db.query(AccessPermission).filter(
        AccessPermission.id == perm_id,
        AccessPermission.patient_id == patient.id,
        AccessPermission.request_status == RequestStatus.PENDING,
    ).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Pending request not found")

    perm.request_status = RequestStatus.REJECTED
    db.commit()
    db.refresh(perm)
    ip = request.client.host if request.client else None
    log_event(db, "ACCESS_REJECTED", "AccessPermission", str(perm_id), current_user.id, ip_address=ip)
    return perm


# ── Query endpoints ─────────────────────────────────────────────────────────


@router.get("/sessions", response_model=list[AccessPermissionOut])
def list_active_sessions(
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    """Patient: view all currently approved/active sharing sessions."""
    return db.query(AccessPermission).filter(
        AccessPermission.patient_id == patient.id,
        AccessPermission.request_status == RequestStatus.APPROVED,
    ).all()


@router.get("/requests", response_model=list[AccessPermissionOut])
def list_incoming_requests(
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    """Patient: view all pending doctor access requests."""
    return db.query(AccessPermission).filter(
        AccessPermission.patient_id == patient.id,
        AccessPermission.request_status == RequestStatus.PENDING,
    ).all()
