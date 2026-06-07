"""
Doctor module — read-only access to patient data via a validated sharing token.

All endpoints require:
  - Authorization: Bearer <doctor_jwt>
  - X-Sharing-Token: <sharing_token>

The sharing token has a limited TTL and is tied to a specific patient.
Accessing these endpoints creates/updates a DoctorAccessLog entry.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.responses import FileResponse
from pathlib import Path
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_sharing_permission, require_doctor
from app.models.access_permission import AccessPermission
from app.models.doctor_access_log import DoctorAccessLog
from app.models.document import Document
from app.models.medical_record import MedicalRecord
from app.models.medication import Medication
from app.models.patient import Patient
from app.models.user import User
from app.schemas.document import DocumentOut
from app.schemas.medical_record import MedicalRecordOut
from app.schemas.medication import MedicationOut
from app.schemas.patient import PatientOut
from app.services.audit_service import log_event

router = APIRouter()


def _get_or_create_session(
    db: Session, doctor: User, perm: AccessPermission
) -> DoctorAccessLog:
    """Return an existing open session or create a new one."""
    session = (
        db.query(DoctorAccessLog)
        .filter(
            DoctorAccessLog.doctor_user_id == doctor.id,
            DoctorAccessLog.access_permission_id == perm.id,
            DoctorAccessLog.session_end == None,  # noqa: E711
        )
        .first()
    )
    if not session:
        session = DoctorAccessLog(
            doctor_user_id=doctor.id,
            patient_id=perm.patient_id,
            access_permission_id=perm.id,
            session_start=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)
    return session


@router.get("/patient", response_model=PatientOut)
def view_patient(
    request: Request,
    current_user: User = Depends(require_doctor),
    perm: AccessPermission = Depends(get_sharing_permission),
    db: Session = Depends(get_db),
):
    """Get the patient's profile via a valid sharing token."""
    _get_or_create_session(db, current_user, perm)
    patient = db.query(Patient).filter(Patient.id == perm.patient_id).first()
    ip = request.client.host if request.client else None
    log_event(
        db,
        "DOCTOR_VIEW_PATIENT",
        "Patient",
        str(perm.patient_id),
        current_user.id,
        ip_address=ip,
    )
    return patient


@router.get("/records", response_model=list[MedicalRecordOut])
def view_records(
    request: Request,
    current_user: User = Depends(require_doctor),
    perm: AccessPermission = Depends(get_sharing_permission),
    db: Session = Depends(get_db),
):
    """Get the patient's medical records via a valid sharing token."""
    session = _get_or_create_session(db, current_user, perm)

    q = db.query(MedicalRecord).filter(MedicalRecord.patient_id == perm.patient_id)
    if perm.family_member_id:
        q = q.filter(MedicalRecord.family_member_id == perm.family_member_id)
    records = q.order_by(MedicalRecord.record_date.desc()).all()

    # Track which records were accessed
    accessed_ids = [str(r.id) for r in records]
    existing = json.loads(session.records_accessed or "[]")
    session.records_accessed = json.dumps(list(set(existing + accessed_ids)))
    db.commit()

    ip = request.client.host if request.client else None
    log_event(
        db, "DOCTOR_VIEW_RECORDS", "MedicalRecord", None, current_user.id, ip_address=ip
    )
    return records


@router.get("/medications", response_model=list[MedicationOut])
def view_medications(
    request: Request,
    current_user: User = Depends(require_doctor),
    perm: AccessPermission = Depends(get_sharing_permission),
    db: Session = Depends(get_db),
):
    """Get the patient's active medications via a valid sharing token."""
    _get_or_create_session(db, current_user, perm)
    medications = (
        db.query(Medication)
        .filter(Medication.patient_id == perm.patient_id, Medication.is_active)
        .all()
    )
    ip = request.client.host if request.client else None
    log_event(
        db,
        "DOCTOR_VIEW_MEDICATIONS",
        "Medication",
        None,
        current_user.id,
        ip_address=ip,
    )
    return medications


@router.get("/documents", response_model=list[DocumentOut])
def view_documents(
    request: Request,
    current_user: User = Depends(require_doctor),
    perm: AccessPermission = Depends(get_sharing_permission),
    db: Session = Depends(get_db),
):
    """Get the patient's uploaded documents via a valid sharing token."""
    _get_or_create_session(db, current_user, perm)

    patient = db.query(Patient).filter(Patient.id == perm.patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    documents = (
        db.query(Document)
        .filter(Document.owner_user_id == patient.user_id)
        .order_by(Document.created_at.desc())
        .all()
    )

    ip = request.client.host if request.client else None
    log_event(
        db, "DOCTOR_VIEW_DOCUMENTS", "Document", None, current_user.id, ip_address=ip
    )
    return documents


@router.get("/documents/{document_id}/download")
def download_document(
    document_id: UUID,
    request: Request,
    current_user: User = Depends(require_doctor),
    perm: AccessPermission = Depends(get_sharing_permission),
    db: Session = Depends(get_db),
):
    """Download a specific patient document via a valid sharing token."""
    _get_or_create_session(db, current_user, perm)

    patient = db.query(Patient).filter(Patient.id == perm.patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    document = (
        db.query(Document)
        .filter(Document.id == document_id, Document.owner_user_id == patient.user_id)
        .first()
    )
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Document not found"
        )

    file_path = Path(document.file_path)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Document file not found"
        )

    ip = request.client.host if request.client else None
    log_event(
        db,
        "DOCTOR_DOWNLOAD_DOCUMENT",
        "Document",
        str(document.id),
        current_user.id,
        ip_address=ip,
    )

    return FileResponse(
        path=str(file_path),
        filename=document.original_filename,
        media_type=document.content_type,
    )


@router.post("/session/end", status_code=204)
def end_session(
    current_user: User = Depends(require_doctor),
    perm: AccessPermission = Depends(get_sharing_permission),
    db: Session = Depends(get_db),
):
    """Doctor explicitly closes the sharing session."""
    session = (
        db.query(DoctorAccessLog)
        .filter(
            DoctorAccessLog.doctor_user_id == current_user.id,
            DoctorAccessLog.access_permission_id == perm.id,
            DoctorAccessLog.session_end == None,  # noqa: E711
        )
        .first()
    )
    if session:
        session.session_end = datetime.now(timezone.utc)
        db.commit()
