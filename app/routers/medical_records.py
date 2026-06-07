from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_patient_profile, require_patient
from app.models.medical_record import MedicalRecord
from app.models.patient import Patient
from app.models.user import User
from app.schemas.medical_record import MedicalRecordCreate, MedicalRecordOut
from app.services.audit_service import log_event

router = APIRouter()


def _get_record(record_id: UUID, patient: Patient, db: Session) -> MedicalRecord:
    record = (
        db.query(MedicalRecord)
        .filter(MedicalRecord.id == record_id, MedicalRecord.patient_id == patient.id)
        .first()
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Record not found"
        )
    return record


@router.get("", response_model=list[MedicalRecordOut])
def list_records(
    family_member_id: UUID | None = None,
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    q = db.query(MedicalRecord).filter(MedicalRecord.patient_id == patient.id)
    if family_member_id is not None:
        q = q.filter(MedicalRecord.family_member_id == family_member_id)
    return q.order_by(MedicalRecord.record_date.desc()).all()


@router.post("", response_model=MedicalRecordOut, status_code=status.HTTP_201_CREATED)
def create_record(
    payload: MedicalRecordCreate,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    # Validate family_member_id belongs to this patient
    if payload.family_member_id:
        from app.models.family_member import FamilyMember

        fm = (
            db.query(FamilyMember)
            .filter(
                FamilyMember.id == payload.family_member_id,
                FamilyMember.owner_patient_id == patient.id,
            )
            .first()
        )
        if not fm:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Family member not found or does not belong to you",
            )

    record = MedicalRecord(
        patient_id=patient.id,
        **payload.model_dump(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    ip = request.client.host if request.client else None
    log_event(
        db,
        "CREATE_RECORD",
        "MedicalRecord",
        str(record.id),
        current_user.id,
        ip_address=ip,
    )
    return record


@router.get("/{record_id}", response_model=MedicalRecordOut)
def get_record(
    record_id: UUID,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    record = _get_record(record_id, patient, db)
    ip = request.client.host if request.client else None
    log_event(
        db,
        "VIEW_RECORD",
        "MedicalRecord",
        str(record.id),
        current_user.id,
        ip_address=ip,
    )
    return record


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(
    record_id: UUID,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    record = _get_record(record_id, patient, db)
    db.delete(record)
    db.commit()
    ip = request.client.host if request.client else None
    log_event(
        db,
        "DELETE_RECORD",
        "MedicalRecord",
        str(record_id),
        current_user.id,
        ip_address=ip,
    )
