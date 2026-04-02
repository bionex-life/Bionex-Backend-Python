from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_patient_profile, require_patient
from app.models.medication import Medication
from app.models.patient import Patient
from app.models.user import User
from app.schemas.medication import MedicationCreate, MedicationOut, MedicationUpdate
from app.services.audit_service import log_event

router = APIRouter()


def _get_medication(med_id: UUID, patient: Patient, db: Session) -> Medication:
    med = (
        db.query(Medication)
        .filter(Medication.id == med_id, Medication.patient_id == patient.id)
        .first()
    )
    if not med:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Medication not found")
    return med


@router.get("", response_model=list[MedicationOut])
def list_medications(
    family_member_id: UUID | None = None,
    is_active: bool | None = None,
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    q = db.query(Medication).filter(Medication.patient_id == patient.id)
    if family_member_id is not None:
        q = q.filter(Medication.family_member_id == family_member_id)
    if is_active is not None:
        q = q.filter(Medication.is_active == is_active)
    return q.all()


@router.post("", response_model=MedicationOut, status_code=status.HTTP_201_CREATED)
def create_medication(
    payload: MedicationCreate,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    if payload.family_member_id:
        from app.models.family_member import FamilyMember

        fm = db.query(FamilyMember).filter(
            FamilyMember.id == payload.family_member_id,
            FamilyMember.owner_patient_id == patient.id,
        ).first()
        if not fm:
            raise HTTPException(status_code=400, detail="Family member not found")

    med = Medication(patient_id=patient.id, **payload.model_dump())
    db.add(med)
    db.commit()
    db.refresh(med)
    ip = request.client.host if request.client else None
    log_event(db, "CREATE_MEDICATION", "Medication", str(med.id), current_user.id, ip_address=ip)
    return med


@router.get("/{med_id}", response_model=MedicationOut)
def get_medication(
    med_id: UUID,
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    return _get_medication(med_id, patient, db)


@router.put("/{med_id}", response_model=MedicationOut)
def update_medication(
    med_id: UUID,
    payload: MedicationUpdate,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    med = _get_medication(med_id, patient, db)
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(med, field, value)
    db.commit()
    db.refresh(med)
    ip = request.client.host if request.client else None
    log_event(db, "UPDATE_MEDICATION", "Medication", str(med.id), current_user.id, ip_address=ip)
    return med


@router.delete("/{med_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_medication(
    med_id: UUID,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    med = _get_medication(med_id, patient, db)
    db.delete(med)
    db.commit()
    ip = request.client.host if request.client else None
    log_event(db, "DELETE_MEDICATION", "Medication", str(med_id), current_user.id, ip_address=ip)
