from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_patient_profile, require_patient
from app.models.patient import Patient
from app.models.user import User
from app.schemas.patient import PatientOut, PatientUpdate
from app.schemas.user import UserOut
from app.services.audit_service import log_event

router = APIRouter()


@router.get("/me", response_model=dict)
def get_my_profile(
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    """Return combined user + patient profile for the logged-in patient."""
    user_data = UserOut.model_validate(current_user).model_dump()
    patient_data = PatientOut.model_validate(patient).model_dump()
    return {**user_data, **patient_data}


@router.put("/me", response_model=PatientOut)
def update_my_profile(
    payload: PatientUpdate,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    # Only allow specific fields to be updated (security: prevent injection)
    allowed_fields = {
        "date_of_birth",
        "gender",
        "blood_group",
        "address",
        "emergency_contact_name",
        "emergency_contact_phone",
    }
    for field, value in payload.model_dump(exclude_none=True).items():
        if field in allowed_fields:
            setattr(patient, field, value)
    db.commit()
    db.refresh(patient)
    ip = request.client.host if request.client else None
    log_event(
        db, "UPDATE_PROFILE", "Patient", str(patient.id), current_user.id, ip_address=ip
    )
    return patient
