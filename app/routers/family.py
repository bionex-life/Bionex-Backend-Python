from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_patient_profile, require_patient
from app.models.family_member import FamilyMember
from app.models.patient import Patient
from app.models.user import User
from app.schemas.family_member import FamilyMemberCreate, FamilyMemberOut, FamilyMemberUpdate
from app.services.audit_service import log_event

router = APIRouter()


def _get_member(member_id: UUID, patient: Patient, db: Session) -> FamilyMember:
    member = (
        db.query(FamilyMember)
        .filter(
            FamilyMember.id == member_id,
            FamilyMember.owner_patient_id == patient.id,
        )
        .first()
    )
    if not member:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Family member not found")
    return member


@router.get("", response_model=list[FamilyMemberOut])
def list_family(
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    return db.query(FamilyMember).filter(FamilyMember.owner_patient_id == patient.id).all()


@router.post("", response_model=FamilyMemberOut, status_code=status.HTTP_201_CREATED)
def add_family_member(
    payload: FamilyMemberCreate,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    member = FamilyMember(owner_patient_id=patient.id, **payload.model_dump())
    db.add(member)
    db.commit()
    db.refresh(member)
    ip = request.client.host if request.client else None
    log_event(db, "ADD_FAMILY_MEMBER", "FamilyMember", str(member.id), current_user.id, ip_address=ip)
    return member


@router.get("/{member_id}", response_model=FamilyMemberOut)
def get_family_member(
    member_id: UUID,
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    return _get_member(member_id, patient, db)


@router.put("/{member_id}", response_model=FamilyMemberOut)
def update_family_member(
    member_id: UUID,
    payload: FamilyMemberUpdate,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    member = _get_member(member_id, patient, db)
    # Only allow specific fields to be updated (security: prevent injection)
    allowed_fields = {'name', 'relationship', 'date_of_birth', 'gender', 'blood_group', 'notes'}
    for field, value in payload.model_dump(exclude_none=True).items():
        if field in allowed_fields:
            setattr(member, field, value)
    db.commit()
    db.refresh(member)
    ip = request.client.host if request.client else None
    log_event(db, "UPDATE_FAMILY_MEMBER", "FamilyMember", str(member.id), current_user.id, ip_address=ip)
    return member


@router.delete("/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_family_member(
    member_id: UUID,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    member = _get_member(member_id, patient, db)
    db.delete(member)
    db.commit()
    ip = request.client.host if request.client else None
    log_event(db, "DELETE_FAMILY_MEMBER", "FamilyMember", str(member_id), current_user.id, ip_address=ip)
