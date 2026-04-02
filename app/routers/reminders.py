from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_patient_profile, require_patient
from app.models.medication import Medication
from app.models.patient import Patient
from app.models.reminder import Reminder, ReminderLog
from app.models.user import User
from app.schemas.reminder import (
    ReminderCreate,
    ReminderLogCreate,
    ReminderLogOut,
    ReminderOut,
    ReminderUpdate,
)

router = APIRouter()


def _get_reminder(reminder_id: UUID, patient: Patient, db: Session) -> Reminder:
    reminder = (
        db.query(Reminder)
        .join(Medication, Medication.id == Reminder.medication_id)
        .filter(Reminder.id == reminder_id, Medication.patient_id == patient.id)
        .first()
    )
    if not reminder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reminder not found")
    return reminder


@router.get("", response_model=list[ReminderOut])
def list_reminders(
    medication_id: UUID | None = None,
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    q = (
        db.query(Reminder)
        .join(Medication, Medication.id == Reminder.medication_id)
        .filter(Medication.patient_id == patient.id)
    )
    if medication_id:
        q = q.filter(Reminder.medication_id == medication_id)
    return q.all()


@router.post("", response_model=ReminderOut, status_code=status.HTTP_201_CREATED)
def create_reminder(
    payload: ReminderCreate,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    med = db.query(Medication).filter(
        Medication.id == payload.medication_id,
        Medication.patient_id == patient.id,
    ).first()
    if not med:
        raise HTTPException(status_code=400, detail="Medication not found")

    reminder = Reminder(**payload.model_dump())
    db.add(reminder)
    db.commit()
    db.refresh(reminder)
    return reminder


@router.put("/{reminder_id}", response_model=ReminderOut)
def update_reminder(
    reminder_id: UUID,
    payload: ReminderUpdate,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    reminder = _get_reminder(reminder_id, patient, db)
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(reminder, field, value)
    db.commit()
    db.refresh(reminder)
    return reminder


@router.delete("/{reminder_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_reminder(
    reminder_id: UUID,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    reminder = _get_reminder(reminder_id, patient, db)
    db.delete(reminder)
    db.commit()


@router.post("/{reminder_id}/log", response_model=ReminderLogOut, status_code=status.HTTP_201_CREATED)
def log_reminder(
    reminder_id: UUID,
    payload: ReminderLogCreate,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    reminder = _get_reminder(reminder_id, patient, db)
    entry = ReminderLog(
        reminder_id=reminder.id,
        scheduled_date=payload.scheduled_date,
        status=payload.status,
        logged_at=datetime.now(timezone.utc).isoformat(),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.get("/{reminder_id}/logs", response_model=list[ReminderLogOut])
def get_reminder_logs(
    reminder_id: UUID,
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    reminder = _get_reminder(reminder_id, patient, db)
    return db.query(ReminderLog).filter(ReminderLog.reminder_id == reminder.id).all()
