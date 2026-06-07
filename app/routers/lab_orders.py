from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_patient_profile, require_patient
from app.models.lab_order import LabOrder, OrderStatus
from app.models.lab_test import LabTest
from app.models.patient import Patient
from app.models.payment import Payment, PaymentStatus
from app.models.user import User
from app.schemas.lab_order import LabOrderCreate, LabOrderOut
from app.services.audit_service import log_event

router = APIRouter()


def _get_order(order_id: UUID, patient: Patient, db: Session) -> LabOrder:
    order = (
        db.query(LabOrder)
        .filter(LabOrder.id == order_id, LabOrder.patient_id == patient.id)
        .first()
    )
    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Order not found"
        )
    return order


@router.get("", response_model=list[LabOrderOut])
def list_orders(
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    return (
        db.query(LabOrder)
        .filter(LabOrder.patient_id == patient.id)
        .order_by(LabOrder.created_at.desc())
        .all()
    )


@router.post("", response_model=LabOrderOut, status_code=status.HTTP_201_CREATED)
def book_order(
    payload: LabOrderCreate,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    test = (
        db.query(LabTest)
        .filter(LabTest.id == payload.lab_test_id, LabTest.is_active)
        .first()
    )
    if not test:
        raise HTTPException(status_code=400, detail="Lab test not found or inactive")

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
            raise HTTPException(status_code=400, detail="Family member not found")

    order = LabOrder(patient_id=patient.id, **payload.model_dump())
    db.add(order)
    db.flush()

    # Create a PENDING payment record
    payment = Payment(
        user_id=current_user.id,
        lab_order_id=order.id,
        amount=test.price,
        status=PaymentStatus.PENDING,
    )
    db.add(payment)
    db.commit()
    db.refresh(order)

    ip = request.client.host if request.client else None
    log_event(
        db, "BOOK_LAB_ORDER", "LabOrder", str(order.id), current_user.id, ip_address=ip
    )
    return order


@router.get("/{order_id}", response_model=LabOrderOut)
def get_order(
    order_id: UUID,
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    return _get_order(order_id, patient, db)


@router.put("/{order_id}/cancel", response_model=LabOrderOut)
def cancel_order(
    order_id: UUID,
    request: Request,
    current_user: User = Depends(require_patient),
    patient: Patient = Depends(get_patient_profile),
    db: Session = Depends(get_db),
):
    order = _get_order(order_id, patient, db)
    if order.status not in (OrderStatus.BOOKED,):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel an order in '{order.status}' status",
        )
    order.status = OrderStatus.CANCELLED
    db.commit()
    db.refresh(order)
    ip = request.client.host if request.client else None
    log_event(
        db,
        "CANCEL_LAB_ORDER",
        "LabOrder",
        str(order.id),
        current_user.id,
        ip_address=ip,
    )
    return order
