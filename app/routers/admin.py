"""
Admin module — management endpoints for ADMIN role only.

Privacy rules enforced here:
  - Admin CAN see: user names, emails, phones, orders, payments, lab test catalogue
  - Admin CANNOT see: medical records, report URLs, health data, encrypted PHI fields
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models.lab_order import LabOrder, OrderStatus
from app.models.payment import Payment
from app.models.user import User
from app.schemas.lab_order import LabOrderOut, LabOrderStatusUpdate
from app.schemas.payment import PaymentOut
from app.schemas.user import UserOut

router = APIRouter()


# ── Users ────────────────────────────────────────────────────────────────────


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """List all registered users — no health data returned."""
    return db.query(User).order_by(User.created_at.desc()).all()


# ── Lab Orders ───────────────────────────────────────────────────────────────


@router.get("/orders", response_model=list[LabOrderOut])
def list_all_orders(
    status_filter: OrderStatus | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """List all lab orders with optional status filter."""
    q = db.query(LabOrder).order_by(LabOrder.created_at.desc())
    if status_filter:
        q = q.filter(LabOrder.status == status_filter)
    return q.all()


@router.put("/orders/{order_id}/status", response_model=LabOrderOut)
def update_order_status(
    order_id: UUID,
    payload: LabOrderStatusUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """Admin updates order status (e.g., SAMPLE_COLLECTED → COMPLETED)."""
    order = db.query(LabOrder).filter(LabOrder.id == order_id).first()
    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Order not found"
        )

    order.status = payload.status
    if payload.report_url:
        order.report_url = payload.report_url
        # Automatically create a medical record for completed orders
        if payload.status == OrderStatus.COMPLETED:
            from app.models.medical_record import MedicalRecord, RecordType

            record = MedicalRecord(
                patient_id=order.patient_id,
                family_member_id=order.family_member_id,
                type=RecordType.LAB_REPORT,
                title=f"Lab Report — {order.lab_test.name if order.lab_test else order.lab_test_id}",
                file_url=payload.report_url,
            )
            db.add(record)

    db.commit()
    db.refresh(order)
    return order


# ── Payments ─────────────────────────────────────────────────────────────────


@router.get("/payments", response_model=list[PaymentOut])
def list_all_payments(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return db.query(Payment).order_by(Payment.created_at.desc()).all()
