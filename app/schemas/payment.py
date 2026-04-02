from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel

from app.models.payment import PaymentStatus


class PaymentOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    user_id: UUID
    lab_order_id: UUID | None
    amount: Decimal
    status: PaymentStatus
    payment_method: str | None
    transaction_id: str | None
    paid_at: datetime | None
    created_at: datetime
    updated_at: datetime
