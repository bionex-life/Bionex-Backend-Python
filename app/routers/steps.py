from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User, UserRole
from app.schemas.steps import StepIngestionResponse, StepLogCreate
from app.services.steps import ingest_steps

router = APIRouter()


@router.post("/{user_id}", response_model=StepIngestionResponse, status_code=status.HTTP_201_CREATED)
def ingest_user_steps(
    user_id: UUID,
    payload: StepLogCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Ingest step counts for a specific user.

    Only the user themselves or an administrator can ingest steps.
    """
    # Authorization check
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot ingest steps for another user",
        )

    # Ensure target user exists
    if current_user.id != user_id:
        target_user = db.query(User).filter(User.id == user_id).first()
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

    daily_total = ingest_steps(db, user_id, payload)
    return StepIngestionResponse(daily_total=daily_total)
