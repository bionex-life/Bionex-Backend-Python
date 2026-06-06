from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User, UserRole
from app.schemas.sleep import SleepIngestionRequest, SleepIngestionResponse
from app.services.sleep import ingest_sleep_records

router = APIRouter()


@router.post(
    "/{user_id}",
    response_model=SleepIngestionResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest_user_sleep(
    user_id: UUID,
    payload: SleepIngestionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Ingest sleep records for a specific user.

    Only the user themselves or an administrator can ingest sleep records.
    """
    # Authorization check: Only the target user themselves or an administrator can ingest sleep logs
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot ingest sleep records for another user",
        )

    # Ensure target user exists when administrator is executing ingestion for another user
    if current_user.id != user_id:
        target_user = db.query(User).filter(User.id == user_id).first()
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

    ingest_sleep_records(db, user_id, payload)
    return SleepIngestionResponse()
