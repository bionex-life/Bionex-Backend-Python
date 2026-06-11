from datetime import date
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User, UserRole
from app.models.user_daily_health import UserDailyHealth
from app.schemas.daily_health import DailyHealthResponse

router = APIRouter()

@router.get("/{user_id}", response_model=DailyHealthResponse)
def get_user_daily_health(
    user_id: UUID,
    from_date: date = Query(..., description="Start date (inclusive)"),
    to_date: date = Query(..., description="End date (inclusive)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve daily health data (steps, sleep, score) for a user."""
    # Authorization: only the user or a doctor/admin can access
    if current_user.id != user_id and current_user.role not in (UserRole.DOCTOR, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot access health data of another user"
        )
    
    records = db.query(UserDailyHealth).filter(
        UserDailyHealth.user_id == user_id,
        UserDailyHealth.record_date >= from_date,
        UserDailyHealth.record_date <= to_date
    ).order_by(UserDailyHealth.record_date.asc()).all()

    return {"data": records}
