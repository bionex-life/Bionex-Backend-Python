from sqlalchemy import Column, Date, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class UserDailyHealth(Base, TimestampMixin):
    __tablename__ = "user_daily_health"

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    record_date = Column(Date, primary_key=True, nullable=False)
    health_score = Column(Integer, nullable=True)
    sleep_quality = Column(JSONB, nullable=True)
    step_count = Column(JSONB, nullable=True)

    user = relationship("User")
