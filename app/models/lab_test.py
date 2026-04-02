import uuid

from sqlalchemy import Boolean, Column, Numeric, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class LabTest(Base, TimestampMixin):
    __tablename__ = "lab_tests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String(500), nullable=False, index=True)
    description = Column(Text, nullable=True)
    category = Column(String(255), nullable=True, index=True)
    price = Column(Numeric(10, 2), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    orders = relationship("LabOrder", back_populates="lab_test")
