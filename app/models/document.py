import uuid

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Document(Base, TimestampMixin):
    __tablename__ = "documents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    owner_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title = Column(String(500), nullable=False)
    description = Column(String(2000), nullable=True)
    original_filename = Column(String(1024), nullable=False)
    content_type = Column(String(100), nullable=False)
    file_path = Column(String(2000), nullable=False)
    size_bytes = Column(Integer, nullable=False)

    owner = relationship("User", back_populates="documents")
