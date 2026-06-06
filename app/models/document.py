import enum
import uuid

from sqlalchemy import Boolean, Column, Enum as SAEnum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class DocumentCategory(str, enum.Enum):
    MEDICAL_REPORT = "medical_report"
    PRESCRIPTION = "prescription"
    LAB_REPORT = "lab_report"
    INSURANCE = "insurance"
    IMAGING = "imaging"
    OTHER = "other"


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

    # ── Share-integration fields ──────────────────────────────────────────────
    category = Column(
        SAEnum(DocumentCategory, name="document_category"),
        nullable=False,
        default=DocumentCategory.OTHER,
        server_default="other",
    )
    source_app = Column(
        String(100), nullable=True
    )  # e.g. "whatsapp", "gmail", "camera"
    is_shared_upload = Column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    owner = relationship("User", back_populates="documents")
