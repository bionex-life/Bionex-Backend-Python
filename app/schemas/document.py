from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.models.document import DocumentCategory


class DocumentOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    owner_user_id: UUID
    title: str
    description: str | None
    original_filename: str
    content_type: str
    size_bytes: int
    category: DocumentCategory
    source_app: str | None
    is_shared_upload: bool
    created_at: datetime
    updated_at: datetime


class ShareTokenOut(BaseModel):
    """Response when a share token is generated."""

    token: str
    expires_at: datetime


class ShareUploadOut(BaseModel):
    """Response for the share-upload endpoint (batch)."""

    uploaded: list[DocumentOut]
    total_files: int
