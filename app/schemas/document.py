from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class DocumentOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    owner_user_id: UUID
    title: str
    description: str | None
    original_filename: str
    content_type: str
    size_bytes: int
    created_at: datetime
    updated_at: datetime
