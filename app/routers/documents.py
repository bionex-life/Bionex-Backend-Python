from __future__ import annotations

import uuid
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models.document import Document
from app.models.user import User
from app.schemas.document import DocumentOut
from app.services.audit_service import log_event

settings = get_settings()
UPLOADS_DIR = Path(settings.UPLOADS_DIR).resolve()
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_FILE_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".pdf": "application/pdf",
}
ALLOWED_CONTENT_TYPES = set(ALLOWED_FILE_TYPES.values())

router = APIRouter()


def _validate_upload_file(file: UploadFile) -> tuple[str, str]:
    filename = file.filename or ""
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_FILE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only JPG, PNG, and PDF files are allowed.",
        )

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported file content type.",
        )

    return filename, extension


def _get_document(document_id: UUID, user: User, db: Session) -> Document:
    document = (
        db.query(Document)
        .filter(Document.id == document_id, Document.owner_user_id == user.id)
        .first()
    )
    if not document:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    return document


@router.post("", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
def upload_document(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(...),
    description: str | None = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not title.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Title cannot be empty")

    original_filename, extension = _validate_upload_file(file)
    content = file.file.read()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty")

    storage_filename = f"{uuid.uuid4().hex}{extension}"
    storage_path = UPLOADS_DIR / storage_filename

    try:
        storage_path.write_bytes(content)
    except OSError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to store uploaded file") from exc

    document = Document(
        owner_user_id=current_user.id,
        title=title.strip(),
        description=description.strip() if description else None,
        original_filename=original_filename,
        content_type=file.content_type,
        file_path=str(storage_path),
        size_bytes=len(content),
    )
    db.add(document)
    db.commit()
    db.refresh(document)

    ip = request.client.host if request.client else None
    log_event(db, "UPLOAD_DOCUMENT", "Document", str(document.id), current_user.id, ip_address=ip)
    return document


@router.get("", response_model=list[DocumentOut])
def list_documents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(Document)
        .filter(Document.owner_user_id == current_user.id)
        .order_by(Document.created_at.desc())
        .all()
    )


@router.get("/{document_id}", response_model=DocumentOut)
def get_document(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _get_document(document_id, current_user, db)


@router.get("/{document_id}/download")
def download_document(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = _get_document(document_id, current_user, db)
    file_path = Path(document.file_path)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document file not found")

    return FileResponse(
        path=str(file_path),
        filename=document.original_filename,
        media_type=document.content_type,
    )


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_document(
    document_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = _get_document(document_id, current_user, db)
    file_path = Path(document.file_path)
    db.delete(document)
    db.commit()

    try:
        if file_path.exists():
            file_path.unlink()
    except OSError:
        pass

    ip = request.client.host if request.client else None
    log_event(db, "DELETE_DOCUMENT", "Document", str(document.id), current_user.id, ip_address=ip)
