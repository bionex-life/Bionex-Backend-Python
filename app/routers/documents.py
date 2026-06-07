from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models.document import Document, DocumentCategory
from app.models.share_token import ShareToken
from app.models.user import User
from app.schemas.document import DocumentOut, ShareTokenOut, ShareUploadOut
from app.services.audit_service import log_event

settings = get_settings()
UPLOADS_DIR = Path(settings.UPLOADS_DIR).resolve()
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# ── Allowed file types ────────────────────────────────────────────────────────
# Original types + expanded set for share-from-external-apps
ALLOWED_FILE_TYPES = {
    # Images
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".heic": "image/heic",
    ".heif": "image/heif",
    ".webp": "image/webp",
    ".tiff": "image/tiff",
    ".tif": "image/tiff",
    # Documents
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".txt": "text/plain",
    ".csv": "text/csv",
}
ALLOWED_CONTENT_TYPES = set(ALLOWED_FILE_TYPES.values())

# Some apps (e.g. WhatsApp, Gmail) send generic content types — accept those too
RELAXED_CONTENT_TYPES = ALLOWED_CONTENT_TYPES | {
    "application/octet-stream",  # Generic binary — validate by extension only
}

router = APIRouter()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _validate_upload_file(
    file: UploadFile, *, relaxed: bool = False
) -> tuple[str, str]:
    """Validate file extension and content type. Returns (filename, extension).

    When ``relaxed=True`` (share-upload), allow ``application/octet-stream``
    because external apps often don't set a precise MIME type.
    """
    filename = file.filename or ""
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_FILE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"File type '{extension}' is not allowed. Accepted: {', '.join(sorted(ALLOWED_FILE_TYPES))}",
        )

    acceptable = RELAXED_CONTENT_TYPES if relaxed else ALLOWED_CONTENT_TYPES
    if file.content_type and file.content_type not in acceptable:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported file content type.",
        )

    return filename, extension


def _validate_file_size(content: bytes) -> None:
    """Reject files exceeding the configured maximum size."""
    if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
        max_mb = settings.MAX_UPLOAD_SIZE_BYTES / (1024 * 1024)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {max_mb:.0f} MB.",
        )


def _store_file(content: bytes, extension: str) -> Path:
    """Write content to a uniquely-named file in UPLOADS_DIR and return path."""
    storage_filename = f"{uuid.uuid4().hex}{extension}"
    storage_path = UPLOADS_DIR / storage_filename
    try:
        UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
        storage_path.write_bytes(content)
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store uploaded file",
        ) from exc
    return storage_path


def _parse_category(raw: str | None) -> DocumentCategory:
    """Convert a category string to a DocumentCategory enum, defaulting to OTHER."""
    if not raw:
        return DocumentCategory.OTHER
    try:
        return DocumentCategory(raw.lower().strip())
    except ValueError:
        return DocumentCategory.OTHER


def _get_document(document_id: UUID, user: User, db: Session) -> Document:
    document = (
        db.query(Document)
        .filter(Document.id == document_id, Document.owner_user_id == user.id)
        .first()
    )
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Document not found"
        )
    return document


def _get_share_token_user(token_str: str, db: Session) -> User:
    """Validate a share token and return the owning User. Marks the token as used."""
    share_token = db.query(ShareToken).filter(ShareToken.token == token_str).first()
    if not share_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid share token",
        )
    if share_token.is_used:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Share token has already been used",
        )
    if share_token.is_expired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Share token has expired",
        )

    # Mark as used
    share_token.is_used = True
    db.flush()

    user = db.query(User).filter(User.id == share_token.user_id, User.is_active).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or inactive",
        )
    return user


# ── Standard document CRUD ────────────────────────────────────────────────────


@router.post("", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
def upload_document(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(...),
    description: str | None = Form(None),
    category: str | None = Form(None),
    source_app: str | None = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not title.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Title cannot be empty"
        )

    original_filename, extension = _validate_upload_file(file)
    content = file.file.read()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty"
        )
    _validate_file_size(content)

    storage_path = _store_file(content, extension)

    document = Document(
        owner_user_id=current_user.id,
        title=title.strip(),
        description=description.strip() if description else None,
        original_filename=original_filename,
        content_type=file.content_type,
        file_path=str(storage_path),
        size_bytes=len(content),
        category=_parse_category(category),
        source_app=source_app.strip().lower() if source_app else "direct_upload",
        is_shared_upload=False,
    )
    db.add(document)
    db.commit()
    db.refresh(document)

    ip = request.client.host if request.client else None
    log_event(
        db,
        "UPLOAD_DOCUMENT",
        "Document",
        str(document.id),
        current_user.id,
        ip_address=ip,
    )
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Document file not found"
        )

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
    log_event(
        db,
        "DELETE_DOCUMENT",
        "Document",
        str(document.id),
        current_user.id,
        ip_address=ip,
    )


# ── Share-intent endpoints ────────────────────────────────────────────────────


@router.post(
    "/share-token", response_model=ShareTokenOut, status_code=status.HTTP_201_CREATED
)
def create_share_token(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a short-lived upload token for use by mobile share extensions.

    The authenticated user calls this endpoint with their regular JWT.
    The returned token can then be passed to ``POST /share-upload`` without
    a JWT — this is essential because mobile share extensions run in a
    sandboxed process with limited access to the host app's keychain.
    """
    token_str = secrets.token_urlsafe(64)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.SHARE_TOKEN_EXPIRE_MINUTES
    )

    share_token = ShareToken(
        user_id=current_user.id,
        token=token_str,
        expires_at=expires_at,
    )
    db.add(share_token)
    db.commit()
    db.refresh(share_token)

    ip = request.client.host if request.client else None
    log_event(
        db,
        "SHARE_TOKEN_CREATED",
        "ShareToken",
        str(share_token.id),
        current_user.id,
        ip_address=ip,
    )

    return ShareTokenOut(token=token_str, expires_at=expires_at)


@router.post(
    "/share-upload", response_model=ShareUploadOut, status_code=status.HTTP_201_CREATED
)
def share_upload(
    request: Request,
    files: List[UploadFile] = File(...),
    share_token: str = Form(...),
    category: str | None = Form(None),
    source_app: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """Upload one or more files using a short-lived share token.

    This endpoint does NOT require a JWT. Instead it validates the
    ``share_token`` form field generated via ``POST /share-token``.

    Up to ``MAX_SHARE_UPLOAD_FILES`` files may be uploaded in a single request.
    Each file is validated for extension, content type, and size.
    """
    # Validate share token and get the user
    user = _get_share_token_user(share_token, db)

    if len(files) > settings.MAX_SHARE_UPLOAD_FILES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Maximum {settings.MAX_SHARE_UPLOAD_FILES} files per share upload.",
        )

    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one file is required.",
        )

    doc_category = _parse_category(category)
    src = source_app.strip().lower() if source_app else "shared"
    uploaded_docs: list[Document] = []

    for file in files:
        original_filename, extension = _validate_upload_file(file, relaxed=True)
        content = file.file.read()
        if not content:
            continue  # skip empty files silently

        _validate_file_size(content)
        storage_path = _store_file(content, extension)

        # Use the original filename as the title for shared uploads
        title = Path(original_filename).stem or "Shared Document"

        document = Document(
            owner_user_id=user.id,
            title=title,
            description=f"Shared from {src}",
            original_filename=original_filename,
            content_type=file.content_type
            or ALLOWED_FILE_TYPES.get(extension, "application/octet-stream"),
            file_path=str(storage_path),
            size_bytes=len(content),
            category=doc_category,
            source_app=src,
            is_shared_upload=True,
        )
        db.add(document)
        uploaded_docs.append(document)

    if not uploaded_docs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="All uploaded files were empty.",
        )

    db.commit()
    for doc in uploaded_docs:
        db.refresh(doc)

    ip = request.client.host if request.client else None
    for doc in uploaded_docs:
        log_event(
            db, "SHARE_UPLOAD_DOCUMENT", "Document", str(doc.id), user.id, ip_address=ip
        )

    return ShareUploadOut(uploaded=uploaded_docs, total_files=len(uploaded_docs))
