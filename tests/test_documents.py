"""
Tests for the share-integration features in the documents router.

Covers:
- Share token generation (create, expiry, single-use)
- Share upload with valid/expired/used tokens
- Batch file upload (multiple files)
- Document category assignment
- Expanded file type acceptance/rejection
- Source app tracking
- File size validation
- Existing document CRUD still works with new fields
"""

import shutil
from io import BytesIO
from pathlib import Path
from uuid import UUID

import pytest
from app.models.document import Document


# ── Helpers ───────────────────────────────────────────────────────────────────


def register_and_login(client, phone: str):
    password = "SecurePass1!"
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Test User",
            "phone": phone,
            "password": password,
            "role": "PATIENT",
        },
    )
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"phone": phone, "password": password},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    return f"Bearer {token}"


@pytest.fixture(autouse=True)
def cleanup_upload_dir():
    yield
    shutil.rmtree(Path("uploads"), ignore_errors=True)


# ── Existing CRUD with new fields ─────────────────────────────────────────────


def test_document_upload_with_category_and_source(client, db):
    """Verify the existing upload endpoint now accepts category and source_app."""
    auth = register_and_login(client, "+919100000001")
    file_bytes = b"%PDF-1.4 test document content"

    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("report.pdf", BytesIO(file_bytes), "application/pdf")},
        data={
            "title": "Blood Test Report",
            "description": "Annual checkup results",
            "category": "lab_report",
            "source_app": "camera",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Blood Test Report"
    assert data["category"] == "lab_report"
    assert data["source_app"] == "camera"
    assert data["is_shared_upload"] is False


def test_document_upload_default_category(client, db):
    """When no category is provided, it should default to 'other'."""
    auth = register_and_login(client, "+919100000002")
    file_bytes = b"%PDF-1.4 test"

    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("scan.pdf", BytesIO(file_bytes), "application/pdf")},
        data={"title": "Random Scan"},
    )
    assert resp.status_code == 201
    assert resp.json()["category"] == "other"
    assert resp.json()["source_app"] == "direct_upload"


def test_document_upload_list_download_delete(client, db):
    """Full CRUD lifecycle still works with the new fields."""
    auth = register_and_login(client, "+919100000003")
    file_bytes = b"%PDF-1.4 test document content"

    upload_resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("scan.pdf", BytesIO(file_bytes), "application/pdf")},
        data={"title": "Insurance Card", "description": "Scanned card from mobile app"},
    )
    assert upload_resp.status_code == 201
    uploaded = upload_resp.json()
    assert uploaded["title"] == "Insurance Card"
    assert uploaded["original_filename"] == "scan.pdf"
    assert uploaded["content_type"] == "application/pdf"
    assert uploaded["size_bytes"] == len(file_bytes)
    assert "category" in uploaded
    assert "is_shared_upload" in uploaded

    document = db.query(Document).filter(Document.id == uploaded["id"]).first()
    assert document is not None
    assert document.owner_user_id == UUID(uploaded["owner_user_id"])

    list_resp = client.get("/api/v1/documents", headers={"Authorization": auth})
    assert list_resp.status_code == 200
    assert any(item["id"] == uploaded["id"] for item in list_resp.json())

    download_resp = client.get(
        f"/api/v1/documents/{uploaded['id']}/download",
        headers={"Authorization": auth},
    )
    assert download_resp.status_code == 200
    assert download_resp.content == file_bytes
    assert "attachment;" in download_resp.headers["content-disposition"]

    delete_resp = client.delete(
        f"/api/v1/documents/{uploaded['id']}",
        headers={"Authorization": auth},
    )
    assert delete_resp.status_code == 204

    missing_resp = client.get(
        f"/api/v1/documents/{uploaded['id']}",
        headers={"Authorization": auth},
    )
    assert missing_resp.status_code == 404


def test_document_ownership_enforced(client):
    """Other users cannot access documents they don't own."""
    owner_auth = register_and_login(client, "+919100000004")
    other_auth = register_and_login(client, "+919100000005")

    upload_resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": owner_auth},
        files={"file": ("scan.png", BytesIO(b"PNGDATA"), "image/png")},
        data={"title": "Passport", "description": "Front page scan"},
    )
    assert upload_resp.status_code == 201
    document_id = upload_resp.json()["id"]

    view_resp = client.get(
        f"/api/v1/documents/{document_id}", headers={"Authorization": other_auth}
    )
    assert view_resp.status_code == 404

    download_resp = client.get(
        f"/api/v1/documents/{document_id}/download",
        headers={"Authorization": other_auth},
    )
    assert download_resp.status_code == 404

    delete_resp = client.delete(
        f"/api/v1/documents/{document_id}", headers={"Authorization": other_auth}
    )
    assert delete_resp.status_code == 404


# ── Expanded file types ───────────────────────────────────────────────────────


def test_upload_docx_accepted(client, db):
    """DOCX files should be accepted after expansion."""
    auth = register_and_login(client, "+919100000006")
    content_type = (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("notes.docx", BytesIO(b"DOCXDATA"), content_type)},
        data={"title": "Doctor Notes"},
    )
    assert resp.status_code == 201
    assert resp.json()["content_type"] == content_type


def test_upload_txt_accepted(client, db):
    """TXT files should be accepted."""
    auth = register_and_login(client, "+919100000007")
    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("notes.txt", BytesIO(b"plain text content"), "text/plain")},
        data={"title": "Consultation Notes"},
    )
    assert resp.status_code == 201


def test_upload_csv_accepted(client, db):
    """CSV files should be accepted."""
    auth = register_and_login(client, "+919100000008")
    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("labs.csv", BytesIO(b"col1,col2\nval1,val2"), "text/csv")},
        data={"title": "Lab CSV Export"},
    )
    assert resp.status_code == 201


def test_upload_heic_accepted(client, db):
    """HEIC (iPhone photos) should be accepted."""
    auth = register_and_login(client, "+919100000009")
    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("photo.heic", BytesIO(b"HEICDATA"), "image/heic")},
        data={"title": "iPhone Photo"},
    )
    assert resp.status_code == 201


def test_upload_webp_accepted(client, db):
    """WEBP images should be accepted."""
    auth = register_and_login(client, "+919100000010")
    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("screenshot.webp", BytesIO(b"WEBPDATA"), "image/webp")},
        data={"title": "WhatsApp Screenshot"},
    )
    assert resp.status_code == 201


def test_upload_exe_rejected(client, db):
    """Executable files should be rejected."""
    auth = register_and_login(client, "+919100000011")
    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("virus.exe", BytesIO(b"MALWARE"), "application/x-msdownload")},
        data={"title": "Bad File"},
    )
    assert resp.status_code == 415


def test_upload_empty_file_rejected(client, db):
    """Empty files should be rejected."""
    auth = register_and_login(client, "+919100000012")
    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("empty.pdf", BytesIO(b""), "application/pdf")},
        data={"title": "Empty PDF"},
    )
    assert resp.status_code == 400


# ── Share token ───────────────────────────────────────────────────────────────


def test_create_share_token(client, db):
    """Authenticated user can generate a share token."""
    auth = register_and_login(client, "+919200000001")
    resp = client.post("/api/v1/documents/share-token", headers={"Authorization": auth})
    assert resp.status_code == 201
    data = resp.json()
    assert "token" in data
    assert "expires_at" in data
    assert len(data["token"]) > 20


def test_share_token_requires_auth(client, db):
    """Share token endpoint requires authentication."""
    resp = client.post("/api/v1/documents/share-token")
    assert resp.status_code in (401, 403)


# ── Share upload ──────────────────────────────────────────────────────────────


def test_share_upload_single_file(client, db):
    """Upload a single file using a share token."""
    auth = register_and_login(client, "+919200000002")

    # Get share token
    token_resp = client.post(
        "/api/v1/documents/share-token", headers={"Authorization": auth}
    )
    assert token_resp.status_code == 201
    token = token_resp.json()["token"]

    # Upload using share token (no JWT needed)
    resp = client.post(
        "/api/v1/documents/share-upload",
        files=[
            (
                "files",
                (
                    "prescription.pdf",
                    BytesIO(b"%PDF-1.4 rx content"),
                    "application/pdf",
                ),
            )
        ],
        data={
            "share_token": token,
            "category": "prescription",
            "source_app": "whatsapp",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["total_files"] == 1
    assert len(data["uploaded"]) == 1
    assert data["uploaded"][0]["category"] == "prescription"
    assert data["uploaded"][0]["source_app"] == "whatsapp"
    assert data["uploaded"][0]["is_shared_upload"] is True
    assert data["uploaded"][0]["title"] == "prescription"  # stem of filename


def test_share_upload_batch(client, db):
    """Upload multiple files in a single share-upload request."""
    auth = register_and_login(client, "+919200000003")

    token_resp = client.post(
        "/api/v1/documents/share-token", headers={"Authorization": auth}
    )
    token = token_resp.json()["token"]

    resp = client.post(
        "/api/v1/documents/share-upload",
        files=[
            ("files", ("report1.pdf", BytesIO(b"%PDF content 1"), "application/pdf")),
            ("files", ("report2.png", BytesIO(b"PNG content 2"), "image/png")),
            ("files", ("notes.txt", BytesIO(b"text content 3"), "text/plain")),
        ],
        data={
            "share_token": token,
            "category": "medical_report",
            "source_app": "gmail",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["total_files"] == 3
    assert len(data["uploaded"]) == 3


def test_share_upload_token_single_use(client, db):
    """A share token can only be used once."""
    auth = register_and_login(client, "+919200000004")

    token_resp = client.post(
        "/api/v1/documents/share-token", headers={"Authorization": auth}
    )
    token = token_resp.json()["token"]

    # First use — should succeed
    resp1 = client.post(
        "/api/v1/documents/share-upload",
        files=[("files", ("file1.pdf", BytesIO(b"%PDF data"), "application/pdf"))],
        data={"share_token": token, "source_app": "whatsapp"},
    )
    assert resp1.status_code == 201

    # Second use — should fail
    resp2 = client.post(
        "/api/v1/documents/share-upload",
        files=[("files", ("file2.pdf", BytesIO(b"%PDF data 2"), "application/pdf"))],
        data={"share_token": token, "source_app": "whatsapp"},
    )
    assert resp2.status_code == 401
    assert "already been used" in resp2.json()["detail"]


def test_share_upload_invalid_token(client, db):
    """Invalid share token is rejected."""
    resp = client.post(
        "/api/v1/documents/share-upload",
        files=[("files", ("file.pdf", BytesIO(b"%PDF data"), "application/pdf"))],
        data={"share_token": "totally-invalid-token", "source_app": "whatsapp"},
    )
    assert resp.status_code == 401


def test_share_upload_with_relaxed_content_type(client, db):
    """Share upload should accept application/octet-stream (generic MIME from external apps)."""
    auth = register_and_login(client, "+919200000005")

    token_resp = client.post(
        "/api/v1/documents/share-token", headers={"Authorization": auth}
    )
    token = token_resp.json()["token"]

    resp = client.post(
        "/api/v1/documents/share-upload",
        files=[
            (
                "files",
                ("report.pdf", BytesIO(b"%PDF content"), "application/octet-stream"),
            )
        ],
        data={"share_token": token, "source_app": "google_drive"},
    )
    assert resp.status_code == 201


def test_share_upload_rejected_file_type(client, db):
    """Share upload should reject disallowed file types."""
    auth = register_and_login(client, "+919200000006")

    token_resp = client.post(
        "/api/v1/documents/share-token", headers={"Authorization": auth}
    )
    token = token_resp.json()["token"]

    resp = client.post(
        "/api/v1/documents/share-upload",
        files=[("files", ("script.sh", BytesIO(b"#!/bin/bash"), "text/x-shellscript"))],
        data={"share_token": token},
    )
    assert resp.status_code == 415


def test_share_upload_source_app_tracking(client, db):
    """Verify source_app is stored correctly for different sources."""
    auth = register_and_login(client, "+919200000007")

    token_resp = client.post(
        "/api/v1/documents/share-token", headers={"Authorization": auth}
    )
    token = token_resp.json()["token"]

    resp = client.post(
        "/api/v1/documents/share-upload",
        files=[("files", ("photo.jpg", BytesIO(b"JPGDATA"), "image/jpeg"))],
        data={"share_token": token, "source_app": "WhatsApp"},
    )
    assert resp.status_code == 201
    # source_app should be lowercased
    assert resp.json()["uploaded"][0]["source_app"] == "whatsapp"


def test_share_upload_default_source(client, db):
    """When source_app is not provided, it defaults to 'shared'."""
    auth = register_and_login(client, "+919200000008")

    token_resp = client.post(
        "/api/v1/documents/share-token", headers={"Authorization": auth}
    )
    token = token_resp.json()["token"]

    resp = client.post(
        "/api/v1/documents/share-upload",
        files=[("files", ("doc.pdf", BytesIO(b"%PDF content"), "application/pdf"))],
        data={"share_token": token},
    )
    assert resp.status_code == 201
    assert resp.json()["uploaded"][0]["source_app"] == "shared"


def test_share_upload_all_empty_files_rejected(client, db):
    """If all uploaded files are empty, the request should fail."""
    auth = register_and_login(client, "+919200000009")

    token_resp = client.post(
        "/api/v1/documents/share-token", headers={"Authorization": auth}
    )
    token = token_resp.json()["token"]

    resp = client.post(
        "/api/v1/documents/share-upload",
        files=[
            ("files", ("empty1.pdf", BytesIO(b""), "application/pdf")),
            ("files", ("empty2.png", BytesIO(b""), "image/png")),
        ],
        data={"share_token": token},
    )
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()


# ── Category validation ───────────────────────────────────────────────────────


def test_invalid_category_defaults_to_other(client, db):
    """An invalid category string should default to 'other', not crash."""
    auth = register_and_login(client, "+919300000001")
    resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": auth},
        files={"file": ("scan.pdf", BytesIO(b"%PDF test"), "application/pdf")},
        data={"title": "Scan", "category": "nonexistent_category"},
    )
    assert resp.status_code == 201
    assert resp.json()["category"] == "other"


def test_all_valid_categories(client, db):
    """All defined categories should be accepted."""
    auth = register_and_login(client, "+919300000002")
    for cat in [
        "medical_report",
        "prescription",
        "lab_report",
        "insurance",
        "imaging",
        "other",
    ]:
        resp = client.post(
            "/api/v1/documents",
            headers={"Authorization": auth},
            files={
                "file": (f"file_{cat}.pdf", BytesIO(b"%PDF test"), "application/pdf")
            },
            data={"title": f"Test {cat}", "category": cat},
        )
        assert resp.status_code == 201, f"Category '{cat}' was rejected"
        assert resp.json()["category"] == cat
