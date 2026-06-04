import shutil
from io import BytesIO
from pathlib import Path
from uuid import UUID

import pytest
from app.models.document import Document


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


def test_document_upload_list_download_delete(client, db):
    auth = register_and_login(client, "+919000000001")
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
    owner_auth = register_and_login(client, "+919000000002")
    other_auth = register_and_login(client, "+919000000003")

    upload_resp = client.post(
        "/api/v1/documents",
        headers={"Authorization": owner_auth},
        files={"file": ("scan.png", BytesIO(b"PNGDATA"), "image/png")},
        data={"title": "Passport", "description": "Front page scan"},
    )
    assert upload_resp.status_code == 201
    document_id = upload_resp.json()["id"]

    view_resp = client.get(f"/api/v1/documents/{document_id}", headers={"Authorization": other_auth})
    assert view_resp.status_code == 404

    download_resp = client.get(f"/api/v1/documents/{document_id}/download", headers={"Authorization": other_auth})
    assert download_resp.status_code == 404

    delete_resp = client.delete(f"/api/v1/documents/{document_id}", headers={"Authorization": other_auth})
    assert delete_resp.status_code == 404
