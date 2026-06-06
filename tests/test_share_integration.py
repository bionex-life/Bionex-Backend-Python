"""
Standalone integration tests for share-integration features.

Uses an in-memory SQLite database so tests run without PostgreSQL.
This file validates all endpoint logic end-to-end.
"""

import shutil
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

# ── Patch the config BEFORE importing app modules ─────────────────────────────
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests-only-32chars!!")
os.environ.setdefault(
    "FIELD_ENCRYPTION_KEY", "dGVzdC1rZXktZm9yLXVuaXQtdGVzdHMtb25seQ=="
)
os.environ.setdefault("DEBUG", "true")

# Monkey-patch JSONB -> JSON and UUID -> String for SQLite BEFORE models are imported
from sqlalchemy.dialects.sqlite import base as sqlite_base

sqlite_base.SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"
sqlite_base.SQLiteTypeCompiler.visit_UUID = lambda self, type_, **kw: "VARCHAR(36)"

from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402

# Disable rate limiting
app.state.limiter.enabled = False
from app.routers.auth import limiter as auth_limiter  # noqa: E402

auth_limiter.enabled = False

# ── SQLite in-memory engine ───────────────────────────────────────────────────
# The project uses schema="bionex" for all tables (PostgreSQL). SQLite doesn't
# have schemas but supports ATTACH DATABASE to simulate them. By attaching a
# second in-memory DB as "bionex", SQLAlchemy's `bionex.users` references resolve.

from sqlalchemy.pool import StaticPool  # noqa: E402

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    # Attach a second in-memory database named "bionex" so that
    # SQLAlchemy's schema-qualified queries (bionex.users, etc.) work.
    cursor.execute("ATTACH DATABASE ':memory:' AS bionex")
    cursor.close()


TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    """Create all tables in the 'bionex' schema, yield a session, then drop."""
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    """FastAPI TestClient that uses the SQLite test DB."""

    def override_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def cleanup_upload_dir():
    yield
    shutil.rmtree(Path("uploads"), ignore_errors=True)


# ── Helpers ───────────────────────────────────────────────────────────────────


def register_and_login(client, phone: str):
    password = "SecurePass1!"
    reg = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Test User",
            "phone": phone,
            "password": password,
            "role": "PATIENT",
        },
    )
    assert reg.status_code == 201, f"Register failed ({reg.status_code}): {reg.json()}"
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"phone": phone, "password": password},
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.json()}"
    return f"Bearer {login_resp.json()['access_token']}"


# ══════════════════════════════════════════════════════════════════════════════
# Test Suite
# ══════════════════════════════════════════════════════════════════════════════


class TestDocumentUploadWithNewFields:
    """Verify existing upload endpoint works with new category/source_app fields."""

    def test_upload_with_category_and_source(self, client, db):
        auth = register_and_login(client, "+919100000001")
        resp = client.post(
            "/api/v1/documents",
            headers={"Authorization": auth},
            files={
                "file": ("report.pdf", BytesIO(b"%PDF-1.4 test"), "application/pdf")
            },
            data={
                "title": "Blood Test",
                "category": "lab_report",
                "source_app": "camera",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["category"] == "lab_report"
        assert data["source_app"] == "camera"
        assert data["is_shared_upload"] is False

    def test_default_category(self, client, db):
        auth = register_and_login(client, "+919100000002")
        resp = client.post(
            "/api/v1/documents",
            headers={"Authorization": auth},
            files={"file": ("scan.pdf", BytesIO(b"%PDF-1.4"), "application/pdf")},
            data={"title": "Scan"},
        )
        assert resp.status_code == 201
        assert resp.json()["category"] == "other"
        assert resp.json()["source_app"] == "direct_upload"

    def test_invalid_category_defaults_to_other(self, client, db):
        auth = register_and_login(client, "+919100000003")
        resp = client.post(
            "/api/v1/documents",
            headers={"Authorization": auth},
            files={"file": ("x.pdf", BytesIO(b"%PDF"), "application/pdf")},
            data={"title": "X", "category": "nonexistent_xyz"},
        )
        assert resp.status_code == 201
        assert resp.json()["category"] == "other"


class TestDocumentCRUD:
    """Full CRUD lifecycle with new fields."""

    def test_upload_list_download_delete(self, client, db):
        auth = register_and_login(client, "+919100000010")
        file_bytes = b"%PDF-1.4 test doc content"

        up = client.post(
            "/api/v1/documents",
            headers={"Authorization": auth},
            files={"file": ("scan.pdf", BytesIO(file_bytes), "application/pdf")},
            data={"title": "Insurance Card"},
        )
        assert up.status_code == 201
        doc = up.json()
        assert doc["title"] == "Insurance Card"
        assert doc["size_bytes"] == len(file_bytes)
        assert "category" in doc

        lst = client.get("/api/v1/documents", headers={"Authorization": auth})
        assert lst.status_code == 200
        assert any(d["id"] == doc["id"] for d in lst.json())

        dl = client.get(
            f"/api/v1/documents/{doc['id']}/download", headers={"Authorization": auth}
        )
        assert dl.status_code == 200
        assert dl.content == file_bytes

        rm = client.delete(
            f"/api/v1/documents/{doc['id']}", headers={"Authorization": auth}
        )
        assert rm.status_code == 204

        gone = client.get(
            f"/api/v1/documents/{doc['id']}", headers={"Authorization": auth}
        )
        assert gone.status_code == 404

    def test_ownership_enforced(self, client, db):
        owner = register_and_login(client, "+919100000011")
        other = register_and_login(client, "+919100000012")

        up = client.post(
            "/api/v1/documents",
            headers={"Authorization": owner},
            files={"file": ("s.png", BytesIO(b"PNG"), "image/png")},
            data={"title": "Passport"},
        )
        assert up.status_code == 201
        doc_id = up.json()["id"]

        assert (
            client.get(
                f"/api/v1/documents/{doc_id}", headers={"Authorization": other}
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/documents/{doc_id}/download", headers={"Authorization": other}
            ).status_code
            == 404
        )
        assert (
            client.delete(
                f"/api/v1/documents/{doc_id}", headers={"Authorization": other}
            ).status_code
            == 404
        )


class TestExpandedFileTypes:
    """Verify expanded file type support."""

    @pytest.mark.parametrize(
        "filename,content_type",
        [
            (
                "notes.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            ("notes.txt", "text/plain"),
            ("labs.csv", "text/csv"),
            ("photo.heic", "image/heic"),
            ("img.webp", "image/webp"),
            ("scan.tiff", "image/tiff"),
            ("scan.tif", "image/tiff"),
            ("doc.doc", "application/msword"),
        ],
    )
    def test_accepted_types(self, client, db, filename, content_type):
        auth = register_and_login(client, f"+91910{abs(hash(filename)) % 100000:05d}")
        resp = client.post(
            "/api/v1/documents",
            headers={"Authorization": auth},
            files={"file": (filename, BytesIO(b"content"), content_type)},
            data={"title": f"Test {filename}"},
        )
        assert resp.status_code == 201, (
            f"{filename} ({content_type}) was rejected: {resp.json()}"
        )

    def test_exe_rejected(self, client, db):
        auth = register_and_login(client, "+919100000020")
        resp = client.post(
            "/api/v1/documents",
            headers={"Authorization": auth},
            files={"file": ("virus.exe", BytesIO(b"BAD"), "application/x-msdownload")},
            data={"title": "Bad"},
        )
        assert resp.status_code == 415

    def test_empty_file_rejected(self, client, db):
        auth = register_and_login(client, "+919100000021")
        resp = client.post(
            "/api/v1/documents",
            headers={"Authorization": auth},
            files={"file": ("e.pdf", BytesIO(b""), "application/pdf")},
            data={"title": "Empty"},
        )
        assert resp.status_code == 400


class TestShareToken:
    """Share token generation and validation."""

    def test_create_share_token(self, client, db):
        auth = register_and_login(client, "+919200000001")
        resp = client.post(
            "/api/v1/documents/share-token", headers={"Authorization": auth}
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "token" in data
        assert "expires_at" in data
        assert len(data["token"]) > 20

    def test_share_token_requires_auth(self, client, db):
        resp = client.post("/api/v1/documents/share-token")
        assert resp.status_code in (401, 403)


class TestShareUpload:
    """Share upload endpoint (token-based, batch support)."""

    def test_single_file(self, client, db):
        auth = register_and_login(client, "+919200000010")
        token = client.post(
            "/api/v1/documents/share-token", headers={"Authorization": auth}
        ).json()["token"]

        resp = client.post(
            "/api/v1/documents/share-upload",
            files=[("files", ("rx.pdf", BytesIO(b"%PDF rx"), "application/pdf"))],
            data={
                "share_token": token,
                "category": "prescription",
                "source_app": "whatsapp",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["total_files"] == 1
        assert data["uploaded"][0]["category"] == "prescription"
        assert data["uploaded"][0]["source_app"] == "whatsapp"
        assert data["uploaded"][0]["is_shared_upload"] is True
        assert data["uploaded"][0]["title"] == "rx"

    def test_batch_upload(self, client, db):
        auth = register_and_login(client, "+919200000011")
        token = client.post(
            "/api/v1/documents/share-token", headers={"Authorization": auth}
        ).json()["token"]

        resp = client.post(
            "/api/v1/documents/share-upload",
            files=[
                ("files", ("r1.pdf", BytesIO(b"%PDF 1"), "application/pdf")),
                ("files", ("r2.png", BytesIO(b"PNG 2"), "image/png")),
                ("files", ("r3.txt", BytesIO(b"text 3"), "text/plain")),
            ],
            data={
                "share_token": token,
                "category": "medical_report",
                "source_app": "gmail",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["total_files"] == 3

    def test_token_single_use(self, client, db):
        auth = register_and_login(client, "+919200000012")
        token = client.post(
            "/api/v1/documents/share-token", headers={"Authorization": auth}
        ).json()["token"]

        r1 = client.post(
            "/api/v1/documents/share-upload",
            files=[("files", ("a.pdf", BytesIO(b"%PDF"), "application/pdf"))],
            data={"share_token": token},
        )
        assert r1.status_code == 201

        r2 = client.post(
            "/api/v1/documents/share-upload",
            files=[("files", ("b.pdf", BytesIO(b"%PDF 2"), "application/pdf"))],
            data={"share_token": token},
        )
        assert r2.status_code == 401
        assert "already been used" in r2.json()["detail"]

    def test_invalid_token(self, client, db):
        resp = client.post(
            "/api/v1/documents/share-upload",
            files=[("files", ("x.pdf", BytesIO(b"%PDF"), "application/pdf"))],
            data={"share_token": "totally-bogus-token"},
        )
        assert resp.status_code == 401

    def test_relaxed_content_type(self, client, db):
        auth = register_and_login(client, "+919200000013")
        token = client.post(
            "/api/v1/documents/share-token", headers={"Authorization": auth}
        ).json()["token"]

        resp = client.post(
            "/api/v1/documents/share-upload",
            files=[("files", ("r.pdf", BytesIO(b"%PDF"), "application/octet-stream"))],
            data={"share_token": token, "source_app": "google_drive"},
        )
        assert resp.status_code == 201

    def test_rejected_file_type(self, client, db):
        auth = register_and_login(client, "+919200000014")
        token = client.post(
            "/api/v1/documents/share-token", headers={"Authorization": auth}
        ).json()["token"]

        resp = client.post(
            "/api/v1/documents/share-upload",
            files=[("files", ("s.sh", BytesIO(b"#!/bin/bash"), "text/x-shellscript"))],
            data={"share_token": token},
        )
        assert resp.status_code == 415

    def test_source_app_lowered(self, client, db):
        auth = register_and_login(client, "+919200000015")
        token = client.post(
            "/api/v1/documents/share-token", headers={"Authorization": auth}
        ).json()["token"]

        resp = client.post(
            "/api/v1/documents/share-upload",
            files=[("files", ("p.jpg", BytesIO(b"JPG"), "image/jpeg"))],
            data={"share_token": token, "source_app": "WhatsApp"},
        )
        assert resp.status_code == 201
        assert resp.json()["uploaded"][0]["source_app"] == "whatsapp"

    def test_default_source(self, client, db):
        auth = register_and_login(client, "+919200000016")
        token = client.post(
            "/api/v1/documents/share-token", headers={"Authorization": auth}
        ).json()["token"]

        resp = client.post(
            "/api/v1/documents/share-upload",
            files=[("files", ("d.pdf", BytesIO(b"%PDF"), "application/pdf"))],
            data={"share_token": token},
        )
        assert resp.status_code == 201
        assert resp.json()["uploaded"][0]["source_app"] == "shared"

    def test_all_empty_files_rejected(self, client, db):
        auth = register_and_login(client, "+919200000017")
        token = client.post(
            "/api/v1/documents/share-token", headers={"Authorization": auth}
        ).json()["token"]

        resp = client.post(
            "/api/v1/documents/share-upload",
            files=[
                ("files", ("e1.pdf", BytesIO(b""), "application/pdf")),
                ("files", ("e2.png", BytesIO(b""), "image/png")),
            ],
            data={"share_token": token},
        )
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()


class TestAllCategories:
    """Verify all defined categories are accepted."""

    @pytest.mark.parametrize(
        "cat",
        [
            "medical_report",
            "prescription",
            "lab_report",
            "insurance",
            "imaging",
            "other",
        ],
    )
    def test_category_accepted(self, client, db, cat):
        auth = register_and_login(client, f"+91930{abs(hash(cat)) % 100000:05d}")
        resp = client.post(
            "/api/v1/documents",
            headers={"Authorization": auth},
            files={"file": (f"{cat}.pdf", BytesIO(b"%PDF"), "application/pdf")},
            data={"title": f"Test {cat}", "category": cat},
        )
        assert resp.status_code == 201
        assert resp.json()["category"] == cat
