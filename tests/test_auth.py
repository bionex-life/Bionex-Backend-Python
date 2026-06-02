"""Auth router integration tests against a real PostgreSQL test database."""


def test_register_patient(client):
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Priya Sharma",
            "phone": "+919876543210",
            "password": "SecurePass1!",
            "role": "PATIENT",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["phone"] == "+919876543210"
    assert data["role"] == "PATIENT"
    assert "hashed_password" not in data


def test_duplicate_registration(client):
    payload = {
        "name": "Priya Sharma",
        "phone": "+919876543210",
        "password": "SecurePass1!",
        "role": "PATIENT",
    }
    client.post("/api/v1/auth/register", json=payload)
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 409


def test_login_success(client):
    client.post(
        "/api/v1/auth/register",
        json={"name": "Raj K", "phone": "+912345678901", "password": "SecurePass1!", "role": "PATIENT"},
    )
    resp = client.post(
        "/api/v1/auth/login",
        json={"phone": "+912345678901", "password": "SecurePass1!"},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()
    assert resp.json()["role"] == "PATIENT"


def test_login_wrong_password(client):
    client.post(
        "/api/v1/auth/register",
        json={"name": "Raj K", "phone": "+912345678901", "password": "SecurePass1!", "role": "PATIENT"},
    )
    resp = client.post(
        "/api/v1/auth/login",
        json={"phone": "+912345678901", "password": "WrongPassword1!"},
    )
    assert resp.status_code == 401


def test_protected_endpoint_without_token(client):
    resp = client.get("/api/v1/patients/me")
    assert resp.status_code == 401
