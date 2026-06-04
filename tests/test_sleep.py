from datetime import datetime, timezone, timedelta
import time
import pytest
from sqlalchemy import func, text

from app.models.sleep_log import SleepLog
from app.models.user_daily_health import UserDailyHealth


@pytest.fixture(autouse=True)
def set_utc_timezone(db):
    db.execute(text("SET TIME ZONE 'UTC'"))


_last_register_time = 0.0


def register_and_login(client, phone, password="SecurePass1!", role="PATIENT"):
    global _last_register_time
    now = time.time()
    elapsed = now - _last_register_time
    if elapsed < 12.1:
        time.sleep(12.1 - elapsed)
    _last_register_time = time.time()

    # Register
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Test User",
            "phone": phone,
            "email": f"{phone.replace('+', '')}@example.com",
            "password": password,
            "role": role,
        },
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    # Login
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"phone": phone, "password": password},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    return token, user_id


def test_sleep_validation_errors(client):
    token, user_id = register_and_login(client, "+918888888881")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Invalid sleep_type
    resp = client.post(
        f"/api/v1/sleep/{user_id}",
        json={
            "records": [
                {
                    "from": "2025-06-03T22:00:00Z",
                    "to": "2025-06-04T06:00:00Z",
                    "sleep_type": "deep_sleep"  # invalid type
                }
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 400

    # 2. from >= to
    resp = client.post(
        f"/api/v1/sleep/{user_id}",
        json={
            "records": [
                {
                    "from": "2025-06-04T06:00:00Z",
                    "to": "2025-06-03T22:00:00Z",
                    "sleep_type": "main"
                }
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 400

    # 3. from == to
    resp = client.post(
        f"/api/v1/sleep/{user_id}",
        json={
            "records": [
                {
                    "from": "2025-06-04T06:00:00Z",
                    "to": "2025-06-04T06:00:00Z",
                    "sleep_type": "main"
                }
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 400


def test_sleep_unauthorized_access(client):
    token1, user_id1 = register_and_login(client, "+918888898282")
    token2, user_id2 = register_and_login(client, "+919876543211")

    headers1 = {"Authorization": f"Bearer {token1}"}

    # User 1 tries to ingest sleep for User 2
    resp = client.post(
        f"/api/v1/sleep/{user_id2}",
        json={
            "records": [
                {
                    "from": "2025-06-03T22:00:00Z",
                    "to": "2025-06-04T06:00:00Z",
                    "sleep_type": "main"
                }
            ]
        },
        headers=headers1,
    )
    assert resp.status_code == 403


def test_sleep_ingest_no_overlap(client, db):
    token, user_id = register_and_login(client, "+918888888884")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        f"/api/v1/sleep/{user_id}",
        json={
            "records": [
                {
                    "from": "2025-06-03T22:00:00Z",
                    "to": "2025-06-04T06:30:00Z",
                    "sleep_type": "main"
                },
                {
                    "from": "2025-06-04T14:00:00Z",
                    "to": "2025-06-04T15:30:00Z",
                    "sleep_type": "nap"
                }
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 201

    # Verify database state
    logs = db.query(SleepLog).filter(SleepLog.user_id == user_id).order_by(SleepLog.period_from).all()
    assert len(logs) == 2
    
    # Check record 1
    assert logs[0].sleep_type == "main"
    assert logs[0].period_from == datetime(2025, 6, 3, 22, 0, tzinfo=timezone.utc)
    assert logs[0].period_to == datetime(2025, 6, 4, 6, 30, tzinfo=timezone.utc)

    # Check record 2
    assert logs[1].sleep_type == "nap"
    assert logs[1].period_from == datetime(2025, 6, 4, 14, 0, tzinfo=timezone.utc)
    assert logs[1].period_to == datetime(2025, 6, 4, 15, 30, tzinfo=timezone.utc)

    # Verify UserDailyHealth summaries
    # Date 2025-06-03 (Record 1 starts on this date)
    dh1 = db.query(UserDailyHealth).filter(
        UserDailyHealth.user_id == user_id,
        UserDailyHealth.record_date == datetime(2025, 6, 3).date()
    ).first()
    assert dh1 is not None
    assert dh1.sleep_quality["total_minutes"] == 510  # 8.5 hours
    assert dh1.sleep_quality["main_minutes"] == 510
    assert dh1.sleep_quality["nap_minutes"] == 0
    assert dh1.sleep_quality["from"] == "2025-06-03T22:00:00Z"
    assert dh1.sleep_quality["to"] == "2025-06-04T06:30:00Z"

    # Date 2025-06-04 (Record 2 starts on this date)
    dh2 = db.query(UserDailyHealth).filter(
        UserDailyHealth.user_id == user_id,
        UserDailyHealth.record_date == datetime(2025, 6, 4).date()
    ).first()
    assert dh2 is not None
    assert dh2.sleep_quality["total_minutes"] == 90  # 1.5 hours
    assert dh2.sleep_quality["main_minutes"] == 0
    assert dh2.sleep_quality["nap_minutes"] == 90
    assert dh2.sleep_quality["from"] == "2025-06-04T14:00:00Z"
    assert dh2.sleep_quality["to"] == "2025-06-04T15:30:00Z"


def test_sleep_ingest_overlap_and_fragments(client, db):
    token, user_id = register_and_login(client, "+918888888885")
    headers = {"Authorization": f"Bearer {token}"}

    # Pre-populate DB with an existing log: 2025-06-03T20:00:00Z to 2025-06-04T08:00:00Z (main, 12 hours)
    db.add(SleepLog(
        user_id=user_id,
        period_from=datetime(2025, 6, 3, 20, 0, tzinfo=timezone.utc),
        period_to=datetime(2025, 6, 4, 8, 0, tzinfo=timezone.utc),
        sleep_type="main"
    ))
    db.commit()

    # Ingest a new overlapping log: 2025-06-03T22:00:00Z to 2025-06-04T06:00:00Z (nap, 8 hours)
    # The existing main log should be split into:
    # 1. Left fragment: 2025-06-03T20:00:00Z to 22:00:00Z (main, 2 hours)
    # 2. Right fragment: 2025-06-04T06:00:00Z to 08:00:00Z (main, 2 hours)
    resp = client.post(
        f"/api/v1/sleep/{user_id}",
        json={
            "records": [
                {
                    "from": "2025-06-03T22:00:00Z",
                    "to": "2025-06-04T06:00:00Z",
                    "sleep_type": "nap"
                }
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 201

    # Verify logs in DB
    logs = db.query(SleepLog).filter(SleepLog.user_id == user_id).order_by(SleepLog.period_from).all()
    assert len(logs) == 3

    # Left fragment
    assert logs[0].period_from == datetime(2025, 6, 3, 20, 0, tzinfo=timezone.utc)
    assert logs[0].period_to == datetime(2025, 6, 3, 22, 0, tzinfo=timezone.utc)
    assert logs[0].sleep_type == "main"

    # New interval
    assert logs[1].period_from == datetime(2025, 6, 3, 22, 0, tzinfo=timezone.utc)
    assert logs[1].period_to == datetime(2025, 6, 4, 6, 0, tzinfo=timezone.utc)
    assert logs[1].sleep_type == "nap"

    # Right fragment
    assert logs[2].period_from == datetime(2025, 6, 4, 6, 0, tzinfo=timezone.utc)
    assert logs[2].period_to == datetime(2025, 6, 4, 8, 0, tzinfo=timezone.utc)
    assert logs[2].sleep_type == "main"

    # Recomputed summary for 2025-06-03:
    # Contains:
    # - Left fragment (starts on 2025-06-03): 20:00 to 22:00 (120 mins, main)
    # - New interval (starts on 2025-06-03): 22:00 to 06:00 next day (480 mins, nap)
    # Total minutes = 600. Nap minutes = 480. Main minutes = 120.
    # Main log starts at 20:00
    dh = db.query(UserDailyHealth).filter(
        UserDailyHealth.user_id == user_id,
        UserDailyHealth.record_date == datetime(2025, 6, 3).date()
    ).first()
    assert dh is not None
    assert dh.sleep_quality["total_minutes"] == 600
    assert dh.sleep_quality["main_minutes"] == 120
    assert dh.sleep_quality["nap_minutes"] == 480
    assert dh.sleep_quality["from"] == "2025-06-03T20:00:00Z"
    assert dh.sleep_quality["to"] == "2025-06-03T22:00:00Z"

    # Recomputed summary for 2025-06-04:
    # Contains:
    # - Right fragment (starts on 2025-06-04): 06:00 to 08:00 (120 mins, main)
    # Total minutes = 120. Nap minutes = 0. Main minutes = 120.
    dh2 = db.query(UserDailyHealth).filter(
        UserDailyHealth.user_id == user_id,
        UserDailyHealth.record_date == datetime(2025, 6, 4).date()
    ).first()
    assert dh2 is not None
    assert dh2.sleep_quality["total_minutes"] == 120
    assert dh2.sleep_quality["main_minutes"] == 120
    assert dh2.sleep_quality["nap_minutes"] == 0
    assert dh2.sleep_quality["from"] == "2025-06-04T06:00:00Z"
    assert dh2.sleep_quality["to"] == "2025-06-04T08:00:00Z"


def test_sleep_internal_batch_merging(client, db):
    token, user_id = register_and_login(client, "+918888888886")
    headers = {"Authorization": f"Bearer {token}"}

    # Ingest internal overlapping records in the batch itself:
    # 1. 2025-06-03T22:00:00Z to 2025-06-04T04:00:00Z (main)
    # 2. 2025-06-04T03:00:00Z to 2025-06-04T07:00:00Z (nap)
    # They overlap. Merged record should be:
    # 2025-06-03T22:00:00Z to 2025-06-04T07:00:00Z (main)
    resp = client.post(
        f"/api/v1/sleep/{user_id}",
        json={
            "records": [
                {
                    "from": "2025-06-03T22:00:00Z",
                    "to": "2025-06-04T04:00:00Z",
                    "sleep_type": "main"
                },
                {
                    "from": "2025-06-04T03:00:00Z",
                    "to": "2025-06-04T07:00:00Z",
                    "sleep_type": "nap"
                }
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 201

    logs = db.query(SleepLog).filter(SleepLog.user_id == user_id).all()
    assert len(logs) == 1
    assert logs[0].period_from == datetime(2025, 6, 3, 22, 0, tzinfo=timezone.utc)
    assert logs[0].period_to == datetime(2025, 6, 4, 7, 0, tzinfo=timezone.utc)
    assert logs[0].sleep_type == "main"


def test_admin_can_ingest_sleep_for_other(client, db):
    admin_token, admin_id = register_and_login(client, "+918888888887", role="ADMIN")
    patient_token, patient_id = register_and_login(client, "+918888888888")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin ingests sleep for patient
    resp = client.post(
        f"/api/v1/sleep/{patient_id}",
        json={
            "records": [
                {
                    "from": "2025-06-03T22:00:00Z",
                    "to": "2025-06-04T06:00:00Z",
                    "sleep_type": "main"
                }
            ]
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201

    logs = db.query(SleepLog).filter(SleepLog.user_id == patient_id).all()
    assert len(logs) == 1
    assert logs[0].period_from == datetime(2025, 6, 3, 22, 0, tzinfo=timezone.utc)
