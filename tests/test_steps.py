from datetime import datetime, timezone

from app.models.step_log import StepLog
from app.models.user_daily_health import UserDailyHealth


def register_and_login(client, phone, password="SecurePass1!", role="PATIENT"):
    # Register
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Test User",
            "phone": phone,
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


def test_validation_errors(client):
    token, user_id = register_and_login(client, "+919999999991")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Negative step count
    resp = client.post(
        f"/api/v1/steps/{user_id}",
        json={
            "step_count": -5,
            "date_time_from": "2025-06-03T04:00:00Z",
            "date_time_to": "2025-06-03T08:00:00Z",
        },
        headers=headers,
    )
    assert resp.status_code == 400

    # 2. date_time_from >= date_time_to
    resp = client.post(
        f"/api/v1/steps/{user_id}",
        json={
            "step_count": 1000,
            "date_time_from": "2025-06-03T08:00:00Z",
            "date_time_to": "2025-06-03T04:00:00Z",
        },
        headers=headers,
    )
    assert resp.status_code == 400

    # 3. date_time_from == date_time_to
    resp = client.post(
        f"/api/v1/steps/{user_id}",
        json={
            "step_count": 1000,
            "date_time_from": "2025-06-03T04:00:00Z",
            "date_time_to": "2025-06-03T04:00:00Z",
        },
        headers=headers,
    )
    assert resp.status_code == 400


def test_unauthorized_access(client):
    token1, user_id1 = register_and_login(client, "+919999999992")
    token2, user_id2 = register_and_login(client, "+919999999993")

    headers1 = {"Authorization": f"Bearer {token1}"}

    # User 1 tries to ingest steps for User 2
    resp = client.post(
        f"/api/v1/steps/{user_id2}",
        json={
            "step_count": 1200,
            "date_time_from": "2025-06-03T04:00:00Z",
            "date_time_to": "2025-06-03T08:00:00Z",
        },
        headers=headers1,
    )
    assert resp.status_code == 403


def test_ingest_no_overlap(client, db):
    token, user_id = register_and_login(client, "+919999999994")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        f"/api/v1/steps/{user_id}",
        json={
            "step_count": 1200,
            "date_time_from": "2025-06-03T04:00:00Z",
            "date_time_to": "2025-06-03T08:00:00Z",
        },
        headers=headers,
    )
    assert resp.status_code == 201
    assert resp.json()["daily_total"] == 1200

    # Verify StepLog record was inserted correctly
    logs = db.query(StepLog).filter(StepLog.user_id == user_id).all()
    assert len(logs) == 1
    assert logs[0].step_count == 1200
    assert logs[0].period_from == datetime(2025, 6, 3, 4, 0, tzinfo=timezone.utc)
    assert logs[0].period_to == datetime(2025, 6, 3, 8, 0, tzinfo=timezone.utc)

    # Verify UserDailyHealth summary record
    health_summary = (
        db.query(UserDailyHealth)
        .filter(
            UserDailyHealth.user_id == user_id,
            UserDailyHealth.record_date == datetime(2025, 6, 3).date(),
        )
        .first()
    )
    assert health_summary is not None
    assert health_summary.step_count["total"] == 1200
    assert "last_updated" in health_summary.step_count


def test_ingest_with_overlaps_and_proration(client, db):
    token, user_id = register_and_login(client, "+919999999995")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Insert existing step logs
    # Existing log 1: 04:00 to 05:00, 300 steps
    log1 = StepLog(
        user_id=user_id,
        step_count=300,
        period_from=datetime(2025, 6, 3, 4, 0, tzinfo=timezone.utc),
        period_to=datetime(2025, 6, 3, 5, 0, tzinfo=timezone.utc),
    )
    # Existing log 2: 07:00 to 08:00, 300 steps
    log2 = StepLog(
        user_id=user_id,
        step_count=300,
        period_from=datetime(2025, 6, 3, 7, 0, tzinfo=timezone.utc),
        period_to=datetime(2025, 6, 3, 8, 0, tzinfo=timezone.utc),
    )
    db.add_all([log1, log2])
    db.commit()

    # 2. Ingest overlapping request: 04:00 to 08:00 (duration: 4 hours), 1200 steps
    # Gaps should be 05:00 to 07:00 (2 hours)
    # Density = 1200 steps / 4 hours = 300 steps/hour
    # Prorated steps for 2-hour gap = 300 * 2 = 600 steps
    resp = client.post(
        f"/api/v1/steps/{user_id}",
        json={
            "step_count": 1200,
            "date_time_from": "2025-06-03T04:00:00Z",
            "date_time_to": "2025-06-03T08:00:00Z",
        },
        headers=headers,
    )
    assert resp.status_code == 201
    # Total steps for the day = 300 (existing) + 300 (existing) + 600 (prorated gap) = 1200
    assert resp.json()["daily_total"] == 1200

    # Check StepLogs in database
    logs = (
        db.query(StepLog)
        .filter(StepLog.user_id == user_id)
        .order_by(StepLog.period_from)
        .all()
    )
    assert len(logs) == 3
    # Check gap log
    assert logs[1].period_from == datetime(2025, 6, 3, 5, 0, tzinfo=timezone.utc)
    assert logs[1].period_to == datetime(2025, 6, 3, 7, 0, tzinfo=timezone.utc)
    assert logs[1].step_count == 600

    # Check UserDailyHealth upsert
    health_summary = (
        db.query(UserDailyHealth)
        .filter(
            UserDailyHealth.user_id == user_id,
            UserDailyHealth.record_date == datetime(2025, 6, 3).date(),
        )
        .first()
    )
    assert health_summary.step_count["total"] == 1200


def test_ingest_full_overlap(client, db):
    token, user_id = register_and_login(client, "+919999999996")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Insert existing step log covering 04:00 to 08:00
    log = StepLog(
        user_id=user_id,
        step_count=1000,
        period_from=datetime(2025, 6, 3, 4, 0, tzinfo=timezone.utc),
        period_to=datetime(2025, 6, 3, 8, 0, tzinfo=timezone.utc),
    )
    db.add(log)
    db.commit()

    # 2. Ingest completely overlapping range: 05:00 to 07:00
    resp = client.post(
        f"/api/v1/steps/{user_id}",
        json={
            "step_count": 500,
            "date_time_from": "2025-06-03T05:00:00Z",
            "date_time_to": "2025-06-03T07:00:00Z",
        },
        headers=headers,
    )
    assert resp.status_code == 201
    # Gaps list should be empty. No new logs inserted.
    # Total steps remains 1000.
    assert resp.json()["daily_total"] == 1000

    # Ensure no new StepLog records
    logs = db.query(StepLog).filter(StepLog.user_id == user_id).all()
    assert len(logs) == 1
    assert logs[0].step_count == 1000


def test_admin_can_ingest_for_other(client):
    admin_token, admin_id = register_and_login(client, "+919999999997", role="ADMIN")
    patient_token, patient_id = register_and_login(client, "+919999999998")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin ingests steps for patient
    resp = client.post(
        f"/api/v1/steps/{patient_id}",
        json={
            "step_count": 800,
            "date_time_from": "2025-06-03T10:00:00Z",
            "date_time_to": "2025-06-03T11:00:00Z",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["daily_total"] == 800
