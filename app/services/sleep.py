import json
from datetime import datetime, timezone, date, timedelta
from uuid import UUID

from sqlalchemy import Date as SQLADate, func, case, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.sleep_log import SleepLog
from app.models.user_daily_health import UserDailyHealth
from app.schemas.sleep import SleepIngestionRequest


def get_utc_date(dt: datetime) -> date:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.date()


def format_utc_iso(dt: datetime) -> str:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def ingest_sleep_records(db: Session, user_id: UUID, payload: SleepIngestionRequest) -> None:
    """Ingest sleep records with overlap resolution, merging, and daily health upsert.

    Runs within a single transaction.
    """
    try:
        # Step 1: Clean the incoming batch
        # Sort records by period_from and merge overlapping intervals within the batch itself
        sorted_records = sorted(payload.records, key=lambda x: x.period_from)
        cleaned_batch = []
        for r in sorted_records:
            if not cleaned_batch:
                cleaned_batch.append({
                    "period_from": r.period_from,
                    "period_to": r.period_to,
                    "sleep_type": r.sleep_type
                })
            else:
                prev = cleaned_batch[-1]
                if r.period_from <= prev["period_to"]:
                    # Overlap within the batch -> Merge intervals
                    prev["period_to"] = max(prev["period_to"], r.period_to)
                    # Priority: main takes precedence over nap
                    if r.sleep_type == "main" or prev["sleep_type"] == "main":
                        prev["sleep_type"] = "main"
                    else:
                        prev["sleep_type"] = "nap"
                else:
                    cleaned_batch.append({
                        "period_from": r.period_from,
                        "period_to": r.period_to,
                        "sleep_type": r.sleep_type
                    })

        # Track all affected dates to recompute daily summaries
        affected_dates = set()

        # Step 2: For each interval in the cleaned batch, resolve overlaps with database
        for interval in cleaned_batch:
            new_from = interval["period_from"]
            new_to = interval["period_to"]
            new_type = interval["sleep_type"]

            affected_dates.add(get_utc_date(new_from))

            # Query existing overlapping logs in DB
            overlapping_logs = (
                db.query(SleepLog)
                .filter(
                    SleepLog.user_id == user_id,
                    SleepLog.period_from < new_to,
                    SleepLog.period_to > new_from,
                )
                .all()
            )

            if not overlapping_logs:
                # No overlaps -> INSERT as-is
                db.add(SleepLog(
                    user_id=user_id,
                    period_from=new_from,
                    period_to=new_to,
                    sleep_type=new_type
                ))
            else:
                surviving_fragments = []
                for log in overlapping_logs:
                    affected_dates.add(get_utc_date(log.period_from))

                    # Compute left fragment
                    if log.period_from < new_from:
                        left_frag = SleepLog(
                            user_id=user_id,
                            period_from=log.period_from,
                            period_to=new_from,
                            sleep_type=log.sleep_type
                        )
                        surviving_fragments.append(left_frag)
                        affected_dates.add(get_utc_date(log.period_from))

                    # Compute right fragment
                    if log.period_to > new_to:
                        right_frag = SleepLog(
                            user_id=user_id,
                            period_from=new_to,
                            period_to=log.period_to,
                            sleep_type=log.sleep_type
                        )
                        surviving_fragments.append(right_frag)
                        affected_dates.add(get_utc_date(new_to))

                # DELETE all overlapping records
                for log in overlapping_logs:
                    db.delete(log)

                # INSERT surviving fragments + new interval
                for frag in surviving_fragments:
                    db.add(frag)

                db.add(SleepLog(
                    user_id=user_id,
                    period_from=new_from,
                    period_to=new_to,
                    sleep_type=new_type
                ))

            # Flush to database so that subsequent iterations query the updated state
            db.flush()

        # Step 3 & 4: Recompute daily summary and UPSERT into user_daily_health for each affected date
        for record_date in affected_dates:
            # Recompute total sleep duration and nap duration for the date
            summary = (
                db.query(
                    func.sum(func.extract("epoch", SleepLog.period_to - SleepLog.period_from) / 60).label("total_minutes"),
                    func.sum(
                        case(
                            (SleepLog.sleep_type == "nap", func.extract("epoch", SleepLog.period_to - SleepLog.period_from) / 60),
                            else_=0
                        )
                    ).label("nap_minutes")
                )
                .filter(
                    SleepLog.user_id == user_id,
                    func.cast(SleepLog.period_from, SQLADate) == record_date
                )
                .first()
            )

            total_minutes = int(round(summary.total_minutes)) if (summary and summary.total_minutes is not None) else 0
            nap_minutes = int(round(summary.nap_minutes)) if (summary and summary.nap_minutes is not None) else 0
            main_minutes = max(0, total_minutes - nap_minutes)

            if total_minutes > 0:
                # Fetch all logs for this date to determine the sleep window
                logs_for_date = (
                    db.query(SleepLog)
                    .filter(
                        SleepLog.user_id == user_id,
                        func.cast(SleepLog.period_from, SQLADate) == record_date
                    )
                    .all()
                )

                main_logs = [log for log in logs_for_date if log.sleep_type == "main"]
                if main_logs:
                    min_from = min(log.period_from for log in main_logs)
                    max_to = max(log.period_to for log in main_logs)
                else:
                    min_from = min(log.period_from for log in logs_for_date)
                    max_to = max(log.period_to for log in logs_for_date)

                sleep_quality = {
                    "total_minutes": total_minutes,
                    "main_minutes": main_minutes,
                    "nap_minutes": nap_minutes,
                    "from": format_utc_iso(min_from),
                    "to": format_utc_iso(max_to),
                    "last_updated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                }
            else:
                sleep_quality = None

            # UPSERT sleep_quality into user_daily_health
            now_utc = datetime.now(timezone.utc)
            stmt = insert(UserDailyHealth).values(
                user_id=user_id,
                record_date=record_date,
                sleep_quality=sleep_quality,
                created_at=now_utc,
                updated_at=now_utc,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["user_id", "record_date"],
                set_={
                    "sleep_quality": stmt.excluded.sleep_quality,
                    "updated_at": now_utc,
                },
            )
            db.execute(stmt)

        # Flush to database so that subsequent trend queries see the updated records
        db.flush()

        # Step 5: Compute sleep score and trend for each affected date
        for record_date in affected_dates:
            # Query the updated daily health record to get the current sleep quality data
            dh_record = (
                db.query(UserDailyHealth)
                .filter(
                    UserDailyHealth.user_id == user_id,
                    UserDailyHealth.record_date == record_date
                )
                .first()
            )
            
            if dh_record and dh_record.sleep_quality and dh_record.sleep_quality.get("total_minutes", 0) > 0:
                main_minutes = dh_record.sleep_quality.get("main_minutes", 0)
                nap_minutes = dh_record.sleep_quality.get("nap_minutes", 0)
                
                # Compute Sleep Score
                sleep_score = compute_sleep_score(main_minutes, nap_minutes)
                
                # Compute Sleep Trend
                sleep_trend = compute_sleep_trend(db, user_id, record_date)
                
                # Merge sleep_score and sleep_trend into sleep_quality using || operator
                merge_data = {
                    "sleep_score": sleep_score,
                    "sleep_trend": sleep_trend
                }
                
                db.execute(
                    text(
                        """
                        UPDATE user_daily_health
                        SET sleep_quality = COALESCE(sleep_quality, CAST('{}' AS jsonb)) || CAST(:merge_data AS jsonb),
                            updated_at = :now_utc
                        WHERE user_id = :user_id AND record_date = :record_date
                        """
                    ),
                    {
                        "user_id": user_id,
                        "record_date": record_date,
                        "merge_data": json.dumps(merge_data),
                        "now_utc": datetime.now(timezone.utc)
                    }
                )

        db.commit()

    except Exception as e:
        db.rollback()
        raise e


def compute_sleep_score(main_minutes: int, nap_minutes: int) -> int:
    hours = main_minutes / 60

    if hours < 3:       base = 0
    elif hours < 4:     base = 25 + (hours - 3) * 20
    elif hours < 5:     base = 45 + (hours - 4) * 17
    elif hours < 6:     base = 62 + (hours - 5) * 13
    elif hours < 6.5:   base = 75 + (hours - 6) * 20
    elif hours < 7:     base = 85 + (hours - 6.5) * 30
    elif hours <= 9:    base = 100
    elif hours <= 10:   base = 95 - (hours - 9) * 10
    elif hours <= 11:   base = 85 - (hours - 10) * 15
    else:               base = 70

    if nap_minutes == 0:       nap_adj = 0
    elif nap_minutes <= 45:    nap_adj = 5
    elif nap_minutes <= 90:    nap_adj = 0
    elif nap_minutes <= 120:   nap_adj = -5
    else:                      nap_adj = -10

    return max(0, min(100, round(base + nap_adj)))


def compute_sleep_trend(db: Session, user_id: UUID, record_date: date) -> dict:
    start_date = record_date - timedelta(days=13)
    
    # Query last 14 days from user_daily_health
    records = (
        db.query(UserDailyHealth)
        .filter(
            UserDailyHealth.user_id == user_id,
            UserDailyHealth.record_date >= start_date,
            UserDailyHealth.record_date <= record_date
        )
        .all()
    )
    
    # Map from record_date to main_minutes
    main_minutes_by_date = {}
    for r in records:
        if r.sleep_quality and "main_minutes" in r.sleep_quality:
            main_minutes_by_date[r.record_date] = r.sleep_quality["main_minutes"]
            
    # Split into last 7 days and days 8-14
    current_week_days = [record_date - timedelta(days=i) for i in range(7)]
    previous_week_days = [record_date - timedelta(days=i) for i in range(7, 14)]
    
    current_week_values = [
        main_minutes_by_date[day]
        for day in current_week_days
        if day in main_minutes_by_date and main_minutes_by_date[day] is not None
    ]
    
    previous_week_values = [
        main_minutes_by_date[day]
        for day in previous_week_days
        if day in main_minutes_by_date and main_minutes_by_date[day] is not None
    ]
    
    # Compute averages
    if current_week_values:
        current_week_avg = round(sum(current_week_values) / len(current_week_values), 2)
    else:
        current_week_avg = None
        
    if previous_week_values:
        previous_week_avg = round(sum(previous_week_values) / len(previous_week_values), 2)
    else:
        previous_week_avg = None
        
    # Compute delta and direction
    if current_week_avg is not None and previous_week_avg is not None:
        delta = round(abs(current_week_avg - previous_week_avg), 2)
        if current_week_avg > previous_week_avg:
            direction = "increase"
        elif current_week_avg < previous_week_avg:
            direction = "decrease"
        else:
            direction = "no_change"
    else:
        previous_week_avg = None
        delta = None
        direction = "no_change"
        
    return {
        "current_week_avg_minutes": current_week_avg,
        "previous_week_avg_minutes": previous_week_avg,
        "delta_minutes": delta,
        "direction": direction
    }
