from datetime import datetime, timezone, date
from uuid import UUID

from sqlalchemy import Date as SQLADate, func, case
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

        db.commit()

    except Exception as e:
        db.rollback()
        raise e
