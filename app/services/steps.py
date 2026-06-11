from datetime import datetime, timezone
from uuid import UUID
from zoneinfo import ZoneInfo

from sqlalchemy import Date, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.step_log import StepLog
from app.models.user_daily_health import UserDailyHealth
from app.schemas.steps import StepLogCreate


def ingest_steps(db: Session, user_id: UUID, payload: StepLogCreate, user_tz: str = "UTC") -> int:
    """Ingest step counts with overlap detection, proration, and daily health upsert.

    Runs within a single transaction.
    """
    try:
        # 1. Query overlapping step logs
        overlapping_logs = (
            db.query(StepLog)
            .filter(
                StepLog.user_id == user_id,
                StepLog.period_from < payload.date_time_to,
                StepLog.period_to > payload.date_time_from,
            )
            .all()
        )

        if not overlapping_logs:
            # No overlaps -> INSERT full interval as-is
            new_log = StepLog(
                user_id=user_id,
                step_count=payload.step_count,
                period_from=payload.date_time_from,
                period_to=payload.date_time_to,
            )
            db.add(new_log)
        else:
            # Overlaps found -> clip and merge
            clipped_intervals = []
            for log in overlapping_logs:
                c_start = max(log.period_from, payload.date_time_from)
                c_end = min(log.period_to, payload.date_time_to)
                if c_start < c_end:
                    clipped_intervals.append((c_start, c_end))

            # Merge clipped ranges into sorted non-overlapping covered list
            clipped_intervals.sort(key=lambda x: x[0])
            merged_covered = []
            for start, end in clipped_intervals:
                if not merged_covered:
                    merged_covered.append((start, end))
                else:
                    prev_start, prev_end = merged_covered[-1]
                    if start <= prev_end:
                        merged_covered[-1] = (prev_start, max(prev_end, end))
                    else:
                        merged_covered.append((start, end))

            # Find gaps (novel sub-intervals) between covered ranges
            gaps = []
            curr = payload.date_time_from
            for start, end in merged_covered:
                if start > curr:
                    gaps.append((curr, start))
                curr = max(curr, end)
            if curr < payload.date_time_to:
                gaps.append((curr, payload.date_time_to))

            # Prorate steps: density = step_count / total_duration_seconds
            total_duration = (
                payload.date_time_to - payload.date_time_from
            ).total_seconds()
            density = payload.step_count / total_duration if total_duration > 0 else 0

            # INSERT only novel sub-intervals with prorated step counts
            for gap_start, gap_end in gaps:
                gap_duration = (gap_end - gap_start).total_seconds()
                if gap_duration > 0:
                    prorated_steps = round(density * gap_duration)
                    new_log = StepLog(
                        user_id=user_id,
                        step_count=prorated_steps,
                        period_from=gap_start,
                        period_to=gap_end,
                    )
                    db.add(new_log)

        # Flush to database to include new step_logs in the query sum
        db.flush()

        # 3. Calculate total steps for the date of request (in user's local timezone)
        tz = ZoneInfo(user_tz)
        date_of_request = payload.date_time_from.astimezone(tz).date()
        sum_result = (
            db.query(func.sum(StepLog.step_count))
            .filter(
                StepLog.user_id == user_id,
                func.cast(func.timezone(user_tz, StepLog.period_from), Date) == date_of_request,
            )
            .scalar()
        )
        total_steps = int(sum_result) if sum_result is not None else 0

        # 4. UPSERT into user_daily_health
        now_utc = datetime.now(timezone.utc)
        stmt = insert(UserDailyHealth).values(
            user_id=user_id,
            record_date=date_of_request,
            step_count={"total": total_steps, "last_updated": now_utc.isoformat()},
            created_at=now_utc,
            updated_at=now_utc,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["user_id", "record_date"],
            set_={
                "step_count": stmt.excluded.step_count,
                "updated_at": now_utc,
            },
        )
        db.execute(stmt)

        db.commit()
        return total_steps

    except Exception as e:
        db.rollback()
        raise e
