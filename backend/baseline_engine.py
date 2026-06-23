"""
baseline_engine.py - Computes rolling traffic baselines per source_type per hour.

Runs every 15 minutes via APScheduler.
For each (source_type, hour_of_day, day_of_week) bucket:
  - Count events per minute over the last 24 hours
  - Compute average and standard deviation
  - Upsert into the baselines table
  - Requires at least 10 samples before baseline is considered valid
"""

from datetime import datetime, timezone, timedelta
from sqlalchemy import func, text
from database import SessionLocal
from models import Baseline, Log


def compute_baselines():
    """Main function - called every 15 minutes by APScheduler."""
    db = SessionLocal()
    try:
        print("[Baseline] Starting baseline computation...")
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=24)

        # Get all distinct source_types in the last 24 hours
        source_types = (
            db.query(Log.source_type)
            .filter(Log.timestamp >= since)
            .distinct()
            .all()
        )
        source_types = [row[0] for row in source_types]

        if not source_types:
            print("[Baseline] No logs found in last 24 hours, skipping.")
            return

        for source_type in source_types:
            _compute_for_source(db, source_type, since, now)

        print(f"[Baseline] Done. Processed {len(source_types)} source type(s).")
    except Exception as e:
        print(f"[Baseline] Error during computation: {e}")
    finally:
        db.close()


def _compute_for_source(db, source_type: str, since: datetime, now: datetime):
    """
    For a given source_type, compute baselines for each
    (hour_of_day, day_of_week) bucket that has data.
    """
    # Pull all logs for this source_type in the last 24 hours
    # Group them by minute so we can count events/minute
    # Then group those minute-counts by hour_of_day + day_of_week
    # to get avg and stddev per time bucket

    # Step 1: count events per minute for this source_type
    # We use a raw SQL approach for clarity
    result = db.execute(
        text("""
            SELECT
                EXTRACT(DOW FROM timestamp)::INT   AS day_of_week,
                EXTRACT(HOUR FROM timestamp)::INT  AS hour_of_day,
                DATE_TRUNC('minute', timestamp)    AS minute_bucket,
                COUNT(*)                           AS event_count
            FROM logs
            WHERE source_type = :source_type
              AND timestamp >= :since
            GROUP BY day_of_week, hour_of_day, minute_bucket
        """),
        {"source_type": source_type, "since": since}
    ).fetchall()

    if not result:
        return

    # Step 2: group by (day_of_week, hour_of_day) and compute avg + stddev
    from collections import defaultdict
    import statistics

    buckets = defaultdict(list)
    for row in result:
        key = (int(row.day_of_week), int(row.hour_of_day))
        buckets[key].append(float(row.event_count))

    # Step 3: upsert into baselines table
    for (day_of_week, hour_of_day), counts in buckets.items():
        sample_count = len(counts)

        # Need at least 10 samples to avoid false positives on first startup
        # Think of it like: you need at least 10 data points before you can
        # say "this is normal" - otherwise one weird event skews everything
        if sample_count < 10:
            continue

        avg_value = statistics.mean(counts)
        stddev_value = statistics.stdev(counts) if sample_count > 1 else 0.0

        # Upsert: insert if not exists, update if exists
        existing = (
            db.query(Baseline)
            .filter(
                Baseline.metric_name == "events_per_minute",
                Baseline.source_type == source_type,
                Baseline.hour_of_day == hour_of_day,
                Baseline.day_of_week == day_of_week,
            )
            .first()
        )

        if existing:
            existing.avg_value = avg_value
            existing.stddev_value = stddev_value
            existing.sample_count = sample_count
            existing.updated_at = datetime.now(timezone.utc)
        else:
            baseline = Baseline(
                metric_name="events_per_minute",
                source_type=source_type,
                hour_of_day=hour_of_day,
                day_of_week=day_of_week,
                avg_value=avg_value,
                stddev_value=stddev_value,
                sample_count=sample_count,
            )
            db.add(baseline)

    db.commit()
    print(f"[Baseline] Updated baselines for source_type='{source_type}'")