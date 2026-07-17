"""
retention.py -- Log retention policy (V4 Day 5).

A daily background job deletes log records older than LOG_RETENTION_DAYS.
Setting LOG_RETENTION_DAYS=0 disables retention entirely (no job runs,
no logs are ever auto-deleted).

Last-run state is kept in memory only (not persisted to the DB) -- the
spec asks the status endpoint to report the last run's result, not to
survive a restart. If persistence across restarts becomes a real
requirement later, this would need a small retention_runs table instead.
"""

import os
from datetime import datetime, timedelta, timezone

from database import SessionLocal
from models import Log

LOG_RETENTION_DAYS = int(os.getenv("LOG_RETENTION_DAYS", "30"))

# In-memory status, updated by run_retention_job(). None until the first run.
_last_run_result = {
    "ran_at": None,
    "deleted_count": None,
    "error": None,
}


def is_retention_enabled() -> bool:
    return LOG_RETENTION_DAYS > 0


def run_retention_job():
    """
    Deletes all Log rows older than LOG_RETENTION_DAYS. Called daily by
    APScheduler. Safe to call even when retention is disabled (no-op).
    """
    global _last_run_result

    if not is_retention_enabled():
        _last_run_result = {
            "ran_at": datetime.now(timezone.utc).isoformat(),
            "deleted_count": 0,
            "error": None,
        }
        print("[Retention] Skipped -- LOG_RETENTION_DAYS=0 (disabled)")
        return

    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=LOG_RETENTION_DAYS)
        deleted = db.query(Log).filter(Log.timestamp < cutoff).delete(synchronize_session=False)
        db.commit()

        _last_run_result = {
            "ran_at": datetime.now(timezone.utc).isoformat(),
            "deleted_count": deleted,
            "error": None,
        }
        print(f"[Retention] Deleted {deleted} log record(s) older than {LOG_RETENTION_DAYS} days")
    except Exception as e:
        db.rollback()
        _last_run_result = {
            "ran_at": datetime.now(timezone.utc).isoformat(),
            "deleted_count": None,
            "error": str(e),
        }
        print(f"[Retention] Error during retention run: {e}")
    finally:
        db.close()


def get_retention_status(scheduler=None) -> dict:
    """
    Returns current policy, next scheduled run (if a scheduler is passed
    in and the job exists), and the last run's result.
    """
    next_run = None
    if scheduler is not None:
        job = scheduler.get_job("retention_job")
        if job and job.next_run_time:
            next_run = job.next_run_time.isoformat()

    return {
        "enabled": is_retention_enabled(),
        "retention_days": LOG_RETENTION_DAYS,
        "next_scheduled_run": next_run,
        "last_run": _last_run_result,
    }