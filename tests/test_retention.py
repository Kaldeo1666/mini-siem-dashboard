"""
tests/test_retention.py -- V4 Day 5: log retention policy.
"""
import pytest
import httpx
import os
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Log

API_URL = os.getenv("API_URL", "http://localhost:8000")
API_KEY = os.getenv("DEFAULT_API_KEY", "dev-local-siem-key-2026")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem:siem_password@db:5432/siem_db")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API_URL, timeout=15.0, headers={"X-API-Key": API_KEY}) as c:
        yield c


@pytest.fixture
def db():
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_retention_deletes_old_logs_only(db):
    """
    Seed 200 log records 40 days old (older than the 30-day default
    retention window) and 5 recent records. Trigger the retention job
    directly (not via the scheduler, to keep the test deterministic and
    fast rather than waiting on a real daily interval). Assert all 200
    old records are gone and the 5 recent ones are untouched.
    """
    import retention

    marker_old = "retentiontest-old"
    marker_recent = "retentiontest-recent"
    now = datetime.now(timezone.utc)
    old_ts = now - timedelta(days=40)

    # Cleanup from any previous run
    db.query(Log).filter(Log.message.like(f"%{marker_old}%")).delete(synchronize_session=False)
    db.query(Log).filter(Log.message.like(f"%{marker_recent}%")).delete(synchronize_session=False)
    db.commit()

    old_logs = [
        Log(
            timestamp=old_ts,
            source_type="json",
            source_ip="203.0.113.99",
            message=f"{marker_old} entry {i}",
        )
        for i in range(200)
    ]
    recent_logs = [
        Log(
            timestamp=now,
            source_type="json",
            source_ip="203.0.113.99",
            message=f"{marker_recent} entry {i}",
        )
        for i in range(5)
    ]
    db.add_all(old_logs)
    db.add_all(recent_logs)
    db.commit()

    old_count_before = db.query(Log).filter(Log.message.like(f"%{marker_old}%")).count()
    assert old_count_before == 200

    # Run the retention job directly
    retention.run_retention_job()

    old_count_after = db.query(Log).filter(Log.message.like(f"%{marker_old}%")).count()
    recent_count_after = db.query(Log).filter(Log.message.like(f"%{marker_recent}%")).count()

    assert old_count_after == 0, "All 200 old records should have been deleted"
    assert recent_count_after == 5, "Recent records should be untouched"

    # Cleanup
    db.query(Log).filter(Log.message.like(f"%{marker_recent}%")).delete(synchronize_session=False)
    db.commit()


class TestRetentionStatusEndpoint:
    def test_status_endpoint_requires_auth(self):
        with httpx.Client(base_url=API_URL, timeout=15.0) as anon:
            r = anon.get("/admin/retention-status")
            assert r.status_code == 401

    def test_status_endpoint_returns_policy(self, client):
        r = client.get("/admin/retention-status")
        assert r.status_code == 200
        data = r.json()
        assert "enabled" in data
        assert "retention_days" in data
        assert "next_scheduled_run" in data
        assert "last_run" in data
        assert data["retention_days"] == 30