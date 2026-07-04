"""
test_baselines.py

Tests the baseline computation engine.
Seeds 48 hours of synthetic logs at a consistent rate,
triggers baseline computation, and asserts results are correct.
"""

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Log, Baseline
from baseline_engine import compute_baselines
import os

# Use the same database as the app
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://siem:siem_password@db:5432/siem_db"
)


@pytest.fixture
def db():
    """Create a fresh database session for each test."""
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_baseline_computation(db):
    """
    Seed 48 hours of synthetic apache logs at a consistent rate
    (10 events per minute), run baseline computation,
    and assert baselines table has valid records.
    """
    # Clean up any existing test data
    db.query(Baseline).filter(Baseline.source_type == "apache_test").delete()
    db.query(Log).filter(Log.source_type == "apache_test").delete()
    db.commit()

    # Seed synthetic logs: 10 events per minute for 48 hours
    # That's 10 * 60 * 48 = 28800 log entries
    # We do every 6 seconds = 10 per minute
    now = datetime.now(timezone.utc)
    logs_to_insert = []

    for minutes_ago in range(24 * 60):  # 24 hours worth of minutes
        for i in range(12):  # 12 events per minute
            log = Log(
                timestamp=now - timedelta(minutes=minutes_ago, seconds=i * 5),
                source_type="apache_test",
                source_ip="10.0.0.1",
                action="/index.html",
                status_code=200,
                message="GET /index.html 200",
            )
            logs_to_insert.append(log)

    db.add_all(logs_to_insert)
    db.commit()
    print(f"Seeded {len(logs_to_insert)} synthetic logs")

    # Run baseline computation
    compute_baselines()

    # Assert baselines were created for apache_test
    baselines = (
        db.query(Baseline)
        .filter(Baseline.source_type == "apache_test")
        .all()
    )

    assert len(baselines) > 0, "No baselines were created"

    for b in baselines:
        assert b.avg_value > 0, f"avg_value should be > 0, got {b.avg_value}"
        assert b.sample_count >= 10, f"sample_count should be >= 10, got {b.sample_count}"
        print(f"Baseline: hour={b.hour_of_day} day={b.day_of_week} avg={b.avg_value:.2f} stddev={b.stddev_value:.2f} samples={b.sample_count}")

    print(f"PASS: {len(baselines)} baseline records created with valid avg_value")

    # Cleanup
    db.query(Baseline).filter(Baseline.source_type == "apache_test").delete()
    db.query(Log).filter(Log.source_type == "apache_test").delete()
    db.commit()