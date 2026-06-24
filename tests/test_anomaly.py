"""
test_anomaly.py

Tests anomaly detection engine.
Test 1: Seed a baseline, inject burst traffic, assert spike alert fires.
Test 2: Seed a silent-hour baseline, inject login, assert unusual-hour alert fires.
"""

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Log, Baseline, Alert, AlertSeverity
from anomaly_engine import detect_anomalies
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://siem:siem_password@db:5432/siem_db"
)


@pytest.fixture
def db():
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_traffic_spike_alert(db):
    """
    Seed a baseline of avg=10, stddev=1 for current hour.
    Inject 50 events in the last minute (way above avg + 3*stddev = 13).
    Assert a HIGH traffic spike alert is created.
    """
    now = datetime.now(timezone.utc)
    hour = now.hour
    dow = now.weekday()

    # Clean up
    db.query(Alert).filter(Alert.rule_name.like("Traffic Volume Spike%")).delete()
    db.query(Baseline).filter(Baseline.source_type == "apache_spike_test").delete()
    db.query(Log).filter(Log.source_type == "apache_spike_test").delete()
    db.commit()

    # Seed baseline: avg=10, stddev=1, so threshold = 10 + 3*1 = 13
    baseline = Baseline(
        metric_name="events_per_minute",
        source_type="apache_spike_test",
        hour_of_day=hour,
        day_of_week=dow,
        avg_value=10.0,
        stddev_value=1.0,
        sample_count=50,
    )
    db.add(baseline)

    # Inject 50 events in the last minute (threshold is 13)
    for i in range(50):
        log = Log(
            timestamp=now - timedelta(seconds=i),
            source_type="apache_spike_test",
            source_ip="10.0.0.1",
            action="/index.html",
            status_code=200,
            message="GET /index.html 200",
        )
        db.add(log)
    db.commit()

    # Run anomaly detection
    detect_anomalies()

    # Assert alert was created
    alert = (
        db.query(Alert)
        .filter(Alert.rule_name == "Traffic Volume Spike - apache_spike_test")
        .first()
    )
    assert alert is not None, "Expected traffic spike alert but none was created"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.mitre_technique_id == "T1498"
    print(f"PASS: Traffic spike alert created - {alert.description}")

    # Cleanup
    db.query(Alert).filter(Alert.rule_name.like("Traffic Volume Spike%")).delete()
    db.query(Baseline).filter(Baseline.source_type == "apache_spike_test").delete()
    db.query(Log).filter(Log.source_type == "apache_spike_test").delete()
    db.commit()


def test_unusual_hour_alert(db):
    """
    Seed a baseline with avg=0 and sample_count=20 for current hour.
    Inject a login event now.
    Assert a MEDIUM unusual-hour alert is created.
    """
    now = datetime.now(timezone.utc)
    hour = now.hour
    dow = now.weekday()

    # Clean up
    db.query(Alert).filter(Alert.rule_name.like("Unusual Hour%")).delete()
    db.query(Baseline).filter(Baseline.source_type == "apache_hour_test").delete()
    db.query(Log).filter(Log.source_type == "apache_hour_test").delete()
    db.commit()

    # Seed baseline: avg=0 at this hour means normally silent
    baseline = Baseline(
        metric_name="events_per_minute",
        source_type="apache_hour_test",
        hour_of_day=hour,
        day_of_week=dow,
        avg_value=0.0,
        stddev_value=0.0,
        sample_count=20,
    )
    db.add(baseline)

    # Inject a login event right now
    log = Log(
        timestamp=now - timedelta(seconds=10),
        source_type="apache_hour_test",
        source_ip="192.168.1.50",
        action="/login",
        status_code=200,
        user="suspicious_user",
        message="POST /login 200",
    )
    db.add(log)
    db.commit()

    # Run anomaly detection
    detect_anomalies()

    # Assert alert was created
    alert = (
        db.query(Alert)
        .filter(Alert.rule_name == "Unusual Hour Login - apache_hour_test")
        .first()
    )
    assert alert is not None, "Expected unusual hour alert but none was created"
    assert alert.severity == AlertSeverity.MEDIUM
    assert alert.mitre_technique_id == "T1078"
    print(f"PASS: Unusual hour alert created - {alert.description}")

    # Cleanup
    db.query(Alert).filter(Alert.rule_name.like("Unusual Hour%")).delete()
    db.query(Baseline).filter(Baseline.source_type == "apache_hour_test").delete()
    db.query(Log).filter(Log.source_type == "apache_hour_test").delete()
    db.commit()