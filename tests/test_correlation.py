"""
test_correlation.py - Tests multi-source correlation engine.

Test 1: SSH failure + web login failure from same IP within 30s -> alert fires
Test 2: Same pair but 120s apart (outside 60s window) -> no alert
"""

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Log, Alert, AlertSeverity, CorrelationRule
from correlation_engine import run_correlation
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


@pytest.fixture
def correlation_rule(db):
    """Create a test correlation rule for SSH -> web login."""
    db.query(CorrelationRule).filter(
        CorrelationRule.name == "Test SSH to Web Login"
    ).delete()
    db.commit()

    rule = CorrelationRule(
        name="Test SSH to Web Login",
        source_type_a="syslog",
        condition_a={"action": "ssh_failed"},
        source_type_b="apache",
        condition_b={"action": "/login", "status_code": 401},
        window_seconds=60,
        severity=AlertSeverity.HIGH,
        mitre_technique_id="T1110",
        enabled=True,
    )
    db.add(rule)
    db.commit()
    yield rule

    db.query(CorrelationRule).filter(
        CorrelationRule.name == "Test SSH to Web Login"
    ).delete()
    db.commit()


def test_correlation_fires_within_window(db, correlation_rule):
    """
    SSH failure followed by web login failure from same IP within 30s.
    Correlation alert should fire.
    """
    test_ip = "10.0.0.55"
    now = datetime.now(timezone.utc)

    # Cleanup
    db.query(Alert).filter(Alert.rule_name == "Test SSH to Web Login").delete()
    db.query(Log).filter(Log.source_ip == test_ip).delete()
    db.commit()

    # Event A: SSH failure (syslog)
    log_a = Log(
        timestamp=now - timedelta(seconds=30),
        source_type="syslog",
        source_ip=test_ip,
        action="ssh_failed",
        status_code=None,
        message="Failed password for root from 10.0.0.55",
        ioc_matched=False,
    )

    # Event B: Web login failure (apache) - 20 seconds later, same IP
    log_b = Log(
        timestamp=now - timedelta(seconds=10),
        source_type="apache",
        source_ip=test_ip,
        action="/login",
        status_code=401,
        message="POST /login 401",
        ioc_matched=False,
    )

    db.add(log_a)
    db.add(log_b)
    db.commit()

    # Run correlation
    run_correlation()

    # Assert alert was created
    alert = (
        db.query(Alert)
        .filter(Alert.rule_name == "Test SSH to Web Login")
        .first()
    )
    assert alert is not None, "Expected correlation alert within window"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.mitre_technique_id == "T1110"
    print(f"PASS: Correlation alert fired - {alert.description}")

    # Cleanup
    db.query(Alert).filter(Alert.rule_name == "Test SSH to Web Login").delete()
    db.query(Log).filter(Log.source_ip == test_ip).delete()
    db.commit()


def test_correlation_no_alert_outside_window(db, correlation_rule):
    """
    SSH failure followed by web login failure but 120s apart.
    Window is 60s so NO alert should fire.
    """
    test_ip = "10.0.0.66"
    now = datetime.now(timezone.utc)

    # Cleanup
    db.query(Alert).filter(Alert.rule_name == "Test SSH to Web Login").delete()
    db.query(Log).filter(Log.source_ip == test_ip).delete()
    db.commit()

    # Event A: SSH failure
    log_a = Log(
        timestamp=now - timedelta(seconds=130),
        source_type="syslog",
        source_ip=test_ip,
        action="ssh_failed",
        status_code=None,
        message="Failed password for root from 10.0.0.66",
        ioc_matched=False,
    )

    # Event B: Web login failure - 120s later (OUTSIDE the 60s window)
    log_b = Log(
        timestamp=now - timedelta(seconds=10),
        source_type="apache",
        source_ip=test_ip,
        action="/login",
        status_code=401,
        message="POST /login 401",
        ioc_matched=False,
    )

    db.add(log_a)
    db.add(log_b)
    db.commit()

    # Run correlation
    run_correlation()

    # Assert NO alert was created
    alert = (
        db.query(Alert)
        .filter(
            Alert.rule_name == "Test SSH to Web Login",
            Alert.source_ip == test_ip,
        )
        .first()
    )
    assert alert is None, "Expected NO correlation alert outside window"
    print("PASS: No alert fired outside time window")

    # Cleanup
    db.query(Log).filter(Log.source_ip == test_ip).delete()
    db.commit()