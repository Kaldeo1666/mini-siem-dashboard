"""
test_ioc.py - Tests IOC management and auto-flagging.

Test 1: Add an IP to IOC list, ingest a log with that IP,
        assert log has ioc_matched=True and alert was created.
Test 2: Bulk upload IOCs, assert correct count added/skipped.
Test 3: Deactivate an IOC, assert it no longer flags logs.
"""

import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Log, IOCEntry, IOCType, Alert
from database import SessionLocal
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


def test_ioc_auto_flagging(db):
    """
    Add a known-bad IP to IOC list.
    Ingest a log from that IP.
    Assert log.ioc_matched=True and a HIGH alert was created.
    """
    from routers.ingest import _check_ioc_and_flag

    test_ip = "192.0.2.99"

    # Cleanup
    db.query(Alert).filter(Alert.rule_name == f"IOC Match - {test_ip}").delete()
    db.query(Log).filter(Log.source_ip == test_ip).delete()
    db.query(IOCEntry).filter(IOCEntry.value == test_ip).delete()
    db.commit()

    # Add IOC entry
    ioc = IOCEntry(
        type=IOCType.ip,
        value=test_ip,
        description="Known C2 server - test",
        source="test",
        active=True,
    )
    db.add(ioc)
    db.commit()

    # Create a log from that IP
    log = Log(
        timestamp=datetime.now(timezone.utc),
        source_type="apache",
        source_ip=test_ip,
        action="/index.html",
        status_code=200,
        message="GET /index.html 200",
        ioc_matched=False,
    )
    db.add(log)
    db.commit()

    # Run IOC check
    _check_ioc_and_flag(db, [log])
    db.commit()

    # Assert log is flagged
    db.refresh(log)
    assert log.ioc_matched == True, "Log should be flagged as ioc_matched"

    # Assert alert was created
    alert = (
        db.query(Alert)
        .filter(Alert.rule_name == f"IOC Match - {test_ip}")
        .first()
    )
    assert alert is not None, "Expected IOC match alert"
    assert str(alert.severity.value) == "HIGH"
    print(f"PASS: IOC auto-flagging works - {alert.description}")

    # Cleanup
    db.query(Alert).filter(Alert.rule_name == f"IOC Match - {test_ip}").delete()
    db.query(Log).filter(Log.source_ip == test_ip).delete()
    db.query(IOCEntry).filter(IOCEntry.value == test_ip).delete()
    db.commit()


def test_ioc_deactivated_does_not_flag(db):
    """
    Add an IOC then deactivate it.
    Ingest a log from that IP.
    Assert log.ioc_matched stays False.
    """
    from routers.ingest import _check_ioc_and_flag

    test_ip = "192.0.2.100"

    # Cleanup
    db.query(Log).filter(Log.source_ip == test_ip).delete()
    db.query(IOCEntry).filter(IOCEntry.value == test_ip).delete()
    db.commit()

    # Add IOC entry but deactivate it
    ioc = IOCEntry(
        type=IOCType.ip,
        value=test_ip,
        description="Deactivated IOC test",
        source="test",
        active=False,
    )
    db.add(ioc)
    db.commit()

    # Create a log from that IP
    log = Log(
        timestamp=datetime.now(timezone.utc),
        source_type="apache",
        source_ip=test_ip,
        action="/index.html",
        status_code=200,
        message="GET /index.html 200",
        ioc_matched=False,
    )
    db.add(log)
    db.commit()

    # Run IOC check
    _check_ioc_and_flag(db, [log])
    db.commit()

    # Assert log is NOT flagged
    db.refresh(log)
    assert log.ioc_matched == False, "Deactivated IOC should not flag logs"
    print("PASS: Deactivated IOC correctly ignored")

    # Cleanup
    db.query(Log).filter(Log.source_ip == test_ip).delete()
    db.query(IOCEntry).filter(IOCEntry.value == test_ip).delete()
    db.commit()