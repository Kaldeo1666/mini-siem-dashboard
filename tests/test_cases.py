"""
tests/test_cases.py
Tests for case management: create, link alerts, add notes, status transitions.
"""
import pytest
import httpx
import os
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Alert, AlertSeverity, AlertStatus, CaseAlert

API_URL = os.getenv("API_URL", "http://localhost:8000")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://siem:siem_password@db:5432/siem_db"
)


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API_URL, timeout=15.0) as c:
        yield c


@pytest.fixture
def db():
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def two_test_alerts(db):
    """Insert two throwaway alerts directly via the DB (no POST /alerts endpoint exists)."""
    marker = f"casetest-{uuid.uuid4().hex[:8]}"

    alert1 = Alert(
        rule_name=f"Test Alert A - {marker}",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
        source_ip="203.0.113.20",
        source_type="json",
        description=f"{marker} test alert one",
        mitre_technique_id="T1110",
    )
    alert2 = Alert(
        rule_name=f"Test Alert B - {marker}",
        severity=AlertSeverity.MEDIUM,
        status=AlertStatus.NEW,
        source_ip="203.0.113.21",
        source_type="json",
        description=f"{marker} test alert two",
        mitre_technique_id="T1078",
    )
    db.add(alert1)
    db.add(alert2)
    db.commit()
    db.refresh(alert1)
    db.refresh(alert2)

    yield alert1, alert2

    # Tests may link these alerts to a case via POST /cases/{id}/alerts,
    # creating case_alerts rows that FK-reference alert.id. Those must be
    # removed before the alerts themselves can be deleted.
    db.query(CaseAlert).filter(
        CaseAlert.alert_id.in_([alert1.id, alert2.id])
    ).delete(synchronize_session=False)
    db.query(Alert).filter(Alert.rule_name.like(f"%{marker}%")).delete(synchronize_session=False)
    db.commit()


class TestCaseManagement:
    def test_full_case_lifecycle(self, client, two_test_alerts):
        alert1, alert2 = two_test_alerts

        r = client.post("/cases", json={
            "title": "Test Investigation",
            "description": "Created by automated test",
            "severity": "HIGH",
            "assignee": "test-analyst",
        })
        assert r.status_code == 200
        case = r.json()
        case_id = case["id"]
        assert case["status"] == "OPEN"

        r2 = client.post(f"/cases/{case_id}/alerts", json={"alert_id": alert1.id})
        assert r2.status_code == 200
        r3 = client.post(f"/cases/{case_id}/alerts", json={"alert_id": alert2.id})
        assert r3.status_code == 200

        r4 = client.post(f"/cases/{case_id}/notes", json={
            "note": "Confirmed brute force pattern, escalating.",
            "author": "test-analyst",
        })
        assert r4.status_code == 200
        assert r4.json()["note"] == "Confirmed brute force pattern, escalating."

        r5 = client.patch(f"/cases/{case_id}", json={"status": "INVESTIGATING"})
        assert r5.status_code == 200
        assert r5.json()["status"] == "INVESTIGATING"

        r6 = client.get(f"/cases/{case_id}")
        assert r6.status_code == 200
        detail = r6.json()
        assert detail["status"] == "INVESTIGATING"
        assert len(detail["alerts"]) == 2
        linked_ids = {a["id"] for a in detail["alerts"]}
        assert alert1.id in linked_ids
        assert alert2.id in linked_ids
        assert len(detail["notes"]) == 1
        assert detail["notes"][0]["note"] == "Confirmed brute force pattern, escalating."

        print(f"PASS: Case {case_id} full lifecycle verified")

    def test_duplicate_alert_link_rejected(self, client, two_test_alerts):
        alert1, _ = two_test_alerts

        r = client.post("/cases", json={"title": "Dup Link Test"})
        case_id = r.json()["id"]

        r2 = client.post(f"/cases/{case_id}/alerts", json={"alert_id": alert1.id})
        assert r2.status_code == 200

        r3 = client.post(f"/cases/{case_id}/alerts", json={"alert_id": alert1.id})
        assert r3.status_code == 400

    def test_list_cases(self, client):
        r = client.get("/cases")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "cases" in data