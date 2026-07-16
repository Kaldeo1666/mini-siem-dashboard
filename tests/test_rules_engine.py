"""
tests/test_rules_engine.py
Tests for alert rules engine, deduplication, and state machine.
"""
import pytest
import httpx
import time
import os

API_URL = os.getenv("API_URL", "http://localhost:8000")

API_KEY = os.getenv("DEFAULT_API_KEY", "dev-local-siem-key-2026")

@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API_URL, timeout=15.0, headers={"X-API-Key": API_KEY}) as c:
        yield c

class TestRuleCRUD:
    def test_get_rules_returns_builtin(self, client):
        r = client.get("/rules")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 5
        names = [rule["name"] for rule in data["rules"]]
        assert "Brute Force Login" in names

    def test_create_rule(self, client):
        payload = {
            "name": "Test Rule",
            "condition_type": "threshold",
            "condition_field": "status_code",
            "condition_value": "500",
            "group_by": "source_ip",
            "threshold": 1,
            "window_seconds": 3600,
            "severity": "LOW",
            "mitre_technique_id": "T9999",
            "cooldown_seconds": 60,
        }
        r = client.post("/rules", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "Test Rule"
        assert data["enabled"] == True
        return data["id"]

    def test_update_rule(self, client):
        # Create then update
        payload = {
            "name": "Update Test Rule",
            "condition_type": "threshold",
            "condition_field": "status_code",
            "condition_value": "404",
            "threshold": 5,
            "window_seconds": 60,
            "severity": "LOW",
        }
        r = client.post("/rules", json=payload)
        rule_id = r.json()["id"]
        r2 = client.put(f"/rules/{rule_id}", json={"threshold": 99})
        assert r2.status_code == 200
        assert r2.json()["threshold"] == 99

    def test_toggle_rule(self, client):
        payload = {
            "name": "Toggle Test Rule",
            "condition_type": "threshold",
            "condition_field": "status_code",
            "condition_value": "404",
            "threshold": 5,
            "window_seconds": 60,
            "severity": "LOW",
        }
        r = client.post("/rules", json=payload)
        rule_id = r.json()["id"]
        r2 = client.patch(f"/rules/{rule_id}/toggle")
        assert r2.status_code == 200
        assert r2.json()["enabled"] == False

    def test_delete_rule(self, client):
        payload = {
            "name": "Delete Test Rule",
            "condition_type": "threshold",
            "condition_field": "status_code",
            "condition_value": "404",
            "threshold": 5,
            "window_seconds": 60,
            "severity": "LOW",
        }
        r = client.post("/rules", json=payload)
        rule_id = r.json()["id"]
        r2 = client.delete(f"/rules/{rule_id}")
        assert r2.status_code == 200
        r3 = client.get(f"/rules/{rule_id}")
        assert r3.status_code == 404


class TestAlertStateMachine:
    def test_alert_status_transition(self, client):
        # Get any existing alert
        r = client.get("/alerts?status=NEW&page_size=1")
        assert r.status_code == 200
        alerts = r.json()["alerts"]
        if not alerts:
            pytest.skip("No NEW alerts available")
        alert_id = alerts[0]["id"]

        # Transition NEW → ACKNOWLEDGED
        r2 = client.patch(f"/alerts/{alert_id}/status",
            json={"status": "ACKNOWLEDGED", "notes": "Test note"})
        assert r2.status_code == 200
        assert r2.json()["status"] == "ACKNOWLEDGED"
        assert r2.json()["acknowledged_at"] is not None

    def test_invalid_transition_rejected(self, client):
        r = client.get("/alerts?page_size=1")
        alerts = r.json()["alerts"]
        if not alerts:
            pytest.skip("No alerts available")
        alert_id = alerts[0]["id"]
        current_status = alerts[0]["status"]
        if current_status == "RESOLVED":
            pytest.skip("Alert already resolved")

        # Try going backwards — should fail
        r2 = client.patch(f"/alerts/{alert_id}/status",
            json={"status": "NEW"})
        assert r2.status_code == 400


class TestRuleTesting:
    def test_rule_test_endpoint(self, client):
        r = client.get("/rules")
        rules = r.json()["rules"]
        rule_id = rules[0]["id"]
        r2 = client.post(f"/rules/{rule_id}/test",
            json={"hours_back": 24})
        assert r2.status_code == 200
        data = r2.json()
        assert "would_have_fired" in data
        assert "sample_matches" in data
        assert "evaluated_window" in data

    def test_alerts_list(self, client):
        r = client.get("/alerts")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "alerts" in data