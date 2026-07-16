"""
tests/test_hunt.py
Tests for the threat hunting filter builder and saved hunts.
"""
import pytest
import httpx
import uuid
import os

API_URL = os.getenv("API_URL", "http://localhost:8000")


API_KEY = os.getenv("DEFAULT_API_KEY", "dev-local-siem-key-2026")

@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API_URL, timeout=15.0, headers={"X-API-Key": API_KEY}) as c:
        yield c


@pytest.fixture(scope="module")
def seeded_logs(client):
    """Seed a small, distinctive set of logs to hunt against.
    Each message carries a unique -A/-B/-C tag so OR/AND queries can be
    scoped precisely to these rows, instead of relying on shared fields
    like status_code that collide with data from other tests."""
    marker = f"hunttest-{uuid.uuid4().hex[:8]}"
    events = [
        {"source_type": "json", "source_ip": "203.0.113.10", "status_code": 401,
         "action": "/login", "message": f"{marker}-A failed login"},
        {"source_type": "json", "source_ip": "203.0.113.10", "status_code": 401,
         "action": "/login", "message": f"{marker}-B failed login again"},
        {"source_type": "json", "source_ip": "203.0.113.11", "status_code": 200,
         "action": "/dashboard", "message": f"{marker}-C normal access"},
    ]
    r = client.post("/ingest/json", json=events)
    assert r.status_code == 200
    assert r.json()["ingested"] == 3
    return marker


class TestHuntPreview:
    def test_preview_returns_only_matching_logs(self, client, seeded_logs):
        marker = seeded_logs
        query = {
            "conditions": [
                {"field": "message", "operator": "contains", "value": marker},
                {"field": "status_code", "operator": "=", "value": "401"},
            ],
            "combinator": "AND",
            "page": 1,
            "page_size": 50,
        }
        r = client.post("/hunt/preview", json=query)
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        for log in data["logs"]:
            assert marker in log["message"]
            assert log["status_code"] == 401

    def test_and_vs_or_result_counts_differ(self, client, seeded_logs):
        marker = seeded_logs

        # Both conditions scoped to marker-unique substrings so results
        # are never polluted by logs from other tests.
        and_query = {
            "conditions": [
                {"field": "message", "operator": "contains", "value": marker},
                {"field": "message", "operator": "contains", "value": f"{marker}-A"},
            ],
            "combinator": "AND",
        }
        or_query = {
            "conditions": [
                {"field": "message", "operator": "contains", "value": f"{marker}-A"},
                {"field": "message", "operator": "contains", "value": f"{marker}-B"},
            ],
            "combinator": "OR",
        }

        r_and = client.post("/hunt/preview", json=and_query)
        r_or = client.post("/hunt/preview", json=or_query)
        assert r_and.status_code == 200
        assert r_or.status_code == 200

        and_total = r_and.json()["total"]
        or_total = r_or.json()["total"]

        # AND (message contains marker AND message contains -A) -> 1 match (log A only)
        # OR  (message contains -A OR message contains -B)      -> 2 matches (logs A and B)
        assert and_total == 1
        assert or_total == 2
        assert and_total != or_total
        print(f"PASS: AND={and_total}, OR={or_total}")


class TestSavedHunts:
    def test_save_and_list_hunt(self, client, seeded_logs):
        marker = seeded_logs
        hunt_name = f"Test Hunt {marker}"
        body = {
            "name": hunt_name,
            "filters": {
                "conditions": [
                    {"field": "message", "operator": "contains", "value": marker}
                ],
                "combinator": "AND",
            },
        }
        r = client.post("/hunts", json=body)
        assert r.status_code == 200
        saved = r.json()
        assert saved["name"] == hunt_name
        hunt_id = saved["id"]

        r2 = client.get("/hunts")
        assert r2.status_code == 200
        names = [h["name"] for h in r2.json()["hunts"]]
        assert hunt_name in names

        r3 = client.delete(f"/hunts/{hunt_id}")
        assert r3.status_code == 200
        assert r3.json()["deleted"] == True

    def test_create_rule_from_hunt(self, client, seeded_logs):
        marker = seeded_logs
        hunt_name = f"Rule Source Hunt {marker}"
        body = {
            "name": hunt_name,
            "filters": {
                "conditions": [
                    {"field": "status_code", "operator": "=", "value": "401"}
                ],
                "combinator": "AND",
            },
        }
        r = client.post("/hunts", json=body)
        hunt_id = r.json()["id"]

        r2 = client.post(f"/hunts/{hunt_id}/create-rule")
        assert r2.status_code == 200
        rule = r2.json()
        assert rule["name"] == f"From Hunt: {hunt_name}"
        assert rule["condition_field"] == "status_code"

        client.delete(f"/hunts/{hunt_id}")