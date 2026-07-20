"""
tests/test_export.py — V5 Day 3: alert export (CSV + JSON).
"""
import pytest
import httpx
import csv
import io
import os

API_URL = os.getenv("API_URL", "http://localhost:8000")
API_KEY = os.getenv("DEFAULT_API_KEY", "dev-local-siem-key-2026")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API_URL, timeout=15.0, headers={"X-API-Key": API_KEY}) as c:
        yield c


class TestAlertExport:
    def test_export_requires_auth(self):
        with httpx.Client(base_url=API_URL, timeout=15.0) as anon:
            r = anon.get("/alerts/export?format=json")
            assert r.status_code == 401

    def test_export_json_returns_array(self, client):
        r = client.get("/alerts/export?format=json")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        if data:
            row = data[0]
            for col in ["id", "rule_name", "severity", "status", "group_value",
                        "matched_count", "first_seen", "last_seen", "mitre_technique_id"]:
                assert col in row

    def test_export_csv_returns_valid_csv(self, client):
        r = client.get("/alerts/export?format=csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        assert "attachment" in r.headers.get("content-disposition", "")

        reader = csv.DictReader(io.StringIO(r.text))
        rows = list(reader)
        assert reader.fieldnames == [
            "id", "rule_name", "severity", "status", "group_value",
            "matched_count", "first_seen", "last_seen", "mitre_technique_id",
        ]

    def test_export_respects_status_filter(self, client):
        r_new = client.get("/alerts/export?format=json&status=NEW")
        r_ack = client.get("/alerts/export?format=json&status=ACKNOWLEDGED")
        assert r_new.status_code == 200
        assert r_ack.status_code == 200
        new_ids = {row["id"] for row in r_new.json()}
        ack_ids = {row["id"] for row in r_ack.json()}
        # A given alert can't be both NEW and ACKNOWLEDGED at once
        assert new_ids.isdisjoint(ack_ids)

    def test_export_invalid_date_returns_400(self, client):
        r = client.get("/alerts/export?format=csv&start=not-a-date")
        assert r.status_code == 400