"""
tests/test_reports.py — V4 Day 1: incident report generation.
"""
import pytest
import httpx
import os
from datetime import datetime, timezone, timedelta

API_URL = os.getenv("API_URL", "http://localhost:8000")


API_KEY = os.getenv("DEFAULT_API_KEY", "dev-local-siem-key-2026")

@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API_URL, timeout=15.0, headers={"X-API-Key": API_KEY}) as c:
        yield c


class TestReportGeneration:
    def test_generate_report_last_24h(self, client):
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=24)
        body = {
            "start_iso": start.isoformat(),
            "end_iso": now.isoformat(),
            "title": "Test 24h Incident Report",
        }
        r = client.post("/reports/generate", json=body)
        assert r.status_code == 200
        data = r.json()
        assert "id" in data
        assert "html" in data
        html = data["html"]
        assert "Executive Summary" in html
        assert "MITRE ATT&amp;CK Technique Heatmap" in html
        assert "Test 24h Incident Report" in html

    def test_get_report_by_id(self, client):
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=1)
        body = {
            "start_iso": start.isoformat(),
            "end_iso": now.isoformat(),
            "title": "Fetchable Report",
        }
        r = client.post("/reports/generate", json=body)
        report_id = r.json()["id"]

        r2 = client.get(f"/reports/{report_id}")
        assert r2.status_code == 200
        assert "Executive Summary" in r2.text
        assert "Fetchable Report" in r2.text

    def test_invalid_date_range_returns_400(self, client):
        body = {"start_iso": "not-a-date", "end_iso": "also-not-a-date", "title": "Bad"}
        r = client.post("/reports/generate", json=body)
        assert r.status_code == 400

    def test_list_reports(self, client):
        r = client.get("/reports")
        assert r.status_code == 200
        assert "reports" in r.json()