"""
tests/test_parse_errors.py — V4 Day 2: parse_errors table + endpoint.
"""
import pytest
import httpx
import uuid
import os

API_URL = os.getenv("API_URL", "http://localhost:8000")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API_URL, timeout=15.0) as c:
        yield c


class TestParseErrors:
    def test_malformed_clf_line_recorded(self, client):
        marker = f"parseerrtest-{uuid.uuid4().hex[:8]}"
        bad_line = f"this is not a valid CLF line at all {marker}"
        r = client.post(
            "/ingest/file",
            files={"file": ("bad.log", (bad_line + "\n").encode(), "text/plain")},
        )
        assert r.status_code == 200
        assert r.json()["failed_count"] == 1

        r2 = client.get("/ingest/parse-errors", params={"page_size": 100})
        assert r2.status_code == 200
        raw_lines = [e["raw_line"] for e in r2.json()["parse_errors"]]
        assert any(marker in line for line in raw_lines)

    def test_malformed_syslog_line_recorded(self, client):
        marker = f"parseerrtest-{uuid.uuid4().hex[:8]}"
        bad_line = f"not a syslog line {marker}"
        r = client.post(
            "/ingest/syslog",
            content=bad_line.encode(),
            headers={"Content-Type": "text/plain"},
        )
        assert r.status_code == 200
        assert r.json()["failed_count"] == 1

        r2 = client.get("/ingest/parse-errors", params={"page_size": 100})
        assert r2.status_code == 200
        raw_lines = [e["raw_line"] for e in r2.json()["parse_errors"]]
        assert any(marker in line for line in raw_lines)

    def test_parse_errors_endpoint_pagination(self, client):
        r = client.get("/ingest/parse-errors", params={"page": 1, "page_size": 10})
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "parse_errors" in data
        assert len(data["parse_errors"]) <= 10