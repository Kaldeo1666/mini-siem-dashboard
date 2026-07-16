"""
tests/test_ingestion.py
────────────────────────
Automated tests for all three ingest endpoints.

Run with:
  pytest tests/ -v

Or against a running Docker stack:
  API_URL=http://localhost:8000 pytest tests/ -v
"""

import os
import pytest
import httpx
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────

API_URL = os.getenv("API_URL", "http://localhost:8000")

# Use a synchronous HTTPX client (simpler for tests; no async fixtures needed)
API_KEY = os.getenv("DEFAULT_API_KEY", "dev-local-siem-key-2026")

@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API_URL, timeout=10.0, headers={"X-API-Key": API_KEY}) as c:
        yield c


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_logs_by_ip(client, ip: str) -> list:
    """Fetch all logs matching a specific source_ip."""
    r = client.get("/logs", params={"source_ip": ip, "page_size": 100})
    assert r.status_code == 200
    return r.json()["logs"]


# ── /ingest/json ──────────────────────────────────────────────────────────────

class TestIngestJson:
    def test_single_event_returns_200(self, client):
        """POST a single JSON log event — should return 200 with ingested=1."""
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_type": "json",
            "source_host": "test-host",
            "level": "INFO",
            "source_ip": "10.20.30.40",
            "message": "pytest: single event test",
        }
        r = client.post("/ingest/json", json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body["ingested"] == 1

    def test_single_event_appears_in_logs(self, client):
        """After ingestion the event must be retrievable via GET /logs."""
        test_ip = "10.99.88.77"
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_type": "json",
            "source_host": "test-host",
            "level": "ERROR",
            "source_ip": test_ip,
            "message": "pytest: verify retrieval",
            "status_code": 500,
        }
        r = client.post("/ingest/json", json=payload)
        assert r.status_code == 200

        logs = get_logs_by_ip(client, test_ip)
        assert len(logs) >= 1
        found = next((l for l in logs if "pytest: verify retrieval" in l["message"]), None)
        assert found is not None, "Ingested log not found in GET /logs"
        assert found["level"] == "ERROR"
        assert found["status_code"] == 500

    def test_array_of_events(self, client):
        """POST an array of 5 events — should return ingested=5."""
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_type": "json",
                "level": "INFO",
                "source_ip": "10.20.30.41",
                "message": f"pytest: batch event {i}",
            }
            for i in range(5)
        ]
        r = client.post("/ingest/json", json=events)
        assert r.status_code == 200
        assert r.json()["ingested"] == 5

    def test_missing_optional_fields_use_defaults(self, client):
        """Only 'message' provided — all other fields should get defaults."""
        r = client.post("/ingest/json", json={"message": "minimal event"})
        assert r.status_code == 200
        assert r.json()["ingested"] == 1

    def test_invalid_json_returns_400(self, client):
        """Sending non-JSON body should return 400."""
        r = client.post(
            "/ingest/json",
            content=b"this is not json",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400


# ── /ingest/file (Apache CLF) ─────────────────────────────────────────────────

class TestIngestFile:
    VALID_CLF = (
        '192.168.1.55 - alice [10/May/2026:14:22:05 +0000] '
        '"POST /api/login HTTP/1.1" 401 512 '
        '"-" "Mozilla/5.0 (Windows NT 10.0)"'
    )
    ANOTHER_VALID_CLF = (
        '10.0.0.1 - - [10/May/2026:09:00:00 +0000] '
        '"GET /index.html HTTP/1.1" 200 2048 '
        '"http://example.com/" "curl/8.7.1"'
    )

    def test_valid_clf_line_ingested(self, client):
        """POST a valid CLF file — should parse and ingest 1 record."""
        content = self.VALID_CLF + "\n"
        r = client.post(
            "/ingest/file",
            files={"file": ("access.log", content.encode(), "text/plain")},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["ingested"] == 1
        assert body["failed_count"] == 0

    def test_clf_fields_parsed_correctly(self, client):
        """Parsed CLF record must have correct IP, status code, and action."""
        test_ip = "192.168.77.55"
        clf_line = (
            f'{test_ip} - frank [15/May/2026:10:30:00 +0000] '
            '"GET /dashboard HTTP/1.1" 200 1024 "-" "TestAgent/1.0"'
        )
        r = client.post(
            "/ingest/file",
            files={"file": ("test.log", (clf_line + "\n").encode(), "text/plain")},
        )
        assert r.status_code == 200
        assert r.json()["ingested"] == 1

        logs = get_logs_by_ip(client, test_ip)
        assert len(logs) >= 1
        found = logs[0]
        assert found["source_ip"] == test_ip
        assert found["status_code"] == 200
        assert "GET /dashboard" in (found["action"] or "")
        assert found["source_type"] == "apache"

    def test_malformed_clf_line_goes_to_failed(self, client):
        """A malformed CLF line must be listed in 'failed', not cause a 500."""
        bad_line = "this is not a valid CLF line at all"
        r = client.post(
            "/ingest/file",
            files={"file": ("bad.log", (bad_line + "\n").encode(), "text/plain")},
        )
        # Must return 200 (not 500!) — batch is never dropped
        assert r.status_code == 200
        body = r.json()
        assert body["ingested"] == 0
        assert body["failed_count"] == 1
        assert bad_line in body["failed"]

    def test_mixed_good_and_bad_lines(self, client):
        """A file with 2 valid lines and 1 bad line — 2 ingested, 1 failed."""
        content = "\n".join([
            self.VALID_CLF,
            "GARBAGE LINE — NOT CLF",
            self.ANOTHER_VALID_CLF,
        ]) + "\n"
        r = client.post(
            "/ingest/file",
            files={"file": ("mixed.log", content.encode(), "text/plain")},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["ingested"] == 2
        assert body["failed_count"] == 1

    def test_empty_file_returns_zero(self, client):
        """Uploading an empty file should return ingested=0 without error."""
        r = client.post(
            "/ingest/file",
            files={"file": ("empty.log", b"", "text/plain")},
        )
        assert r.status_code == 200
        assert r.json()["ingested"] == 0


# ── /ingest/syslog ────────────────────────────────────────────────────────────

class TestIngestSyslog:
    RFC5424_LINE = (
        "<34>1 2026-05-28T10:00:00Z web01 sshd 1234 - - "
        "Failed password for root from 1.2.3.4 port 54321 ssh2"
    )
    BSD_LINE = (
        "<36>May 28 10:00:00 db-server sshd[5678]: "
        "Accepted publickey for karan from 10.0.0.5 port 44321 ssh2"
    )

    def test_rfc5424_line_ingested(self, client):
        """POST a valid RFC 5424 syslog line — should ingest 1 record."""
        r = client.post(
            "/ingest/syslog",
            content=self.RFC5424_LINE.encode(),
            headers={"Content-Type": "text/plain"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["ingested"] == 1
        assert body["failed_count"] == 0

    def test_bsd_syslog_line_ingested(self, client):
        """POST a BSD syslog line — should ingest 1 record."""
        r = client.post(
            "/ingest/syslog",
            content=self.BSD_LINE.encode(),
            headers={"Content-Type": "text/plain"},
        )
        assert r.status_code == 200
        assert r.json()["ingested"] == 1

    def test_multiple_syslog_lines(self, client):
        """POST multiple syslog lines in one body — all should be ingested."""
        body = "\n".join([self.RFC5424_LINE, self.BSD_LINE]) + "\n"
        r = client.post(
            "/ingest/syslog",
            content=body.encode(),
            headers={"Content-Type": "text/plain"},
        )
        assert r.status_code == 200
        assert r.json()["ingested"] == 2

    def test_malformed_syslog_line_in_failed(self, client):
        """A line that doesn't match any syslog format goes to 'failed'."""
        bad = "not a syslog line"
        r = client.post(
            "/ingest/syslog",
            content=bad.encode(),
            headers={"Content-Type": "text/plain"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["ingested"] == 0
        assert body["failed_count"] == 1


# ── Health check ──────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_endpoint(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_logs_stats_endpoint(self, client):
        r = client.get("/logs/stats")
        assert r.status_code == 200
        body = r.json()
        assert "total" in body
        assert "by_source_type" in body
        assert "by_level" in body
