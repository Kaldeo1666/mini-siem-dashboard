
"""
tests/test_auth.py - V4 Day 4: API key authentication.
"""
import pytest
import httpx
import os

API_URL = os.getenv("API_URL", "http://localhost:8000")
API_KEY = os.getenv("DEFAULT_API_KEY", "dev-local-siem-key-2026")
MASTER_KEY = os.getenv("MASTER_API_KEY", "master-key-change-in-prod")


@pytest.fixture(scope="module")
def anon_client():
    with httpx.Client(base_url=API_URL, timeout=15.0) as c:
        yield c


@pytest.fixture(scope="module")
def auth_client():
    with httpx.Client(base_url=API_URL, timeout=15.0, headers={"X-API-Key": API_KEY}) as c:
        yield c


ENDPOINTS_REQUIRING_AUTH = [
    ("GET", "/logs"),
    ("GET", "/alerts"),
    ("GET", "/rules"),
]


class TestAuthRequired:
    @pytest.mark.parametrize("method,path", ENDPOINTS_REQUIRING_AUTH)
    def test_rejected_without_key(self, anon_client, method, path):
        r = anon_client.request(method, path)
        assert r.status_code == 401

    def test_ingest_rejected_without_key(self, anon_client):
        r = anon_client.post("/ingest/json", json={"message": "no key test"})
        assert r.status_code == 401

    def test_rejected_with_invalid_key(self, anon_client):
        r = anon_client.get("/logs", headers={"X-API-Key": "totally-wrong-key"})
        assert r.status_code == 401


class TestAuthAccepted:
    @pytest.mark.parametrize("method,path", ENDPOINTS_REQUIRING_AUTH)
    def test_accepted_with_valid_key(self, auth_client, method, path):
        r = auth_client.request(method, path)
        assert r.status_code == 200

    def test_ingest_accepted_with_valid_key(self, auth_client):
        r = auth_client.post("/ingest/json", json={"message": "valid key test"})
        assert r.status_code == 200


class TestKeyIssuance:
    def test_create_key_rejected_without_master_key(self, anon_client):
        r = anon_client.post("/auth/keys", json={"name": "should-fail"})
        assert r.status_code == 401

    def test_create_key_with_valid_master_key(self, anon_client):
        r = anon_client.post(
            "/auth/keys",
            json={"name": "test-issued-key"},
            headers={"X-Master-Key": MASTER_KEY},
        )
        assert r.status_code == 200
        data = r.json()
        assert "api_key" in data
        assert data["name"] == "test-issued-key"

    def test_health_does_not_require_key(self, anon_client):
        r = anon_client.get("/health")
        assert r.status_code == 200