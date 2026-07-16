"""
scripts/locustfile.py — Ingestion performance benchmark (V4 Day 3).

Target: 1000 events/second sustained on POST /ingest/json.
Run from the HOST machine (not inside Docker) against the published
port 8000 — locust is a load-testing tool, not a runtime dependency,
so it doesn't belong in backend/requirements.txt or the container image.

Usage:
  locust -f scripts/locustfile.py --host http://localhost:8000

Then open http://localhost:8089 in a browser, set:
  - Number of users: 50
  - Ramp up: 10/s
  - Run for: 60s

Or run headless (no browser UI), which is what we use to capture a
reproducible number for progress.md:
  locust -f scripts/locustfile.py --host http://localhost:8000 \
    --headless -u 50 -r 10 -t 60s --csv scripts/bench_results
"""

import random
from datetime import datetime, timezone
from locust import HttpUser, task, between

NORMAL_IPS = ["203.0.113.10", "198.51.100.20", "192.0.2.50", "10.0.0.15"]
PATHS = ["/", "/index.html", "/api/v1/users", "/dashboard", "/login"]


def make_event():
    ip = random.choice(NORMAL_IPS)
    path = random.choice(PATHS)
    status = random.choices([200, 201, 401, 404, 500], weights=[70, 10, 10, 7, 3])[0]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "json",
        "source_host": "bench-host",
        "level": "INFO" if status < 400 else "WARN",
        "source_ip": ip,
        "action": f"GET {path}",
        "status_code": status,
        "message": f"Benchmark event {path} -> {status}",
    }


class IngestUser(HttpUser):
    # Near-zero wait between requests — we want to push throughput hard,
    # not simulate realistic human pacing.
    wait_time = between(0.01, 0.05)

    @task
    def ingest_batch(self):
        # Send 20 events per request. At 50 users firing roughly every
        # 20-30ms, this batch size is what gets us into the 1000
        # events/sec range without needing an unreasonable user count.
        batch = [make_event() for _ in range(20)]
        self.client.post("/ingest/json", json=batch, name="/ingest/json [batch=20]")