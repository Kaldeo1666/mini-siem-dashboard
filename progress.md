# Progress — Mini SIEM Dashboard

# Mini SIEM Dashboard — Progress Log

## V3 — Day 1 (2026-07-04)

**Goal:** Clear leftover V1/V2 test debt, build GeoIP foundation.

### Fixed — leftover test debt from async→sync migration (V2)
- Removed stale `await db.execute()` / `await db.commit()` / `await db.delete()` calls
  in `alerts.py`, `logs.py`, `rules.py` (sync SQLAlchemy doesn't use await)
- Fixed renamed field references: `Alert.last_seen` → `Alert.triggered_at`,
  `rule.threshold` → `rule.threshold_count` (kept public API field name as
  `threshold` via a `_map_fields()` translation layer in `rules.py`)
- Added missing `to_dict()` methods on `Log`, `AlertRule`, `Alert` models
- Fixed `uuid.UUID(alert_id)` / `uuid.UUID(rule_id)` → both are integer PKs,
  changed to `int(...)`
- Added missing DB columns: `alert_rules.condition_type`, `alert_rules.group_by`,
  `alerts.notes`, `logs.level`, `logs.source_host`, `logs.ingested_at`
- Relaxed `alert_rules.condition_operator` to nullable (API never collects it)
- Removed a dead duplicate `@router.post("/json")` stub in `ingest.py` that was
  shadowing the real `ingest_json_raw` handler
- Added missing `"failed"` line-list to `/ingest/file` and `/ingest/syslog`
  responses (was already tracking failures, just not returning them)
- Added missing `/health` endpoint
- Result: `test_ingestion.py` (25/25) and `test_rules_engine.py` (30/30) now
  100% passing — full test suite green from V0-V2

### Added — GeoIP foundation
- Bundled MaxMind GeoLite2-Country database (`geoip/GeoLite2-Country.mmdb`)
- Built `geoip/resolver.py`: resolves an IP to country via `geoip_cache` table
  (7-day TTL) with fallback to the `.mmdb` file on cache miss/expiry
- Wired GeoIP resolution into `_bulk_insert` in `ingest.py` — every unique
  `source_ip` in an ingested batch gets resolved/cached automatically
- Verified end-to-end: ingested a log with `8.8.8.8`, confirmed
  `geoip_cache` correctly stored `country_name: "United States"`
- Known gap: only Country-level data bundled (no City `.mmdb` yet), so
  `city` stays NULL in `geoip_cache` for now — acceptable for Day 1, will
  revisit if city-level granularity is needed later

### Next (Day 2)
- Events/minute aggregation feed over the existing WebSocket, grouped by
  `source_type`
- Begin dashboard frontend: events/minute line chart, top-10 source IPs tables

## V2 — Anomaly Detection + Correlation + IOC (Complete)
- Baseline engine: 15-min rolling averages per source_type per hour
- Anomaly Type 1: Traffic volume spike (3-sigma rule) - MITRE T1498
- Anomaly Type 2: Unusual hour login activity - MITRE T1078
- Anomaly Type 3: New user agent string detection - MITRE T1036
- Anomaly Type 4: Impossible travel via GeoIP - MITRE T1078
- Multi-source correlation engine (SSH + web login rule)
- IOC list management: CRUD API + bulk upload
- IOC auto-flagging on every log ingestion (60-min deduplication)
- MITRE ATT&CK technique badges on all alert cards (clickable)
- Stretch: 50 known-bad IPs seeded from threat intel
- Stretch: /baselines/visualize endpoint for 24-hour heatmap
- 7 V2 tests passing (test_baselines, test_anomaly x4, test_ioc x2, test_correlation x2)

## V1 — Alert Rules Engine (Complete)
- Rule data model with CRUD API
- 5 built-in MITRE ATT&CK detection rules
- Alert state machine (New -> Resolved)
- APScheduler evaluation every 30 seconds
- WebSocket real-time alert push
- AlertsPanel in React UI
- 9/9 tests passing

## V0 — Foundation (Complete)
- FastAPI + React + PostgreSQL + Docker Compose
- Normalized logs table, 3 ingest endpoints
- Log generator script (500 events/min)
- Paginated log viewer with filters
- 16/16 tests passing