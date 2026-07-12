# Progress — Mini SIEM Dashboard

### Next: V4 — Hardening, Reports, Performance & API Security (Weeks 9-10)

## V3 — Complete (2026-07-11)

**Final test suite: 41 passed, 1 warning, 0 failed, 0 errors** (`docker exec siem_api pytest tests/ -v`)

### Day 7 — Test suite close-out
- Fixed `tests/conftest.py`: sys.path resolution was hardcoded for host-only
  layout (`tests/../backend`), which broke inside the `siem_api` container
  where `models.py` etc. live directly under `/app`. Now checks both
  candidate paths so the same conftest works in Docker and on the host.
- Wrote `tests/test_hunt.py`: filter preview (single + combined conditions),
  AND vs OR combinator logic (scoped to marker-unique substrings to avoid
  false positives from unrelated logs in the shared `logs` table), saved
  hunt CRUD, create-rule-from-hunt.
- Wrote `tests/test_cases.py`: full case lifecycle (create → link 2 alerts →
  add note → transition OPEN→INVESTIGATING → verify persistence),
  duplicate-alert-link rejection (400), list-cases pagination. Alerts are
  seeded directly via SQLAlchemy since no `POST /alerts` endpoint exists.
- Fixed `tests/test_correlation.py` cleanup: the built-in "SSH Brute Force to
  Web Login Attempt" correlation rule (seeded at app startup) has identical
  match conditions to the test's own fixture rule, so both fire on the same
  test logs, producing two alerts referencing the same log rows. Cleanup now
  filters by `source_ip` (unique to the test) instead of by rule name, so
  both alerts are removed before the underlying logs are deleted — avoids a
  `ForeignKeyViolation` on `alerts_correlation_log_a_id_fkey`.
- Fixed `tests/test_cases.py` fixture teardown: alerts linked to a case via
  `POST /cases/{id}/alerts` create `case_alerts` join rows that FK-reference
  `alerts.id`. Teardown now deletes `case_alerts` rows first, then the
  alerts — avoids a `ForeignKeyViolation` on `case_alerts_alert_id_fkey`.
- Confirmed `backend/tests/` directory is empty and unused — the real
  suite lives at the project-root `tests/`, mounted via
  `./tests:/app/tests` in `docker-compose.yml`.

### Day 6 — Attack pattern timeline
- Added `correlation_log_a_id` / `correlation_log_b_id` FK columns to
  `Alert` (required a manual `ALTER TABLE` since the DB already existed);
  fixed `correlation_engine.py` to actually populate those references
- Seeded a second correlation rule, "Recon Scan to Exploitation" — a
  simplified single-event approximation of the V2 stretch goal (full
  version would need a >50-count threshold on condition_a; noted honestly
  in a `main.py` code comment rather than glossed over)
- New `GET /alerts/{id}/timeline` endpoint; new `AttackTimeline.jsx`
  swimlane modal; wired a "⚔️ Timeline" button into `AlertsPanel.jsx`
- **Significant bug found during testing:** syslog ingestion had never
  extracted `source_ip` from message text — always `NULL`. This silently
  broke the SSH-brute-force correlation rule since V2, since the
  correlation engine explicitly filters out logs with `source_ip IS NULL`.
  Root-caused via log tracing; fixed with a new `_extract_ip_from_message()`
  regex helper wired into both RFC5424 and BSD syslog parsing branches.
  Confirmed working live (`[Correlation] Alert fired: SSH Brute Force →
  Web Login Attempt | 10.0.0.55`).

### Day 5 — Case management
- New `Case`, `CaseAlert`, `CaseNote` models; new `routers/cases.py`
  (create/list/patch cases, link alerts, add timestamped notes)
- New `CasesPage.jsx`: create case, link alerts, notes timeline, status
  transitions OPEN → INVESTIGATING → CLOSED; added as a third tab
- Verified live end-to-end

### Day 4 — Threat hunting interface
- New `SavedHunt` model; new `routers/hunt.py` (ad-hoc filter preview with
  AND/OR combinator, save/list/delete named hunts, create-rule-from-hunt)
- New `HuntPage.jsx`: filter builder, live preview table, saved hunts
  sidebar; added as a tab in `App.jsx`
- Verified live end-to-end: built a hunt, previewed 44 matches, promoted it
  to a real alert rule, deleted the hunt

### Day 3 — GeoIP surfacing in the UI
- Enriched `/logs` and `/logs/top-ips` responses with `country_code` /
  `country_name` pulled from `geoip_cache` (resolver built Day 1)
- Verified live: country flags render correctly in the top-IPs table;
  private/reserved IPs correctly show as unknown rather than erroring

### Bugs found and fixed along the way (pre-existing, not introduced this week)
- `AlertsPanel.jsx` had a malformed `<a` tag in the MITRE badge link that
  broke the whole page on rebuild
- CORS only allowed `localhost:5173`; the frontend actually runs on `3000`
  — this silently caused "Failed to fetch" everywhere despite the backend
  returning 200s
- Removed 4 stale duplicate config files sitting in `frontend/src/` instead
  of `frontend/`

### Day 2 — WebSocket infrastructure + live dashboard foundation
- Discovered `/ws/alerts` had never been wired up — `engine.py`'s alert-firing
  logic called a dead `ws_manager = None` stub, so real-time push silently
  did nothing since V1. Built `ws_manager.py` (`set_loop()` +
  `broadcast_sync()` for thread-safe broadcast from APScheduler's background
  thread), added the real `routers/ws.py` endpoint, wired `main.py` to
  capture the event loop at startup, fixed `engine.py` to actually broadcast,
  and fixed a second pre-existing bug where `_fire_alert()` never returned
  `True` (was undercounting fired alerts since V1).
- New `/logs/events-per-minute` and `/logs/top-ips` endpoints
- New `EventsChart.jsx` (Recharts line chart, per-source_type series) and
  `TopIPsTable.jsx` components, wired into `App.jsx`
- Verified live: WebSocket upgrades correctly (101 Switching Protocols),
  new alerts appear in the UI without a page refresh

### Day 1 — Test debt cleanup + GeoIP foundation
**Goal:** Clear leftover V1/V2 test debt, build GeoIP foundation.

**Fixed — leftover test debt from async→sync migration (V2)**
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

**Added — GeoIP foundation**
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

### V3 Definition of Done
- [x] Real-time dashboard (events/minute chart, top-10 IPs, GeoIP flags)
- [x] Threat hunting interface (filter builder, saved hunts, create-rule)
- [x] Case management (create, link alerts, notes, status transitions)
- [x] Attack pattern timeline (SSH brute force → web login swimlane)
- [x] GeoIP enrichment on `/logs` and `/logs/top-ips`
- [x] All Core + Integration tests passing (41/41)
- [x] Note: "Recon Scan to Exploitation" correlation rule is a simplified
      single-event approximation of the full V2 stretch goal (which called
      for a >50-count threshold on condition_a) — documented honestly in
      `main.py` as a code comment, not silently glossed over.

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