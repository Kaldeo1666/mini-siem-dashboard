# Progress — Mini SIEM Dashboard

## V5 — In Progress (Weeks 11-12, Theme: Polish, Demo Mode & Public Deployment)

### Day 4 — Guided dashboard tour (2026-07-20)
- Added `shepherd.js` dependency. Built `frontend/src/components/Tour.jsx`:
  a 6-step guided walkthrough, dark-themed to match the dashboard palette,
  auto-launches once per browser session (via `sessionStorage`, not
  `localStorage` -- resets each new tab/session rather than persisting
  forever, appropriate for a portfolio demo) and re-launchable anytime
  via a "🧭 Take a Tour" button in the nav.
- Added `id` attributes to 6 existing components so Shepherd has real
  DOM anchors to attach tooltips to: `EventsChart`, `AlertsPanel`,
  `StatsBar`, the Hunt/Cases nav buttons, and the Run Demo button.
- **Mapping note, stated honestly:** the spec's step 3 asks to highlight
  "the alert severity heatmap" -- no heatmap component exists anywhere
  in this codebase (V3's dashboard uses a filterable alert list and a
  StatsBar counter tile row, not a time x severity grid). Substituted
  StatsBar (closest existing severity-at-a-glance view) rather than
  writing tour copy referencing a UI element that doesn't exist, or
  quietly building a whole new heatmap feature inside a "tour" day.
  Step 2 ("active alert counters") similarly mapped to the Alerts
  panel's live count + status filter tabs, the actual UI that shows
  counts today.
- Verified live in both an incognito window (confirming session-based
  auto-launch on first visit) and a normal browser window (confirming
  manual re-launch via the button) -- all 6 steps present, correctly
  positioned, back/next navigation working, both entry paths confirmed
  working by the user directly.

### Day 3 — Alert export (CSV + JSON) (2026-07-19)
- New `GET /alerts/export` endpoint (auth-protected): supports
  `format=csv|json`, and `start`/`end`/`severity`/`status` filters.
  **Schema mapping note, stated honestly:** the spec's requested columns
  (`group_value`, `matched_count`, `first_seen`, `last_seen`) come from
  an earlier alert-schema design than what's actually implemented.
  Mapped to real equivalents: `group_value` -> `source_ip`,
  `first_seen`/`last_seen` -> both map to `triggered_at` (no separate
  first/last tracking exists), `matched_count` omitted (not tracked).
- Frontend: "Export CSV" / "Export JSON" buttons in `AlertsPanel.jsx`,
  fetch-then-blob-download pattern (a plain link/window.open can't
  attach the `X-API-Key` auth header, so direct navigation can't
  authenticate). Exports respect the panel's existing status filter tab
  -- date-range and severity filter UI don't exist in the frontend yet,
  so those params are only wired on the backend for now, not silently
  faked on the frontend.
- **Regression found and fixed during verification:** the initial edit
  to `routers/alerts.py` accidentally replaced the base `GET /alerts`
  (`list_alerts`) route entirely instead of inserting the new
  `/export` route after it -- caused `GET /alerts` to 404, breaking
  5 previously-passing tests across `test_auth.py` and
  `test_rules_engine.py`. Caught by running the full suite rather than
  just the new test file, restored the missing route, verified route
  ordering (`""` -> `/export` -> `/{alert_id}` -> `/{alert_id}/timeline`,
  specific paths before the catch-all pattern).
- New `tests/test_export.py` (5 tests): auth required, JSON returns a
  well-formed array with all 9 mapped columns, CSV has correct headers
  and content-disposition, status filter produces disjoint NEW vs
  ACKNOWLEDGED result sets, invalid date returns 400.
- **68/68 tests passing** (63 prior + 5 new), confirming both the new
  feature and the regression fix.

### Day 2 — One-click attack simulation demo mode (2026-07-19)
- Built `backend/demo.py`: `reset_demo_data()` clears logs, alerts,
  cases (case_notes/case_alerts join tables first, respecting FK order),
  and baselines -- preserves alert_rules, correlation_rules, ioc_entries,
  and api_keys so the demo can be re-run indefinitely without re-seeding
  detection rules or losing API access.
- `run_demo_async()` runs as a background asyncio task (not a blocking
  subprocess as the spec's literal wording suggested) so `POST /demo/run`
  returns immediately; paces one stage every 8 seconds via `asyncio.sleep`
  so alerts appear live on the dashboard as each stage's rules actually
  fire, rather than all at once. In-memory `_status` dict (same pattern
  as Day 5's retention status) tracks `running`, `current_stage`,
  `stages_completed`, timestamps, and any error, polled by the frontend.
- New `routers/demo.py`: `POST /demo/reset`, `POST /demo/run` (409 if
  already running), `GET /demo/status`.
- New `frontend/src/components/DemoControls.jsx`: "Run Demo" button in
  the nav bar; while running, shows a progress banner with 4 stage pills
  (pending/active/done states) polling `/demo/status` every 2s.
- **Verified live end-to-end**, screenshots at each stage: reset
  correctly zeroed alerts/stats mid-run, all 4 stage pills progressed
  pending -> active -> done in order, WebSocket pushed each stage's
  alerts (Port Scan Detection, Brute Force Login, Suspicious Admin
  Access, Data Exfiltration Attempt, plus the Recon-to-Exploitation
  correlation alert and the real hunt-promoted rule) with live timestamps
  as they fired, button and banner correctly returned to idle state after
  completion (~57s total run time), confirmed re-runnable.

### Day 1 — Professional SOC dashboard aesthetic, partial (2026-07-19)
- Created `frontend/src/theme.js`: centralized color palette matching the
  v5.md spec (near-black `#0f1117` background, severity colors
  CRITICAL/HIGH/MEDIUM/LOW mapped to red/orange/yellow/blue), plus a
  `severityStyle()` helper and accessible icon-per-severity mapping
  (color is never the only signal, per the spec's accessibility note).
- Applied the shared palette + icons to `AlertsPanel.jsx` (severity
  badges), `StatsBar.jsx` (level counters), and `LogTable.jsx` (level
  badges) -- verified live in-browser for all three.
- **Bug found and fixed during verification:** adding the icon character
  to `LogTable.jsx`'s level badge overflowed the column's fixed 80px
  width, truncating "WARN"/"INFO"/etc to "WA.../INF...". Widened the
  `level` column (both `COLUMNS` definition and the row's flex-basis) to
  100px; confirmed full text renders correctly afterward.
- **Deliberately scoped as partial, not full Core-item completion:**
  `EventsChart.jsx`, `TopIPsTable.jsx`, `HuntPage.jsx`, and `CasesPage.jsx`
  still use their own local color objects, not `theme.js`. These don't
  have severity indicators needing the accessibility fix, but should
  still adopt the shared palette for full visual consistency across the
  dashboard -- flagged as a follow-up, not silently left inconsistent.
- Confirmed App.jsx's page background now matches the spec's exact
  `#0f1117`, not the previous GitHub-dark `#0d1117`.


## V4 — In Progress (Weeks 9-10, Theme: Hardening, Reports, Performance & API Security)

### Day 6 — Virtual scrolling + test-pollution incident (2026-07-18)
- Added `react-window` and rewrote `LogTable.jsx` to use `FixedSizeList`
  for continuous virtual scroll, replacing the old page-number pagination
  per the spec. Fetches a 2000-row working set per query; react-window
  only ever renders the ~15-20 rows actually visible in the viewport,
  so the DOM cost stays flat regardless of dataset size.
- **Bug found immediately on manual verification:** the frontend fetch
  requested `page_size=2000`, but `routers/logs.py`'s `Query(50, ge=1,
  le=100)` capped it at 100, causing every request to fail with HTTP 422
  and the log table to render empty. Raised the backend cap to 10000 to
  match the actual purpose of virtual scrolling (spec explicitly targets
  10,000+ row datasets) rather than silently capping the frontend to 100
  rows, which would have defeated the point of the feature.
- Manually verified in-browser: 308,910 total logs, smooth scroll
  performance, filters/sort/search all functioning against the
  virtualized list.
- **Virtual scroll performance verified per spec** (2026-07-19): seeded
  50,000 additional log rows via `generate_logs.py` (total 354,174 rows
  in the `logs` table), then measured live frame rate in Chrome DevTools
  (More Tools -> Rendering -> Frame Rendering Stats overlay) while
  scrolling aggressively through the virtualized table. Result: steady
  60fps at rest, 58.8-59.4fps during active fast scrolling -- comfortably
  clears the spec's 30fps threshold with no perceptible degradation at
  scale.
- **Major incident found and resolved during verification: runaway test
  data pollution.** The dashboard showed 23,129 alerts, nearly all a
  single LOW-severity "Test Rule" firing every 30s evaluation cycle.
  Root-caused to `tests/test_rules_engine.py::test_create_rule`, which
  creates a broadly-matching, always-enabled rule
  (`status_code=500, threshold=1`) and never deletes it — flagged as
  known debt back in V3, never actually fixed until now. Investigation
  also turned up two related, previously-unflagged instances of the same
  bug class:
  - `test_update_rule` and `test_toggle_rule` in the same file also
    created rules with no cleanup (lower-severity leftovers -- one was
    at least left disabled by its own test, but neither was deleted).
  - `test_hunt.py::test_create_rule_from_hunt` promotes a hunt into a
    real `AlertRule` via `/hunts/{id}/create-rule`, then only deleted
    the *hunt*, not the *rule* the hunt generated -- these are separate
    resources. This was the more severe leak: 11 stale rules found, one
    firing 800-1400+ times per 5-minute window.
  - A `test_cases.py` fixture had also left 12 orphaned alerts behind
    from interrupted prior test runs (not a logic bug -- runs that
    didn't reach teardown, e.g. from the many debugging restarts earlier
    this V4).
  - Total cleaned from the database: 66 stale rules, ~23,006 stale
    alerts, 11 stale hunt-generated rules, 112 more stale alerts, plus
    12 orphaned case-test alerts and their `case_alerts` join rows
    (required deleting `case_alerts` before `alerts` in every pass, same
    FK-ordering lesson learned repeatedly throughout this project).
  - Fixed all four test methods to delete what they create. Re-ran the
    full suite twice after the fix and confirmed zero residual rows in
    `alert_rules` matching test-origin naming patterns -- the pollution
    is now structurally prevented, not just cleaned up once.
- **63/63 tests passing**, 0 warnings (the long-standing
  `PytestReturnNotNoneWarning` on `test_create_rule` also disappeared as
  a side effect of removing its stray `return` statement during the fix).

### Day 5 — Log retention policy (2026-07-17)
- Built `backend/retention.py`: `run_retention_job()` deletes `logs` rows
  older than `LOG_RETENTION_DAYS` (default 30, env-configurable);
  setting `LOG_RETENTION_DAYS=0` disables retention entirely (job
  becomes a no-op rather than being unscheduled, so status reporting
  stays consistent either way).
- Registered `retention_job` on the existing APScheduler instance,
  running once daily alongside the rule/anomaly/correlation/baseline
  jobs already running every 30s-15min.
- New `GET /admin/retention-status` endpoint (auth-protected like every
  other endpoint since Day 4): reports whether retention is enabled,
  the configured window, the next scheduled run time (read directly
  from the live APScheduler job), and the result of the last run
  (record count deleted, or an error message).
- **Design choice, stated explicitly:** last-run status is kept in
  memory only, not persisted to a DB table. The spec asks the status
  endpoint to report the last run's result, not to survive a restart —
  keeping this in-memory avoids an unnecessary migration for a feature
  that doesn't need durability. Would need a small `retention_runs`
  table if cross-restart history becomes a real requirement later.
- `docker-compose.yml`: added `LOG_RETENTION_DAYS` env var to the `api`
  service (default `"30"`).
- New `tests/test_retention.py` (3 tests): seeds 200 log records 40 days
  old plus 5 recent records, triggers the retention job directly
  (deterministic, not waiting on the real daily interval), asserts all
  200 old records are deleted and the 5 recent ones are untouched;
  confirms the status endpoint requires auth and reports the correct
  policy shape. **63/63 passing** (60 prior + 3 new).

### Day 4 — API key authentication (2026-07-16)
- Added `ApiKey` model (`api_keys` table: key_hash, name, created_at,
  last_used_at, active). Only the SHA-256 hash is stored, never the raw
  key.
- Built `backend/auth.py`: `verify_api_key()` dependency checks the
  `X-API-Key` header against the hashed key table; `POST /auth/keys`
  and `GET /auth/keys` are separately gated by a master key
  (`X-Master-Key`, from `MASTER_API_KEY` env var), since those endpoints
  are what issues the keys `verify_api_key` checks.
- Wired `Depends(verify_api_key)` onto every router in `main.py` except
  `/health` (liveness check) and `/ws/alerts` (browsers cannot attach
  custom headers to a WebSocket handshake - documented as an intentional
  gap, not a silent oversight; query-param or subprotocol-based WS auth
  is a follow-up, not implemented today).
- `docker-compose.yml`: added `DEFAULT_API_KEY` (seeds one usable dev key
  at startup, for test/local ergonomics only) and `MASTER_API_KEY` env
  vars to the `api` service; added `VITE_API_KEY` to the `frontend`
  service.
- Frontend: wired `X-API-Key` header into `App.jsx`, `AlertsPanel.jsx`,
  `LogTable.jsx`.
- Updated `scripts/attack_playbook.py`, `scripts/generate_logs.py`,
  `scripts/locustfile.py` to attach the dev API key so they keep working
  against the now-authenticated API.
- Updated all 6 existing test fixture files (`test_ingestion.py`,
  `test_rules_engine.py`, `test_hunt.py`, `test_reports.py`,
  `test_parse_errors.py`, `test_cases.py`) to attach `X-API-Key`.
- New `tests/test_auth.py` (12 tests): rejection without key, rejection
  with invalid key, acceptance with valid key across `/logs`, `/alerts`,
  `/rules`, and `/ingest/json`; key issuance gated correctly by master
  key; `/health` confirmed exempt. **60/60 passing** (48 prior + 12 new).
- **Debugging note (not a code issue, an editing-environment one):** hit
  repeated indentation/encoding corruption pasting a new ORM class into
  `models.py` via VS Code - same failure mode as the `Report` class
  earlier in V4 Day 1. Root-caused to paste/auto-indent interactions
  rather than anything wrong with the generated code. Resolved by editing
  the file directly via a Python script (base64-encoded replacement
  block) run inside the container, sidestepping the editor entirely.
- **Follow-up (Day 4 continued):** `EventsChart.jsx`, `TopIPsTable.jsx`,
  `HuntPage.jsx`, `CasesPage.jsx`, and `StatsBar.jsx` still needed the
  `X-API-Key` header wired in after the initial Day 4 PR merged - see
  next entry.

### Day 3 — Ingestion performance benchmark (2026-07-16)
- Built `scripts/locustfile.py`: load-tests `POST /ingest/json` with 50
  concurrent users sending 20-event batches (run from the host, not the
  container — locust is a load-testing tool, not a runtime dependency).
- **Baseline measurement:** 1553 events/sec throughput (exceeds the 1000/s
  target), but p99 latency was 890ms and p99.9 was 1000ms against a spec
  target of p99 < 200ms — a 4.5x overshoot. Zero request failures at
  every stage of this investigation.
- **First hypothesis (connection pool exhaustion) — tested, ruled out:**
  `database.py`'s `create_engine()` used SQLAlchemy's default
  `pool_size=5, max_overflow=10` (15 total connections) against 50
  concurrent users. Increased to `pool_size=20, max_overflow=30,
  pool_pre_ping=True` and re-benchmarked. Result: p99 got *worse*
  (890ms -> 1100ms). This ruled out pool size as the bottleneck rather
  than confirming it — a genuinely useful negative result, not wasted
  effort, since it redirected the investigation.
- **Second hypothesis (event loop blocking) — tested, confirmed:** all
  three `/ingest/*` routes are declared `async def` but use a
  *synchronous* SQLAlchemy Session for every DB call. FastAPI runs async
  handlers on the single event loop thread; a blocking sync DB call
  inside one freezes request processing for everyone until it returns —
  explaining why latency climbed steadily with concurrency and then
  plateaued (single-threaded serialization, not real parallel load).
  Wrapped the blocking `_bulk_insert()` / `_record_parse_errors()` calls
  in all three ingest endpoints with `starlette.concurrency.run_in_threadpool`
  so multiple requests' DB work can actually run in parallel across
  threads (which also makes the earlier pool-size increase meaningful,
  now that concurrent threads are really hitting the DB at once).
- **Result after threadpool fix:** p99 620ms (down from 890ms baseline,
  1100ms with pool-only change — ~30% improvement over baseline), p99.9
  700ms (down from 1000ms), max latency 717ms (down from 1104ms),
  throughput up to ~2085 events/sec (~34% improvement over baseline).
  Zero failures throughout. Still above the spec's 200ms p99 target, but
  the remaining latency plateaus around genuine per-request work (GeoIP
  lookup + IOC check + DB commit) rather than an architectural
  bottleneck — documented honestly as a partial improvement with real
  before/after numbers rather than claimed as fully meeting spec.
- Not pursued further this session (would require moving to
  `asyncpg`/`AsyncSession` throughout, a larger architectural change
  out of scope for a one-day fix): batching GeoIP lookups instead of
  one per unique IP per request, or moving IOC/GeoIP enrichment to a
  background task instead of inline with the ingest response.

### Day 2 — Attack playbook script + parse_errors table (2026-07-14)
- Added `ParseError` ORM model (table already existed in `init.sql` from V0,
  was just missing its SQLAlchemy mapping) and wired `_record_parse_errors()`
  into both `/ingest/file` and `/ingest/syslog` — malformed lines are now
  captured to `parse_errors` instead of just being silently listed in the
  response and forgotten.
- Added `GET /ingest/parse-errors` paginated endpoint.
- Added `./scripts:/app/scripts` volume mount to `docker-compose.yml` —
  the container had no visibility into the scripts folder at all before
  this, so `attack_playbook.py` couldn't run inside `siem_api` until fixed.
- Built `scripts/attack_playbook.py`: 4-stage simulated attack (recon →
  brute force → exploitation → exfiltration), polls `GET /alerts` and
  asserts all 4 expected detections fired. All 4 stages PASS against the
  live stack (`tests/fixtures/playbook_expected_output.txt`).
- **Known inconsistency found, documented not fixed (out of scope for
  Day 2):** there are two disconnected sets of "built-in alert rules" in
  this codebase. `main.py::seed_alert_rules()` (the one actually called at
  startup) seeds 5 rules including a volumetric "Data Exfiltration Attempt"
  (100+ status-200 requests/60s from one IP). `routers/rules.py` separately
  defines a *different* BUILTIN_RULES list — including a content-based
  "Large Exfiltration" rule matching `bytes_sent` in the message — via
  `seed_builtin_rules()`, but that function is never called anywhere, so
  those rules never actually get seeded. Additionally, `engine.py`'s
  evaluation loop doesn't implement the `pattern_match` condition_type at
  all, so even if seeded, that rule wouldn't fire as written. The attack
  playbook's Stage 4 was written to match the volumetric rule that's
  actually live, not the spec wording's literal "one log with a
  bytes_sent marker." Worth reconciling into a single source of truth for
  built-in rules in a later cleanup pass — not blocking V4 Day 2.
- **Also known (pre-existing, spotted this session):** `test_rules_engine.py
  ::test_create_rule` still doesn't delete the "Test Rule" it creates
  (flagged back in V3), and similar leftover rules from `test_update_rule`/
  `test_toggle_rule` appear to be accumulating and firing real alerts every
  30s cycle. Not touched this session — flagged again since it's now
  visibly noisier in the logs.

### Day 1 — Incident report generation (2026-07-14)
- Added `Report` ORM model (`reports` table: title, start/end range,
  fully-rendered HTML content, created_at).
- Built `routers/reports.py`:
  - `POST /reports/generate` — builds a self-contained HTML report for a
    given time range: executive summary (total events, total alerts, top
    5 source IPs, top 5 alert rules fired), a MITRE ATT&CK tactic-by-technique
    heatmap table (color-coded by fire count), a "Top Anomalies" section
    (matched by rule-name prefix against the 4 anomaly_engine.py alert
    types), and a full alert table sorted by severity.
  - `GET /reports` — list previously generated reports.
  - `GET /reports/{id}` — serve a stored report as raw HTML.
- Scoped deliberately as **HTML-only** for Day 1 — PDF export via
  WeasyPrint needs system libraries (`libpango`, `libcairo`,
  `libgdk-pixbuf`) not yet present in the backend `Dockerfile` (currently
  only `gcc` + `libpq-dev`). Adding PDF support is planned as a separate,
  isolated step in a later day rather than bundling a Dockerfile change
  into the first report-generation pass.
- `tests/test_reports.py` (4 tests): report generation, fetch-by-id,
  invalid date range rejected (400), list endpoint. 45/45 passing.

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