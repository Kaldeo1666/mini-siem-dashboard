# Agent Context — Mini SIEM Dashboard

This file orients an AI assistant (or a new human contributor) to the current architecture. Update it whenever the architecture changes materially — new routers, new background jobs, new external integrations.

## What this project is

A self-hosted SIEM demonstrating SOC-analyst-relevant engineering: multi-format log ingestion, rule-based and statistical detection, multi-source correlation, threat hunting, case management, and reporting. Built version-by-version (V0 through V5) with a running build log in `progress.md`.

## Stack

- **Backend:** FastAPI (sync SQLAlchemy, not async ORM — routes are `async def` but DB calls are sync, wrapped in `run_in_threadpool` where they'd otherwise block the event loop under concurrent load; see V4 Day 3 in `progress.md` for why)
- **Frontend:** React 18 + Vite, no framework beyond that (inline styles, no CSS-in-JS library, no component library)
- **Database:** PostgreSQL, schema in `db/init.sql`
- **Scheduler:** APScheduler running inside the FastAPI process (not a separate worker) — 6 background jobs: rule evaluation (30s), anomaly detection (30s), correlation (30s), baseline computation (15min), retention (daily)

## Background jobs (all registered in `backend/main.py`'s `lifespan`)

| Job | Interval | File |
|---|---|---|
| `evaluate_rules` | 30s | `engine.py` |
| `detect_anomalies` | 30s | `anomaly_engine.py` |
| `run_correlation` | 30s | `correlation_engine.py` |
| `compute_baselines` | 15min | `baseline_engine.py` |
| `run_retention_job` | 1 day | `retention.py` |

## Authentication (added V4 Day 4)

Every router except `/health` and `/ws/alerts` is gated by `Depends(verify_api_key)` in `main.py`. Keys are SHA-256 hashed in the `api_keys` table; raw keys are shown once at creation via `POST /auth/keys`, which is itself gated by a separate `MASTER_API_KEY` (env var, not stored in the DB). `/ws/alerts` is **intentionally** unauthenticated — browsers cannot attach custom headers to a WebSocket handshake, so header-based auth doesn't apply; this is a documented gap, not an oversight.

## Known technical debt (intentionally not yet fixed — see `progress.md` for full detail)

- **Two disconnected "built-in rules" systems:** `main.py::seed_alert_rules()` (actually called at startup, seeds 5 real rules) vs. `routers/rules.py::seed_builtin_rules()` (defines a *different* rule set, never actually called). `engine.py`'s evaluator also doesn't implement the `pattern_match` condition type, so even if the second set were seeded it wouldn't fire as written.
- **Simplified correlation rule:** "Recon Scan to Exploitation" fires on a single 404-then-200 pair, not the full V2 stretch-goal spec (>50 count threshold on the first condition) — `engine.py`'s correlation matching doesn't support count thresholds yet.
- **Weak hardcoded dev credentials:** `DEFAULT_API_KEY` and `MASTER_API_KEY` in `docker-compose.yml` are placeholder values, committed to git. Must be overridden with real secrets before any public deployment (V5 deployment day).

## Data model highlights

- `Log` — normalized schema for all ingested events regardless of source format
- `Alert` — fired by either the rules engine, anomaly engine, or correlation engine; `correlation_log_a_id`/`correlation_log_b_id` (nullable FKs to `Log`) distinguish correlation alerts and power the attack-timeline UI
- `AlertRule` / `CorrelationRule` — detection configuration
- `Case` / `CaseAlert` / `CaseNote` — investigation grouping; `CaseAlert` is a join table, must be deleted before its referenced `Alert`/`Case` rows (recurring FK-ordering lesson throughout this project's history)
- `SavedHunt` — stored ad-hoc filter sets, can be promoted into an `AlertRule` via `/hunts/{id}/create-rule`
- `ApiKey` — hashed keys only, never raw
- `Report` — stores fully-rendered HTML snapshots, not live views
- `Baseline` / `GeoIPCache` / `IOCEntry` / `ParseError` — supporting tables for anomaly detection, GeoIP caching, threat intel, and ingestion error tracking respectively

## Testing conventions

- Full suite lives at the **project-root** `tests/` (mounted via `./tests:/app/tests`), run with `docker exec siem_api pytest tests/ -v`. A duplicate `backend/tests/` folder existed early on and was confirmed empty/unused — do not recreate it.
- Test fixtures that create real DB rows (rules, hunts, cases) **must** delete what they create in teardown. This project has hit the same class of bug — a test creating a broadly-matching, always-enabled `AlertRule` and never deleting it — three separate times (`test_create_rule`, `test_update_rule`, `test_toggle_rule`, `test_create_rule_from_hunt`), each time causing thousands of stray alerts to accumulate in production data. Always add teardown when a test calls a `POST`/creates a resource.
- FK deletion order matters throughout: join tables (`case_alerts`) before their parents, `Alert` before `Log` (correlation alerts reference specific log rows).

## Frontend conventions

- `frontend/src/theme.js` is the single source of truth for colors — `COLORS.severity.{CRITICAL,HIGH,MEDIUM,LOW}` for alert/log severity, each with a `color`, `bg`, and `icon` (accessibility requirement: severity is never color-only).
- `App.jsx` exports `API_BASE`, `API_KEY`, `API_HEADERS` — every component's `fetch()` call must include `API_HEADERS`, or it will 401 against the authenticated backend.
- No browser storage APIs beyond `sessionStorage` for the tour's one-time-per-session flag — `localStorage` is explicitly avoided per this environment's artifact rules.

## Where to look for X

| Need | File |
|---|---|
| Add a new detection rule | `main.py::seed_alert_rules()` + `engine.py` if a new condition_type is needed |
| Change ingestion parsing | `routers/ingest.py` |
| Add a new API endpoint | `routers/<resource>.py`, then register in `main.py` with `Depends(verify_api_key)` unless it's meant to be public |
| Change the dashboard's colors | `frontend/src/theme.js` only — don't hardcode hex values in components |
| Understand what changed and why, chronologically | `progress.md` (kept in reverse-chronological order: most recent day/version first) |