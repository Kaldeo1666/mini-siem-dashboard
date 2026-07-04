\# Agent Context — Mini SIEM Dashboard


# Mini SIEM Dashboard — Agent Context

## Current State
Version: V2 Complete
Branch workflow: feature branch -> PR -> merge to main daily

## Stack
- Backend: FastAPI (Python), sync SQLAlchemy, psycopg2-binary
- Frontend: React/Vite
- Database: PostgreSQL (siem_db, user: siem)
- Orchestration: Docker Compose
- Scheduler: APScheduler (runs every 30s for rules/anomaly/correlation, 15min for baselines)

## Key Files
- backend/main.py - App entry, seeds rules/IOCs, starts scheduler
- backend/engine.py - Alert rules evaluation (sync)
- backend/baseline_engine.py - Baseline computation
- backend/anomaly_engine.py - Anomaly types 1-4
- backend/correlation_engine.py - Multi-source correlation
- backend/seed_iocs.py - 50 known-bad IPs seeder
- backend/routers/ioc.py - IOC CRUD API
- backend/routers/ingest.py - Log ingestion (sync, with IOC auto-flagging)
- db/init.sql - V2 schema (source of truth)
- geoip/GeoLite2-Country.mmdb - GeoIP database for impossible travel

## Database
- Connection: postgresql://siem:siem_password@db:5432/siem_db
- Tables: logs, alert_rules, alerts, baselines, ioc_entries, seen_user_agents, correlation_rules, parse_errors

## V2 Features Complete
1. Baseline engine (15-min intervals)
2. Anomaly detection types 1-4
3. Multi-source correlation engine
4. IOC list management + auto-flagging
5. MITRE badges on alert cards
6. 50 known-bad IPs seeded
7. /baselines/visualize endpoint

## Known Issues
- Old V1 tests (test_ingestion.py, test_rules_engine.py) failing
  because ingest.py was rewritten from async to sync in V2
  Fix planned for V3 polish

## Next: V3
- Real-time dashboard with charts
- GeoIP enrichment
- Threat hunting
- Case management

