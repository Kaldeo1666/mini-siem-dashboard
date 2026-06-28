# Progress — Mini SIEM Dashboard

# Mini SIEM Dashboard — Progress Log

## V0 — Foundation (Complete)
- FastAPI + React + PostgreSQL + Docker Compose
- Normalized logs table, 3 ingest endpoints
- Log generator script (500 events/min)
- Paginated log viewer with filters
- 16/16 tests passing

## V1 — Alert Rules Engine (Complete)
- Rule data model with CRUD API
- 5 built-in MITRE ATT&CK detection rules
- Alert state machine (New -> Resolved)
- APScheduler evaluation every 30 seconds
- WebSocket real-time alert push
- AlertsPanel in React UI
- 9/9 tests passing

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

## Up Next — V3
- Real-time dashboard (charts, heatmap, counters)
- GeoIP enrichment on log viewer
- Threat hunting filter builder + saved hunts
- Case management
- Attack pattern timeline