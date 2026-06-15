# Progress — Mini SIEM Dashboard

## Current Version: v1

**Started:** 2026-05-29
**Status:** ✅ Complete

---

## v0 Checklist — ✅ Complete
All core items done, 16/16 tests passing.

---

## v1 Checklist

### Core
- [x] alert_rules table with all required columns
- [x] alerts table with state machine columns
- [x] GET/POST/PUT/DELETE /rules CRUD API
- [x] PATCH /rules/{id}/toggle enable/disable
- [x] Alert deduplication — cooldown window
- [x] 5 built-in rules seeded at startup
- [x] Rules evaluation engine — runs every 30 seconds
- [x] Alert state machine — NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED
- [x] PATCH /alerts/{id}/status with timestamp logging
- [x] POST /rules/{id}/test — dry run endpoint
- [x] WebSocket /ws/alerts — real-time push
- [x] GET /alerts with status/severity filters

### Integration & Quality
- [x] 9/9 tests passing in test_rules_engine.py
- [x] Alerts panel in React dashboard
- [x] WebSocket live alerts in frontend
- [x] Engine verified — 9 alerts fired automatically

### Stretch Goals
- [ ] Impossible Travel rule
- [ ] Rule versioning
- [ ] Alert comment system