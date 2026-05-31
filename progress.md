# Progress — Mini SIEM Dashboard

## Current Version: v0

**Started:** 2026-05-29
**Status:** 🟡 In Progress

---

## v0 Checklist

### Core
- [x] Repo initialized with FastAPI backend + React (Vite) frontend
- [x] `docker-compose.yml` with `api`, `frontend`, `db` services
- [x] Normalized `logs` table with all required columns + indexes
- [x] `POST /ingest/json` — accepts single JSON event or array
- [x] `POST /ingest/file` — Apache CLF multipart upload with parse error tracking
- [x] `POST /ingest/syslog` — RFC 5424 + BSD syslog line parsing
- [x] Log generator script (`scripts/generate_logs.py`) with `--rate`, `--count`, `--mode` flags
- [x] Paginated log viewer (25/50/100 rows per page)
- [x] Source type filter dropdown
- [x] Time range filter (Last 1h / 6h / 24h / All)
- [x] Column-click sorting (timestamp, source_type, source_host, source_ip, status_code)

### Integration & Quality
- [x] `tests/test_ingestion.py` covering all 3 endpoints
- [x] CORS configured — no browser console errors
- [x] Generator script verified → logs appear in viewer within 5 seconds
- [x] `docker compose down && up` — data persists (volume configured)

### Stretch Goals
- [ ] `POST /ingest/windows_event` — Windows Event XML
- [ ] `POST /ingest/firewall` — iptables DENY log format
- [x] Live row-count badge in nav bar (refreshes every 10 seconds) ✅

---

## Notes

- `parse_errors` table added to capture malformed lines without dropping batches
- BSD syslog assumes current year (format has no year field — known limitation)
- Frontend uses Vite proxy so no hardcoded API URL in production builds
