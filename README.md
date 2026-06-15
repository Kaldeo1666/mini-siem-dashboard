\# Mini SIEM Dashboard



A lightweight self-hosted SIEM with log ingestion, real-time alerting, and threat detection.



!\[Dashboard](screenshot-v1.png)



\## Features

\- 3 log formats: JSON, Apache CLF, Syslog

\- Alert rules engine — evaluates every 30 seconds

\- 5 built-in detection rules with MITRE ATT\&CK tags

\- Real-time WebSocket alert push to dashboard

\- React dashboard with live alerts panel and log viewer

\- Alert state machine: New → Acknowledged → Investigating → Resolved



\## Quick Start

```bash

docker compose up --build

```

Open http://localhost:3000



\## Generate test traffic

```bash

python scripts/generate\_logs.py --rate 200 --count 500

```



\## Run tests

```bash

pytest tests/ -v

```



\## Stack

\- Backend: Python FastAPI + SQLAlchemy

\- Database: PostgreSQL

\- Frontend: React + Vite

\- Infrastructure: Docker Compose

