"""
routers/ingest.py — Three log ingestion endpoints.

POST /ingest/json    — accepts a single JSON log or array of logs
POST /ingest/file    — accepts a multipart file upload (Apache CLF format)
POST /ingest/syslog  — accepts raw syslog lines in the request body
"""

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Log

router = APIRouter(prefix="/ingest", tags=["ingestion"])


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _level_from_status(status_code: int | None) -> str:
    """Derive a severity level from an HTTP status code."""
    if status_code is None:
        return "INFO"
    if status_code >= 500:
        return "ERROR"
    if status_code in (401, 403):
        return "WARN"
    if status_code >= 400:
        return "WARN"
    return "INFO"


async def _bulk_insert(db: AsyncSession, logs: list[Log]) -> int:
    """Insert a list of Log objects and commit. Returns count inserted."""
    db.add_all(logs)
    await db.commit()
    return len(logs)


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint 1 — JSON ingestion
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/json")
async def ingest_json(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Accept a single JSON log object OR a JSON array of log objects.

    Minimum required field: none — all fields are optional and will be
    defaulted if missing.  The raw payload is always stored.

    Example body (single):
        {"timestamp": "2026-05-28T10:00:00Z", "level": "ERROR",
         "source_ip": "1.2.3.4", "message": "Login failed"}

    Example body (array):
        [{"message": "event 1"}, {"message": "event 2"}]
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body must be valid JSON")

    # Normalize to a list regardless of input shape
    events: list[dict] = body if isinstance(body, list) else [body]

    records: list[Log] = []
    for event in events:
        if not isinstance(event, dict):
            continue  # skip non-object entries in the array

        # Parse timestamp — accept ISO strings or epoch ints
        ts_raw = event.get("timestamp")
        try:
            if isinstance(ts_raw, (int, float)):
                ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
            elif isinstance(ts_raw, str):
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            else:
                ts = datetime.now(timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)

        status = event.get("status_code") or event.get("status")
        try:
            status = int(status) if status is not None else None
        except (ValueError, TypeError):
            status = None

        records.append(Log(
            timestamp=ts,
            source_type=event.get("source_type", "json"),
            source_host=event.get("source_host", event.get("host", "unknown")),
            level=event.get("level", _level_from_status(status)).upper(),
            source_ip=event.get("source_ip") or event.get("ip") or None,
            user=event.get("user") or event.get("username") or None,
            action=event.get("action") or event.get("method") or None,
            status_code=status,
            message=str(event.get("message", "")),
            raw=str(event),
        ))

    count = await _bulk_insert(db, records)
    return {"ingested": count}


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint 2 — Apache CLF file upload
# ──────────────────────────────────────────────────────────────────────────────

# Apache Combined Log Format regex
# Example line:
#   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://ref.com/" "Mozilla/5.0"
CLF_REGEX = re.compile(
    r'(?P<ip>\S+)'            # client IP
    r'\s+\S+'                 # ident (usually -)
    r'\s+(?P<user>\S+)'       # auth user (- if none)
    r'\s+\[(?P<time>[^\]]+)\]'# timestamp in [DD/Mon/YYYY:HH:MM:SS ±HHMM]
    r'\s+"(?P<request>[^"]*)"'# request line  "METHOD /path HTTP/x"
    r'\s+(?P<status>\d{3})'   # status code
    r'\s+(?P<size>\S+)'       # response size
    r'(?:\s+"(?P<referer>[^"]*)")?'  # optional referer
    r'(?:\s+"(?P<ua>[^"]*)")?'       # optional user-agent
)

CLF_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_clf_line(line: str) -> Log | None:
    """
    Parse one Apache CLF line into a Log object.
    Returns None if the line doesn't match the pattern.
    """
    match = CLF_REGEX.match(line.strip())
    if not match:
        return None

    d = match.groupdict()

    # Parse timestamp
    try:
        ts = datetime.strptime(d["time"], CLF_TIME_FORMAT)
    except ValueError:
        ts = datetime.now(timezone.utc)

    # Parse request line into method + path
    request_parts = d["request"].split()
    method = request_parts[0] if len(request_parts) >= 1 else None
    path = request_parts[1] if len(request_parts) >= 2 else None
    action = f"{method} {path}" if method and path else d["request"] or None

    status = int(d["status"]) if d["status"] else None
    user = d["user"] if d["user"] != "-" else None

    return Log(
        timestamp=ts,
        source_type="apache",
        source_host="unknown",
        level=_level_from_status(status),
        source_ip=d["ip"],
        user=user,
        action=action,
        status_code=status,
        message=f'{d["request"]} → {status}',
        raw=line.strip(),
    )


@router.post("/file")
async def ingest_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Accept a multipart file upload containing Apache CLF log lines.
    Returns count of successfully ingested records and list of lines
    that failed to parse.
    """
    content = await file.read()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as UTF-8")

    lines = text.splitlines()
    records: list[Log] = []
    failed: list[str] = []

    for line in lines:
        if not line.strip():
            continue  # skip blank lines
        log = _parse_clf_line(line)
        if log:
            records.append(log)
        else:
            failed.append(line)

    count = await _bulk_insert(db, records) if records else 0
    return {
        "ingested": count,
        "failed": failed,
        "failed_count": len(failed),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint 3 — Syslog ingestion
# ──────────────────────────────────────────────────────────────────────────────

# RFC 5424 syslog regex
# <priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_REGEX = re.compile(
    r"<(?P<priority>\d+)>"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>\S+)\s*"
    r"(?P<message>.*)"
)

# BSD syslog (RFC 3164)
# <priority>Month DD HH:MM:SS hostname program[pid]: message
BSD_REGEX = re.compile(
    r"<(?P<priority>\d+)>"
    r"(?P<month>[A-Za-z]+)\s+"
    r"(?P<day>\d+)\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)"
)

SYSLOG_SEVERITY = {
    0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL",  # Emergency, Alert, Critical
    3: "ERROR",                                     # Error
    4: "WARN",                                      # Warning
    5: "INFO", 6: "INFO",                           # Notice, Informational
    7: "DEBUG",                                     # Debug
}


def _priority_to_level(priority: int) -> str:
    severity = priority % 8  # lower 3 bits are severity
    return SYSLOG_SEVERITY.get(severity, "INFO")


def _parse_syslog_line(line: str) -> Log | None:
    """Try RFC 5424 first, fall back to BSD syslog."""
    line = line.strip()

    # Try RFC 5424
    m = RFC5424_REGEX.match(line)
    if m:
        d = m.groupdict()
        priority = int(d["priority"])
        try:
            ts = datetime.fromisoformat(d["timestamp"].replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(timezone.utc)

        return Log(
            timestamp=ts,
            source_type="syslog",
            source_host=d["hostname"] if d["hostname"] != "-" else "unknown",
            level=_priority_to_level(priority),
            source_ip=None,
            user=None,
            action=d["appname"] if d["appname"] != "-" else None,
            status_code=None,
            message=d["message"],
            raw=line,
        )

    # Try BSD syslog
    m = BSD_REGEX.match(line)
    if m:
        d = m.groupdict()
        priority = int(d["priority"])
        # Build a timestamp (BSD syslog has no year — assume current year)
        current_year = datetime.now().year
        try:
            ts = datetime.strptime(
                f"{current_year} {d['month']} {d['day']} {d['time']}",
                "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)

        return Log(
            timestamp=ts,
            source_type="syslog",
            source_host=d["hostname"],
            level=_priority_to_level(priority),
            source_ip=None,
            user=None,
            action=d["program"],
            status_code=None,
            message=d["message"],
            raw=line,
        )

    return None


@router.post("/syslog")
async def ingest_syslog(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Accept raw syslog lines in the request body (one per line).
    Supports RFC 5424 and BSD syslog (RFC 3164) formats.
    """
    body = await request.body()
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode body as UTF-8")

    lines = text.splitlines()
    records: list[Log] = []
    failed: list[str] = []

    for line in lines:
        if not line.strip():
            continue
        log = _parse_syslog_line(line)
        if log:
            records.append(log)
        else:
            failed.append(line)

    count = await _bulk_insert(db, records) if records else 0
    return {
        "ingested": count,
        "failed": failed,
        "failed_count": len(failed),
    }
