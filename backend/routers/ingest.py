"""
routers/ingest.py - Three log ingestion endpoints.

POST /ingest/json    - accepts a single JSON log or array of logs
POST /ingest/file    - accepts a multipart file upload (Apache CLF format)
POST /ingest/syslog  - accepts raw syslog lines in the request body

V2 addition: every ingested log is checked against active IOC entries.
If source_ip matches a known-bad IP, ioc_matched=True and a HIGH alert fires.
"""

import re
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from sqlalchemy.orm import Session
from database import get_db
from models import Log, IOCEntry, Alert, AlertSeverity, AlertStatus, ParseError
from geoip.resolver import resolve_ip

router = APIRouter(prefix="/ingest", tags=["ingestion"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _level_from_status(status_code):
    if status_code is None:
        return "INFO"
    if status_code >= 500:
        return "ERROR"
    if status_code in (401, 403):
        return "WARN"
    if status_code >= 400:
        return "WARN"
    return "INFO"


def _check_ioc_and_flag(db: Session, logs: list):
    """
    Cross-reference source_ip of each log against active IOC entries.
    If match found:
      - Set log.ioc_matched = True
      - Fire a HIGH alert (with 60-min deduplication)

    Think of this like a bouncer checking every guest against a blacklist.
    """
    # Get all active IP-type IOCs in one query (efficient - one DB call)
    active_iocs = (
        db.query(IOCEntry)
        .filter(IOCEntry.active == True, IOCEntry.type == "ip")
        .all()
    )

    if not active_iocs:
        return

    # Build a dict for fast lookup: {ip_string: ioc_object}
    ioc_map = {ioc.value: ioc for ioc in active_iocs}

    now = datetime.now(timezone.utc)
    cooldown_start = now - timedelta(minutes=60)

    for log in logs:
        if not log.source_ip:
            continue

        ip_str = str(log.source_ip)
        if ip_str not in ioc_map:
            continue

        # Match found!
        log.ioc_matched = True
        matched_ioc = ioc_map[ip_str]

        # Check cooldown - don't fire duplicate alerts within 60 minutes
        existing_alert = (
            db.query(Alert)
            .filter(
                Alert.rule_name == f"IOC Match - {ip_str}",
                Alert.triggered_at >= cooldown_start,
                Alert.status != AlertStatus.RESOLVED,
            )
            .first()
        )

        if not existing_alert:
            alert = Alert(
                rule_id=None,
                rule_name=f"IOC Match - {ip_str}",
                severity=AlertSeverity.HIGH,
                status=AlertStatus.NEW,
                source_ip=ip_str,
                source_type=log.source_type,
                description=(
                    f"Log from known-bad IP {ip_str} matched IOC entry. "
                    f"Description: {matched_ioc.description or 'N/A'}. "
                    f"Source: {matched_ioc.source or 'N/A'}"
                ),
                mitre_technique_id="T1071",
            )
            db.add(alert)
            print(f"[IOC] Alert fired for matched IP: {ip_str}")

def _record_parse_errors(db: Session, failed_lines: list, endpoint: str):
    """Persist lines that failed to parse into parse_errors, so operators
    can diagnose a misconfigured log shipper instead of silently losing
    data. Never raises — a logging failure must not break ingestion."""
    if not failed_lines:
        return
    for line in failed_lines:
        db.add(ParseError(
            raw_line=line,
            endpoint=endpoint,
            error_msg="Line did not match any known format for this endpoint",
        ))
    db.commit()

def _bulk_insert(db: Session, logs: list) -> int:
    """Insert logs, run IOC check, resolve GeoIP, commit. Returns count inserted."""
    if not logs:
        return 0
    _check_ioc_and_flag(db, logs)
    _enrich_geoip(db, logs)
    db.add_all(logs)
    db.commit()
    return len(logs)
def _enrich_geoip(db: Session, logs: list):
    """
    Resolve each unique source_ip in this batch and populate/refresh
    the geoip_cache table. We don't store country/city on the Log row
    itself — other parts of the app look it up from geoip_cache by IP
    when needed (e.g. the top-IPs table, alert cards).
    """
    seen_ips = set()
    for log in logs:
        if not log.source_ip:
            continue
        ip_str = str(log.source_ip)
        if ip_str in seen_ips:
            continue
        seen_ips.add(ip_str)
        resolve_ip(db, ip_str)





@router.post("/json")
async def ingest_json_raw(
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body must be valid JSON")

    events = body if isinstance(body, list) else [body]
    records = []

    for event in events:
        if not isinstance(event, dict):
            continue

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
            source_host=event.get("source_host"),
            level=event.get("level"),
            source_ip=event.get("source_ip") or event.get("ip") or None,
            user=event.get("user") or event.get("username") or None,
            action=event.get("action") or event.get("method") or None,
            status_code=status,
            message=str(event.get("message", "")),
            raw=str(event),
            ioc_matched=False,
        ))

    count = _bulk_insert(db, records)
    return {"ingested": count}


# ── Endpoint 2 - Apache CLF file upload ──────────────────────────────────────

CLF_REGEX = re.compile(
    r'(?P<ip>\S+)'
    r'\s+\S+'
    r'\s+(?P<user>\S+)'
    r'\s+\[(?P<time>[^\]]+)\]'
    r'\s+"(?P<request>[^"]*)"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<ua>[^"]*)")?'
)

CLF_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_clf_line(line: str):
    match = CLF_REGEX.match(line.strip())
    if not match:
        return None

    d = match.groupdict()

    try:
        ts = datetime.strptime(d["time"], CLF_TIME_FORMAT)
    except ValueError:
        ts = datetime.now(timezone.utc)

    request_parts = d["request"].split()
    method = request_parts[0] if len(request_parts) >= 1 else None
    path = request_parts[1] if len(request_parts) >= 2 else None
    action = f"{method} {path}" if method and path else d["request"] or None

    status = int(d["status"]) if d["status"] else None
    user = d["user"] if d["user"] != "-" else None

    return Log(
        timestamp=ts,
        source_type="apache",
        source_ip=d["ip"],
        user=user,
        action=action,
        status_code=status,
        level=_level_from_status(status),
        message=f'{d["request"]} -> {status}',
        raw=line.strip(),
        ioc_matched=False,
    )


@router.post("/file")
async def ingest_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    content = await file.read()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as UTF-8")

    lines = text.splitlines()
    records = []
    failed = []

    for line in lines:
        if not line.strip():
            continue
        log = _parse_clf_line(line)
        if log:
            records.append(log)
        else:
            failed.append(line)

    count = _bulk_insert(db, records)
    _record_parse_errors(db, failed, "/ingest/file")
    return {"ingested": count, "failed_count": len(failed), "failed": failed}


# ── Endpoint 3 - Syslog ingestion ────────────────────────────────────────────

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

BSD_REGEX = re.compile(
    r"<(?P<priority>\d+)>"
    r"(?P<month>[A-Za-z]+)\s+"
    r"(?P<day>\d+)\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)"
)

_IP_IN_MESSAGE_REGEX = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _extract_ip_from_message(message: str):
    """
    Syslog has no structured IP field — the IP (if any) is embedded in
    free text, e.g. 'ssh_failed login attempt from 203.0.113.51'. This
    is a best-effort extraction so IP-based correlation/detection rules
    have something to match against.
    """
    match = _IP_IN_MESSAGE_REGEX.search(message)
    return match.group(1) if match else None


SYSLOG_SEVERITY = {
    0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL",
    3: "ERROR",
    4: "WARN",
    5: "INFO", 6: "INFO",
    7: "DEBUG",
}


def _priority_to_level(priority: int) -> str:
    severity = priority % 8
    return SYSLOG_SEVERITY.get(severity, "INFO")


def _parse_syslog_line(line: str):
    line = line.strip()

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
            source_ip=_extract_ip_from_message(d["message"]),
            source_host=d["hostname"] if d["hostname"] != "-" else None,
            user=None,
            action=d["appname"] if d["appname"] != "-" else None,
            status_code=None,
            level=_priority_to_level(priority),
            message=d["message"],
            raw=line,
            ioc_matched=False,
        )

    m = BSD_REGEX.match(line)
    if m:
        d = m.groupdict()
        priority = int(d["priority"])
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
            source_ip=_extract_ip_from_message(d["message"]),
            source_host=d["hostname"] if d["hostname"] != "-" else None,
            user=None,
            action=d["program"],
            status_code=None,
            level=_priority_to_level(priority),
            message=d["message"],
            raw=line,
            ioc_matched=False,
        )

    return None


@router.post("/syslog")
async def ingest_syslog(
    request: Request,
    db: Session = Depends(get_db),
):
    body = await request.body()
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode body as UTF-8")

    lines = text.splitlines()
    records = []
    failed = []

    for line in lines:
        if not line.strip():
            continue
        log = _parse_syslog_line(line)
        if log:
            records.append(log)
        else:
            failed.append(line)

    count = _bulk_insert(db, records)
    _record_parse_errors(db, failed, "/ingest/syslog")
    return {"ingested": count, "failed_count": len(failed), "failed": failed}


@router.get("/parse-errors")
async def list_parse_errors(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
):
    """Lists recent parse errors so operators can diagnose a misconfigured
    log shipper — e.g. lines consistently failing from one source."""
    total = db.query(ParseError).count()
    offset = (page - 1) * page_size
    errors = (
        db.query(ParseError)
        .order_by(ParseError.created_at.desc())
        .offset(offset)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "parse_errors": [e.to_dict() for e in errors],
    }


