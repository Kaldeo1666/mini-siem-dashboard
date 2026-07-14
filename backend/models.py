from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Boolean,
    Text, Enum, JSON, ForeignKey, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func
import enum

Base = declarative_base()

# ── Existing Enums ────────────────────────────────────────────────────────────

class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AlertStatus(str, enum.Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"

# ── V2 New Enum ───────────────────────────────────────────────────────────────

class IOCType(str, enum.Enum):
    ip = "ip"
    domain = "domain"
    hash = "hash"

# ── Existing Tables ───────────────────────────────────────────────────────────

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    source_type = Column(String(50), nullable=False, index=True)
    level = Column(String(20), nullable=True, index=True)
    source_host = Column(String(255), nullable=True)
    ingested_at = Column(DateTime(timezone=True), server_default=func.now())
    source_ip = Column(INET, nullable=True, index=True)
    action = Column(String(255), nullable=True)
    status_code = Column(Integer, nullable=True)
    user = Column(String(255), nullable=True)
    message = Column(Text, nullable=True)
    raw = Column(Text, nullable=True)

    # ── V2 addition ──
    ioc_matched = Column(Boolean, default=False, nullable=False)
    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_type": self.source_type,
            "source_ip": str(self.source_ip) if self.source_ip else None,
            "action": self.action,
            "status_code": self.status_code,
            "user": self.user,
            "message": self.message,
            "raw": self.raw,
            "ioc_matched": self.ioc_matched,
            "level": self.level,
            "source_host": self.source_host,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
        }


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    condition_type = Column(String(20), nullable=False, default="threshold")
    group_by = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    source_type = Column(String(50), nullable=True)
    condition_field = Column(String(100), nullable=False)
    condition_operator = Column(String(20), nullable=True, default="=")
    condition_value = Column(String(255), nullable=False)
    severity = Column(Enum(AlertSeverity), nullable=False)
    time_window_seconds = Column(Integer, default=300)
    threshold_count = Column(Integer, default=1)
    cooldown_seconds = Column(Integer, default=300)
    enabled = Column(Boolean, default=True)
    mitre_technique_id = Column(String(20), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "source_type": self.source_type,
            "condition_field": self.condition_field,
            "condition_operator": self.condition_operator,
            "condition_value": self.condition_value,
            "severity": self.severity.value if self.severity else None,
            "time_window_seconds": self.time_window_seconds,
            "threshold_count": self.threshold_count,
            "cooldown_seconds": self.cooldown_seconds,
            "enabled": self.enabled,
            "mitre_technique_id": self.mitre_technique_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "threshold": self.threshold_count,
            "window_seconds": self.time_window_seconds,
        }


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("alert_rules.id"), nullable=True)
    rule_name = Column(String(255), nullable=False)
    severity = Column(Enum(AlertSeverity), nullable=False)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW)
    source_ip = Column(INET, nullable=True)
    source_type = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    mitre_technique_id = Column(String(20), nullable=True)
    triggered_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)

    # V3 Day 6: for correlation alerts, points at the two Log rows that
    # triggered the multi-stage detection — lets the frontend reconstruct
    # an accurate attack timeline instead of re-guessing which logs matched.
    correlation_log_a_id = Column(Integer, ForeignKey("logs.id"), nullable=True)
    correlation_log_b_id = Column(Integer, ForeignKey("logs.id"), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value if self.severity else None,
            "status": self.status.value if self.status else None,
            "source_ip": str(self.source_ip) if self.source_ip else None,
            "source_type": self.source_type,
            "description": self.description,
            "mitre_technique_id": self.mitre_technique_id,
            "triggered_at": self.triggered_at.isoformat() if self.triggered_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "notes": self.notes,
            "is_correlation": self.correlation_log_a_id is not None,
        }


# ── V2 New Tables ─────────────────────────────────────────────────────────────

class Baseline(Base):
    """
    Stores the 'normal' traffic pattern for each metric.
    Keyed by (metric_name, source_type, hour_of_day, day_of_week).

    Example row:
      metric_name  = "events_per_minute"
      source_type  = "apache"
      hour_of_day  = 14          (2pm)
      day_of_week  = 1           (Monday)
      avg_value    = 42.3        (normally 42 events/min at 2pm Monday)
      stddev_value = 5.1         (give or take 5)
      sample_count = 96          (based on 96 data points)
    """
    __tablename__ = "baselines"

    id = Column(Integer, primary_key=True, index=True)
    metric_name = Column(String(100), nullable=False)
    source_type = Column(String(50), nullable=False)
    hour_of_day = Column(Integer, nullable=False)     # 0–23
    day_of_week = Column(Integer, nullable=False)     # 0=Monday, 6=Sunday
    avg_value = Column(Float, default=0.0)
    stddev_value = Column(Float, default=0.0)
    sample_count = Column(Integer, default=0)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("metric_name", "source_type", "hour_of_day", "day_of_week",
                         name="uq_baseline_bucket"),
    )


class IOCEntry(Base):
    """
    Stores known-bad IPs, domains, or file hashes.
    Every new log is checked against active entries here.

    Example row:
      type        = "ip"
      value       = "192.168.1.100"
      description = "Known C2 server"
      source      = "AbuseIPDB"
    """
    __tablename__ = "ioc_entries"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(Enum(IOCType), nullable=False)
    value = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    source = Column(String(255), nullable=True)
    added_at = Column(DateTime(timezone=True), server_default=func.now())
    active = Column(Boolean, default=True)


class SeenUserAgent(Base):
    """
    Tracks every unique browser/client fingerprint we've ever seen.
    When a brand new one appears → fire a LOW alert.

    Example row:
      user_agent  = "Mozilla/5.0 (compatible; Googlebot/2.1)"
      source_type = "apache"
      first_seen  = 2024-06-23 14:32:00
    """
    __tablename__ = "seen_user_agents"

    id = Column(Integer, primary_key=True, index=True)
    user_agent = Column(Text, nullable=False)
    source_type = Column(String(50), nullable=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("user_agent", "source_type", name="uq_user_agent_source"),
    )


class CorrelationRule(Base):
    """
    Multi-source detection: fires when event A is followed by event B
    from the same IP within a time window.

    Example built-in rule:
      name         = "SSH brute force → web login attempt"
      source_type_a = "syslog"
      condition_a   = {"action": "ssh_failed"}
      source_type_b = "apache"
      condition_b   = {"action": "/login", "status_code": 401}
      window_seconds = 60
      severity      = HIGH
      mitre_technique_id = "T1110"
    """
    __tablename__ = "correlation_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    source_type_a = Column(String(50), nullable=False)
    condition_a = Column(JSON, nullable=False)
    source_type_b = Column(String(50), nullable=False)
    condition_b = Column(JSON, nullable=False)
    window_seconds = Column(Integer, default=60)
    severity = Column(Enum(AlertSeverity), nullable=False)
    mitre_technique_id = Column(String(20), nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
class CaseStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CLOSED = "CLOSED"


class Case(Base):
    """
    Groups related alerts into a single investigation. Analysts work
    a case from OPEN → INVESTIGATING → CLOSED, attaching alerts and
    timestamped notes as they dig in.
    """
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(CaseStatus), default=CaseStatus.OPEN, nullable=False)
    severity = Column(Enum(AlertSeverity), nullable=True)
    assignee = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value if self.status else None,
            "severity": self.severity.value if self.severity else None,
            "assignee": self.assignee,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class CaseAlert(Base):
    """Join table linking cases to the alerts that belong to them."""
    __tablename__ = "case_alerts"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)

    __table_args__ = (
        UniqueConstraint("case_id", "alert_id", name="uq_case_alert"),
    )


class CaseNote(Base):
    """A timestamped investigation note attached to a case."""
    __tablename__ = "case_notes"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    note = Column(Text, nullable=False)
    author = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "case_id": self.case_id,
            "note": self.note,
            "author": self.author,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }



class SavedHunt(Base):
    """
    A named, reusable set of hunt filter conditions.
    Example: name="Failed admin logins", filters_json={
        "conditions": [{"field": "action", "operator": "contains", "value": "/admin"}],
        "combinator": "AND"
    }
    """
    __tablename__ = "saved_hunts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    filters_json = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "filters": self.filters_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class GeoIPCache(Base):
    """
    Caches IP → country/city lookups so we don't hit the GeoLite2
    database on every single request. Think of it as a phonebook:
    first time we see an IP we look it up and write it down here;
    next time, we just read the cached answer.

    Entries expire after 7 days (checked in application code when reading,
    not enforced by the DB itself).

    Example row:
      ip           = "8.8.8.8"
      country_code = "US"
      country_name = "United States"
      city         = "Mountain View"
    """
    __tablename__ = "geoip_cache"

    ip = Column(INET, primary_key=True)
    country_code = Column(String(2), nullable=True)
    country_name = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    cached_at = Column(DateTime(timezone=True), server_default=func.now())

class ParseError(Base):
    """A log line that failed to parse during ingestion. Captured so a
    misconfigured log shipper can be diagnosed instead of the whole batch
    silently failing. Table already exists in init.sql from V0 — this adds
    the missing ORM mapping."""
    __tablename__ = "parse_errors"

    id = Column(Integer, primary_key=True, index=True)
    raw_line = Column(Text, nullable=False)
    endpoint = Column(String(64), nullable=False)
    error_msg = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "raw_line": self.raw_line,
            "endpoint": self.endpoint,
            "error_msg": self.error_msg,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

class Report(Base):
    """A generated incident report. HTML is stored fully rendered so GET /reports/{id} can serve it directly without recomputation."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    start_iso = Column(DateTime(timezone=True), nullable=False)
    end_iso = Column(DateTime(timezone=True), nullable=False)
    html_content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "start_iso": self.start_iso.isoformat() if self.start_iso else None,
            "end_iso": self.end_iso.isoformat() if self.end_iso else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }