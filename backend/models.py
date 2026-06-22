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
    source_ip = Column(INET, nullable=True, index=True)
    action = Column(String(255), nullable=True)
    status_code = Column(Integer, nullable=True)
    user = Column(String(255), nullable=True)
    message = Column(Text, nullable=True)
    raw = Column(Text, nullable=True)

    # ── V2 addition ──
    ioc_matched = Column(Boolean, default=False, nullable=False)


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_type = Column(String(50), nullable=True)
    condition_field = Column(String(100), nullable=False)
    condition_operator = Column(String(20), nullable=False)
    condition_value = Column(String(255), nullable=False)
    severity = Column(Enum(AlertSeverity), nullable=False)
    time_window_seconds = Column(Integer, default=300)
    threshold_count = Column(Integer, default=1)
    cooldown_seconds = Column(Integer, default=300)
    enabled = Column(Boolean, default=True)
    mitre_technique_id = Column(String(20), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


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