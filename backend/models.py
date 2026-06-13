"""
models.py — SQLAlchemy ORM model that maps to the `logs` table.

Think of this as a Python class that represents one row in the database.
SQLAlchemy uses it to build SQL queries for you.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Text, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, INET

from database import Base


class Log(Base):
    """One normalized log record — regardless of source format."""

    __tablename__ = "logs"

    # --- Primary key ---
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # --- Core fields ---
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_host: Mapped[str] = mapped_column(String(255), nullable=False, default="unknown")
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="INFO", index=True)

    # --- Network / auth fields ---
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Content fields ---
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    raw: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # --- Metadata ---
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    ioc_matched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    def to_dict(self) -> dict:
        """Convert to a plain dict for JSON serialization."""
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_type": self.source_type,
            "source_host": self.source_host,
            "level": self.level,
            "source_ip": str(self.source_ip) if self.source_ip else None,
            "user": self.user,
            "action": self.action,
            "status_code": self.status_code,
            "message": self.message,
            "raw": self.raw,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "ioc_matched": self.ioc_matched,
        }

class AlertRule(Base):
    """One configurable detection rule."""

    __tablename__ = "alert_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    condition_type: Mapped[str] = mapped_column(String(32), nullable=False)
    condition_field: Mapped[str] = mapped_column(String(64), nullable=False)
    condition_value: Mapped[str] = mapped_column(String(255), nullable=False)
    group_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "condition_type": self.condition_type,
            "condition_field": self.condition_field,
            "condition_value": self.condition_value,
            "group_by": self.group_by,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "severity": self.severity,
            "mitre_technique_id": self.mitre_technique_id,
            "enabled": self.enabled,
            "cooldown_seconds": self.cooldown_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Alert(Base):
    """One fired alert instance."""

    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="NEW")
    group_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    matched_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "rule_id": str(self.rule_id),
            "rule_name": self.rule_name,
            "severity": self.severity,
            "status": self.status,
            "group_value": self.group_value,
            "matched_count": self.matched_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "notes": self.notes,
            "mitre_technique_id": self.mitre_technique_id,
        }