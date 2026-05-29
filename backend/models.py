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
