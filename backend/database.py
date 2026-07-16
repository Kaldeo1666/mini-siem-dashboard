from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from models import (
    Base, Log, AlertRule, Alert,
    Baseline, IOCEntry, SeenUserAgent, CorrelationRule
)
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://siem:siem_password@db:5432/siem_db"
)

# Default pool_size=5/max_overflow=10 (15 total connections) was
# saturating under concurrent load during the V4 Day 3 benchmark —
# median latency climbed from ~210ms to ~570ms and p99 hit 890ms
# (spec target: p99 < 200ms) as requests queued for a free connection.
# Sized up based on that measurement, not guessed in advance.
engine = create_engine(DATABASE_URL, pool_size=20, max_overflow=30, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables that don't exist yet."""
    Base.metadata.create_all(bind=engine)