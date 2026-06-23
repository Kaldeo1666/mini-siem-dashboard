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

engine = create_engine(DATABASE_URL)
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