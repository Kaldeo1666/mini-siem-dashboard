"""
database.py — async SQLAlchemy engine & session factory.

Every route that needs DB access calls `get_db()` via FastAPI's
dependency injection system.
"""

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

# Read from environment variable set in docker-compose.yml
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://siem:siem_password@localhost:5432/siem_db"
)

# Create the async engine
# pool_pre_ping=True — automatically reconnects if the DB dropped the connection
engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

# Session factory — call this to get a DB session
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

class Base(DeclarativeBase):
    """Base class that all SQLAlchemy models inherit from."""
    pass


async def get_db():
    """
    FastAPI dependency — yields a DB session, closes it when the request ends.
    Usage in a route:
        async def my_route(db: AsyncSession = Depends(get_db)):
    """
    async with AsyncSessionLocal() as session:
        yield session
