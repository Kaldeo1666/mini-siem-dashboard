"""
main.py — FastAPI application entry point.
"""

from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from database import engine, Base, AsyncSessionLocal
from routers import ingest, logs, rules, alerts
from engine import evaluate_rules
import engine as engine_module
from ws_manager import manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Database tables ready")

    # Seed built-in rules
    async with AsyncSessionLocal() as db:
        await rules.seed_builtin_rules(db)
        print("✅ Built-in rules seeded")

    # Connect WebSocket manager to engine
    engine_module.ws_manager = manager

    # Start the rules evaluation scheduler
    scheduler = AsyncIOScheduler()
    scheduler.add_job(evaluate_rules, "interval", seconds=30)
    scheduler.start()
    print("✅ Rules engine started — evaluating every 30 seconds")

    yield

    scheduler.shutdown()
    await engine.dispose()


app = FastAPI(
    title="Mini SIEM API",
    description="Log ingestion, querying, and alerting for a lightweight SIEM.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest.router)
app.include_router(logs.router)
app.include_router(rules.router)
app.include_router(alerts.router)


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/health", tags=["meta"])
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/", tags=["meta"])
async def root():
    return {"message": "Mini SIEM API", "docs": "/docs"}