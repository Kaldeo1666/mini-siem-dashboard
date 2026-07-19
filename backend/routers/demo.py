"""
routers/demo.py — API endpoints for demo mode (V5 Day 2).
"""

import asyncio
from fastapi import APIRouter, HTTPException

import demo
from auth import MASTER_API_KEY

router = APIRouter(prefix="/demo", tags=["demo"])

# The demo needs a real API key to authenticate its own ingestion calls
# back to the API. Rather than looking one up from the DB (which risks
# picking a revoked/inactive key), it reuses the same DEFAULT_API_KEY
# env var the rest of the dev/test tooling already relies on.
import os
DEMO_API_KEY = os.getenv("DEFAULT_API_KEY", "dev-local-siem-key-2026")
DEMO_API_BASE = "http://localhost:8000"


@router.post("/reset")
async def reset_demo():
    """Clears logs, alerts, cases, baselines. Preserves rules/IOCs/keys."""
    if demo.get_demo_status()["running"]:
        raise HTTPException(status_code=409, detail="Cannot reset while a demo run is in progress")
    demo.reset_demo_data()
    return {"reset": True}


@router.post("/run")
async def run_demo():
    """
    Starts the 4-stage attack simulation as a background task and
    returns immediately. Poll GET /demo/status for progress.
    """
    if demo.get_demo_status()["running"]:
        raise HTTPException(status_code=409, detail="A demo run is already in progress")

    asyncio.create_task(demo.run_demo_async(DEMO_API_BASE, DEMO_API_KEY))
    return {"started": True}


@router.get("/status")
async def demo_status():
    return demo.get_demo_status()