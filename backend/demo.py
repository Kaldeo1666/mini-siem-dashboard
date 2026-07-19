"""
demo.py — One-click attack simulation demo mode (V5 Day 2).

POST /demo/reset — clears logs, alerts, cases, baselines. Preserves
                   alert_rules, correlation_rules, ioc_entries, api_keys.
POST /demo/run   — resets, then runs the 4-stage attack live, pacing one
                   stage every 8 seconds so alerts appear in real time
                   on the dashboard via the existing WebSocket broadcast.
GET  /demo/status — current run state, for the frontend's progress banner.

Runs as an asyncio background task so the HTTP response for POST /demo/run
returns immediately; the frontend polls /demo/status for progress.
"""

import asyncio
from datetime import datetime, timezone

import httpx
from sqlalchemy import text

from database import SessionLocal
from models import Log, Alert, Case, CaseAlert, CaseNote, Baseline

ATTACKER_IP = "10.99.0.1"
STAGE_DELAY_SECONDS = 8

_status = {
    "running": False,
    "current_stage": None,
    "stages_completed": [],
    "started_at": None,
    "finished_at": None,
    "error": None,
}


def get_demo_status() -> dict:
    return dict(_status)


def reset_demo_data():
    """
    Clears logs, alerts, cases, and baselines. Preserves alert_rules,
    correlation_rules, ioc_entries, and api_keys -- so the demo can be
    re-run indefinitely without re-seeding detection rules or losing
    API key access.

    Deletion order respects foreign keys: case_notes and case_alerts
    (children of cases/alerts) must go before cases and alerts
    themselves; alerts must go before logs, since correlation alerts
    reference specific log rows.
    """
    db = SessionLocal()
    try:
        db.query(CaseNote).delete(synchronize_session=False)
        db.query(CaseAlert).delete(synchronize_session=False)
        db.query(Case).delete(synchronize_session=False)
        db.query(Alert).delete(synchronize_session=False)
        db.query(Log).delete(synchronize_session=False)
        db.query(Baseline).delete(synchronize_session=False)
        db.commit()
        print("[Demo] Reset complete: logs, alerts, cases, baselines cleared")
    except Exception as e:
        db.rollback()
        print(f"[Demo] Reset error: {e}")
        raise
    finally:
        db.close()


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


async def _stage_1_recon(client, api_base):
    events = [
        {
            "timestamp": _now_iso(),
            "source_type": "apache",
            "source_ip": ATTACKER_IP,
            "action": f"GET /path{i}",
            "status_code": 404,
            "message": f"GET /path{i} HTTP/1.1 404",
        }
        for i in range(50)
    ]
    await client.post(f"{api_base}/ingest/json", json=events, timeout=15.0)


async def _stage_2_brute_force(client, api_base):
    events = [
        {
            "timestamp": _now_iso(),
            "source_type": "apache",
            "source_ip": ATTACKER_IP,
            "action": "POST /login",
            "status_code": 401,
            "user": "admin",
            "message": f"Failed login attempt #{i} for admin from {ATTACKER_IP}",
        }
        for i in range(15)
    ]
    await client.post(f"{api_base}/ingest/json", json=events, timeout=15.0)


async def _stage_3_exploitation(client, api_base):
    event = {
        "timestamp": _now_iso(),
        "source_type": "apache",
        "source_ip": ATTACKER_IP,
        "action": "POST /admin/login",
        "status_code": 200,
        "user": "admin",
        "message": f"Successful admin login from {ATTACKER_IP}",
    }
    await client.post(f"{api_base}/ingest/json", json=event, timeout=15.0)


async def _stage_4_exfiltration(client, api_base):
    events = [
        {
            "timestamp": _now_iso(),
            "source_type": "apache",
            "source_ip": ATTACKER_IP,
            "action": "GET /export/full_dump",
            "status_code": 200,
            "message": f"Large transfer #{i} complete: bytes_sent=15728640 from {ATTACKER_IP}",
        }
        for i in range(100)
    ]
    await client.post(f"{api_base}/ingest/json", json=events, timeout=15.0)


STAGES = [
    ("Recon", _stage_1_recon),
    ("Brute Force", _stage_2_brute_force),
    ("Exploitation", _stage_3_exploitation),
    ("Exfiltration", _stage_4_exfiltration),
]


async def run_demo_async(api_base: str, api_key: str):
    """
    The actual demo run, executed as a background asyncio task so
    POST /demo/run can return immediately. Paces one stage every
    STAGE_DELAY_SECONDS so alerts appear live on the dashboard as each
    stage's rules fire, rather than all at once.
    """
    global _status
    _status = {
        "running": True,
        "current_stage": None,
        "stages_completed": [],
        "started_at": _now_iso(),
        "finished_at": None,
        "error": None,
    }

    try:
        reset_demo_data()

        async with httpx.AsyncClient(headers={"X-API-Key": api_key}) as client:
            for stage_name, stage_fn in STAGES:
                _status["current_stage"] = stage_name
                print(f"[Demo] Running stage: {stage_name}")
                await stage_fn(client, api_base)
                _status["stages_completed"].append(stage_name)
                await asyncio.sleep(STAGE_DELAY_SECONDS)

        _status["current_stage"] = None
        _status["finished_at"] = _now_iso()
        print("[Demo] Run complete")
    except Exception as e:
        _status["error"] = str(e)
        print(f"[Demo] Run failed: {e}")
    finally:
        _status["running"] = False