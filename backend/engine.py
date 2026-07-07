"""
engine.py - Alert Rules Evaluation Engine

Runs every 30 seconds via APScheduler.
For each enabled rule:
  1. Query logs within the rule's time window
  2. Group by source_ip
  3. If count exceeds threshold -> fire an alert
  4. Deduplicate - don't re-fire within cooldown window
"""

import re
from datetime import datetime, timezone, timedelta
from sqlalchemy import func, and_, cast
from sqlalchemy.dialects.postgresql import INET as PG_INET

from database import SessionLocal
from models import AlertRule, Alert, AlertSeverity, AlertStatus, Log

# WebSocket manager - broadcasts fired alerts to connected dashboard clients
from ws_manager import manager as ws_manager


def evaluate_rules():
    """Main function - called every 30 seconds by APScheduler."""
    db = SessionLocal()
    try:
        rules = db.query(AlertRule).filter(AlertRule.enabled == True).all()
        fired = 0
        for rule in rules:
            try:
                count = _evaluate_single_rule(db, rule)
                fired += count
            except Exception as e:
                print(f"[Engine] Error evaluating rule '{rule.name}': {e}")
        if fired:
            print(f"[Engine] Cycle complete - {fired} alert(s) fired")
    finally:
        db.close()


def _evaluate_single_rule(db, rule: AlertRule) -> int:
    """
    Evaluate one rule against recent logs.
    Returns number of new alerts fired.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=rule.time_window_seconds)

    # Base filter: logs within the time window
    conditions = [Log.timestamp >= window_start]

    # Filter by source_type if specified
    if rule.source_type:
        conditions.append(Log.source_type == rule.source_type)

    # Add condition based on operator
    field = rule.condition_field
    operator = rule.condition_operator
    value = rule.condition_value

    if hasattr(Log, field):
        col = getattr(Log, field)
        if operator == "eq":
            # Try integer comparison for status_code
            try:
                conditions.append(col == int(value))
            except ValueError:
                conditions.append(col == value)
        elif operator == "contains":
            conditions.append(col.ilike(f"%{value}%"))
        elif operator == "gt":
            conditions.append(col > float(value))
        elif operator == "lt":
            conditions.append(col < float(value))

    where = and_(*conditions)

    # Group by source_ip and count
    rows = (
        db.query(Log.source_ip, func.count().label("cnt"))
        .filter(where)
        .group_by(Log.source_ip)
        .having(func.count() >= rule.threshold_count)
        .all()
    )

    fired = 0
    for source_ip, matched_count in rows:
        group_str = str(source_ip) if source_ip else "global"
        did_fire = _fire_alert(db, rule, group_str, matched_count, now)
        if did_fire:
            fired += 1

    return fired


def _fire_alert(db, rule: AlertRule, source_ip: str, matched_count: int, now: datetime) -> bool:
    """
    Fire an alert if deduplication allows it.
    Returns True if a new alert was created.
    """
    # Check for existing active alert within cooldown
    cooldown_start = now - timedelta(seconds=rule.cooldown_seconds)
    existing = (
        db.query(Alert)
        .filter(
            and_(
                Alert.rule_id == rule.id,
                Alert.source_ip == cast(source_ip, PG_INET) if source_ip != "global" else Alert.source_ip == None,
                Alert.status != AlertStatus.RESOLVED,
                Alert.triggered_at >= cooldown_start,
            )
        )
        .first()
    )

    if existing:
        # Still within cooldown - don't re-fire
        return False

    # Create new alert
    alert = Alert(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        status=AlertStatus.NEW,
        source_ip=source_ip if source_ip != "global" else None,
        source_type=rule.source_type,
        description=f"Rule '{rule.name}' triggered {matched_count} times in {rule.time_window_seconds}s",
        mitre_technique_id=rule.mitre_technique_id,
    )
    db.add(alert)
    db.commit()

    ws_manager.broadcast_sync(alert.to_dict())
    print(f"[Engine] Alert fired: '{rule.name}' | {source_ip} | {rule.severity}")
    return True

