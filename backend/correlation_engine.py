"""
correlation_engine.py - Multi-source event correlation.

Checks if a log matching condition_a from source_type_a
is followed by a log matching condition_b from source_type_b
from the SAME source_ip within window_seconds.

Built-in rule: SSH brute force -> web login attempt
  - Failed SSH log + failed web login from same IP within 60s
  - Fires HIGH alert with MITRE T1110
"""

from datetime import datetime, timezone, timedelta
from sqlalchemy import and_
from database import SessionLocal
from models import Alert, AlertSeverity, AlertStatus, CorrelationRule, Log


def run_correlation():
    """Main function - called every 30 seconds by APScheduler."""
    db = SessionLocal()
    try:
        rules = (
            db.query(CorrelationRule)
            .filter(CorrelationRule.enabled == True)
            .all()
        )
        for rule in rules:
            try:
                _evaluate_correlation_rule(db, rule)
            except Exception as e:
                print(f"[Correlation] Error evaluating rule '{rule.name}': {e}")
    except Exception as e:
        print(f"[Correlation] Error: {e}")
    finally:
        db.close()


def _matches_conditions(log: Log, conditions: dict) -> bool:
    """
    Check if a log matches all conditions in the dict.

    conditions is a JSON dict like:
      {"action": "/login", "status_code": 401}
      {"action": "ssh_failed"}

    For each key-value pair:
      - If the key is "status_code", compare as integer
      - Otherwise do a case-insensitive substring match
    """
    for field, expected in conditions.items():
        actual = getattr(log, field, None)
        if actual is None:
            return False
        if field == "status_code":
            try:
                if int(actual) != int(expected):
                    return False
            except (ValueError, TypeError):
                return False
        else:
            if str(expected).lower() not in str(actual).lower():
                return False
    return True


def _fire_correlation_alert(db, rule: CorrelationRule, source_ip: str,
                             log_a: Log, log_b: Log):
    """Fire a correlation alert with 60-minute deduplication."""
    cooldown_start = datetime.now(timezone.utc) - timedelta(minutes=60)

    existing = (
        db.query(Alert)
        .filter(
            and_(
                Alert.rule_name == rule.name,
                Alert.source_ip == source_ip,
                Alert.status != AlertStatus.RESOLVED,
                Alert.triggered_at >= cooldown_start,
            )
        )
        .first()
    )

    if existing:
        return False

    time_diff = abs((log_b.timestamp - log_a.timestamp).total_seconds())

    alert = Alert(
        rule_id=None,
        rule_name=rule.name,
        severity=rule.severity,
        status=AlertStatus.NEW,
        source_ip=source_ip,
        source_type=f"{rule.source_type_a}+{rule.source_type_b}",
        description=(
            f"Correlation rule '{rule.name}' triggered. "
            f"Event A ({rule.source_type_a}) followed by "
            f"Event B ({rule.source_type_b}) from same IP {source_ip} "
            f"within {int(time_diff)}s."
        ),
        mitre_technique_id=rule.mitre_technique_id,
    )
    db.add(alert)
    db.commit()
    print(f"[Correlation] Alert fired: {rule.name} | {source_ip}")
    return True


def _evaluate_correlation_rule(db, rule: CorrelationRule):
    """
    For a given correlation rule, find all logs matching condition_a
    in the last (window_seconds * 2) period, then check if any log
    matching condition_b from the same IP follows within window_seconds.
    """
    now = datetime.now(timezone.utc)
    lookback = now - timedelta(seconds=rule.window_seconds * 2)

    # Get all logs matching condition_a from source_type_a
    logs_a = (
        db.query(Log)
        .filter(
            and_(
                Log.source_type == rule.source_type_a,
                Log.timestamp >= lookback,
                Log.source_ip.isnot(None),
            )
        )
        .all()
    )

    # Filter by condition_a
    matching_a = [log for log in logs_a if _matches_conditions(log, rule.condition_a)]

    if not matching_a:
        return

    # For each matching A event, look for a B event from same IP
    for log_a in matching_a:
        source_ip = str(log_a.source_ip)
        window_end = log_a.timestamp + timedelta(seconds=rule.window_seconds)

        # Find logs matching condition_b from same IP within the window
        logs_b = (
            db.query(Log)
            .filter(
                and_(
                    Log.source_type == rule.source_type_b,
                    Log.source_ip == log_a.source_ip,
                    Log.timestamp >= log_a.timestamp,
                    Log.timestamp <= window_end,
                )
            )
            .all()
        )

        matching_b = [log for log in logs_b if _matches_conditions(log, rule.condition_b)]

        if matching_b:
            _fire_correlation_alert(db, rule, source_ip, log_a, matching_b[0])