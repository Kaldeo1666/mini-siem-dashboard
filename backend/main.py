from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler
from database import init_db, SessionLocal
from models import AlertRule, AlertSeverity, CorrelationRule, Baseline
from routers import logs, ingest, rules, alerts
import routers.ioc as ioc
import engine
import baseline_engine
import anomaly_engine
import correlation_engine
from seed_iocs import seed_known_bad_ips

scheduler = BackgroundScheduler()


def seed_alert_rules():
    db = SessionLocal()
    try:
        if db.query(AlertRule).count() == 0:
            rules_data = [
                AlertRule(
                    name="Brute Force Login",
                    description="Multiple failed logins from same IP",
                    source_type="apache",
                    condition_field="status_code",
                    condition_operator="eq",
                    condition_value="401",
                    severity=AlertSeverity.HIGH,
                    time_window_seconds=300,
                    threshold_count=5,
                    cooldown_seconds=600,
                    mitre_technique_id="T1110",
                ),
                AlertRule(
                    name="Suspicious Admin Access",
                    description="Access to admin endpoints",
                    source_type="apache",
                    condition_field="action",
                    condition_operator="contains",
                    condition_value="/admin",
                    severity=AlertSeverity.MEDIUM,
                    time_window_seconds=60,
                    threshold_count=1,
                    cooldown_seconds=300,
                    mitre_technique_id="T1078",
                ),
                AlertRule(
                    name="High Error Rate",
                    description="Spike in 500 errors",
                    source_type="apache",
                    condition_field="status_code",
                    condition_operator="eq",
                    condition_value="500",
                    severity=AlertSeverity.MEDIUM,
                    time_window_seconds=300,
                    threshold_count=10,
                    cooldown_seconds=300,
                    mitre_technique_id="T1499",
                ),
                AlertRule(
                    name="Port Scan Detection",
                    description="Multiple different endpoints from same IP",
                    source_type="apache",
                    condition_field="status_code",
                    condition_operator="eq",
                    condition_value="404",
                    severity=AlertSeverity.HIGH,
                    time_window_seconds=60,
                    threshold_count=10,
                    cooldown_seconds=300,
                    mitre_technique_id="T1046",
                ),
                AlertRule(
                    name="Data Exfiltration Attempt",
                    description="Large number of successful requests",
                    source_type="apache",
                    condition_field="status_code",
                    condition_operator="eq",
                    condition_value="200",
                    severity=AlertSeverity.LOW,
                    time_window_seconds=60,
                    threshold_count=100,
                    cooldown_seconds=600,
                    mitre_technique_id="T1041",
                ),
            ]
            db.add_all(rules_data)
            db.commit()
            print("Seeded 5 built-in alert rules")
    finally:
        db.close()


def seed_correlation_rules():
    db = SessionLocal()
    try:
        if db.query(CorrelationRule).count() == 0:
            rule = CorrelationRule(
                name="SSH Brute Force to Web Login Attempt",
                source_type_a="syslog",
                condition_a={"action": "ssh_failed"},
                source_type_b="apache",
                condition_b={"action": "/login", "status_code": 401},
                window_seconds=60,
                severity=AlertSeverity.HIGH,
                mitre_technique_id="T1110",
                enabled=True,
            )
            db.add(rule)
            db.commit()
            print("Seeded 1 built-in correlation rule")
    finally:
        db.close()


def seed_ioc_list():
    db = SessionLocal()
    try:
        seed_known_bad_ips(db)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_alert_rules()
    seed_correlation_rules()
    seed_ioc_list()
    scheduler.add_job(engine.evaluate_rules, "interval", seconds=30, id="rule_eval")
    scheduler.add_job(baseline_engine.compute_baselines, "interval", minutes=15, id="baseline_compute")
    scheduler.add_job(anomaly_engine.detect_anomalies, "interval", seconds=30, id="anomaly_detect")
    scheduler.add_job(correlation_engine.run_correlation, "interval", seconds=30, id="correlation_run")
    scheduler.start()
    print("Scheduler started")
    yield
    scheduler.shutdown()
    print("Scheduler stopped")


app = FastAPI(title="Mini SIEM Dashboard", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router)
app.include_router(ingest.router)
app.include_router(rules.router)
app.include_router(alerts.router)
app.include_router(ioc.router)
@app.get("/health")
def health_check():
    """Simple liveness check — used by tests and monitoring."""
    return {"status": "ok"}


@app.get("/baselines/visualize")
def visualize_baselines(metric: str = "events_per_minute", source_type: str = "apache"):
    """
    Stretch goal: Returns hourly average for a given metric as a
    24-hour array suitable for rendering a heatmap.

    Example response:
    {
      "metric": "events_per_minute",
      "source_type": "apache",
      "hours": [
        {"hour": 0, "avg": 0.0, "stddev": 0.0, "sample_count": 0},
        {"hour": 1, "avg": 2.3, ...},
        ...
      ]
    }
    """
    db = SessionLocal()
    try:
        baselines = (
            db.query(Baseline)
            .filter(
                Baseline.metric_name == metric,
                Baseline.source_type == source_type,
            )
            .all()
        )

        hours_data = {h: {"hour": h, "avg": 0.0, "stddev": 0.0, "sample_count": 0}
                      for h in range(24)}

        for b in baselines:
            if b.hour_of_day in hours_data:
                existing = hours_data[b.hour_of_day]
                if b.sample_count > existing["sample_count"]:
                    hours_data[b.hour_of_day] = {
                        "hour": b.hour_of_day,
                        "avg": round(b.avg_value, 2),
                        "stddev": round(b.stddev_value, 2),
                        "sample_count": b.sample_count,
                    }

        return {
            "metric": metric,
            "source_type": source_type,
            "hours": list(hours_data.values()),
        }
    finally:
        db.close()