-- ============================================================
-- Mini SIEM Database Schema - V2
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- Core Tables
-- ============================================================

CREATE TABLE IF NOT EXISTS logs (
    id              SERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_type     VARCHAR(50) NOT NULL,
    source_ip       INET,
    action          VARCHAR(255),
    status_code     INT,
    "user"          VARCHAR(255),
    message         TEXT,
    raw             TEXT,
    ioc_matched     BOOLEAN NOT NULL DEFAULT FALSE
);
ALTER TABLE logs ADD COLUMN IF NOT EXISTS level VARCHAR(20);
ALTER TABLE logs ADD COLUMN IF NOT EXISTS source_host VARCHAR(255);
ALTER TABLE logs ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE INDEX IF NOT EXISTS idx_logs_timestamp   ON logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp   ON logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_source_ip   ON logs (source_ip);
CREATE INDEX IF NOT EXISTS idx_logs_source_type ON logs (source_type);

CREATE TABLE IF NOT EXISTS parse_errors (
    id          SERIAL PRIMARY KEY,
    raw_line    TEXT NOT NULL,
    endpoint    VARCHAR(64) NOT NULL,
    error_msg   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- V1: Alert Rules Engine
-- ============================================================

CREATE TABLE IF NOT EXISTS alert_rules (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    source_type         VARCHAR(50),
    condition_field     VARCHAR(100) NOT NULL,
    condition_operator  VARCHAR(20) NOT NULL,
    condition_value     VARCHAR(255) NOT NULL,
    severity            VARCHAR(16) NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    time_window_seconds INT NOT NULL DEFAULT 300,
    threshold_count     INT NOT NULL DEFAULT 1,
    cooldown_seconds    INT NOT NULL DEFAULT 300,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    mitre_technique_id  VARCHAR(20),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS group_by VARCHAR(50);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS group_by VARCHAR(50);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE alert_rules ALTER COLUMN condition_operator DROP NOT NULL;
ALTER TABLE alert_rules ALTER COLUMN condition_operator SET DEFAULT '=';

CREATE TABLE IF NOT EXISTS alerts (
CREATE TABLE IF NOT EXISTS alerts (
    id                  SERIAL PRIMARY KEY,
    rule_id             INT REFERENCES alert_rules(id) ON DELETE SET NULL,
    rule_name           VARCHAR(255) NOT NULL,
    severity            VARCHAR(16) NOT NULL,
    status              VARCHAR(16) NOT NULL DEFAULT 'NEW'
                            CHECK (status IN ('NEW','ACKNOWLEDGED','INVESTIGATING','RESOLVED')),
    source_ip           INET,
    source_type         VARCHAR(50),
    description         TEXT,
    mitre_technique_id  VARCHAR(20),
    triggered_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at     TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered  ON alerts (triggered_at DESC);

-- ============================================================
-- V2: Anomaly Detection & IOC Tables
-- ============================================================

CREATE TABLE IF NOT EXISTS baselines (
    id           SERIAL PRIMARY KEY,
    metric_name  VARCHAR(100) NOT NULL,
    source_type  VARCHAR(50) NOT NULL,
    hour_of_day  INT NOT NULL,
    day_of_week  INT NOT NULL,
    avg_value    FLOAT NOT NULL DEFAULT 0.0,
    stddev_value FLOAT NOT NULL DEFAULT 0.0,
    sample_count INT NOT NULL DEFAULT 0,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (metric_name, source_type, hour_of_day, day_of_week)
);

CREATE TABLE IF NOT EXISTS ioc_entries (
    id          SERIAL PRIMARY KEY,
    type        VARCHAR(16) NOT NULL CHECK (type IN ('ip','domain','hash')),
    value       VARCHAR(255) NOT NULL,
    description TEXT,
    source      VARCHAR(255),
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active      BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_entries (value);

CREATE TABLE IF NOT EXISTS seen_user_agents (
    id          SERIAL PRIMARY KEY,
    user_agent  TEXT NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_agent, source_type)
);

CREATE TABLE IF NOT EXISTS correlation_rules (
    id                 SERIAL PRIMARY KEY,
    name               VARCHAR(255) NOT NULL,
    source_type_a      VARCHAR(50) NOT NULL,
    condition_a        JSONB NOT NULL,
    source_type_b      VARCHAR(50) NOT NULL,
    condition_b        JSONB NOT NULL,
    window_seconds     INT NOT NULL DEFAULT 60,
    severity           VARCHAR(16) NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    mitre_technique_id VARCHAR(20),
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS geoip_cache (
    ip INET PRIMARY KEY,
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    city VARCHAR(100),
    cached_at TIMESTAMPTZ NOT NULL DEFAULT now()
);