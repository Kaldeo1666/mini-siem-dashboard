-- ============================================================
-- Mini SIEM Database Schema
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- for gen_random_uuid()

-- Main normalized logs table
CREATE TABLE IF NOT EXISTS logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL,
    source_type     VARCHAR(32) NOT NULL
                        CHECK (source_type IN ('apache','nginx','syslog','json','firewall','windows_event')),
    source_host     VARCHAR(255) NOT NULL DEFAULT 'unknown',
    level           VARCHAR(16) NOT NULL DEFAULT 'INFO'
                        CHECK (level IN ('DEBUG','INFO','WARN','ERROR','CRITICAL')),
    source_ip       INET,
    "user"          VARCHAR(255),
    action          VARCHAR(512),
    status_code     INT,
    message         TEXT NOT NULL DEFAULT '',
    raw             TEXT NOT NULL DEFAULT '',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ioc_matched     BOOLEAN NOT NULL DEFAULT FALSE
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_logs_timestamp    ON logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_source_ip    ON logs (source_ip);
CREATE INDEX IF NOT EXISTS idx_logs_source_type  ON logs (source_type);
CREATE INDEX IF NOT EXISTS idx_logs_level        ON logs (level);

-- Table to record lines that failed to parse (never lose data)
CREATE TABLE IF NOT EXISTS parse_errors (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_line    TEXT NOT NULL,
    endpoint    VARCHAR(64) NOT NULL,
    error_msg   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- V1: Alert Rules Engine Tables
-- ============================================================

CREATE TABLE IF NOT EXISTS alert_rules (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               VARCHAR(255) NOT NULL,
    description        TEXT,
    condition_type     VARCHAR(32) NOT NULL
                         CHECK (condition_type IN ('threshold','rate','new_entity','pattern_match')),
    condition_field    VARCHAR(64) NOT NULL,
    condition_value    VARCHAR(255) NOT NULL,
    group_by           VARCHAR(64),
    threshold          INT NOT NULL DEFAULT 1,
    window_seconds     INT NOT NULL DEFAULT 60,
    severity           VARCHAR(16) NOT NULL
                         CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    mitre_technique_id VARCHAR(16),
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    cooldown_seconds   INT NOT NULL DEFAULT 300,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id            UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    rule_name          VARCHAR(255) NOT NULL,
    severity           VARCHAR(16) NOT NULL,
    status             VARCHAR(16) NOT NULL DEFAULT 'NEW'
                         CHECK (status IN ('NEW','ACKNOWLEDGED','INVESTIGATING','RESOLVED')),
    group_value        VARCHAR(255),
    matched_count      INT NOT NULL DEFAULT 1,
    first_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at    TIMESTAMPTZ,
    resolved_at        TIMESTAMPTZ,
    notes              TEXT,
    mitre_technique_id VARCHAR(16)
);

CREATE INDEX IF NOT EXISTS idx_alerts_rule_id   ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts (last_seen DESC);
