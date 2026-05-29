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
