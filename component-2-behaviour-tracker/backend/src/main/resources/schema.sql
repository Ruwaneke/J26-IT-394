-- =============================================================================
-- Developer Behaviour Tracker - Database Schema (PostgreSQL DDL Script)
-- Database Name: developer_behavior
-- =============================================================================

-- 1. Table: developers
CREATE TABLE IF NOT EXISTS developers (
    id BIGSERIAL PRIMARY KEY,
    developer_identifier VARCHAR(255) NOT NULL UNIQUE,
    github_id VARCHAR(100) UNIQUE,
    github_username VARCHAR(255),
    email VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_developer_identifier ON developers(developer_identifier);

-- GitHub identity columns for databases created before GitHub auth integration
ALTER TABLE developers ADD COLUMN IF NOT EXISTS github_id VARCHAR(100) UNIQUE;
ALTER TABLE developers ADD COLUMN IF NOT EXISTS github_username VARCHAR(255);
ALTER TABLE developers ADD COLUMN IF NOT EXISTS email VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_developer_github_id ON developers(github_id);

-- 2. Table: security_events
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    developer_id BIGINT NOT NULL REFERENCES developers(id) ON DELETE CASCADE,
    vulnerability_type VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    file_name VARCHAR(500) NOT NULL,
    line_number INT NOT NULL,
    message TEXT NOT NULL,
    detected_at TIMESTAMP NOT NULL,
    current_status VARCHAR(50) NOT NULL DEFAULT 'DETECTED',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_se_developer_id ON security_events(developer_id);
CREATE INDEX IF NOT EXISTS idx_se_detected_at ON security_events(detected_at);
CREATE INDEX IF NOT EXISTS idx_se_vulnerability_type ON security_events(vulnerability_type);
CREATE INDEX IF NOT EXISTS idx_se_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_se_current_status ON security_events(current_status);

-- 3. Table: behaviour_logs
CREATE TABLE IF NOT EXISTS behaviour_logs (
    id BIGSERIAL PRIMARY KEY,
    developer_id BIGINT NOT NULL REFERENCES developers(id) ON DELETE CASCADE,
    security_event_id BIGINT REFERENCES security_events(id) ON DELETE SET NULL,
    action_type VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    context_metadata TEXT,
    time_since_detection_seconds BIGINT,
    session_id VARCHAR(255),
    source VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_bl_developer_id ON behaviour_logs(developer_id);
CREATE INDEX IF NOT EXISTS idx_bl_security_event_id ON behaviour_logs(security_event_id);
CREATE INDEX IF NOT EXISTS idx_bl_timestamp ON behaviour_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_bl_action_type ON behaviour_logs(action_type);

-- 4. Table: vulnerability_lifecycle_history
CREATE TABLE IF NOT EXISTS vulnerability_lifecycle_history (
    id BIGSERIAL PRIMARY KEY,
    security_event_id BIGINT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
    previous_status VARCHAR(50),
    new_status VARCHAR(50) NOT NULL,
    changed_at TIMESTAMP NOT NULL,
    changed_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vlh_security_event_id ON vulnerability_lifecycle_history(security_event_id);
CREATE INDEX IF NOT EXISTS idx_vlh_changed_at ON vulnerability_lifecycle_history(changed_at);
