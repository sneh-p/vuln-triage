-- 001_init.sql
-- Initial migration to define vulnerability-triage database schema

-- 1. Assets Table
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL UNIQUE,
    environment VARCHAR(50) NOT NULL CHECK (environment IN ('prod', 'staging', 'dev', 'sandbox', 'unknown')),
    business_crit INT NOT NULL CHECK (business_crit >= 1 AND business_crit <= 5),
    ip VARCHAR(255),
    owner_team TEXT,
    tags TEXT[],
    updated_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 2. Findings Table
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    asset_id INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve VARCHAR(50) NOT NULL,
    plugin_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    description TEXT,
    cvss_base NUMERIC(3,1) NOT NULL CHECK (cvss_base >= 0.0 AND cvss_base <= 10.0),
    cvss_vector TEXT,
    severity VARCHAR(50) NOT NULL,
    detected_at TIMESTAMP NOT NULL,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    vendor_advisory TEXT,
    raw JSONB,
    scanner VARCHAR(50) NOT NULL DEFAULT 'unknown',
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (asset_id, plugin_id, cve)
);

-- 3. Enrichment Table
CREATE TABLE IF NOT EXISTS enrichment (
    cve VARCHAR(50) PRIMARY KEY,
    epss NUMERIC(7,6) NOT NULL DEFAULT 0.0,
    in_kev BOOLEAN NOT NULL DEFAULT FALSE,
    public_exploit BOOLEAN NOT NULL DEFAULT FALSE,
    last_enriched_at TIMESTAMP NOT NULL
);

-- 4. Triage Table
CREATE TABLE IF NOT EXISTS triage (
    id SERIAL PRIMARY KEY,
    finding_id INT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'ticketed', 'closed')),
    priority_score NUMERIC(7,2) NOT NULL DEFAULT 0.0,
    rationale TEXT,
    assigned_to VARCHAR(255),
    notes TEXT,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS triage_finding_active_idx ON triage (finding_id) WHERE status IN ('pending', 'approved');
CREATE UNIQUE INDEX IF NOT EXISTS triage_finding_pending_idx ON triage (finding_id) WHERE status = 'pending';
CREATE UNIQUE INDEX IF NOT EXISTS triage_finding_approved_idx ON triage (finding_id) WHERE status = 'approved';

-- 5. Tickets Table
CREATE TABLE IF NOT EXISTS tickets (
    id SERIAL PRIMARY KEY,
    triage_id INT NOT NULL REFERENCES triage(id) ON DELETE CASCADE,
    external_system VARCHAR(50) NOT NULL CHECK (external_system IN ('jira', 'servicenow', 'github', 'autotask', 'autotask-stub')),
    external_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 6. Audit Events Table
CREATE TABLE IF NOT EXISTS audit_events (
    id SERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(100) NOT NULL,
    target_id VARCHAR(255) NOT NULL,
    details JSONB,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Migration to clean duplicates and enforce unique constraint on triage(finding_id)
DELETE FROM triage WHERE id NOT IN (SELECT MAX(id) FROM triage GROUP BY finding_id);
ALTER TABLE triage ADD CONSTRAINT triage_finding_id_unique UNIQUE (finding_id);

