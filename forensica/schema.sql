-- schema.sql
-- PostgreSQL schema for FORENSICA

CREATE TABLE IF NOT EXISTS cases (
    case_id VARCHAR(255) PRIMARY KEY,
    evidence_path TEXT,
    risk_score INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    case_id VARCHAR(255) REFERENCES cases(case_id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE,
    source VARCHAR(255),
    event_type VARCHAR(255),
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    case_id VARCHAR(255) REFERENCES cases(case_id) ON DELETE CASCADE,
    claim TEXT,
    confidence INT,
    artifacts JSONB,
    source_agent VARCHAR(255),
    is_validated BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    case_id VARCHAR(255) REFERENCES cases(case_id) ON DELETE CASCADE,
    ioc_value VARCHAR(255),
    ioc_type VARCHAR(255),
    source_agent VARCHAR(255),
    confidence INT,
    enrichment_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detections (
    id SERIAL PRIMARY KEY,
    case_id VARCHAR(255) REFERENCES cases(case_id) ON DELETE CASCADE,
    rule_name VARCHAR(255),
    content TEXT,
    rule_type VARCHAR(255), -- Sigma, Splunk SPL, KQL
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    case_id VARCHAR(255) REFERENCES cases(case_id) ON DELETE CASCADE,
    report_type VARCHAR(50), -- soc, executive, remediation
    content TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
