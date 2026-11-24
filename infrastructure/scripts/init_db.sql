-- Ashlynx WebSec Scanner - PostgreSQL Initial Database Setup
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Schema creation
CREATE SCHEMA IF NOT EXISTS ashlynx;

-- Create minimal audit log structure to verify system bootstrap
CREATE TABLE IF NOT EXISTS system_bootstrap (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    bootstrap_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL DEFAULT 'INITIALIZED'
);

INSERT INTO system_bootstrap (status) VALUES ('INITIALIZED');
