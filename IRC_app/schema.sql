-- RFeye IRC Server — persistence schema.
-- Run once against your PostgreSQL database before starting the server:
--   psql "$DATABASE_URL" -f schema.sql

CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,          -- Pico W MAC address
    name        TEXT NOT NULL,
    lat         DOUBLE PRECISION,
    lon         DOUBLE PRECISION,
    battery     REAL,                       -- NULL until firmware reports it
    mic_status  TEXT,                       -- NULL until firmware reports it
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    online      BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS incidents (
    id                TEXT PRIMARY KEY,           -- e.g. INC-2026-0847
    node_id           TEXT REFERENCES nodes(id),
    node_name         TEXT NOT NULL,
    classification    TEXT,                        -- 'GUNSHOT', 'DISTRESS_VOCAL', ... (NULL until classifier exists)
    confidence        REAL,                         -- 0.0-1.0                          (NULL until classifier exists)
    angle             REAL,
    tdoa12            REAL,
    tdoa13            REAL,
    lat               DOUBLE PRECISION,
    lon               DOUBLE PRECISION,
    confirming_nodes  INTEGER,                      -- NULL until multi-node corroboration exists
    total_nodes       INTEGER,
    status            TEXT NOT NULL DEFAULT 'open', -- open, dispatched, resolved, dismissed
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at);

CREATE TABLE IF NOT EXISTS incident_audit_log (
    id           SERIAL PRIMARY KEY,
    incident_id  TEXT REFERENCES incidents(id),
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    severity     TEXT NOT NULL,      -- DANGER, SUCCESS, WARNING, INFO
    message      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON incident_audit_log (ts);
