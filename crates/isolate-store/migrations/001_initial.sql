-- isolate event store schema
-- Migration 001: initial tables
-- NOTE: PRAGMA journal_mode and synchronous are set in Store::open() before migrations run,
-- because PRAGMAs that change modes cannot execute inside a transaction.

PRAGMA foreign_keys = ON;

-- ── Events ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS events (
    seq         INTEGER NOT NULL,
    isobox_id   TEXT    NOT NULL,
    backend     TEXT    NOT NULL,
    kind        TEXT    NOT NULL,  -- syscall | network | file | process | exec | alert | raw
    timestamp   TEXT    NOT NULL,  -- ISO 8601
    body_json   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_isobox_ts
    ON events (isobox_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_kind
    ON events (kind);

-- ── Alerts ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS alerts (
    alert_id      TEXT    NOT NULL PRIMARY KEY,
    isobox_id     TEXT    NOT NULL,
    severity      TEXT    NOT NULL,  -- info | warn | critical | emergency
    title         TEXT    NOT NULL,
    detail        TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL,
    anomaly_score REAL,
    action_taken  TEXT    NOT NULL,
    paladin_level INTEGER,
    full_json     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_isobox_ts
    ON alerts (isobox_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_severity
    ON alerts (severity);

-- ── Behavioral baselines ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS baselines (
    workload_class   TEXT    NOT NULL,
    window_minutes   INTEGER NOT NULL,  -- 5, 60, 1440
    updated_at       TEXT    NOT NULL,
    sample_count     INTEGER NOT NULL DEFAULT 0,
    data_msgpack     BLOB    NOT NULL,  -- compressed baseline histogram
    PRIMARY KEY (workload_class, window_minutes)
);

-- ── Policy audit log ──────────────────────────────────────────────────────────
-- Append-only. Never delete rows. Used for compliance and rollback.

CREATE TABLE IF NOT EXISTS policy_audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    isobox_id    TEXT    NOT NULL,
    version      INTEGER NOT NULL,
    author       TEXT    NOT NULL,
    reason       TEXT,
    timestamp    TEXT    NOT NULL,
    policy_json  TEXT    NOT NULL
);

-- ── IOC match log ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ioc_matches (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    isobox_id        TEXT    NOT NULL,
    timestamp        TEXT    NOT NULL,
    indicator_type   TEXT    NOT NULL,
    indicator_value  TEXT    NOT NULL,
    feed             TEXT    NOT NULL,
    confidence       REAL    NOT NULL,
    threat_type      TEXT,
    event_json       TEXT
);

CREATE INDEX IF NOT EXISTS idx_ioc_isobox
    ON ioc_matches (isobox_id, timestamp DESC);

-- ── Isobox registry ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS isoboxes (
    id           TEXT    NOT NULL PRIMARY KEY,
    name         TEXT    NOT NULL,
    state        TEXT    NOT NULL,  -- starting | running | frozen | stopped | killed | error
    config_json  TEXT    NOT NULL,
    started_at   TEXT    NOT NULL,
    stopped_at   TEXT
);

-- ── Paladin escalation log ────────────────────────────────────────────────────
-- Append-only record of every paladin action.

CREATE TABLE IF NOT EXISTS paladin_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    isobox_id    TEXT    NOT NULL,
    timestamp    TEXT    NOT NULL,
    level        INTEGER NOT NULL,
    level_name   TEXT    NOT NULL,
    reason       TEXT    NOT NULL,
    triggered_by TEXT    NOT NULL,  -- "heartbeat_timeout" | "anomaly" | "manual" | "tripwire"
    outcome      TEXT    NOT NULL   -- "success" | "partial" | "failed"
);
