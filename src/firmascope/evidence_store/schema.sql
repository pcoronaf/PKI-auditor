-- Esquema del expediente de auditoria de FirmaScope.
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS session (
    id            TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    started_at    REAL NOT NULL,
    ended_at      REAL,
    config_json   TEXT NOT NULL,
    versions_json TEXT NOT NULL,
    chain_head    TEXT NOT NULL DEFAULT '',
    note          TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    id         TEXT NOT NULL UNIQUE,
    session    TEXT NOT NULL,
    timestamp  REAL NOT NULL,
    type       TEXT NOT NULL,
    context    TEXT NOT NULL,
    origin     TEXT NOT NULL,
    source     TEXT NOT NULL,
    sensor     TEXT NOT NULL,
    tags_json  TEXT NOT NULL,
    data_json  TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_type_idx ON events(type);
CREATE INDEX IF NOT EXISTS events_ts_idx ON events(timestamp);

CREATE TABLE IF NOT EXISTS requests (
    id            TEXT PRIMARY KEY,
    session       TEXT NOT NULL,
    timestamp     REAL NOT NULL,
    method        TEXT NOT NULL,
    url           TEXT NOT NULL,
    host          TEXT NOT NULL,
    registrable   TEXT NOT NULL,
    third_party   INTEGER NOT NULL DEFAULT 0,
    resource_type TEXT NOT NULL DEFAULT '',
    initiator     TEXT NOT NULL DEFAULT '',
    stack_json    TEXT NOT NULL DEFAULT '[]',
    headers_json  TEXT NOT NULL DEFAULT '{}',
    body_size     INTEGER NOT NULL DEFAULT 0,
    body_digest   TEXT NOT NULL DEFAULT '',
    body_ref      TEXT NOT NULL DEFAULT '',
    tags_json     TEXT NOT NULL DEFAULT '[]',
    status        INTEGER,
    response_size INTEGER,
    redirect_from TEXT NOT NULL DEFAULT '',
    sensor        TEXT NOT NULL DEFAULT 'cdp',
    context       TEXT NOT NULL DEFAULT 'main'
);
CREATE INDEX IF NOT EXISTS requests_ts_idx ON requests(timestamp);

CREATE TABLE IF NOT EXISTS scripts (
    id          TEXT PRIMARY KEY,
    session     TEXT NOT NULL,
    url         TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size        INTEGER NOT NULL,
    third_party INTEGER NOT NULL DEFAULT 0,
    inline      INTEGER NOT NULL DEFAULT 0,
    sourcemap   TEXT NOT NULL DEFAULT '',
    path        TEXT NOT NULL DEFAULT '',
    context     TEXT NOT NULL DEFAULT 'main'
);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    session       TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    title         TEXT NOT NULL,
    status        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    TEXT NOT NULL,
    summary       TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id         TEXT PRIMARY KEY,
    session    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    path       TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    size       INTEGER NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id         TEXT PRIMARY KEY,
    session    TEXT NOT NULL,
    name       TEXT NOT NULL,
    timestamp  REAL NOT NULL,
    network    TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);
