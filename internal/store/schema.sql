CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
    key  TEXT PRIMARY KEY,
    blob BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS machines (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    addr       TEXT NOT NULL,
    arch       TEXT NOT NULL DEFAULT '',
    host_key   TEXT NOT NULL DEFAULT '',
    schedule   TEXT NOT NULL DEFAULT '',
    clean      INTEGER NOT NULL DEFAULT 0,
    created    INTEGER NOT NULL,
    last_visit INTEGER
);

CREATE TABLE IF NOT EXISTS snapshots (
    machine_id INTEGER PRIMARY KEY REFERENCES machines(id),
    taken      INTEGER NOT NULL,
    blob       BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id      INTEGER NOT NULL REFERENCES machines(id),
    meta_blob       BLOB NOT NULL,
    report_blob     BLOB NOT NULL,
    collection_blob BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_by_machine ON reports(machine_id, id DESC);

CREATE TABLE IF NOT EXISTS exceptions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id INTEGER NOT NULL REFERENCES machines(id),
    blob       BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    time   INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
