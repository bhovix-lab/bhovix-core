-- The `chain` audit's tables in the store's database (slice 2 P3). Ported from WARDEN audit.py `_PG_SCHEMA`
-- (main c78d7709): rows and checkpoints are append-only even to a role that could UPDATE, DELETE or TRUNCATE.
-- The outbox is not: reconcile deletes a queued outcome once it is in the chain.
CREATE TABLE IF NOT EXISTS audit_entries (
    seq BIGINT PRIMARY KEY,
    at TEXT NOT NULL,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    body TEXT NOT NULL,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL,
    event_id TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    seq BIGINT PRIMARY KEY,
    hash TEXT NOT NULL,
    signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_outbox (
    event_id TEXT PRIMARY KEY,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_entries_by_run ON audit_entries (run_id, seq);

CREATE OR REPLACE FUNCTION hadavin_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS
$f$ BEGIN RAISE EXCEPTION 'the audit log is append-only'; END $f$;

CREATE OR REPLACE TRIGGER audit_entries_append_only BEFORE UPDATE OR DELETE ON audit_entries
    FOR EACH ROW EXECUTE FUNCTION hadavin_audit_append_only();
CREATE OR REPLACE TRIGGER audit_checkpoints_append_only BEFORE UPDATE OR DELETE ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION hadavin_audit_append_only();
CREATE OR REPLACE TRIGGER audit_entries_no_truncate BEFORE TRUNCATE ON audit_entries
    FOR EACH STATEMENT EXECUTE FUNCTION hadavin_audit_append_only();
CREATE OR REPLACE TRIGGER audit_checkpoints_no_truncate BEFORE TRUNCATE ON audit_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION hadavin_audit_append_only();
