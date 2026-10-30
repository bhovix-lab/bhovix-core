-- Hadavin core store, version 0001. One column per model field (a contract for Portal v0): Decimal ->
-- NUMERIC(18,6), datetime -> TIMESTAMPTZ, dict/list -> JSONB, enums -> TEXT CHECK. Applied only by
-- `hadavin-sdk migrate` under a migration role; the runtime role gets SELECT, INSERT, UPDATE.

CREATE TABLE runs (
    run_id         TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    agent_id       TEXT NOT NULL,
    principal_id   TEXT NOT NULL,
    trigger_kind   TEXT NOT NULL CHECK (trigger_kind IN ('event', 'schedule', 'user')),
    trigger_ref    TEXT NOT NULL,
    state          TEXT NOT NULL CHECK (state IN (
        'RECEIVED', 'WORKING', 'NO_ACTION', 'PLAN_READY', 'NEEDS_PERSON', 'DENIED', 'WAITING_FOR_APPROVAL',
        'EXECUTING', 'REJECTED', 'EXPIRED', 'VERIFYING', 'SUCCEEDED', 'ROLLED_BACK', 'STOPPED')),
    reason_code    TEXT,
    cost_usd       NUMERIC(18, 6) NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX runs_by_state_age ON runs (state, updated_at);

CREATE TABLE plans (
    run_id           TEXT PRIMARY KEY,
    plan_id          TEXT NOT NULL UNIQUE,
    schema_version   INTEGER NOT NULL,
    agent_id         TEXT NOT NULL,
    action_id        TEXT NOT NULL,
    action_version   INTEGER NOT NULL,
    risk_class       TEXT NOT NULL CHECK (risk_class IN ('read_only', 'reversible', 'sign_off')),
    inputs           JSONB NOT NULL,
    target           JSONB NOT NULL,
    idempotency_key  TEXT NOT NULL,
    expected_outcome TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL
);

CREATE TABLE gate_decisions (
    run_id         TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    plan_hash      TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('allow', 'needs_approval', 'deny')),
    rule_id        TEXT NOT NULL,
    ts             TIMESTAMPTZ NOT NULL
);

CREATE TABLE approval_requests (
    approval_id     TEXT PRIMARY KEY,
    schema_version  INTEGER NOT NULL,
    run_id          TEXT NOT NULL,
    plan_hash       TEXT NOT NULL,
    risk_class      TEXT NOT NULL CHECK (risk_class IN ('read_only', 'reversible', 'sign_off')),
    chain_id        TEXT NOT NULL,
    steps           JSONB NOT NULL,
    current_step    INTEGER NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')),
    step_expires_at TIMESTAMPTZ NOT NULL,
    requested_by    TEXT NOT NULL,
    summary         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX approval_requests_by_status ON approval_requests (status, step_expires_at);

CREATE TABLE approval_decisions (
    seq            BIGSERIAL PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    approval_id    TEXT NOT NULL,
    plan_hash      TEXT NOT NULL,
    step           INTEGER NOT NULL,
    decision       TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    approver_id    TEXT NOT NULL,
    channel        TEXT NOT NULL,
    reason         TEXT NOT NULL,
    decided_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX approval_decisions_by_request ON approval_decisions (approval_id, seq);

CREATE TABLE dead_letters (
    seq            BIGSERIAL PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    run_id         TEXT NOT NULL,
    reason         TEXT NOT NULL,
    errors         JSONB NOT NULL,
    ts             TIMESTAMPTZ NOT NULL
);
CREATE INDEX dead_letters_by_run ON dead_letters (run_id, seq);

CREATE TABLE spend (
    agent_id TEXT NOT NULL,
    day      DATE NOT NULL,
    usd      NUMERIC(18, 6) NOT NULL,
    PRIMARY KEY (agent_id, day)
);

CREATE TABLE kill_switch (
    id             SMALLINT PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    "on"           BOOLEAN NOT NULL,
    "by"           TEXT,
    ts             TIMESTAMPTZ NOT NULL
);
