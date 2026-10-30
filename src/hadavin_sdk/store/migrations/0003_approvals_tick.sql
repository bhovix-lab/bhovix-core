-- Hadavin core store, version 0003 (slice 2 P7): channel send tracking, one decision per approval step,
-- an exact month spend counter, the kill switch row, and tick step state.

-- A request whose channel send failed keeps sent_at NULL; the next tick resends it.
ALTER TABLE approval_requests ADD COLUMN sent_at TIMESTAMPTZ;
ALTER TABLE approval_requests ADD COLUMN channel_ref TEXT;

-- One accepted decision per approval step: a second (racing or replayed) one is refused.
ALTER TABLE approval_decisions ADD CONSTRAINT approval_decisions_one_per_step UNIQUE (approval_id, step);

-- Month totals kept by the same atomic upsert as the day rows (no sum over rows another writer is adding).
CREATE TABLE spend_month (
    agent_id TEXT NOT NULL,
    month    DATE NOT NULL CHECK (EXTRACT(DAY FROM month) = 1),
    usd      NUMERIC NOT NULL,
    PRIMARY KEY (agent_id, month)
);
INSERT INTO spend_month (agent_id, month, usd)
SELECT agent_id, date_trunc('month', day)::date, SUM(usd) FROM spend GROUP BY 1, 2;

-- The kill switch row always exists; a missing row is read as "stopped" (fail closed).
INSERT INTO kill_switch (id, schema_version, "on", "by", ts)
VALUES (1, 1, FALSE, NULL, now())
ON CONFLICT (id) DO NOTHING;

-- One row per tick step: when it last ran, last succeeded, and its last error (redacted).
CREATE TABLE tick_state (
    step        TEXT PRIMARY KEY CHECK (step ~ '^[a-z_]+$'),
    last_run_at TIMESTAMPTZ NOT NULL,
    last_ok_at  TIMESTAMPTZ,
    last_error  TEXT
);
