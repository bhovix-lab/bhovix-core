"""Forward-only schema migrations for the Postgres store (`hadavin-sdk migrate`).

Run under a migration role, never by the runtime. Every pending `migrations/NNNN_*.sql` file is applied in one
transaction under a transaction-scoped advisory lock, so two concurrent runs apply each file once. Pattern
ported from WARDEN `audit.py:migrate` (main a1e76cbf). Rollback = restore the snapshot taken before migrating.
"""

from __future__ import annotations

import re
from pathlib import Path

from psycopg import sql

from hadavin_sdk.errors import ConfigError
from hadavin_sdk.store.postgres import connect

MIGRATIONS = Path(__file__).parent / "migrations"
TABLES = (
    "runs",
    "plans",
    "gate_decisions",
    "approval_requests",
    "approval_decisions",
    "dead_letters",
    "spend",
    "spend_month",
    "kill_switch",
    "tick_state",
)
# Written once, never changed: the runtime role gets SELECT, INSERT only (no UPDATE).
APPEND_ONLY = frozenset({"approval_decisions", "dead_letters", "gate_decisions"})
_LOCK = int.from_bytes(b"hadvnmig", "big") >> 1  # one fixed key for every migrate run
_ROLE = re.compile(r"[a-z_][a-z0-9_]{0,62}")


def migrate(
    dsn: str,
    *,
    runtime_role: str | None = None,
    iam_auth: bool = False,
    region: str | None = None,
    sslmode: str | None = None,
    sslrootcert: str | None = None,
) -> list[str]:
    """Apply pending migrations; return the versions applied by this call. With `runtime_role`, grant it
    SELECT, INSERT (and UPDATE where rows change) on the core tables and USAGE on the id sequences, nothing
    else; never DELETE or TRUNCATE."""
    if runtime_role is not None and not _ROLE.fullmatch(runtime_role):
        raise ConfigError(f"not a plain database role name: {runtime_role!r}")
    applied = []
    with (
        connect(
            dsn, iam_auth=iam_auth, region=region, sslmode=sslmode, sslrootcert=sslrootcert
        ) as db,
        db.transaction(),
    ):
        db.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK,))
        db.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        done = {r[0] for r in db.execute("SELECT version FROM schema_migrations").fetchall()}
        for path in sorted(MIGRATIONS.glob("*.sql")):
            if path.stem in done:
                continue
            db.execute(path.read_text(encoding="utf-8"))  # a file shipped in this package
            db.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (path.stem,))
            applied.append(path.stem)
        if runtime_role:
            role = sql.Identifier(runtime_role)
            schema = db.execute("SELECT current_schema()").fetchone()[0]
            db.execute(
                sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), role)
            )
            for table in TABLES:
                db.execute(sql.SQL("REVOKE ALL ON {} FROM {}").format(sql.Identifier(table), role))
                privileges = "SELECT, INSERT" if table in APPEND_ONLY else "SELECT, INSERT, UPDATE"
                db.execute(
                    sql.SQL("GRANT {} ON {} TO {}").format(
                        sql.SQL(privileges), sql.Identifier(table), role
                    )
                )
            for seq in ("approval_decisions_seq_seq", "dead_letters_seq_seq"):
                db.execute(
                    sql.SQL("GRANT USAGE ON SEQUENCE {} TO {}").format(sql.Identifier(seq), role)
                )
    return applied
