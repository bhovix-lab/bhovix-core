"""Postgres store (`pip install hadavin-sdk[pg]`). Same Protocol as `memory`; compare-and-set is in SQL, so it
holds across processes. The schema comes from `hadavin-sdk migrate` (`store/migrate.py`), never from here.

Connect pattern ported from WARDEN `audit.py:_pg_connect` (main a1e76cbf): with `iam_auth` and no password in
the DSN, the login is a 15-minute RDS IAM token and TLS is required.
"""

from __future__ import annotations

import threading
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from hadavin_sdk.errors import ConfigError
from hadavin_sdk.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    DeadLetter,
    GateDecision,
    KillSwitch,
    Plan,
    Run,
    RunState,
    now,
)
from hadavin_sdk.store.protocol import NotFound, StaleState


def connect(dsn: str, *, iam_auth: bool = False, region: str | None = None) -> psycopg.Connection:
    extra: dict[str, Any] = {}
    if iam_auth:
        from psycopg.conninfo import conninfo_to_dict

        parts = conninfo_to_dict(dsn)
        if not parts.get("password"):
            import boto3  # the `aws` extra; checked when the store is built

            token = boto3.client("rds", region_name=region).generate_db_auth_token(
                DBHostname=parts["host"],
                Port=int(parts.get("port") or 5432),
                DBUsername=parts["user"],
            )
            extra = {"password": token, "sslmode": "require"}
    return psycopg.connect(dsn, autocommit=True, connect_timeout=10, **extra)


def build(settings, deps) -> PostgresStore:
    """Table factory: the DSN is a platform secret named in the settings (never the executor's)."""
    if settings.iam_auth:
        try:
            import boto3  # noqa: F401
        except ImportError as exc:
            raise ConfigError(
                "store postgres with iam_auth needs: pip install hadavin-sdk[aws]"
            ) from exc
    dsn = deps.resolve(settings.dsn_secret_name)
    try:
        conn = connect(dsn, iam_auth=settings.iam_auth, region=settings.region)
    except psycopg.OperationalError as exc:
        # The class only: driver messages can carry the host and user.
        raise ConfigError(f"store postgres: cannot connect ({exc.__class__.__name__})") from None
    return PostgresStore(conn)


def _row(model: BaseModel) -> dict[str, Any]:
    """Model -> column values: dicts/lists as JSONB, enums as their text, everything else as is."""
    py, js = model.model_dump(), model.model_dump(mode="json")
    out = {}
    for k, v in py.items():
        if isinstance(v, dict | list):
            out[k] = Jsonb(js[k])
        elif isinstance(v, Enum):
            out[k] = js[k]
        else:
            out[k] = v
    return out


class PostgresStore:
    # ponytail: one connection behind one lock per process; a pool (psycopg_pool) when throughput matters.
    # A dropped connection fails the call (the run ends safely); reconnect-on-error arrives with S11 hosting.
    def __init__(self, conn: psycopg.Connection) -> None:
        self._db = conn
        self._lock = threading.Lock()

    # --- generic helpers ---------------------------------------------------------------------------------

    def _exec(self, query, params=()) -> psycopg.Cursor:
        return self._db.cursor(row_factory=dict_row).execute(query, params)

    def _insert(self, table: str, model: BaseModel, upsert_on: str | None = None) -> None:
        row = _row(model)
        cols = [sql.Identifier(c) for c in row]
        query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            sql.Identifier(table),
            sql.SQL(", ").join(cols),
            sql.SQL(", ").join(sql.Placeholder() * len(row)),
        )
        if upsert_on:
            query += sql.SQL(" ON CONFLICT ({}) DO UPDATE SET {}").format(
                sql.Identifier(upsert_on),
                sql.SQL(", ").join(sql.SQL("{0} = EXCLUDED.{0}").format(c) for c in cols),
            )
        with self._lock:
            self._exec(query, list(row.values()))

    def _select(self, model: type[BaseModel], table: str, where: str, params, tail: str = ""):
        """`where` and `tail` are fixed SQL text from this module; values always go through `params`."""
        cols = sql.SQL(", ").join(sql.Identifier(c) for c in model.model_fields)
        query = sql.SQL("SELECT {} FROM {} WHERE {}{}").format(
            cols, sql.Identifier(table), sql.SQL(where), sql.SQL(tail)
        )
        with self._lock:
            rows = self._exec(query, params).fetchall()
        return [model.model_validate(r) for r in rows]

    def _one(self, model: type[BaseModel], table: str, key: str, value: str):
        found = self._select(model, table, f"{key} = %s", (value,))
        if not found:
            raise NotFound(value)
        return found[0]

    # --- runs --------------------------------------------------------------------------------------------

    def create_run(self, run: Run) -> None:
        try:
            self._insert("runs", run)
        except psycopg.errors.UniqueViolation:
            raise StaleState(f"run exists: {run.run_id}") from None

    def get_run(self, run_id: str) -> Run:
        return self._one(Run, "runs", "run_id", run_id)

    def _missing_or_stale(self, table: str, key: str, value: str, stale: str) -> Exception:
        with self._lock:
            exists = self._exec(
                sql.SQL("SELECT 1 FROM {} WHERE {} = %s").format(
                    sql.Identifier(table), sql.Identifier(key)
                ),
                (value,),
            ).fetchone()
        return StaleState(stale) if exists else NotFound(value)

    def transition(
        self, run_id: str, expected: RunState, new: RunState, reason_code: str | None = None
    ) -> Run:
        with self._lock:
            row = self._exec(
                "UPDATE runs SET state = %s, reason_code = %s, updated_at = %s "
                "WHERE run_id = %s AND state = %s RETURNING run_id",
                (new.value, reason_code, now(), run_id, expected.value),
            ).fetchone()
        if row is None:
            raise self._missing_or_stale("runs", "run_id", run_id, f"{run_id}: expected {expected}")
        return self.get_run(run_id)

    def _update_run(self, query: str, value: Any, run_id: str) -> None:
        with self._lock:
            cur = self._exec(query, (value, run_id))
        if cur.rowcount == 0:
            raise NotFound(run_id)

    def add_cost(self, run_id: str, usd: Decimal) -> None:
        self._update_run("UPDATE runs SET cost_usd = cost_usd + %s WHERE run_id = %s", usd, run_id)

    def touch(self, run_id: str) -> None:
        self._update_run("UPDATE runs SET updated_at = %s WHERE run_id = %s", now(), run_id)

    def list_runs(self, state: RunState, updated_before: datetime, limit: int = 100) -> list[Run]:
        return self._select(
            Run,
            "runs",
            "state = %s AND updated_at < %s",
            (state.value, updated_before, limit),
            " ORDER BY updated_at LIMIT %s",
        )

    # --- plans and gate decisions --------------------------------------------------------------------------

    def save_plan(self, plan: Plan) -> None:
        self._insert("plans", plan, upsert_on="run_id")

    def get_plan(self, run_id: str) -> Plan:
        return self._one(Plan, "plans", "run_id", run_id)

    def save_gate_decision(self, decision: GateDecision) -> None:
        self._insert("gate_decisions", decision, upsert_on="run_id")

    def get_gate_decision(self, run_id: str) -> GateDecision:
        return self._one(GateDecision, "gate_decisions", "run_id", run_id)

    # --- approvals -----------------------------------------------------------------------------------------

    def save_approval_request(self, req: ApprovalRequest) -> None:
        self._insert("approval_requests", req, upsert_on="approval_id")

    def get_approval_request(self, approval_id: str) -> ApprovalRequest:
        return self._one(ApprovalRequest, "approval_requests", "approval_id", approval_id)

    def update_approval_request(
        self, req: ApprovalRequest, expected_status: str, expected_step: int
    ) -> None:
        row = _row(req)
        sets = sql.SQL(", ").join(
            sql.SQL("{} = %s").format(sql.Identifier(c)) for c in row if c != "approval_id"
        )
        query = sql.SQL(
            "UPDATE approval_requests SET {} WHERE approval_id = %s AND status = %s AND current_step = %s"
        ).format(sets)
        values = [v for c, v in row.items() if c != "approval_id"]
        with self._lock:
            cur = self._exec(query, [*values, req.approval_id, expected_status, expected_step])
        if cur.rowcount == 0:
            raise self._missing_or_stale(
                "approval_requests",
                "approval_id",
                req.approval_id,
                f"{req.approval_id}: not {expected_status}/{expected_step}",
            )

    def list_due_approvals(self, now: datetime) -> list[ApprovalRequest]:
        return self._select(
            ApprovalRequest,
            "approval_requests",
            "status = 'PENDING' AND step_expires_at <= %s",
            (now,),
        )

    def save_approval_decision(self, decision: ApprovalDecision) -> None:
        self._insert("approval_decisions", decision)

    def get_approval_decision(self, approval_id: str) -> ApprovalDecision | None:
        found = self._select(
            ApprovalDecision,
            "approval_decisions",
            "approval_id = %s",
            (approval_id,),
            " ORDER BY seq DESC LIMIT 1",
        )
        return found[0] if found else None

    def list_approvals(self, statuses: set[ApprovalStatus]) -> list[ApprovalRequest]:
        return self._select(
            ApprovalRequest,
            "approval_requests",
            "status = ANY(%s)",
            (sorted(statuses),),
            " ORDER BY created_at",
        )

    # --- dead letters, spend, kill switch ------------------------------------------------------------------

    def add_dead_letter(self, dl: DeadLetter) -> None:
        self._insert("dead_letters", dl)

    def list_dead_letters(self, run_id: str) -> list[DeadLetter]:
        return self._select(DeadLetter, "dead_letters", "run_id = %s", (run_id,), " ORDER BY seq")

    _MONTH = "SELECT COALESCE(SUM(usd), 0) AS m FROM spend WHERE agent_id = %s AND date_trunc('month', day) = date_trunc('month', %s::date)"

    def add_spend(self, agent_id: str, day: date, usd: Decimal) -> tuple[Decimal, Decimal]:
        with self._lock, self._db.transaction():
            d = self._exec(
                "INSERT INTO spend (agent_id, day, usd) VALUES (%s, %s, %s) "
                "ON CONFLICT (agent_id, day) DO UPDATE SET usd = spend.usd + EXCLUDED.usd RETURNING usd",
                (agent_id, day, usd),
            ).fetchone()["usd"]
            m = self._exec(self._MONTH, (agent_id, day)).fetchone()["m"]
        return Decimal(d), Decimal(m)

    def spend_totals(self, agent_id: str, day: date) -> tuple[Decimal, Decimal]:
        with self._lock:
            d = self._exec(
                "SELECT usd FROM spend WHERE agent_id = %s AND day = %s", (agent_id, day)
            ).fetchone()
            m = self._exec(self._MONTH, (agent_id, day)).fetchone()["m"]
        return (Decimal(d["usd"]) if d else Decimal(0)), Decimal(m)

    def get_kill_switch(self) -> KillSwitch:
        found = self._select(KillSwitch, "kill_switch", "id = 1", ())
        return found[0] if found else KillSwitch()

    def set_kill_switch(self, ks: KillSwitch) -> None:
        row = {"id": 1, **_row(ks)}
        cols = [sql.Identifier(c) for c in row]
        query = sql.SQL(
            "INSERT INTO kill_switch ({}) VALUES ({}) ON CONFLICT (id) DO UPDATE SET {}"
        ).format(
            sql.SQL(", ").join(cols),
            sql.SQL(", ").join(sql.Placeholder() * len(row)),
            sql.SQL(", ").join(sql.SQL("{0} = EXCLUDED.{0}").format(c) for c in cols[1:]),
        )
        with self._lock:
            self._exec(query, list(row.values()))
