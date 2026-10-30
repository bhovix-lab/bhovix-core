"""Slice 2 P2: postgres store, `hadavin-sdk migrate`, and the CLI kill switch on a shared store.

Tests that need a database skip without HADAVIN_TEST_PG_DSN (CI runs the postgres service)."""

import re
import threading

import pytest
import yaml

from hadavin_sdk import cli
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.backends.table import PostgresSettings
from hadavin_sdk.config import ConfigError, load_config
from hadavin_sdk.models import (
    ApprovalDecision,
    ApprovalRequest,
    DeadLetter,
    GateDecision,
    KillSwitch,
    Plan,
    Run,
)

pytest.importorskip("psycopg", reason="needs hadavin-sdk[pg]")

from hadavin_sdk.store.migrate import MIGRATIONS, migrate
from tests.contracts.kinds.store_postgres import pg_schema

TABLES = {
    "runs": Run,
    "plans": Plan,
    "gate_decisions": GateDecision,
    "approval_requests": ApprovalRequest,
    "approval_decisions": ApprovalDecision,
    "dead_letters": DeadLetter,
    "kill_switch": KillSwitch,
}
EXTRA_COLUMNS = {"approval_decisions": {"seq"}, "dead_letters": {"seq"}, "kill_switch": {"id"}}


def _sql_columns(text: str) -> dict[str, set[str]]:
    out = {}
    for table, body in re.findall(r"CREATE TABLE (\w+) \((.*?)\n\);", text, re.DOTALL):
        cols = re.findall(r'^\s+"?(\w+)"?\s+[A-Z]', body, re.MULTILINE)
        out[table] = {c for c in cols if c != "PRIMARY"}
    return out


def test_schema_has_one_column_per_model_field():
    cols = _sql_columns((MIGRATIONS / "0001_core.sql").read_text(encoding="utf-8"))
    for table, model in TABLES.items():
        assert cols[table] == set(model.model_fields) | EXTRA_COLUMNS.get(table, set()), table


def test_iam_auth_needs_region():
    with pytest.raises(ValueError, match="iam_auth needs region"):
        PostgresSettings(kind="postgres", dsn_secret_name="d", iam_auth=True)  # noqa: S106 - a name


def test_runtime_role_must_be_a_plain_name():
    with pytest.raises(ConfigError, match="plain database role"):
        migrate("postgresql://unused", runtime_role="x; DROP TABLE runs")


# --- CLI ---------------------------------------------------------------------------------------------


def _use_postgres(cfg_dir):
    path = cfg_dir / "config.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["backends"]["store"] = {"kind": "postgres", "dsn_secret_name": "pg-dsn"}
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def test_migrate_refused_for_memory_store(cfg_dir, capsys):
    assert cli.main(["--config", str(cfg_dir), "migrate"]) == 2
    assert "postgres store" in capsys.readouterr().err


def test_migrate_does_not_need_a_valid_registry(cfg_dir, monkeypatch, capsys):
    _use_postgres(cfg_dir)
    (cfg_dir / "agents.yaml").write_text("- not: an agent\n", encoding="utf-8")
    monkeypatch.delenv("HADAVIN_MIGRATE_DSN", raising=False)
    assert (
        cli.main(["--config", str(cfg_dir), "migrate"]) == 2
    )  # reaches the DSN check, not the registry
    assert "HADAVIN_MIGRATE_DSN" in capsys.readouterr().err


def test_migrate_needs_the_migration_dsn(cfg_dir, monkeypatch, capsys):
    _use_postgres(cfg_dir)
    monkeypatch.delenv("HADAVIN_MIGRATE_DSN", raising=False)
    assert cli.main(["--config", str(cfg_dir), "migrate"]) == 2
    assert "HADAVIN_MIGRATE_DSN" in capsys.readouterr().err


def test_cli_limits_without_a_readable_dsn_is_a_config_error(cfg_dir):
    _use_postgres(
        cfg_dir
    )  # configured `fake` secrets are empty: a real secrets kind (P4) holds the DSN
    with pytest.raises(ConfigError, match="'pg-dsn' cannot be read"):
        cli.main(["--config", str(cfg_dir), "limits", "stop", "--by", "user:a"])


# --- with a database ---------------------------------------------------------------------------------


@pytest.fixture
def fresh_dsn():
    yield from pg_schema(migrated=False)


@pytest.fixture
def migrated_dsn():
    yield from pg_schema()


def test_two_concurrent_migrate_runs_apply_once(fresh_dsn):
    applied = []

    def run():
        applied.append(migrate(fresh_dsn))

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(applied, key=len) == [[], ["0001_core"]]
    assert migrate(fresh_dsn) == []


def test_runtime_role_can_write_but_not_delete(fresh_dsn):
    import psycopg
    from psycopg import sql

    role = "rt_" + fresh_dsn.rsplit("search_path=t_", 1)[1][:8]
    with psycopg.connect(fresh_dsn, autocommit=True) as db:
        db.execute(sql.SQL("CREATE ROLE {}").format(sql.Identifier(role)))
    try:
        migrate(fresh_dsn, runtime_role=role)
        with psycopg.connect(fresh_dsn, autocommit=True) as db:

            def can(priv):
                q = "SELECT has_table_privilege(%s, 'runs', %s)"
                return db.execute(q, (role, priv)).fetchone()[0]

            assert can("SELECT") and can("INSERT") and can("UPDATE")
            schema = db.execute("SELECT current_schema()").fetchone()[0]
            q = "SELECT has_schema_privilege(%s, %s, 'USAGE')"
            assert db.execute(q, (role, schema)).fetchone()[0]
            assert not can("DELETE") and not can("TRUNCATE")
    finally:
        with psycopg.connect(fresh_dsn, autocommit=True) as db:
            db.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_cli_kill_switch_reaches_every_process(cfg_dir, monkeypatch, capsys):
    for dsn in pg_schema():
        _use_postgres(cfg_dir)
        monkeypatch.setattr(
            "hadavin_sdk.backends.builtin.fake_secrets",
            lambda settings, deps, dsn=dsn: FakeSecretProvider({"pg-dsn": dsn}),
        )
        assert cli.main(["--config", str(cfg_dir), "limits", "stop", "--by", "user:a"]) == 0
        from hadavin_sdk.backends import make

        other = make(
            "store", load_config(cfg_dir).backends.store, FakeSecretProvider({"pg-dsn": dsn})
        )
        assert (other.get_kill_switch().on, other.get_kill_switch().by) == (True, "user:a")
        assert cli.main(["--config", str(cfg_dir), "limits", "reset", "--by", "user:a"]) == 0
        assert other.get_kill_switch().on is False
        other._db.close()


def test_plan_hash_survives_a_non_utc_timestamp():
    from datetime import UTC, datetime, timedelta, timezone

    from hadavin_sdk.models import Target

    ist = timezone(timedelta(hours=5, minutes=30))
    kw = {
        "plan_id": "pln-x",
        "run_id": "run-x",
        "agent_id": "a",
        "action_id": "x",
        "action_version": 1,
        "risk_class": "reversible",
        "inputs": {},
        "target": Target(system="s"),
        "idempotency_key": "k",
        "expected_outcome": "o",
    }
    at = datetime(2026, 10, 31, 1, 0, tzinfo=ist)
    assert Plan(**kw, created_at=at).hash() == Plan(**kw, created_at=at.astimezone(UTC)).hash()
    with pytest.raises(ValueError, match="timezone-aware"):
        Plan(**kw, created_at=datetime(2026, 10, 31))  # noqa: DTZ001 - the naive value under test


def test_cas_race_across_two_connections_has_one_winner(migrated_dsn):
    from hadavin_sdk.backends import make
    from hadavin_sdk.models import RunState
    from hadavin_sdk.store.protocol import StaleState

    dsn = migrated_dsn
    settings = PostgresSettings(kind="postgres", dsn_secret_name="pg-dsn")  # noqa: S106 - a name
    a, b = (make("store", settings, FakeSecretProvider({"pg-dsn": dsn})) for _ in range(2))
    run = Run(agent_id="a", principal_id="p", trigger_kind="event", trigger_ref="t")
    a.create_run(run)
    results, gate = [], threading.Barrier(2)

    def race(store):
        gate.wait()
        try:
            store.transition(run.run_id, RunState.RECEIVED, RunState.WORKING)
            results.append("won")
        except StaleState:
            results.append("stale")

    threads = [threading.Thread(target=race, args=(s,)) for s in (a, b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["stale", "won"]
    a._db.close()
    b._db.close()
