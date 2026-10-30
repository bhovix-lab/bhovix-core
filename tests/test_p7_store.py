"""Slice 2 P7 store hardening: TLS rules, append-only grants, fail-closed kill switch, exact month spend.

Database tests skip without HADAVIN_TEST_PG_DSN (CI runs the postgres service)."""

import threading
from datetime import date
from decimal import Decimal

import pytest

pytest.importorskip("psycopg", reason="needs hadavin-sdk[pg]")

from psycopg import sql

from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import PostgresSettings
from hadavin_sdk.config import ConfigError
from hadavin_sdk.store.migrate import migrate
from hadavin_sdk.store.postgres import tls_mode
from tests.contracts.kinds.store_postgres import pg_schema

REMOTE = "postgresql://app@db.example.internal:5432/core"
PW = "pw" + "-p7"  # built from parts


# --- TLS (no database) -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dsn,setting,iam,want",
    [
        (REMOTE, None, False, "require"),  # non-local host: TLS by default
        ("postgresql://app@localhost/core", None, False, None),  # loopback keeps the DSN's choice
        ("host=/var/run/postgresql dbname=core", None, False, None),  # unix socket
        (
            REMOTE + "?sslmode=verify-full",
            None,
            False,
            "verify-full",
        ),  # the DSN's stronger mode kept
        (REMOTE, "disable", False, "disable"),  # an explicit setting wins (no iam)
        ("postgresql://app@127.0.0.2/core", None, False, None),  # all of 127/8 is loopback
        ("hostaddr=10.0.0.5 dbname=core", None, False, "require"),  # hostaddr counts as the host
    ],
)
def test_tls_mode(dsn, setting, iam, want):
    assert tls_mode(dsn, iam_auth=iam, sslmode=setting) == want


def test_pghost_counts_as_the_host(monkeypatch):
    monkeypatch.setenv("PGHOST", "db.example.internal")
    assert tls_mode("dbname=core") == "require"


def test_iam_verifies_the_server_by_default():
    ca = "/etc/ssl/rds-bundle.pem"
    assert tls_mode(REMOTE, iam_auth=True, sslrootcert=ca) == "verify-full"
    assert (
        tls_mode("postgresql://app@localhost/core", iam_auth=True, sslrootcert=ca) == "verify-full"
    )
    assert tls_mode(REMOTE, iam_auth=True, sslmode="verify-ca", sslrootcert=ca) == "verify-ca"
    with pytest.raises(ConfigError, match="sslrootcert"):
        tls_mode(REMOTE, iam_auth=True)


@pytest.mark.parametrize("weak", ["disable", "allow", "prefer", "require"])
def test_iam_refuses_an_unverified_server(weak):
    with pytest.raises(ConfigError, match="verified server"):
        tls_mode(REMOTE, iam_auth=True, sslmode=weak, sslrootcert="/ca.pem")
    with pytest.raises(ConfigError, match="verified server"):
        tls_mode(f"{REMOTE}?sslmode={weak}", iam_auth=True, sslrootcert="/ca.pem")


def test_iam_runtime_dsn_with_a_password_is_refused():
    pytest.importorskip("boto3")
    settings = PostgresSettings(
        kind="postgres",
        dsn_secret_name="pg-dsn",  # noqa: S106 - a name
        iam_auth=True,
        region="test-region-1",
    )
    dsn = f"postgresql://app:{PW}@db.example.internal/core"
    with pytest.raises(ConfigError, match="must not carry a password") as err:
        make("store", settings, FakeSecretProvider({"pg-dsn": dsn}))
    assert PW not in str(err.value)


# --- with a database ---------------------------------------------------------------------------------


@pytest.fixture
def fresh_dsn():
    yield from pg_schema(migrated=False)


@pytest.fixture
def store():
    for dsn in pg_schema():
        settings = PostgresSettings(kind="postgres", dsn_secret_name="pg-dsn")  # noqa: S106 - a name
        s = make("store", settings, FakeSecretProvider({"pg-dsn": dsn}))
        yield s
        s._db.close()


def test_append_only_tables_get_no_update(fresh_dsn):
    import psycopg

    role = "rt_" + fresh_dsn.rsplit("search_path=t_", 1)[1][:8]
    with psycopg.connect(fresh_dsn, autocommit=True) as db:
        db.execute(sql.SQL("CREATE ROLE {}").format(sql.Identifier(role)))
    try:
        migrate(fresh_dsn, runtime_role=role)
        with psycopg.connect(fresh_dsn, autocommit=True) as db:

            def can(table, priv):
                q = "SELECT has_table_privilege(%s, %s, %s)"
                return db.execute(q, (role, table, priv)).fetchone()[0]

            for table in ("approval_decisions", "dead_letters", "gate_decisions"):
                assert can(table, "INSERT") and can(table, "SELECT")
                assert not can(table, "UPDATE") and not can(table, "DELETE"), table
            for table in ("runs", "approval_requests", "spend_month", "tick_state", "kill_switch"):
                assert can(table, "UPDATE") and not can(table, "DELETE"), table
    finally:
        with psycopg.connect(fresh_dsn, autocommit=True) as db:
            db.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_migrate_seeds_the_kill_switch_off(store):
    ks = store.get_kill_switch()
    assert ks.on is False


def test_missing_kill_switch_row_fails_closed(store, caplog):
    with store._lock:
        store._exec("DELETE FROM kill_switch")
    ks = store.get_kill_switch()
    assert ks.on is True and ks.by == "system:kill_switch_row_missing"
    assert "kill_switch row missing" in caplog.text


def test_month_spend_is_exact_under_concurrent_writers(fresh_dsn):
    migrate(fresh_dsn)
    settings = PostgresSettings(kind="postgres", dsn_secret_name="pg-dsn")  # noqa: S106 - a name
    stores = [make("store", settings, FakeSecretProvider({"pg-dsn": fresh_dsn})) for _ in range(4)]
    days = [date(2026, 3, d) for d in (1, 2, 3, 4)]
    gate = threading.Barrier(len(stores))

    def charge(s, day):
        gate.wait()
        for _ in range(25):
            s.add_spend("a", day, Decimal("0.01"))

    threads = [threading.Thread(target=charge, args=a) for a in zip(stores, days, strict=True)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert stores[0].spend_totals("a", days[0]) == (Decimal("0.25"), Decimal("1.00"))
    for s in stores:
        s._db.close()
