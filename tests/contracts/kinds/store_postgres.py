"""The `postgres` store kind. Needs HADAVIN_TEST_PG_DSN (CI: the postgres service); skipped without it, so the
laptop needs no Docker. Each test gets its own schema, migrated fresh and dropped afterwards."""

import os
import uuid

import pytest

from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import PostgresSettings
from tests.contracts.kinds import kind


def pg_schema(migrated=True):
    """Yield a DSN whose search_path is a fresh (migrated) schema; drop the schema afterwards."""
    dsn = os.environ.get("HADAVIN_TEST_PG_DSN")
    if not dsn:
        pytest.skip("HADAVIN_TEST_PG_DSN not set (the postgres service runs in CI)")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    from hadavin_sdk.store.migrate import migrate

    schema = f"t_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(dsn, autocommit=True) as db:
        db.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    scoped = make_conninfo(dsn, options=f"-c search_path={schema}")
    if migrated:
        migrate(scoped)
    try:
        yield scoped
    finally:
        with psycopg.connect(dsn, autocommit=True) as db:
            db.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


@kind("store", "postgres")
def postgres(tmp_path):
    for dsn in pg_schema():
        settings = PostgresSettings(kind="postgres", dsn_secret_name="pg-dsn")  # noqa: S106 - a name
        store = make("store", settings, FakeSecretProvider({"pg-dsn": dsn}))
        yield store
        store._db.close()
