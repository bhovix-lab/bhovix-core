"""The `chain` audit, its checkpoints, signers and anchors (slice 2 P3).

Ported from WARDEN main c78d7709 with their case names: `tests/test_audit_log.py`, `test_audit_anchor_s12.py`,
`test_audit_threads.py`, `test_audit_transaction_s9152.py`, and the PostgreSQL schema checks of
`test_audit_pg_g6.py` (run against a real database here, when HADAVIN_TEST_PG_DSN is set). Edits: rows are
AuditEvents; the database is the store's (in-memory SQLite on the `memory` store); the anchor bucket is moto's.
Not ported: WARDEN's CLI flags (`--db`, `--public-key`, `keygen`), its env-var wiring (`runtime.audit_signer`),
`intact`/`head`/`entries(since)` (incident-record reads Hadavin has no caller for) and the IAM-login migrate
cases (P2's `store.migrate` owns roles and grants).
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import boto3
import pytest
import yaml
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from moto import mock_aws

from hadavin_sdk import cli
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.audit import chain as audit
from hadavin_sdk.audit.anchor_s3 import S3Anchor
from hadavin_sdk.audit.signer import (
    KmsSigner,
    LocalSigner,
    generate_key,
    load_private_key,
    load_public_key,
    verify_signature,
)
from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import (
    AwsKmsSettings,
    ChainSettings,
    KindSettings,
    S3ObjectLockSettings,
)
from hadavin_sdk.config import _anchor_refusals, load_config, parse_backends
from hadavin_sdk.errors import ConfigError
from hadavin_sdk.models import AuditEvent
from hadavin_sdk.registry import load_registry
from tests.conftest import make_cfg, qualify
from tests.contracts.kinds.audit_chain import KEY_ALIAS, REGION, kms_stub

BUCKET = "anchors-" + "contract"


@pytest.fixture
def key():
    return LocalSigner(Ed25519PrivateKey.generate())


def _event(run_id="run-1", i=0):
    return AuditEvent(
        run_id=run_id,
        domain="step",
        operation=f"n{i}",
        principal="p",
        source="s",
        result="ünïcode ok",
    )


def _log(key, rows=5, every=100, anchor=None):
    log = audit.ChainAudit(audit._Db.memory(), key, anchor, every)
    for i in range(rows):
        log.write_intent(_event(i=i))
    log.checkpoint()
    return log


def _raw(log):
    """What an attacker with the database does: drop the guard rails and write SQL directly."""
    db = log._db.conn
    for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall():
        db.execute(f"DROP TRIGGER {name}")
    return db


def _rechain(db, edit_seq, body, key=None):
    """The careful attacker: change one row, recompute every later hash (and re-sign with the key)."""
    rows = db.execute(
        "SELECT seq, at, run_id, kind, body FROM audit_entries ORDER BY seq"
    ).fetchall()
    prev = audit.GENESIS
    for seq, at, run_id, kind, b in rows:
        b = body if seq == edit_seq else b
        digest = audit._hash(prev, seq, at, run_id, kind, b)
        db.execute(
            "UPDATE audit_entries SET body = ?, prev = ?, hash = ? WHERE seq = ?",
            (b, prev, digest, seq),
        )
        prev = digest
    if key is not None:
        for (seq,) in db.execute("SELECT seq FROM audit_checkpoints").fetchall():
            (head,) = db.execute("SELECT hash FROM audit_entries WHERE seq = ?", (seq,)).fetchone()
            sig = key.sign(audit._signed_message(seq, head)).hex()
            db.execute(
                "UPDATE audit_checkpoints SET hash = ?, signature = ? WHERE seq = ?",
                (head, sig, seq),
            )


# --- test_audit_log.py -------------------------------------------------------------------------------


def test_an_untouched_log_verifies_and_is_fully_signed(key):
    log = _log(key)
    result = log.verify()
    assert result.ok
    assert result.rows == 5
    assert result.signed_through == 5
    assert result.unsigned_tail == 0
    assert [e.operation for e in log.events("run-1")] == ["n0", "n1", "n2", "n3", "n4"]


def test_rows_cannot_be_updated_or_deleted_through_sql(key):
    db = _log(key)._db.conn
    for sql in (
        "UPDATE audit_entries SET body = '{}' WHERE seq = 2",
        "DELETE FROM audit_entries WHERE seq = 2",
        "DELETE FROM audit_checkpoints",
    ):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            db.execute(sql)


def test_an_edited_row_is_found(key):
    log = _log(key)
    _raw(log).execute(
        'UPDATE audit_entries SET body = \'{"result":"nothing happened"}\' WHERE seq = 3'
    )
    assert "row 3 was changed after it was written" in log.verify().problems


def test_a_deleted_row_is_found(key):
    log = _log(key)
    _raw(log).execute("DELETE FROM audit_entries WHERE seq = 2")
    assert "row 2 is missing (next row is 3)" in log.verify().problems


def test_rewriting_a_row_and_recomputing_every_later_hash_is_caught_by_the_signature(key):
    """The chain is internally consistent again afterwards; only the signed checkpoint remembers."""
    log = _log(key)
    _rechain(_raw(log), 2, '{"result":"approved by someone else"}')
    assert log.verify().problems == ["checkpoint 5 was signed over a different history"]


def test_a_checkpoint_signed_with_another_key_is_rejected(key):
    log = _log(key)
    forger = Ed25519PrivateKey.generate()
    db = _raw(log)
    (head,) = db.execute("SELECT hash FROM audit_checkpoints WHERE seq = 5").fetchone()
    db.execute(
        "UPDATE audit_checkpoints SET signature = ? WHERE seq = 5",
        (forger.sign(audit._signed_message(5, head)).hex(),),
    )
    assert "checkpoint 5 has an invalid signature" in log.verify().problems


def test_cutting_the_tail_but_keeping_its_checkpoint_is_found(key):
    log = _log(key)
    _raw(log).execute("DELETE FROM audit_entries WHERE seq >= 4")
    assert "checkpoint 5 was signed over a different history" in log.verify().problems


def test_rows_after_the_last_checkpoint_are_reported_as_unsigned(key):
    log = _log(key)
    log.write_intent(_event("run-2"))
    result = log.verify()
    assert result.ok
    assert result.unsigned_tail == 1


def test_a_checkpoint_is_written_automatically_every_n_rows(key):
    log = _log(key, rows=7, every=3)
    seqs = log._db.run("SELECT seq FROM audit_checkpoints ORDER BY seq")
    assert [s for (s,) in seqs] == [3, 6, 7]


def test_a_damaged_database_is_a_finding_not_a_crash(key):
    log = _log(key)
    log._db.conn.close()
    result = log.verify()
    assert not result.ok and result.unreadable
    assert "cannot be read" in result.problems[0]


def test_keys_round_trip_and_a_passphrase_is_required_when_set(tmp_path):
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    passphrase = b"correct " + b"horse"
    generate_key(priv, pub, passphrase=passphrase, base=tmp_path)
    signer = LocalSigner(load_private_key(priv, passphrase))
    message = audit._signed_message(1, audit.GENESIS)
    assert verify_signature(load_public_key(pub), signer.sign(message), message)
    with pytest.raises(TypeError):
        load_private_key(priv)  # encrypted, no passphrase given
    with pytest.raises(FileExistsError):
        generate_key(tmp_path / "k2.pem", pub, base=tmp_path)  # never over an existing key
    with pytest.raises(ValueError, match="outside"):
        generate_key(tmp_path.parent / "x.pem", tmp_path / "x.pub", base=tmp_path)


def test_audit_verify_exits_0_when_intact_and_1_when_tampered(key, capsys):
    log = _log(key)
    assert cli.audit_verify(log) == 0
    assert "5 rows, signed through row 5" in capsys.readouterr().out
    _raw(log).execute("UPDATE audit_entries SET kind = 'nothing' WHERE seq = 1")
    assert cli.audit_verify(log) == 1
    out = capsys.readouterr().out
    assert "PROBLEM: row 1 was changed after it was written" in out
    assert "NOT intact" in out
    log._db.conn.close()  # an outage is "could not verify" (exit 3), never reported as tampering
    assert cli.audit_verify(log) == 3
    out = capsys.readouterr().out
    assert "could not verify: the audit cannot be read" in out and "PROBLEM" not in out


def test_audit_verify_refuses_a_memory_store(tmp_path, capsys, monkeypatch):
    """The memory chain lives inside one process; a separate CLI process would verify an empty chain."""
    monkeypatch.setenv(
        "HADAVIN_CONFIG_DIR", str(tmp_path)
    )  # main() sets it; restored after the test
    assert cli.main(["--config", str(make_cfg(tmp_path)), "audit", "verify"]) == 2
    assert "refused" in capsys.readouterr().err


# --- test_audit_anchor_s12.py ------------------------------------------------------------------------


@pytest.fixture
def bucket():
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(
            Bucket=BUCKET,
            ObjectLockEnabledForBucket=True,
            CreateBucketConfiguration={"LocationConstraint": REGION},
        )
        yield s3


def test_a_history_rewritten_and_re_signed_with_the_key_is_caught_by_its_anchors(key, bucket):
    log = _log(key, rows=3, anchor=S3Anchor(BUCKET, bucket))
    assert log.verify().ok
    _rechain(_raw(log), 1, '{"result":"attacker"}', key)
    anchors = log.anchor
    log.anchor = None
    assert log.verify().ok, "with the key alone, the rewrite is invisible: why anchors exist"
    log.anchor = anchors
    found = log.verify().problems
    assert any("differs from its anchor" in p for p in found), found


def test_a_checkpoint_that_was_never_anchored_or_an_anchor_with_no_checkpoint_is_reported(key):
    log = _log(key, rows=1)
    rows = log._db.run(audit._ALL_ROWS)
    cps = log._db.run("SELECT seq, hash, signature FROM audit_checkpoints ORDER BY seq")
    problems = audit.verify_rows(rows, cps, key.public_key(), anchors={}).problems
    assert any("never anchored" in p for p in problems)
    problems = audit.verify_rows(
        rows, cps, key.public_key(), {1: ("x", "y"), 99: ("h", "s")}
    ).problems
    assert any("anchor 99 has no checkpoint" in p for p in problems)


def test_checkpoints_are_signed_by_kms_and_verify_with_its_public_key():
    client = kms_stub()
    log = _log(KmsSigner(KEY_ALIAS, client), rows=1)
    signs = [
        (p["KeyId"], p["MessageType"], p["SigningAlgorithm"])
        for n, p in client.calls
        if n == "Sign"
    ]
    assert signs == [(KEY_ALIAS, "RAW", "ED25519_SHA_512")]
    assert log.verify().ok


def test_the_backend_table_builds_the_kms_signer_and_the_anchor_from_config(monkeypatch, bucket):
    client = kms_stub()
    made = []
    real_client = boto3.client

    def fake_client(service, **kw):
        c = kw["config"]  # bounded: checkpoints are signed and anchored inline
        made.append(
            (
                service,
                kw.get("region_name"),
                c.connect_timeout,
                c.read_timeout,
                c.retries["total_max_attempts"],
            )
        )
        return client if service == "kms" else real_client(service, **kw)

    monkeypatch.setattr(boto3, "client", fake_client)
    signer = make("signer", AwsKmsSettings(kind="aws_kms", key_id=KEY_ALIAS, region=REGION))
    assert isinstance(signer, KmsSigner) and signer.key_id == KEY_ALIAS
    anchor = S3ObjectLockSettings(
        kind="s3_object_lock", bucket=BUCKET, region=REGION, retain_days=30
    )
    store = make("store", KindSettings(kind="memory"))
    log = make("audit", ChainSettings(kind="chain", anchor=anchor), store=store, signer=signer)
    assert (log.anchor.bucket, log.anchor.mode, log.anchor.retain) == (
        BUCKET,
        "GOVERNANCE",
        timedelta(days=30),
    )
    bounded = (3, 5, 2)  # timeouts, and at most 2 requests in total
    assert made == [("kms", REGION, *bounded), ("s3", REGION, *bounded)]
    with pytest.raises(ConfigError, match="needs a signer"):
        make("audit", ChainSettings(kind="chain", anchor=anchor), store=store)


# --- test_audit_threads.py ---------------------------------------------------------------------------


def test_appends_and_reads_from_many_threads_keep_one_whole_chain(key):
    log = audit.ChainAudit(audit._Db.memory(), key, None, 25)

    def work(n):
        for i in range(50):
            key_ = log.write_intent(_event(f"run-{n}", i))
            log.events(f"run-{n}")
            assert log.verify_object(key_)

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(work, range(8)))
    assert len(log.events()) == 400
    log.checkpoint()
    v = log.verify()
    assert v.ok, v.problems
    assert v.rows == 400 and v.signed_through == 400


# --- test_audit_transaction_s9152.py -----------------------------------------------------------------


def _db():
    db = audit._Db.memory()
    db.run("CREATE TABLE t (x INTEGER)")
    return db


def _fail_after(db, statement, error):
    with db.transaction() as q:
        q(statement)
        raise ValueError(error)


def test_an_error_in_the_body_keeps_nothing_and_is_the_error_raised():
    db = _db()
    with pytest.raises(ValueError, match="the body failed"):
        _fail_after(db, "INSERT INTO t VALUES (1)", "the body failed")
    assert db.run("SELECT count(*) FROM t") == [(0,)]
    assert not db.conn.in_transaction


def test_a_body_whose_transaction_is_already_gone_raises_its_own_error():
    db = _db()
    with pytest.raises(ValueError, match="after the rollback"):
        _fail_after(db, "ROLLBACK", "after the rollback")
    assert not db.conn.in_transaction


def test_a_clean_body_is_committed():
    db = _db()
    with db.transaction() as q:
        q("INSERT INTO t VALUES (1)")
    assert db.run("SELECT count(*) FROM t") == [(1,)]
    assert not db.conn.in_transaction


# --- Hadavin additions (design 4.3, 4.6, 4.8, 6) -----------------------------------------------------


def test_each_anchor_is_locked_dated_and_never_overwritten(key, bucket):
    puts = []
    real_put = bucket.put_object

    def spy(**kw):
        puts.append(kw)
        return real_put(**kw)

    bucket.put_object = spy
    anchor = S3Anchor(BUCKET, bucket, retain=timedelta(days=1))
    log = _log(key, rows=2, anchor=anchor)
    assert len(puts) == 1
    put = puts[0]
    assert (put["Key"], put["ObjectLockMode"], put["IfNoneMatch"]) == (
        "anchors/000000000002.json",
        "GOVERNANCE",
        "*",
    )
    assert put["ObjectLockRetainUntilDate"] > anchor.clock()
    assert anchor.all() == {
        2: tuple(log._db.run("SELECT hash, signature FROM audit_checkpoints")[0])
    }
    with pytest.raises(ClientError, match="PreconditionFailed"):
        anchor.put(2, "forged", "forged")  # IfNoneMatch: an anchor is never replaced


def test_a_deleted_tail_is_detected_against_the_anchor(key, bucket):
    log = _log(key, rows=3, anchor=S3Anchor(BUCKET, bucket))
    db = _raw(log)
    db.execute("DELETE FROM audit_entries WHERE seq >= 2")
    db.execute("DELETE FROM audit_checkpoints")
    problems = log.verify().problems
    assert "anchor 3 has no checkpoint here: the database lost history" in problems


def test_a_checkpoint_that_cannot_be_signed_or_anchored_fails_open_and_is_retried(key, caplog):
    class Flaky:
        def __init__(self, fail):
            self.fail, self.puts = fail, {}

        def put(self, seq, head, sig):
            if self.fail:
                raise ConnectionError("anchor store down")
            self.puts[seq] = (head, sig)

        def all(self):
            return dict(self.puts)

    anchor = Flaky(fail=True)
    log = audit.ChainAudit(audit._Db.memory(), key, anchor, 2)
    real_sign = key.sign
    key.sign = lambda m: (_ for _ in ()).throw(TimeoutError("kms down"))
    with caplog.at_level(logging.ERROR):
        log.write_intent(_event(i=0))
        log.write_intent(_event(i=1))  # the inline checkpoint fails: the append still succeeds
    assert "not signed (TimeoutError)" in caplog.text
    assert log.signed_through() == 0 and len(log.events()) == 2
    key.sign = real_sign
    assert log.checkpoint() == 2  # signed now; the anchor is still down
    assert "not anchored (ConnectionError)" in caplog.text
    anchor.fail = False
    log.write_intent(_event(i=2))
    assert log.checkpoint() == 3
    assert set(anchor.puts) == {2, 3}  # the failed anchor was retried
    assert log.verify().ok


def test_an_outcome_that_cannot_be_appended_waits_in_the_outbox(key, monkeypatch):
    log = audit.ChainAudit(audit._Db.memory(), key)
    first, later = _event(i=0), _event(i=1)
    real = log._append
    monkeypatch.setattr(log, "_append", lambda e: (_ for _ in ()).throw(OSError("down")))
    assert log.write_outcome(first) is None
    assert log._db.run("SELECT event_id FROM audit_outbox") == [(first.event_id,)]
    monkeypatch.setattr(log, "_append", real)
    log.write_intent(later)
    assert log.reconcile() == 1
    assert [e.event_id for e in log.events()] == [later.event_id, first.event_id]
    assert log._db.run("SELECT event_id FROM audit_outbox") == []
    assert log.reconcile() == 0


def test_an_unsigned_chain_still_verifies_its_links():
    log = audit.ChainAudit(audit._Db.memory())
    log.write_intent(_event())
    assert log.checkpoint() is None
    assert log.verify().ok and log.verify().unsigned_tail == 1


def _backends(audit_entry, signer="none"):
    raw = {
        "signer": signer,
        "audit": audit_entry,
        "llm": {"kind": "fake", "recorded_dir": "r"},
    }
    return parse_backends(raw, Path("."))


ANCHOR = {"kind": "s3_object_lock", "bucket": BUCKET, "region": REGION}
KMS = {"kind": "aws_kms", "key_id": KEY_ALIAS, "region": REGION}


@pytest.mark.parametrize(
    "env,audit_entry,signer,refused",
    [
        ("prod", {"kind": "chain", "anchor": ANCHOR | {"retention_ack": True}}, KMS, []),
        (
            "prod",
            {"kind": "chain", "anchor": ANCHOR},
            KMS,
            ["without an anchor with retention_ack"],
        ),
        ("prod", {"kind": "chain"}, KMS, ["without an anchor with retention_ack"]),
        (
            "prod",
            {"kind": "chain", "anchor": ANCHOR | {"retention_ack": True}},
            {"kind": "ed25519_local", "private_key_path": "k.pem"},
            ["signer: ed25519_local"],
        ),
        ("pilot", {"kind": "chain", "anchor": ANCHOR}, KMS, []),
        ("pilot", {"kind": "chain"}, {"kind": "ed25519_local", "private_key_path": "k.pem"}, []),
        (
            "pilot",
            {"kind": "chain", "anchor": ANCHOR | {"mode": "COMPLIANCE", "retention_ack": True}},
            KMS,
            ["COMPLIANCE outside prod"],
        ),
        (
            "prod",
            {"kind": "chain", "anchor": ANCHOR | {"mode": "COMPLIANCE", "retention_ack": True}},
            KMS,
            [],
        ),
    ],
)
def test_the_environment_table_rules_for_signers_and_anchors(env, audit_entry, signer, refused):
    found = _anchor_refusals(env, _backends(audit_entry, signer))
    assert len(found) == len(refused)
    assert all(want in got for want, got in zip(refused, found, strict=True))


def test_an_unknown_anchor_kind_or_mode_is_a_config_error():
    for bad in ({**ANCHOR, "kind": "gcs_bucket_lock"}, {**ANCHOR, "mode": "LEGAL_HOLD"}):
        with pytest.raises(ConfigError):
            _backends({"kind": "chain", "anchor": bad})


def test_the_app_builds_the_chain_audit_from_config(tmp_path):
    from hadavin_sdk.app import build

    cfg_dir = make_cfg(tmp_path)
    path = cfg_dir / "config.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["backends"]["audit"] = {"kind": "chain", "checkpoint_every": 2}
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    qualify(load_registry(load_config(cfg_dir)))
    token = "fixture" + "-value"  # built from parts
    app = build(cfg_dir, ["test-agent"], secrets=FakeSecretProvider({"fixture-token": token}))
    assert isinstance(app.audit, audit.ChainAudit) and app.audit.signer is None


# --- PostgreSQL (test_audit_pg_g6.py, against a real database) ----------------------------------------

MIGRATION = Path(audit.__file__).parents[1] / "store" / "migrations" / "0002_audit_chain.sql"


@pytest.fixture
def pg_chain(key):
    dsn = os.environ.get("HADAVIN_TEST_PG_DSN")
    if not dsn:
        pytest.skip("HADAVIN_TEST_PG_DSN not set (the postgres service runs in CI)")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    schema = f"t_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(dsn, autocommit=True) as db:
        db.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    conn = psycopg.connect(make_conninfo(dsn, options=f"-c search_path={schema}"), autocommit=True)
    conn.execute(MIGRATION.read_text(encoding="utf-8"))
    try:
        yield audit.ChainAudit(audit._Db(conn, threading.Lock(), pg=True), key, None, 3), conn
    finally:
        conn.close()
        with psycopg.connect(dsn, autocommit=True) as db:
            db.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def test_postgres_chain_appends_verifies_and_refuses_update_delete_truncate(pg_chain):
    import psycopg

    log, conn = pg_chain
    keys = [log.write_intent(_event(i=i)) for i in range(4)]
    with pytest.raises(audit.DuplicateEvent):
        log.write_intent(_event(i=0).model_copy(update={"event_id": keys[0]}))
    assert all(log.verify_object(k) for k in keys)
    assert [e.event_id for e in log.events("run-1")] == keys
    v = log.verify()
    assert v.ok and (v.rows, v.signed_through) == (4, 3), v.problems
    for statement in (
        "UPDATE audit_entries SET body = '{}' WHERE seq = 2",
        "DELETE FROM audit_entries WHERE seq = 2",
        "TRUNCATE audit_entries",
        "DELETE FROM audit_checkpoints",
    ):
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute(statement)


def test_postgres_appends_from_many_threads_keep_one_whole_chain(pg_chain):
    log, _ = pg_chain

    def work(n):
        for i in range(10):
            log.write_intent(_event(f"run-{n}", i))

    with ThreadPoolExecutor(4) as pool:
        list(pool.map(work, range(4)))
    v = log.verify()
    assert v.ok and v.rows == 40, v.problems
