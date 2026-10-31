"""`chain` audit: an append-only hash chain in the store's database, with signed checkpoints and anchors.

Ported from WARDEN `audit.py` (main c78d7709): `_Store`, `AuditLog`, `_hash`, `_signed_message`, `verify` and its
checks, and the append-only `_PG_SCHEMA` pattern (here `store/migrations/0002_audit_chain.sql`). Edits: the
message prefix is `hadavin-audit`; rows are AuditEvents (hashes and codes only) and the AuditSink Protocol sits on
top; the signer and anchor come from the backend table; a checkpoint that cannot be signed or anchored is
logged and retried, never raised (signing is evidence, not a gate: design 4.8).

Three layers, because each one alone is beatable:
* **Append-only.** Triggers abort any UPDATE, DELETE or TRUNCATE. Anyone who can write the database can drop a
  trigger, so this is a guard rail, not proof.
* **Hash chain.** Each row's hash covers the previous row's hash and all of its own fields, so an edited,
  removed or reordered row breaks every link after it.
* **Signed checkpoints** every `checkpoint_every` rows, over `hadavin-audit:{seq}:{head}`. Someone who edits a
  row AND recomputes every later hash cannot recompute the signature; someone who also holds the key cannot
  rewrite the anchors (S3 Object Lock, written by another principal).

Honest limits: rows after the last checkpoint are chained but not yet signed (`verify` reports the tail). On
the `memory` store the chain is an in-memory SQLite database and is lost on restart, like the store.
"""

from __future__ import annotations

import contextlib
import hashlib
import inspect
import json
import logging
import sqlite3
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any

from hadavin_sdk.audit.protocol import AuditUnavailable, DuplicateEvent
from hadavin_sdk.audit.signer import Alg, Signer, verify_signature
from hadavin_sdk.errors import ConfigError
from hadavin_sdk.models import AuditEvent

GENESIS = "0" * 64
_LOG = logging.getLogger("hadavin_sdk.audit.chain")
# One chain, many writers: each append holds this transaction-scoped advisory lock (a fixed key).
_PG_LOCK = int.from_bytes(b"hadvnaud", "big") >> 1

_SQLITE_SCHEMA = """
CREATE TABLE audit_entries (seq INTEGER PRIMARY KEY, at TEXT NOT NULL, run_id TEXT NOT NULL,
    kind TEXT NOT NULL, body TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL,
    event_id TEXT NOT NULL UNIQUE);
CREATE TABLE audit_checkpoints (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TABLE audit_outbox (event_id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE INDEX audit_entries_by_run ON audit_entries (run_id, seq);
""" + "".join(
    f"CREATE TRIGGER {t}_no_{op.lower()} BEFORE {op} ON {t} "
    "BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;\n"
    for t in ("audit_entries", "audit_checkpoints")
    for op in ("UPDATE", "DELETE")
)
_ALL_ROWS = (
    "SELECT seq, at, run_id, kind, body, prev, hash, event_id FROM audit_entries ORDER BY seq"
)


def _hash(prev: str, seq: int, at: str, run_id: str, kind: str, body: str) -> str:
    material = json.dumps(
        [prev, seq, at, run_id, kind, body], ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _takes_meta(put: Callable) -> bool:
    params = inspect.signature(put).parameters.values()
    names = {p.name for p in params}
    return any(p.kind is p.VAR_KEYWORD for p in params) or {"alg", "key_id"} <= names


def _signed_message(seq: int, head: str) -> bytes:
    return f"hadavin-audit:{seq}:{head}".encode()


class _Db:
    """The few statements the chain runs, on SQLite (the `memory` store) or the `postgres` store's connection.
    One lock per connection: on postgres it is the store's own, so no store statement lands inside an audit
    transaction (WARDEN 2026-10-15: a read inside another thread's BEGIN ... COMMIT failed CI twice)."""

    def __init__(self, conn: Any, lock: Any, pg: bool) -> None:
        self.conn, self.lock, self.pg = conn, lock, pg

    @classmethod
    def memory(cls) -> _Db:
        conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
        conn.executescript(_SQLITE_SCHEMA)
        return cls(conn, threading.Lock(), pg=False)

    def _q(self, sql: str, params: tuple = ()) -> list[tuple]:
        cur = self.conn.execute(sql.replace("?", "%s") if self.pg else sql, params)
        return cur.fetchall() if cur.description else []

    def run(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self.lock:
            return self._q(sql, params)

    @contextlib.contextmanager
    def transaction(self) -> Iterator[Callable[..., list[tuple]]]:
        with self.lock:
            if self.pg:
                with self.conn.transaction():
                    self.conn.execute("SELECT pg_advisory_xact_lock(%s)", (_PG_LOCK,))
                    yield self._q
                return
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._q
                self.conn.execute("COMMIT")
            finally:
                # Only a transaction still open is rolled back: a ROLLBACK with none raised "no transaction is
                # active" over the error that ended it (WARDEN, Sonar python:S9152).
                if self.conn.in_transaction:
                    self.conn.execute("ROLLBACK")


@dataclass
class Verification:
    rows: int = 0
    signed_through: int = 0
    problems: list[str] = field(default_factory=list)
    unreadable: bool = (
        False  # the audit or its anchors could not be read: not checked, not "tampered"
    )

    @property
    def ok(self) -> bool:
        return not self.problems

    @property
    def unsigned_tail(self) -> int:
        return self.rows - self.signed_through


class ChainAudit:
    """The AuditSink Protocol over the chain, plus `checkpoint()` (inline every N rows, and from `tick`) and
    `verify()`. Keys returned by the writes are event ids."""

    def __init__(
        self,
        db: _Db,
        signer: Signer | None = None,
        anchor: Any = None,
        checkpoint_every: int = 100,
    ) -> None:
        self._db, self.signer, self.anchor = db, signer, anchor
        # A custom anchor kind written before alg and key_id existed takes three arguments: it still works (its
        # objects just lack the two fields) and is logged once, instead of failing every put with a TypeError.
        self._anchor_takes_meta = not hasattr(anchor, "put") or _takes_meta(anchor.put)
        if not self._anchor_takes_meta:
            _LOG.warning(
                "audit anchor put() takes no alg/key_id: its objects will not verify offline"
            )
        self.checkpoint_every = checkpoint_every
        # Last resort when even the outbox table cannot be written (the database is down): drained by reconcile.
        self._pending: list[AuditEvent] = []
        # Checkpoints whose anchor put failed: retried by the next checkpoint() (ponytail: in-process only; a
        # restart drops the list and `verify` then reports "never anchored", which is the truth).
        self._unanchored: dict[int, tuple[str, str]] = {}

    # --- AuditSink ----------------------------------------------------------------------------------

    def _append(self, event: AuditEvent) -> str:
        body = event.model_dump_json()
        at = event.ts.astimezone(UTC).isoformat(timespec="microseconds")
        kind = f"{event.domain}.{event.operation}"
        with self._db.transaction() as q:
            if q("SELECT 1 FROM audit_entries WHERE event_id = ?", (event.event_id,)):
                raise DuplicateEvent(event.event_id)
            last = q("SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1")
            seq, prev = (last[0][0] + 1, last[0][1]) if last else (1, GENESIS)
            q(
                "INSERT INTO audit_entries (seq, at, run_id, kind, body, prev, hash, event_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    seq,
                    at,
                    event.run_id,
                    kind,
                    body,
                    prev,
                    _hash(prev, seq, at, event.run_id, kind, body),
                    event.event_id,
                ),
            )
        if self.signer is not None and seq % self.checkpoint_every == 0:
            self.checkpoint()
        return event.event_id

    def write_intent(self, event: AuditEvent) -> str:
        try:
            return self._append(event)
        except DuplicateEvent:
            raise
        except Exception as exc:
            raise AuditUnavailable(f"intent {event.event_id}: {exc.__class__.__name__}") from exc

    def write_outcome(self, event: AuditEvent) -> str | None:
        """Never raises: the chain, then the outbox table, then memory (all drained by reconcile)."""
        try:
            return self._append(event)
        except DuplicateEvent:
            return event.event_id
        except Exception:  # noqa: BLE001 - the contract is "never raises"
            try:
                self._db.run(
                    "INSERT INTO audit_outbox (event_id, body) VALUES (?, ?) "
                    "ON CONFLICT (event_id) DO NOTHING",
                    (event.event_id, event.model_dump_json()),
                )
            except Exception:  # noqa: BLE001
                self._pending.append(event)
            return None

    def reconcile(self) -> int:
        done = 0
        for event in list(self._pending):
            if self._drain(event):
                self._pending.remove(event)
                done += 1
        try:
            queued = self._db.run("SELECT event_id, body FROM audit_outbox ORDER BY event_id")
        except Exception:  # noqa: BLE001 - the database is still down: retried next time
            return done
        for event_id, body in queued:
            if self._drain(AuditEvent.model_validate_json(body)):
                self._db.run("DELETE FROM audit_outbox WHERE event_id = ?", (event_id,))
                done += 1
        return done

    def _drain(self, event: AuditEvent) -> bool:
        try:
            self._append(event)
        except DuplicateEvent:
            pass
        except Exception:  # noqa: BLE001 - stays queued, retried next time
            return False
        return True

    def verify_object(self, key: str) -> bool:
        """The event's row holds its own content's hash and links to the row before it, which holds its own."""
        found = self._db.run("SELECT seq FROM audit_entries WHERE event_id = ?", (key,))
        if not found:
            return False
        s = found[0][0]
        rows = self._db.run(
            "SELECT seq, at, run_id, kind, body, prev, hash FROM audit_entries "
            "WHERE seq IN (?, ?) ORDER BY seq",
            (s - 1, s),
        )
        by = {r[0]: r for r in rows}
        row, before = by.get(s), by.get(s - 1)
        if row is None or (s > 1 and before is None):
            return False
        prev = before[6] if before else GENESIS
        return (
            row[5] == prev
            and _hash(row[5], *row[:5]) == row[6]
            and (before is None or _hash(before[5], *before[:5]) == before[6])
        )

    def events(self, run_id: str | None = None) -> list[AuditEvent]:
        if run_id is None:
            rows = self._db.run("SELECT body FROM audit_entries ORDER BY seq")
        else:
            rows = self._db.run(
                "SELECT body FROM audit_entries WHERE run_id = ? ORDER BY seq", (run_id,)
            )
        return [AuditEvent.model_validate_json(body) for (body,) in rows]

    # --- checkpoints and verification ---------------------------------------------------------------

    def signed_through(self) -> int:
        """The last row a checkpoint covers (0 when none does)."""
        top = self._db.run("SELECT MAX(seq) FROM audit_checkpoints")
        return int(top[0][0]) if top and top[0][0] is not None else 0

    def checkpoint(self) -> int | None:
        """Sign the current head (once) and anchor it. Returns the head's seq, or None when there is nothing to
        sign, no signer, or the signing failed. Never raises: a failure is logged by its kind only and the next
        call retries; the chain itself is untouched."""
        if self.signer is None:
            return None
        try:
            self._retry_anchors()
            last = self._db.run("SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1")
            if not last:
                return None
            seq, head = last[0]
            if self.signed_through() >= seq:
                return seq
            signature = self.signer.sign(_signed_message(seq, head)).hex()
            new = self._db.run(
                "INSERT INTO audit_checkpoints (seq, hash, signature) VALUES (?, ?, ?) "
                "ON CONFLICT (seq) DO NOTHING RETURNING seq",
                (seq, head, signature),
            )
        except Exception as exc:  # noqa: BLE001 - evidence, not a gate (design 4.8)
            _LOG.error("audit checkpoint not signed (%s); retried next time", type(exc).__name__)
            return None
        if new and self.anchor is not None:
            self._anchor(seq, head, signature)
        return seq

    def _anchor(self, seq: int, head: str, signature: str) -> None:
        try:
            if self._anchor_takes_meta:
                self.anchor.put(
                    seq, head, signature, alg=self.signer.alg, key_id=self.signer.key_id
                )
            else:
                self.anchor.put(seq, head, signature)
        except Exception as exc:  # noqa: BLE001 - an anchor outage must not stop the recording
            _LOG.error(
                "audit checkpoint %s not anchored (%s); retried next time", seq, type(exc).__name__
            )
            self._unanchored[seq] = (head, signature)
        else:
            self._unanchored.pop(seq, None)

    def _retry_anchors(self) -> None:
        for seq, (head, signature) in sorted(self._unanchored.items()):
            self._anchor(seq, head, signature)

    def verify(self) -> Verification:
        """Recompute the whole chain, check every checkpoint signature and, with an anchor, every anchor. Never
        raises: damage or an unreachable store is a finding."""
        try:
            rows = self._db.run(_ALL_ROWS)
            checkpoints = self._db.run(
                "SELECT seq, hash, signature FROM audit_checkpoints ORDER BY seq"
            )
            public = self.signer.public_key() if self.signer is not None else None
            anchors = self.anchor.all() if self.anchor is not None else None
        except Exception as exc:  # noqa: BLE001
            # The class only: driver messages can carry the host and user.
            return Verification(
                problems=[f"the audit cannot be read ({type(exc).__name__})"], unreadable=True
            )
        alg = self.signer.alg if self.signer is not None else "ed25519"
        return verify_rows(rows, checkpoints, public, anchors, alg)


def verify_rows(
    rows: list,
    checkpoints: list,
    public_key: bytes | None,
    anchors: dict[int, tuple[str, str]] | None = None,
    alg: Alg = "ed25519",
) -> Verification:
    """Rows and checkpoints as read from the tables, in seq order. With `anchors`, every checkpoint must also
    match the copy written out of reach when it was made."""
    result = Verification(rows=len(rows))
    hashes = _check_chain(rows, result.problems)
    if public_key is None:
        if checkpoints:
            result.problems.append("checkpoints exist but no signer is configured to check them")
    else:
        _check_checkpoints(checkpoints, hashes, public_key, result, alg)
    if anchors is not None:
        _check_anchors(checkpoints, anchors, result.problems)
    return result


def _check_chain(rows: list, problems: list[str]) -> dict[int, str]:
    hashes: dict[int, str] = {}
    prev = GENESIS
    for expected, row in enumerate(rows, 1):
        seq, at, run_id, kind, body, stored_prev, stored_hash, event_id = row
        if seq != expected:
            problems.append(f"row {expected} is missing (next row is {seq})")
        if stored_prev != prev:
            problems.append(f"row {seq} does not link to the row before it")
        if _hash(stored_prev, seq, at, run_id, kind, body) != stored_hash:
            problems.append(f"row {seq} was changed after it was written")
        elif _body_event_id(body) != event_id:
            # The event_id column is outside the hash (it is the dedupe index); the body inside it names
            # the event, so a changed column (pointing verify_object or a dedupe elsewhere) is caught here.
            problems.append(f"row {seq} event id column does not match its body")
        hashes[seq] = stored_hash
        prev = stored_hash
    return hashes


def _body_event_id(body: str) -> str | None:
    try:
        return json.loads(body).get("event_id")
    except (ValueError, AttributeError):
        return None


def _check_checkpoints(
    checkpoints: list,
    hashes: dict[int, str],
    public_key: bytes,
    result: Verification,
    alg: Alg = "ed25519",
) -> None:
    for seq, head, signature in checkpoints:
        try:
            raw = bytes.fromhex(signature)
        except ValueError:
            raw = b""
        if not verify_signature(public_key, raw, _signed_message(seq, head), alg):
            result.problems.append(f"checkpoint {seq} has an invalid signature")
            continue
        if hashes.get(seq) != head:
            result.problems.append(f"checkpoint {seq} was signed over a different history")
            continue
        result.signed_through = max(result.signed_through, seq)


def _check_anchors(
    checkpoints: list, anchors: dict[int, tuple[str, str]], problems: list[str]
) -> None:
    stored = {seq: (head, signature) for seq, head, signature in checkpoints}
    for seq, pair in sorted(stored.items()):
        if seq not in anchors:
            problems.append(f"checkpoint {seq} was never anchored")
        elif anchors[seq] != pair:
            problems.append(f"checkpoint {seq} differs from its anchor: the history was rewritten")
    for seq in sorted(set(anchors) - set(stored)):
        problems.append(f"anchor {seq} has no checkpoint here: the database lost history")


def verify_anchor_bodies(bodies: list[bytes], public_key: bytes) -> list[str]:
    """Offline: check the anchor objects alone against a public key. The scheme and key name come from each
    body (`alg`, `key_id`), so nothing else has to be known; a body without them is a finding."""
    if not bodies:
        return ["no anchor objects given: nothing was verified"]
    problems = []
    key_ids = set()
    seqs: set[int] = set()
    for raw in bodies:
        try:
            a = json.loads(raw)
            seq, head, alg = a["seq"], a["hash"], a["alg"]
            key_id = a["key_id"]
            if type(seq) is not int or seq < 1 or not isinstance(key_id, str) or not key_id:
                raise TypeError("seq or key_id")
            key_ids.add(key_id)
            signature = bytes.fromhex(a["signature"])
        except (ValueError, KeyError, TypeError):
            problems.append("an anchor body is unreadable or has no alg and key_id")
            continue
        if seq in seqs:
            problems.append(f"anchor {seq} appears twice")
        seqs.add(seq)
        if not verify_signature(public_key, signature, _signed_message(seq, head), alg):
            problems.append(f"anchor {seq} has an invalid signature")
    if len(key_ids) > 1:
        problems.append(f"anchors report {len(key_ids)} different key IDs: {sorted(key_ids)}")
    return problems


# --------------------------------------------------------------------------- table factory


def build(settings, deps) -> ChainAudit:
    """`backends.audit: {kind: chain, checkpoint_every, anchor}`, in the store's database."""
    from hadavin_sdk.store.memory import MemoryStore

    store = deps.store
    if isinstance(store, MemoryStore):
        db = _Db.memory()
    elif hasattr(store, "_db") and hasattr(store, "_lock"):
        # The postgres store's connection and lock (one connection per process; schema from `migrate`).
        db = _Db(store._db, store._lock, pg=True)
        try:
            db.run("SELECT 1 FROM audit_checkpoints LIMIT 1")
        except Exception as exc:  # noqa: BLE001 - any driver error here means "not migrated or unreachable"
            raise ConfigError(
                f"audit chain: the audit tables are missing; run hadavin-sdk migrate "
                f"({type(exc).__name__})"
            ) from None
    else:
        raise ConfigError("audit chain: needs store memory or postgres")
    if deps.anchor is not None and deps.signer is None:
        raise ConfigError("audit chain: an anchor needs a signer (backends.signer)")
    # The anchor is its own capability (backends.anchor), built before the audit and handed in through Deps.
    return ChainAudit(db, deps.signer, deps.anchor, settings.checkpoint_every)
