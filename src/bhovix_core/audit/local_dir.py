"""Local-folder audit sink for slice 1 (laptop, fakes).

Each object is written to a temp file, fsynced, then hard-linked into place: the link fails if the object exists,
so a retry never makes a second object and a crash never leaves a half-written one.

Limitation (stated, not hidden): ``verify_object`` compares against ``index.jsonl`` in the same folder, so someone
who can write the folder can rewrite both. There is no hash chain or signature here; tamper evidence comes with
the S3 Object Lock sink and the signed daily checkpoint (owner decision OD-4, before the first deployment).
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from pathlib import Path

from bhovix_core.audit.protocol import AuditUnavailable, DuplicateEvent
from bhovix_core.models import AuditEvent


class LocalDirSink:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.outbox = self.root / "outbox"
        self.index = self.root / "index.jsonl"
        self._lock = threading.Lock()
        # Last resort when even the outbox folder cannot be written: kept in memory for reconcile.
        self._pending: list[AuditEvent] = []

    def _indexed(self, key: str) -> bool:
        # ponytail: O(n) scan of index.jsonl, only on the rare duplicate/half-write path of the local sink.
        # Fine at laptop scale; keep an in-memory key set (or let S3's object listing answer) if it ever matters.
        if not self.index.exists():
            return False
        return any(json.loads(x)["key"] == key for x in self.index.read_text("utf-8").splitlines())

    def _write(self, event: AuditEvent) -> str:
        body = event.model_dump_json().encode("utf-8")
        key = f"{event.event_id}.json"
        entry = {"key": key, "run_id": event.run_id, "sha256": hashlib.sha256(body).hexdigest()}
        with self._lock:
            self.objects.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.objects, prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(body)
                    f.flush()
                    os.fsync(f.fileno())
                try:
                    os.link(tmp, self.objects / key)  # atomic, and fails if the object exists
                except FileExistsError:
                    # Same bytes and no index line = a half-finished earlier write: finish it.
                    if self._indexed(key) or (self.objects / key).read_bytes() != body:
                        raise DuplicateEvent(event.event_id) from None
            finally:
                Path(tmp).unlink(missing_ok=True)
            with open(self.index, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
        return key

    def write_intent(self, event: AuditEvent) -> str:
        try:
            return self._write(event)
        except DuplicateEvent:
            raise
        except OSError as exc:
            raise AuditUnavailable(f"intent {event.event_id}: {exc.__class__.__name__}") from exc

    def write_outcome(self, event: AuditEvent) -> str | None:
        """Never raises: object store, then outbox, then memory (drained by reconcile)."""
        try:
            return self._write(event)
        except DuplicateEvent:
            return f"{event.event_id}.json"
        except Exception:  # noqa: BLE001 - disk errors, a corrupt index line: the contract is "never raises"
            try:
                self.outbox.mkdir(parents=True, exist_ok=True)
                (self.outbox / f"{event.event_id}.json").write_text(
                    event.model_dump_json(), encoding="utf-8"
                )
            except Exception:  # noqa: BLE001
                self._pending.append(event)
            return None

    def reconcile(self) -> int:
        done = 0
        for event in list(self._pending):
            try:
                self._write(event)
            except DuplicateEvent:
                pass
            except OSError:
                continue
            self._pending.remove(event)
            done += 1
        if not self.outbox.exists():
            return done
        for path in sorted(self.outbox.glob("*.json")):
            event = AuditEvent.model_validate_json(path.read_text(encoding="utf-8"))
            try:
                self._write(event)
            except DuplicateEvent:
                pass
            except OSError:
                continue
            path.unlink()
            done += 1
        return done

    def verify_object(self, key: str) -> bool:
        body = (self.objects / key).read_bytes()
        digest = hashlib.sha256(body).hexdigest()
        for line in self.index.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            if entry["key"] == key:
                return entry["sha256"] == digest
        return False

    def events(self, run_id: str | None = None) -> list[AuditEvent]:
        """Read back, in write order (index order)."""
        if not self.index.exists():
            return []
        out = []
        for line in self.index.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            if run_id is None or entry["run_id"] == run_id:
                out.append(
                    AuditEvent.model_validate_json(
                        (self.objects / entry["key"]).read_text(encoding="utf-8")
                    )
                )
        return out
