"""Local-folder audit sink. Objects are opened with mode "x", so a retry never makes a second object."""

from __future__ import annotations

import hashlib
import json
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

    def _write(self, event: AuditEvent) -> str:
        body = event.model_dump_json().encode("utf-8")
        key = f"{event.event_id}.json"
        with self._lock:
            self.objects.mkdir(parents=True, exist_ok=True)
            try:
                with open(self.objects / key, "xb") as f:
                    f.write(body)
            except FileExistsError:
                raise DuplicateEvent(event.event_id) from None
            entry = {"key": key, "run_id": event.run_id, "sha256": hashlib.sha256(body).hexdigest()}
            with open(self.index, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        return key

    def write_intent(self, event: AuditEvent) -> str:
        try:
            return self._write(event)
        except DuplicateEvent:
            raise
        except OSError as exc:
            raise AuditUnavailable(f"intent {event.event_id}: {exc.__class__.__name__}") from exc

    def write_outcome(self, event: AuditEvent) -> str | None:
        try:
            return self._write(event)
        except DuplicateEvent:
            return f"{event.event_id}.json"
        except OSError:
            self.outbox.mkdir(parents=True, exist_ok=True)
            (self.outbox / f"{event.event_id}.json").write_text(
                event.model_dump_json(), encoding="utf-8"
            )
            return None

    def reconcile(self) -> int:
        if not self.outbox.exists():
            return 0
        done = 0
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
