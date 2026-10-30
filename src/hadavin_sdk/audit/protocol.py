"""Audit sink Protocol: write-once events, hashes and codes only. ``local_dir`` now, ``s3`` at S11."""

from __future__ import annotations

from typing import Protocol

from hadavin_sdk.models import AuditEvent


class AuditUnavailable(RuntimeError):
    """An intent event could not be written; the side effect must not happen."""


class DuplicateEvent(RuntimeError):
    pass


class AuditSink(Protocol):
    def write_intent(self, event: AuditEvent) -> str:
        """Write before a side effect. Raises AuditUnavailable on any failure."""
        ...

    def write_outcome(self, event: AuditEvent) -> str | None:
        """Write after a side effect. On failure the event goes to the outbox; never raises."""
        ...

    def reconcile(self) -> int:
        """Drain the outbox. Returns how many events were written."""
        ...

    def verify_object(self, key: str) -> bool: ...
