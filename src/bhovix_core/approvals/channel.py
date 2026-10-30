"""Approval channel Protocol and the fake channel. Channel text is template-built, redacted and link-free."""

from __future__ import annotations

import re
from typing import Protocol

from bhovix_core.guard.redact import redact
from bhovix_core.models import ApprovalRequest

# Copied then edited from WARDEN gate.py: no clickable links or images in text people act on.
_LINK = re.compile(r"(?i)\b(?:https?|ftp)://\S+|\bwww\.\S+|!\[[^\]]*\]\([^)]*\)|<[^>|]+\|[^>]*>")


def clean(text: str) -> str:
    text, _ = redact(text)
    return _LINK.sub("[link removed]", text)


class Channel(Protocol):
    name: str

    def send(self, req: ApprovalRequest, approver_ids: list[str]) -> str: ...
    def update(self, req: ApprovalRequest) -> None: ...
    def notify(self, principal_id: str, text: str) -> None: ...


class FakeChannel:
    name = "fake"

    def __init__(self) -> None:
        self.sent: list[tuple[str, str, list[str]]] = []
        self.updates: list[tuple[str, str]] = []
        self.notices: list[tuple[str, str]] = []

    def send(self, req: ApprovalRequest, approver_ids: list[str]) -> str:
        self.sent.append((req.approval_id, clean(req.summary), list(approver_ids)))
        return f"fake-{len(self.sent)}"

    def update(self, req: ApprovalRequest) -> None:
        self.updates.append((req.approval_id, req.status))

    def notify(self, principal_id: str, text: str) -> None:
        self.notices.append((principal_id, clean(text)))
